import {
  AccessVerifier,
  BetterAuthServer,
} from '../../src/api/index.js';
import { ServerResponse } from '../../src/messages/response.js';
import {
  Hasher,
  IdentityVerifier,
  Noncer,
  Rfc3339Nano,
  Secp256r1,
  Secp256r1Verifier,
  ServerAuthenticationKeyStore,
  ServerAuthenticationNonceStore,
  ServerRecoveryHashStore,
  ServerTimeLockStore,
  TokenEncoder,
  VerificationKeyStore,
} from '../../src/tests/implementation/index.js';

interface MockTokenAttributes {
  permissionsByRole: Record<string, string[]>;
}

interface MockRequestPayload {
  foo: string;
  bar: string;
}

interface MockResponsePayload {
  wasFoo: string;
  wasBar: string;
}

class WorkerServer {
  // static persistent store
  private static stores = (globalThis as any).__stores ??= {
    accessKeyHash: new ServerTimeLockStore(12 * 3600),
    accessNonce: new ServerTimeLockStore(30),
    authenticationKey: new ServerAuthenticationKeyStore(),
    authenticationNonce: new ServerAuthenticationNonceStore(60),
    recoveryHash: new ServerRecoveryHashStore(),
  };
  private readonly ba: BetterAuthServer;
  private readonly av: AccessVerifier;
  private readonly serverResponseKey: Secp256r1;
  private readonly accessKeyStore: VerificationKeyStore;
  private readonly serverAccessKey: Secp256r1;

  constructor() {
    const { accessKeyHash, accessNonce, authenticationKey, authenticationNonce, recoveryHash } = WorkerServer.stores;

    const crypto = {
      hasher: new Hasher(),
      verifier: new Secp256r1Verifier(),
      noncer: new Noncer(),
      keyPair: { access: new Secp256r1(), response: new Secp256r1() },
    };

    const encoding = {
      identityVerifier: new IdentityVerifier(),
      timestamper: new Rfc3339Nano(),
      tokenEncoder: new TokenEncoder(),
    };

    const config = { accessInMinutes: 15, refreshInHours: 12 };

    this.serverResponseKey = crypto.keyPair.response;
    this.serverAccessKey = crypto.keyPair.access;
    this.accessKeyStore = new VerificationKeyStore();

    this.ba = new BetterAuthServer({
      crypto,
      encoding,
      expiry: config,
      store: {
        access: { keyHash: accessKeyHash },
        authentication: { key: authenticationKey, nonce: authenticationNonce },
        recovery: { hash: recoveryHash },
      },
    });

    this.av = new AccessVerifier({
      crypto: { verifier: crypto.verifier },
      encoding: { tokenEncoder: encoding.tokenEncoder, timestamper: encoding.timestamper },
      store: { access: { nonce: accessNonce, key: this.accessKeyStore } },
    });
  }

  static async getInstance(): Promise<WorkerServer> {
    const g = globalThis as any;
    if (!g.server) {
      const server = new WorkerServer();
      await server.serverResponseKey.generate();
      await server.serverAccessKey.generate();
      const serverAccessIdentity = await server.serverAccessKey.identity();
      await server.accessKeyStore.add(serverAccessIdentity, server.serverAccessKey);
      g.server = server;
      console.log('[Worker] BetterAuthServer ready');
    }
    return g.server;
  }

  private async wrapResponse(body: string, logic: (message: string) => Promise<string>): Promise<Response> {
    try {
      const data = await logic(body);
      return new Response(data, {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    } catch (e) {
      console.error('error:', e);
      return new Response(JSON.stringify({ error: 'an error occurred' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  }

  private routes(): Record<string, (body: string) => Promise<Response>> {
    return {
      '/account/create': body => this.wrapResponse(body, m => this.ba.createAccount(m)),
      '/account/recover': body => this.wrapResponse(body, m => this.ba.recoverAccount(m)),
      '/account/delete': body => this.wrapResponse(body, m => this.ba.deleteAccount(m)),
      '/session/request': body => this.wrapResponse(body, m => this.ba.requestSession(m)),
      '/session/create': body => this.wrapResponse(body, m => this.ba.createSession<MockTokenAttributes>(m, {
        permissionsByRole: { admin: ['read', 'write'] },
      })),
      '/session/refresh': body => this.wrapResponse(body, m => this.ba.refreshSession(m)),
      '/device/link': body => this.wrapResponse(body, m => this.ba.linkDevice(m)),
      '/device/unlink': body => this.wrapResponse(body, m => this.ba.unlinkDevice(m)),
      '/device/rotate': body => this.wrapResponse(body, m => this.ba.rotateDevice(m)),
      '/recovery/change': body => this.wrapResponse(body, m => this.ba.changeRecoveryKey(m)),
      '/key/response': body => this.wrapResponse(body, async () => this.serverResponseKey.public()),
      '/foo/bar': body => this.wrapResponse(body, m => this.respondToAccessRequest(m, false)),
      '/bad/nonce': body => this.wrapResponse(body, m => this.respondToAccessRequest(m, true)),
    };
  }

  private async respondToAccessRequest(message: string, badNonce: boolean): Promise<string> {
    const [request, _token, requestNonce] = await this.av.verify<MockRequestPayload, MockTokenAttributes>(message);

    const serverIdentity = await this.serverResponseKey.identity();
    const nonce = badNonce ? '0A0123456789' : requestNonce;

    const response = new ServerResponse<MockResponsePayload>(
      { wasFoo: request.foo, wasBar: request.bar },
      serverIdentity,
      nonce,
    );

    await response.sign(this.serverResponseKey);

    return await response.serialize();
  }

  async handleRequest(request: Request): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const url = new URL(request.url);
    console.log('[Worker] request url:', url.toString());
    const routes = this.routes();
    const availablePaths = Object.keys(routes);
    if (!(url.pathname in routes)) {
      console.warn('[Worker] Route not found:', url.pathname);
      console.warn('[Worker] Available routes:', availablePaths);
      return new Response(JSON.stringify({
        error: 'Route not found',
        requested: url.pathname,
        available: availablePaths
      }), { status: 404, headers: { 'Content-Type': 'application/json' } });
    }
    const handler = routes[url.pathname];

    const body = await request.text();
    return handler(body);
  }
}

export default {
  async fetch(request: Request): Promise<Response> {
    try {
      const server = await WorkerServer.getInstance();
      return server.handleRequest(request);
    } catch (err) {
      console.error('[Worker]', err);
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};
