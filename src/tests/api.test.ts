import { describe, expect, it } from 'vitest'
import { AccessVerifier, BetterAuthClient, BetterAuthServer } from '../api'
import {
  IAuthenticationPaths,
  INetwork,
  ISigningKey,
  IVerificationKey,
  IVerifier,
} from '../interfaces'
import {
  ClientRotatingKeyStore,
  ClientValueStore,
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
} from './implementation'
import { AccessRequest, ServerResponse } from '../messages'

const DEBUG_LOGGING = false
const authenticationPaths: IAuthenticationPaths = {
  register: {
    create: '/register/create',
    link: '/register/link',
    recover: '/register/recover',
  },
  authenticate: {
    start: '/authenticate/start',
    finish: '/authenticate/finish',
  },
  rotate: {
    authentication: '/rotate/authentication',
    access: '/rotate/access',
  },
}

interface IMockAccessAttributes {
  permissionsByRole: object
}

class MockAccessAttributes implements IMockAccessAttributes {
  constructor(public permissionsByRole: object) {}
}

class MockNetworkServer implements INetwork {
  constructor(
    private readonly betterAuthServer: BetterAuthServer,
    private readonly accessVerifier: AccessVerifier,
    private readonly responseSigner: ISigningKey,
    private readonly attributes: IMockAccessAttributes,
    private readonly paths: IAuthenticationPaths
  ) {}

  async respondToAccessRequest(message: string, nonce?: string): Promise<string> {
    const request = AccessRequest.parse<IFakeRequest>(message)

    let replyNonce = request.payload.access.nonce
    if (typeof nonce !== 'undefined') {
      replyNonce = nonce
    }

    const response = new FakeResponse(
      {
        wasFoo: request.payload.request.foo,
        wasBar: request.payload.request.bar,
      },
      await this.responseSigner.public(),
      replyNonce
    )

    await response.sign(this.responseSigner)
    return response.serialize()
  }

  async sendRequest(path: string, message: string): Promise<string> {
    if (DEBUG_LOGGING) {
      console.log(message)
    }

    const reply = await this._sendRequest(path, message)

    if (DEBUG_LOGGING) {
      console.log(reply)
    }

    return reply
  }

  async _sendRequest(path: string, message: string): Promise<string> {
    let accessIdentity: string
    let attributes: MockAccessAttributes

    switch (path) {
      case this.paths.register.create:
        return await this.betterAuthServer.createAccount(message)
      case this.paths.register.recover:
        return await this.betterAuthServer.recoverAccount(message)
      case this.paths.register.link:
        return await this.betterAuthServer.linkDevice(message)
      case this.paths.rotate.authentication:
        return await this.betterAuthServer.rotateAuthenticationKey(message)
      case this.paths.authenticate.start:
        return await this.betterAuthServer.startAuthentication(message)
      case this.paths.authenticate.finish:
        return await this.betterAuthServer.finishAuthentication(message, this.attributes)
      case this.paths.rotate.access:
        return await this.betterAuthServer.refreshAccessToken<IMockAccessAttributes>(message)
      case '/foo/bar':
        ;[accessIdentity, attributes] = await this.accessVerifier.verify<
          IFakeRequest,
          IMockAccessAttributes
        >(message)

        if (typeof accessIdentity === 'undefined') {
          throw 'null identity'
        }

        if (!accessIdentity.startsWith('E')) {
          throw 'unexpected identity format'
        }

        if (accessIdentity.length !== 44) {
          throw 'unexpected identity length'
        }

        if (JSON.stringify(attributes) !== JSON.stringify(this.attributes)) {
          throw 'attributes do not match'
        }

        return await this.respondToAccessRequest(message)
      case '/bad/nonce':
        ;[accessIdentity, attributes] = await this.accessVerifier.verify<
          IFakeRequest,
          IMockAccessAttributes
        >(message)

        if (typeof accessIdentity === 'undefined') {
          throw 'null identity'
        }

        if (!accessIdentity.startsWith('E')) {
          throw 'unexpected identity format'
        }

        if (accessIdentity.length !== 44) {
          throw 'unexpected identity length'
        }

        if (JSON.stringify(attributes) !== JSON.stringify(this.attributes)) {
          throw 'attributes do not match'
        }

        return await this.respondToAccessRequest(message, '0A0123456789abcdefghijkl')
      default:
        throw 'unexpected message'
    }
  }
}

interface IFakeRequest {
  foo: string
  bar: string
}

interface IFakeResponse {
  wasFoo: string
  wasBar: string
}

class FakeResponse extends ServerResponse<IFakeResponse> {
  static parse(message: string): FakeResponse {
    return ServerResponse._parse(message, FakeResponse)
  }
}

async function executeFlow(
  betterAuthClient: BetterAuthClient,
  eccVerifier: IVerifier,
  responseSigner: ISigningKey
) {
  await betterAuthClient.rotateAuthenticationKey()
  await betterAuthClient.authenticate()
  await betterAuthClient.refreshAccessToken()

  await testAccess(betterAuthClient, eccVerifier, responseSigner)
}

async function testAccess(
  betterAuthClient: BetterAuthClient,
  eccVerifier: IVerifier,
  responseSigner: ISigningKey
): Promise<void> {
  const message = {
    foo: 'bar',
    bar: 'foo',
  }
  const reply = await betterAuthClient.makeAccessRequest<IFakeRequest>('/foo/bar', message)
  const response = FakeResponse.parse(reply)

  await response.verify(eccVerifier, await responseSigner.public())

  if (response.payload.response.wasFoo !== 'bar' || response.payload.response.wasBar !== 'foo') {
    throw 'invalid data returned'
  }
}

async function createServer(args: {
  expiry: {
    accessLifetimeInMinutes: number
    authenticationChallengeLifetimeInSeconds: number
    refreshLifetimeInHours: number
  }
  keys: {
    accessSigner: ISigningKey
    responseSigner: ISigningKey
  }
}): Promise<BetterAuthServer> {
  const eccVerifier = new Secp256r1Verifier()
  const hasher = new Hasher()
  const noncer = new Noncer()

  const accessKeyHashStore = new ServerTimeLockStore(60 * 60 * args.expiry.refreshLifetimeInHours)
  const authenticationNonceStore = new ServerAuthenticationNonceStore(
    args.expiry.authenticationChallengeLifetimeInSeconds
  )

  const betterAuthServer = new BetterAuthServer({
    crypto: {
      hasher: hasher,
      keyPair: {
        access: args.keys.accessSigner,
        response: args.keys.responseSigner,
      },
      noncer: noncer,
      verifier: eccVerifier,
    },
    encoding: {
      identityVerifier: new IdentityVerifier(),
      timestamper: new Rfc3339Nano(),
      tokenEncoder: new TokenEncoder(),
    },
    expiry: {
      accessInMinutes: args.expiry.accessLifetimeInMinutes,
      refreshInHours: args.expiry.refreshLifetimeInHours,
    },
    store: {
      access: {
        // the lock time is the refresh lifetime in seconds
        keyHash: accessKeyHashStore,
      },
      authentication: {
        key: new ServerAuthenticationKeyStore(),
        nonce: authenticationNonceStore,
      },
      recovery: {
        hash: new ServerRecoveryHashStore(),
      },
    },
  })

  return betterAuthServer
}

async function createVerifier(args: {
  expiry: {
    accessWindowInSeconds: number
  }
  keys: {
    accessVerifier: IVerificationKey
  }
}): Promise<AccessVerifier> {
  const eccVerifier = new Secp256r1Verifier()
  const accessNonceStore = new ServerTimeLockStore(args.expiry.accessWindowInSeconds)

  const accessVerifier = new AccessVerifier({
    crypto: {
      publicKey: {
        access: args.keys.accessVerifier,
      },
      verifier: eccVerifier,
    },
    encoding: {
      tokenEncoder: new TokenEncoder(),
      timestamper: new Rfc3339Nano(),
    },
    store: {
      access: {
        nonce: accessNonceStore,
      },
    },
  })

  return accessVerifier
}

describe('api', () => {
  it('completes auth flows', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()
    const recoverySigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()
    await recoverySigner.generate()

    const betterAuthServer = await createServer({
      expiry: {
        refreshLifetimeInHours: 12,
        accessLifetimeInMinutes: 15,
        authenticationChallengeLifetimeInSeconds: 60,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      },
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner,
      },
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes,
      authenticationPaths
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)
    await executeFlow(betterAuthClient, eccVerifier, responseSigner)
  })

  it('recovers from loss', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()
    const recoverySigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()
    await recoverySigner.generate()

    const betterAuthServer = await createServer({
      expiry: {
        refreshLifetimeInHours: 12,
        accessLifetimeInMinutes: 15,
        authenticationChallengeLifetimeInSeconds: 60,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      },
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner,
      },
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes,
      authenticationPaths
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const recoveredBetterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: new Hasher(),
        noncer: new Noncer(),
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)
    const identity = await betterAuthClient.identity()
    await recoveredBetterAuthClient.recoverAccount(identity, recoverySigner)
    await executeFlow(recoveredBetterAuthClient, eccVerifier, responseSigner)
  })

  it('links another device', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()
    const recoverySigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()
    await recoverySigner.generate()

    const betterAuthServer = await createServer({
      expiry: {
        refreshLifetimeInHours: 12,
        accessLifetimeInMinutes: 15,
        authenticationChallengeLifetimeInSeconds: 60,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      },
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner,
      },
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes,
      authenticationPaths
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const linkedBetterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: new Hasher(),
        noncer: new Noncer(),
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)
    const identity = await betterAuthClient.identity()

    // get link container from the new device
    const linkContainer = await linkedBetterAuthClient.generateLinkContainer(identity)
    if (DEBUG_LOGGING) {
      console.log(linkContainer)
    }

    // submit an endorsed link container with existing device
    await betterAuthClient.linkDevice(linkContainer)
    await executeFlow(linkedBetterAuthClient, eccVerifier, responseSigner)
  })

  it('rejects expired authentication challenges', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()
    const recoverySigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()
    await recoverySigner.generate()

    const betterAuthServer = await createServer({
      expiry: {
        refreshLifetimeInHours: 12,
        accessLifetimeInMinutes: 15,
        authenticationChallengeLifetimeInSeconds: -5,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      },
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner,
      },
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes,
      authenticationPaths
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    try {
      await executeFlow(betterAuthClient, eccVerifier, responseSigner)
      throw 'expected a failure'
    } catch (e: unknown) {
      expect(e).toBe('expired nonce')
    }
  })

  it('rejects expired refresh tokens', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()
    const recoverySigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()
    await recoverySigner.generate()

    const betterAuthServer = await createServer({
      expiry: {
        refreshLifetimeInHours: -1,
        accessLifetimeInMinutes: 15,
        authenticationChallengeLifetimeInSeconds: 60,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      },
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner,
      },
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes,
      authenticationPaths
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    try {
      await executeFlow(betterAuthClient, eccVerifier, responseSigner)
      throw 'expected a failure'
    } catch (e: unknown) {
      expect(e).toBe('refresh has expired')
    }
  })

  it('rejects expired access tokens', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()
    const recoverySigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()
    await recoverySigner.generate()

    const betterAuthServer = await createServer({
      expiry: {
        refreshLifetimeInHours: 12,
        accessLifetimeInMinutes: -1,
        authenticationChallengeLifetimeInSeconds: 60,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      },
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner,
      },
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes,
      authenticationPaths
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    try {
      await executeFlow(betterAuthClient, eccVerifier, responseSigner)
      throw 'expected a failure'
    } catch (e: unknown) {
      expect(e).toBe('token expired')
    }
  })

  it('detects tampered access tokens', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()
    const recoverySigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()
    await recoverySigner.generate()

    const betterAuthServer = await createServer({
      expiry: {
        refreshLifetimeInHours: 12,
        accessLifetimeInMinutes: 15,
        authenticationChallengeLifetimeInSeconds: 60,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      },
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner,
      },
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes,
      authenticationPaths
    )

    const accessTokenStore = new ClientValueStore()
    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: accessTokenStore,
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    const tokenEncoder = new TokenEncoder()
    try {
      await betterAuthClient.authenticate()
      const token = await accessTokenStore.get()
      const tokenString = await tokenEncoder.decode(token.substring(88))
      const tamperedTokenString = tokenString.replace('"identity":"E', '"identity":"X')
      const tamperedToken = await tokenEncoder.encode(tamperedTokenString)
      await accessTokenStore.store(token.substring(0, 88) + tamperedToken)
      await testAccess(betterAuthClient, eccVerifier, responseSigner)

      throw 'expected a failure'
    } catch (e: unknown) {
      expect(e).toBe('invalid signature')
    }
  })

  it('detects mismatched access nonce', async () => {
    const hasher = new Hasher()
    const noncer = new Noncer()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()
    const recoverySigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()
    await recoverySigner.generate()

    const betterAuthServer = await createServer({
      expiry: {
        refreshLifetimeInHours: 12,
        accessLifetimeInMinutes: 15,
        authenticationChallengeLifetimeInSeconds: 60,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      },
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner,
      },
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes,
      authenticationPaths
    )

    const accessTokenStore = new ClientValueStore()
    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: mockNetworkServer,
      },
      paths: authenticationPaths,
      store: {
        identifier: {
          device: new ClientValueStore(),
          identity: new ClientValueStore(),
        },
        key: {
          access: new ClientRotatingKeyStore(),
          authentication: new ClientRotatingKeyStore(),
        },
        token: {
          access: accessTokenStore,
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    try {
      await betterAuthClient.authenticate()
      const message = {
        foo: 'bar',
        bar: 'foo',
      }
      await betterAuthClient.makeAccessRequest<IFakeRequest>('/bad/nonce', message)

      throw 'expected a failure'
    } catch (e: unknown) {
      expect(e).toBe('incorrect nonce')
    }
  })
})
