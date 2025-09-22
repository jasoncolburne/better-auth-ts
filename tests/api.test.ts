import { beforeAll, describe, it } from 'vitest'
import { AccessVerifier, BetterAuthClient, BetterAuthServer } from '../src/api'
import { INetwork, ISalter, ISigningKey, IVerifier } from '../src/interfaces'
import {
  ServerAccessNonceStore,
  ServerAuthenticationKeyStore,
  ServerAuthenticationNonceStore,
  ServerAuthenticationRegistrationTokenStore,
  ServerPassphraseAuthenticationKeyStore,
  ServerPassphraseRegistrationTokenStore,
  ServerRefreshKeyStore,
  ServerRefreshNonceStore,
} from './server.storage.mocks'
import {
  Digester,
  Ed25519Verifier,
  KeyDeriver,
  Noncer,
  Secp256r1,
  Secp256r1Verifier,
} from './crypto'
import {
  ClientRefreshNonceStore,
  ClientRotatingKeyStore,
  ClientSingleKeyStore,
  ClientValueStore,
} from './client.storage.mocks'
import { AccessRequest, ServerResponse } from '../src/messages'

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
    private readonly noncer: ISalter,
    private readonly attributes: IMockAccessAttributes
  ) {}

  async respondToAccessRequest(message: string): Promise<string> {
    const request = AccessRequest.parse<IFakeRequest>(message)

    const response = new FakeResponse(
      {
        wasFoo: request.payload.request.foo,
        wasBar: request.payload.request.bar,
      },
      await this.responseSigner.public(),
      request.payload.access.nonce
    )

    await response.sign(this.responseSigner)
    return response.serialize()
  }

  async sendRequest(path: string, message: string): Promise<string> {
    switch (path) {
      case '/auth/key/register':
        return await this.betterAuthServer.registerAuthenticationKey(message)
      case '/auth/key/rotate':
        return await this.betterAuthServer.rotateAuthenticationKey(message)
      case '/auth/key/begin':
        return await this.betterAuthServer.beginAuthentication(message)
      case '/auth/key/complete':
        return await this.betterAuthServer.completeAuthentication(message)
      case '/auth/passphrase/register':
        return await this.betterAuthServer.registerPassphraseAuthenticationKey(message)
      case '/auth/passphrase/begin':
        return await this.betterAuthServer.beginPassphraseAuthentication(message)
      case '/auth/passphrase/complete':
        return await this.betterAuthServer.completePassphraseAuthentication(message)
      case '/auth/refresh':
        return await this.betterAuthServer.refreshAccessToken<MockAccessAttributes>(
          message,
          this.attributes
        )
      case '/foo/bar':
        if (!(await this.accessVerifier.verify<IFakeRequest>(message))) {
          throw 'invalid signature'
        }

        return await this.respondToAccessRequest(message)
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

describe('api', () => {
  let betterAuthServer: BetterAuthServer
  let betterAuthClient: BetterAuthClient
  let responseSigner: Secp256r1
  let accessSigner: Secp256r1
  let eccVerifier: IVerifier
  let edVerifier: IVerifier

  beforeAll(async () => {
    responseSigner = new Secp256r1()
    accessSigner = new Secp256r1()

    await responseSigner.generate()
    await accessSigner.generate()

    eccVerifier = new Secp256r1Verifier()
    edVerifier = new Ed25519Verifier()

    betterAuthServer = new BetterAuthServer(
      {
        token: {
          registration: {
            key: new ServerAuthenticationRegistrationTokenStore(),
            passphrase: new ServerPassphraseRegistrationTokenStore(),
          },
        },
        key: {
          authentication: new ServerAuthenticationKeyStore(),
          passphrase: new ServerPassphraseAuthenticationKeyStore(),
          refresh: new ServerRefreshKeyStore(),
        },
        nonce: {
          authentication: new ServerAuthenticationNonceStore(),
          refresh: new ServerRefreshNonceStore(),
          access: new ServerAccessNonceStore(),
        },
      },
      {
        keyPairs: {
          response: responseSigner,
          access: accessSigner,
        },
        verification: {
          key: eccVerifier,
          passphrase: edVerifier,
        },
        nonce: new Noncer(),
        digest: new Digester(),
      }
    )

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)
    const accessVerifier = new AccessVerifier(
      {
        accessNonce: new ServerAccessNonceStore(),
      },
      {
        publicKeys: {
          access: accessSigner,
        },
        verification: {
          key: eccVerifier,
        },
      }
    )
    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      new Noncer(),
      attributes
    )

    betterAuthClient = new BetterAuthClient(
      {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
          session: new ClientValueStore(),
        },
        nonce: {
          refresh: new ClientRefreshNonceStore(),
        },
        token: {
          refresh: new ClientValueStore(),
          access: new ClientValueStore(),
        },
        key: {
          authentication: new ClientRotatingKeyStore(),
          refresh: new ClientSingleKeyStore(),
          access: new ClientSingleKeyStore(),
        },
      },
      {
        digest: new Digester(),
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
        keyDerivation: new KeyDeriver(),
        nonce: new Noncer(),
      },
      {
        network: mockNetworkServer,
      }
    )
  })

  it('completes passphrase auth flow', async () => {
    const passphraseRegistrationMaterials =
      await betterAuthServer.generatePassphraseRegistrationMaterials()

    const passphrase = 'testPassphrase'
    await betterAuthClient.registerPassphraseAuthenticationKey(
      passphraseRegistrationMaterials,
      passphrase
    )
    await betterAuthClient.authenticateWithPassphrase(passphrase)
    await betterAuthClient.refreshAccessToken()

    const reply = await betterAuthClient.makeAccessRequest<IFakeRequest>('/foo/bar', {
      foo: 'foo-y',
      bar: 'bar-y',
    })

    const response = FakeResponse.parse(reply)

    if (!(await response.verify(eccVerifier, await responseSigner.public()))) {
      throw 'invalid signature'
    }

    if (
      response.payload.response.wasFoo !== 'foo-y' ||
      response.payload.response.wasBar !== 'bar-y'
    ) {
      throw 'invalid data returned'
    }
  }, 5000)

  it('completes key auth flow', async () => {
    const registrationMaterials = await betterAuthServer.generateRegistrationMaterials()

    await betterAuthClient.registerAuthenticationKey(registrationMaterials)
    await betterAuthClient.rotateAuthenticationKey()
    await betterAuthClient.authenticate()
    await betterAuthClient.refreshAccessToken()

    const reply = await betterAuthClient.makeAccessRequest<IFakeRequest>('/foo/bar', {
      foo: 'foo-y',
      bar: 'bar-y',
    })
    const response = FakeResponse.parse(reply)

    if (!(await response.verify(eccVerifier, await responseSigner.public()))) {
      throw 'invalid signature'
    }

    if (
      response.payload.response.wasFoo !== 'foo-y' ||
      response.payload.response.wasBar !== 'bar-y'
    ) {
      throw 'invalid data returned'
    }
  }, 5000)
})
