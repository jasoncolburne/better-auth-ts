import { beforeAll, describe, it } from 'vitest'
import { AccessVerifier, BetterAuthClient, BetterAuthServer } from '../src/api'
import { IDigester, INetwork, INoncer, ISigningKey, IVerifier } from '../src/interfaces'
import {
  ServerTimeLockStore,
  ServerAuthenticationKeyStore,
  ServerAuthenticationNonceStore,
  ServerAuthenticationRegistrationTokenStore,
  ServerRecoveryKeyDigestStore,
} from './server.storage.mocks'
import {
  Digester,
  Noncer,
  Secp256r1,
  Secp256r1Verifier,
} from './crypto'
import {
  ClientRotatingKeyStore,
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
      case '/auth/create':
        return await this.betterAuthServer.createAccount(message)
      case '/auth/recover':
        return await this.betterAuthServer.recoverAccount(message)
      case '/auth/link':
        return await this.betterAuthServer.linkDevice(message)
      case '/auth/rotate':
        return await this.betterAuthServer.rotateAuthenticationKey(message)
      case '/auth/begin':
        return await this.betterAuthServer.beginAuthentication(message)
      case '/auth/complete':
        return await this.betterAuthServer.completeAuthentication(message, this.attributes)
      case '/auth/refresh':
        return await this.betterAuthServer.refreshAccessToken<IMockAccessAttributes>(message)
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

    if (!(await response.verify(eccVerifier, await responseSigner.public()))) {
      throw 'invalid signature'
    }

    if (
      response.payload.response.wasFoo !== 'bar' ||
      response.payload.response.wasBar !== 'foo'
    ) {
      throw 'invalid data returned'
    }
}

describe('api', () => {
  let betterAuthServer: BetterAuthServer
  let betterAuthClient: BetterAuthClient
  let recoveryKey: Secp256r1
  let responseSigner: Secp256r1
  let accessSigner: Secp256r1
  let eccVerifier: IVerifier
  let digester: IDigester
  let noncer: INoncer
  let mockNetworkServer: INetwork

  beforeAll(async () => {
    responseSigner = new Secp256r1()
    accessSigner = new Secp256r1()

    await responseSigner.generate()
    await accessSigner.generate()

    eccVerifier = new Secp256r1Verifier()
    digester = new Digester()
    noncer = new Noncer()

    recoveryKey = new Secp256r1()
    await recoveryKey.generate()

    const refreshLifetimeInHours = 12
    const accessLifetimeInMinutes = 15
    const authenticationChallengeLifetimeInSeconds = 60
    const creationTimeoutInMinutes = 30
    const accessWindowInSeconds = 30

    betterAuthServer = new BetterAuthServer(
      {
        registration: {
          token: new ServerAuthenticationRegistrationTokenStore(creationTimeoutInMinutes),
        },
        recovery: {
          key: new ServerRecoveryKeyDigestStore()
        },
        authentication: {
          key: new ServerAuthenticationKeyStore(),
          nonce: new ServerAuthenticationNonceStore(authenticationChallengeLifetimeInSeconds),
        },
        access: {
          // the lock time is the refresh lifetime in seconds
          keyDigest: new ServerTimeLockStore(60 * 60 * refreshLifetimeInHours)
        }
      },
      {
        keyPairs: {
          response: responseSigner,
          access: accessSigner,
        },
        verifier: eccVerifier,
        noncer: noncer,
        digester: digester,
      },
      {
        accessInMinutes: accessLifetimeInMinutes,
        refreshInHours: refreshLifetimeInHours,
      }
    )

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)
    const accessVerifier = new AccessVerifier(
      {
        access: {
          nonce: new ServerTimeLockStore(accessWindowInSeconds),
        }
      },
      {
        publicKeys: {
          access: accessSigner,
        },
        verifier: eccVerifier,
      }
    )
    mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes
    )

    betterAuthClient = new BetterAuthClient(
      {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
        key: {
          authentication: new ClientRotatingKeyStore(),
          access: new ClientRotatingKeyStore(),
        },
      },
      {
        digester: new Digester(),
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
        noncer: new Noncer(),
      },
      {
        network: mockNetworkServer,
      }
    )
  })

  it('completes auth flows', async () => {
    const creationContainer = await betterAuthServer.generateCreationContainer()
    const recoveryKeyDigest = await digester.sum(await recoveryKey.public())

    await betterAuthClient.createAccount(creationContainer, recoveryKeyDigest)
    await betterAuthClient.rotateAuthenticationKey()
    await betterAuthClient.authenticate()
    await betterAuthClient.refreshAccessToken()

    await testAccess(betterAuthClient, eccVerifier, responseSigner)
  })

  it('recovers from loss', async () => {
    const recoveredBetterAuthClient = new BetterAuthClient(
      {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
        key: {
          authentication: new ClientRotatingKeyStore(),
          access: new ClientRotatingKeyStore(),
        },
      },
      {
        digester: new Digester(),
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
        noncer: new Noncer(),
      },
      {
        network: mockNetworkServer,
      }
    )

    // this is saved with the recovery key/derivation material, wherever that is
    const accountId = await betterAuthClient.accountId()

    await recoveredBetterAuthClient.recoverAccount(accountId, recoveryKey)

    await recoveredBetterAuthClient.rotateAuthenticationKey()
    await recoveredBetterAuthClient.authenticate()
    await recoveredBetterAuthClient.refreshAccessToken()

    await testAccess(betterAuthClient, eccVerifier, responseSigner)
  })

  it('links another device', async () => {
    const linkedBetterAuthClient = new BetterAuthClient(
      {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
        },
        token: {
          access: new ClientValueStore(),
        },
        key: {
          authentication: new ClientRotatingKeyStore(),
          access: new ClientRotatingKeyStore(),
        },
      },
      {
        digester: new Digester(),
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
        noncer: new Noncer(),
      },
      {
        network: mockNetworkServer,
      }
    )

    // get account id from the existing device
    const accountId = await betterAuthClient.accountId()

    // get link container from the new device
    const linkContainer = await linkedBetterAuthClient.generateLinkContainer(accountId)

    // submit link containe with existing device
    await betterAuthClient.linkDevice(linkContainer)

    // authenticate and request resource access with the new device
    await linkedBetterAuthClient.rotateAuthenticationKey()
    await linkedBetterAuthClient.authenticate()
    await linkedBetterAuthClient.refreshAccessToken()

    await testAccess(betterAuthClient, eccVerifier, responseSigner)
  })
})
