import { beforeAll, describe, expect, it } from 'vitest'
import { AccessVerifier, BetterAuthClient, BetterAuthServer } from '../src/api'
import { IDigester, INetwork, INoncer, IServerRecoveryKeyDigestStore, ISigningKey, IVerificationKey, IVerifier } from '../src/interfaces'
import {
  ServerTimeLockStore,
  ServerAuthenticationKeyStore,
  ServerAuthenticationNonceStore,
  ServerCreationTokenStore,
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
    // this abstraction exists so we can easily log, do other stuff, etc
    // console.log(message)
    const reply = await this._sendRequest(path, message)
    // console.log(reply)
    return reply
  }

  async _sendRequest(path: string, message: string): Promise<string> {
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
          throw 'access denied'
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

async function createServer(args: {
  expiry: {
    accessLifetimeInMinutes: number,
    authenticationChallengeLifetimeInSeconds: number,
    creationTimeoutInMinutes: number,
    refreshLifetimeInHours: number,
  },
  keys: {
    accessSigner: ISigningKey,
    responseSigner: ISigningKey,
  }
}): Promise<BetterAuthServer> {
  const eccVerifier = new Secp256r1Verifier()
  const digester = new Digester()
  const noncer = new Noncer()

  const accessKeyDigestStore = new ServerTimeLockStore(60 * 60 * args.expiry.refreshLifetimeInHours)
  const authenticationNonceStore = new ServerAuthenticationNonceStore(args.expiry.authenticationChallengeLifetimeInSeconds)
  const creationTokenStore = new ServerCreationTokenStore(args.expiry.creationTimeoutInMinutes)

  const betterAuthServer = new BetterAuthServer({
    crypto: {
      digester: digester,
      keyPairs: {
        access: args.keys.accessSigner,
        response: args.keys.responseSigner,
      },
      noncer: noncer,
      verifier: eccVerifier,
    },
    expiry: {
      accessInMinutes: args.expiry.accessLifetimeInMinutes,
      refreshInHours: args.expiry.refreshLifetimeInHours,
    },
    store: {
      access: {
        // the lock time is the refresh lifetime in seconds
        keyDigest: accessKeyDigestStore
      },
      authentication: {
        key: new ServerAuthenticationKeyStore(),
        nonce: authenticationNonceStore
      },
      creation: {
        token: creationTokenStore,
      },
      recovery: {
        key: new ServerRecoveryKeyDigestStore()
      },
    },
  })

  return betterAuthServer
}

async function createVerifier(args: {
  expiry: {
    accessWindowInSeconds: number
  },
  keys: {
    accessVerifier: IVerificationKey
  }
}): Promise<AccessVerifier> {
  const eccVerifier = new Secp256r1Verifier()
  const digester = new Digester()
  const noncer = new Noncer()

  const accessNonceStore = new ServerTimeLockStore(args.expiry.accessWindowInSeconds)

  const accessVerifier = new AccessVerifier({
    crypto: {
      publicKeys: {
        access: args.keys.accessVerifier,
      },
      verifier: eccVerifier,
    },
    store: {
      access: {
        nonce: accessNonceStore,
      }
    }
  })

  return accessVerifier
}

describe('api', () => {
  it('completes auth flows', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const digester = new Digester()
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
        creationTimeoutInMinutes: 30,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      }
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner
      }
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        digester: digester,
        noncer: noncer,
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      io: {
        network: mockNetworkServer,
      },
      store: {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
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

    const creationContainer = await betterAuthServer.generateCreationContainer()
    const recoveryKeyDigest = await digester.sum(await recoverySigner.public())

    await betterAuthClient.createAccount(creationContainer, recoveryKeyDigest)
    await executeFlow(betterAuthClient, eccVerifier, responseSigner)
  })

  it('recovers from loss', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const digester = new Digester()
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
        creationTimeoutInMinutes: 30,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      }
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner
      }
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        digester: digester,
        noncer: noncer,
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      io: {
        network: mockNetworkServer,
      },
      store: {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
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
        digester: new Digester(),
        noncer: new Noncer(),
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      io: {
        network: mockNetworkServer,
      },
      store: {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
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

    const creationContainer = await betterAuthServer.generateCreationContainer()
    const recoveryKeyDigest = await digester.sum(await recoverySigner.public())

    await betterAuthClient.createAccount(creationContainer, recoveryKeyDigest)

    // this is saved with the recovery key/derivation material, wherever that is
    const accountId = await betterAuthClient.accountId()

    await recoveredBetterAuthClient.recoverAccount(accountId, recoverySigner)
    await executeFlow(recoveredBetterAuthClient, eccVerifier, responseSigner)
  })

  it('links another device', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const digester = new Digester()
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
        creationTimeoutInMinutes: 30,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      }
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner
      }
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        digester: digester,
        noncer: noncer,
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      io: {
        network: mockNetworkServer,
      },
      store: {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
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
        digester: new Digester(),
        noncer: new Noncer(),
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      io: {
        network: mockNetworkServer,
      },
      store: {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
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

    const creationContainer = await betterAuthServer.generateCreationContainer()
    const recoveryKeyDigest = await digester.sum(await recoverySigner.public())
    
    await betterAuthClient.createAccount(creationContainer, recoveryKeyDigest)

    // get account id from the existing device
    const accountId = await betterAuthClient.accountId()

    // get link container from the new device
    const linkContainer = await linkedBetterAuthClient.generateLinkContainer(accountId)
    // console.log(linkContainer)

    // submit an endorsed link container with existing device
    await betterAuthClient.linkDevice(linkContainer)
    await executeFlow(linkedBetterAuthClient, eccVerifier, responseSigner)
  })

  it(('rejects expired creation tokens'), async () => {
    const eccVerifier = new Secp256r1Verifier()
    const digester = new Digester()
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
        creationTimeoutInMinutes: -1,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      }
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner
      }
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        digester: digester,
        noncer: noncer,
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      io: {
        network: mockNetworkServer,
      },
      store: {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
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

    const creationContainer = await betterAuthServer.generateCreationContainer()
    const recoveryKeyDigest = await digester.sum(await recoverySigner.public())
    

    try {
      await betterAuthClient.createAccount(creationContainer, recoveryKeyDigest)
      throw 'unexpected failure'
    } catch(e: unknown) {
      expect(e).toBe('expired token')
    }
  })

  it(('rejects expired authentication challenges'), async () => {
    const eccVerifier = new Secp256r1Verifier()
    const digester = new Digester()
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
        creationTimeoutInMinutes: 30,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      }
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner
      }
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        digester: digester,
        noncer: noncer,
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      io: {
        network: mockNetworkServer,
      },
      store: {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
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

    const creationContainer = await betterAuthServer.generateCreationContainer()
    const recoveryKeyDigest = await digester.sum(await recoverySigner.public())
    
    await betterAuthClient.createAccount(creationContainer, recoveryKeyDigest)

    try {
      await executeFlow(betterAuthClient, eccVerifier, responseSigner)
      throw 'unexpected failure'
    } catch(e: unknown) {
      expect(e).toBe('expired nonce')
    }
  })

  it(('rejects expired refresh tokens'), async () => {
    const eccVerifier = new Secp256r1Verifier()
    const digester = new Digester()
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
        creationTimeoutInMinutes: 30,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      }
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner
      }
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        digester: digester,
        noncer: noncer,
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      io: {
        network: mockNetworkServer,
      },
      store: {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
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

    const creationContainer = await betterAuthServer.generateCreationContainer()
    const recoveryKeyDigest = await digester.sum(await recoverySigner.public())
    
    await betterAuthClient.createAccount(creationContainer, recoveryKeyDigest)

    try {
      await executeFlow(betterAuthClient, eccVerifier, responseSigner)
      throw 'unexpected failure'
    } catch(e: unknown) {
      expect(e).toBe('refresh has expired')
    }
  })

  it(('rejects expired access tokens'), async () => {
    const eccVerifier = new Secp256r1Verifier()
    const digester = new Digester()
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
        creationTimeoutInMinutes: 30,
      },
      keys: {
        accessSigner: accessSigner,
        responseSigner: responseSigner,
      }
    })

    const accessVerifier = await createVerifier({
      expiry: {
        accessWindowInSeconds: 30,
      },
      keys: {
        // this would typically not be a signing key pair
        //  instead, a verification key (the interface contract) is required
        accessVerifier: accessSigner
      }
    })

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)

    const mockNetworkServer = new MockNetworkServer(
      betterAuthServer,
      accessVerifier,
      responseSigner,
      attributes
    )

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        digester: digester,
        noncer: noncer,
        publicKeys: {
          response: responseSigner, // this would only be a public key in production
        },
      },
      io: {
        network: mockNetworkServer,
      },
      store: {
        identifier: {
          account: new ClientValueStore(),
          device: new ClientValueStore(),
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

    const creationContainer = await betterAuthServer.generateCreationContainer()
    const recoveryKeyDigest = await digester.sum(await recoverySigner.public())
    
    await betterAuthClient.createAccount(creationContainer, recoveryKeyDigest)

    try {
      await executeFlow(betterAuthClient, eccVerifier, responseSigner)
      throw 'unexpected failure'
    } catch(e: unknown) {
      expect(e).toBe('access denied')
    }
  })
})
