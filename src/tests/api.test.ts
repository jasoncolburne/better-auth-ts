import { describe, expect, it } from 'vitest'
import { AccessVerifier, BetterAuthClient, BetterAuthServer } from '../api/index.js'
import {
  IAuthenticationPaths,
  IClientValueStore,
  INetwork,
  IServerAuthenticationKeyStore,
  IServerRecoveryHashStore,
  ISigningKey,
  IVerificationKeyStore,
  IVerifier,
} from '../interfaces/index.js'
import {
  Base64,
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
  VerificationKeyStore,
} from './implementation/index.js'
import { AccessRequest, AccessToken, ClientRequest, ServerResponse } from '../messages/index.js'
import { randomInt } from 'crypto'

const DEBUG_LOGGING = false
const authenticationPaths: IAuthenticationPaths = {
  account: {
    create: '/account/create',
    recover: '/account/recover',
    delete: '/account/delete',
  },
  session: {
    request: '/session/request',
    create: '/session/create',
    refresh: '/session/refresh',
  },
  device: {
    rotate: '/device/rotate',
    link: '/device/link',
    unlink: '/device/unlink',
  },
  recovery: {
    change: '/recovery/change',
  },
}

interface IMockAccessAttributes {
  permissionsByRole: object
}

class MockAccessAttributes {
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
    let request: FakeRequest
    let token: AccessToken<MockAccessAttributes>
    let nonce: string

    switch (path) {
      case this.paths.account.create:
        return await this.betterAuthServer.createAccount(message)
      case this.paths.account.recover:
        return await this.betterAuthServer.recoverAccount(message)
      case this.paths.account.delete:
        return await this.betterAuthServer.deleteAccount(message)
      case this.paths.device.link:
        return await this.betterAuthServer.linkDevice(message)
      case this.paths.device.rotate:
        return await this.betterAuthServer.rotateDevice(message)
      case this.paths.session.request:
        return await this.betterAuthServer.requestSession(message)
      case this.paths.session.create:
        return await this.betterAuthServer.createSession(message, this.attributes)
      case this.paths.session.refresh:
        return await this.betterAuthServer.refreshSession<MockAccessAttributes>(message)
      case this.paths.device.unlink:
        return await this.betterAuthServer.unlinkDevice(message)
      case this.paths.recovery.change:
        return await this.betterAuthServer.changeRecoveryKey(message)
      case '/foo/bar':
        ;[request, token, nonce] = await this.accessVerifier.verify<
          FakeRequest,
          MockAccessAttributes
        >(message)

        if (typeof request === 'undefined') {
          throw 'null identity'
        }

        if (typeof token === 'undefined') {
          throw 'null token'
        }

        if (!token.identity.startsWith('E')) {
          throw 'unexpected identity format'
        }

        if (token.identity.length !== 44) {
          throw 'unexpected identity length'
        }

        if (!nonce.startsWith('0A')) {
          throw 'unexpected nonce format'
        }

        if (nonce.length !== 24) {
          throw 'unexpected nonce length'
        }

        if (JSON.stringify(token.attributes) !== JSON.stringify(this.attributes)) {
          throw 'attributes do not match'
        }

        return await this.respondToAccessRequest(message)
      case '/bad/nonce':
        ;[request, token, nonce] = await this.accessVerifier.verify<
          FakeRequest,
          MockAccessAttributes
        >(message)

        if (typeof request === 'undefined') {
          throw 'null response'
        }

        if (typeof token === 'undefined') {
          throw 'null token'
        }

        if (!token.identity.startsWith('E')) {
          throw 'unexpected identity format'
        }

        if (token.identity.length !== 44) {
          throw 'unexpected identity length'
        }

        if (!nonce.startsWith('0A')) {
          throw 'unexpected nonce format'
        }

        if (nonce.length !== 24) {
          throw 'unexpected nonce length'
        }

        if (JSON.stringify(token.attributes) !== JSON.stringify(this.attributes)) {
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

class FakeRequest extends ClientRequest<IFakeRequest> {}

class FakeResponse extends ServerResponse<IFakeResponse> {
  static parse(message: string): FakeResponse {
    return ServerResponse._parse(message, FakeResponse)
  }
}

async function executeFlow(
  betterAuthClient: BetterAuthClient,
  eccVerifier: IVerifier,
  responseVerificationKeyStore: IVerificationKeyStore
) {
  await betterAuthClient.rotateDevice()
  await betterAuthClient.createSession()
  await betterAuthClient.refreshSession()
  await betterAuthClient.rotateDevice()
  await betterAuthClient.rotateDevice()
  await betterAuthClient.refreshSession()

  await testAccess(betterAuthClient, eccVerifier, responseVerificationKeyStore)
}

async function testAccess(
  betterAuthClient: BetterAuthClient,
  eccVerifier: IVerifier,
  responseVerificationKeyStore: IVerificationKeyStore
): Promise<void> {
  const message = {
    foo: 'bar',
    bar: 'foo',
  }
  const reply = await betterAuthClient.makeAccessRequest<IFakeRequest>('/foo/bar', message)
  const response = FakeResponse.parse(reply)

  const responseKey = await responseVerificationKeyStore.get(response.payload.access.serverIdentity)
  await response.verify(eccVerifier, await responseKey.public())

  if (response.payload.response.wasFoo !== 'bar' || response.payload.response.wasBar !== 'foo') {
    throw 'invalid data returned'
  }
}

interface IServerArgs {
  keys: {
    accessSigner: ISigningKey
    responseSigner: ISigningKey
  }
  expiry?: {
    accessLifetimeInMinutes?: number
    authenticationChallengeLifetimeInSeconds?: number
    refreshLifetimeInHours?: number
  }
  store?: {
    authenticationKey?: IServerAuthenticationKeyStore
    recoveryHash?: IServerRecoveryHashStore
  }
}

interface IVerifierArgs {
  expiry: {
    accessWindowInSeconds: number
  }
  keys: {
    accessSigner: ISigningKey
  }
}

async function createServer(args: IServerArgs): Promise<BetterAuthServer> {
  const eccVerifier = new Secp256r1Verifier()
  const hasher = new Hasher()
  const noncer = new Noncer()

  const accessKeyHashStore = new ServerTimeLockStore(
    60 * 60 * (args.expiry?.refreshLifetimeInHours ?? 12)
  )
  const authenticationNonceStore = new ServerAuthenticationNonceStore(
    args.expiry?.authenticationChallengeLifetimeInSeconds ?? 60
  )

  const accessVerificationKeyStore = new VerificationKeyStore()
  await accessVerificationKeyStore.add(
    await args.keys.accessSigner.identity(),
    args.keys.accessSigner
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
      accessInMinutes: args.expiry?.accessLifetimeInMinutes ?? 15,
      refreshInHours: args.expiry?.refreshLifetimeInHours ?? 12,
    },
    store: {
      access: {
        verificationKey: accessVerificationKeyStore,
        // the lock time is the refresh lifetime in seconds
        keyHash: accessKeyHashStore,
      },
      authentication: {
        key: args.store?.authenticationKey ?? new ServerAuthenticationKeyStore(),
        nonce: authenticationNonceStore,
      },
      recovery: {
        hash: args.store?.recoveryHash ?? new ServerRecoveryHashStore(),
      },
    },
  })

  return betterAuthServer
}

async function createVerifier(args: IVerifierArgs): Promise<AccessVerifier> {
  const eccVerifier = new Secp256r1Verifier()
  const accessNonceStore = new ServerTimeLockStore(args.expiry.accessWindowInSeconds)
  const accessVerificationKeyStore = new VerificationKeyStore()
  await accessVerificationKeyStore.add(
    await args.keys.accessSigner.identity(),
    args.keys.accessSigner
  )

  const accessVerifier = new AccessVerifier({
    crypto: {
      verifier: eccVerifier,
    },
    encoding: {
      tokenEncoder: new TokenEncoder(),
      timestamper: new Rfc3339Nano(),
    },
    store: {
      access: {
        nonce: accessNonceStore,
        key: accessVerificationKeyStore,
      },
    },
  })

  return accessVerifier
}

async function createClient(args: {
  server: IServerArgs
  verifier: IVerifierArgs
  accessTokenStore?: IClientValueStore
}): Promise<BetterAuthClient> {
  const hasher = new Hasher()
  const noncer = new Noncer()

  const betterAuthServer = await createServer(args.server)
  const accessVerifier = await createVerifier(args.verifier)

  const map = {
    admin: ['read', 'write'],
  }
  const attributes = new MockAccessAttributes(map)

  const mockNetworkServer = new MockNetworkServer(
    betterAuthServer,
    accessVerifier,
    args.server.keys.responseSigner,
    attributes,
    authenticationPaths
  )

  const responseKeyStore = new VerificationKeyStore()
  await responseKeyStore.add(
    await args.server.keys.responseSigner.identity(),
    args.server.keys.responseSigner
  )

  return new BetterAuthClient({
    crypto: {
      hasher: hasher,
      noncer: noncer,
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
        response: responseKeyStore,
      },
      token: {
        access: args.accessTokenStore ?? new ClientValueStore(),
      },
    },
  })
}

describe('api', () => {
  it('completes auth flows', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()

    const responseKeyStore = new VerificationKeyStore()
    await responseKeyStore.add(await responseSigner.identity(), responseSigner)

    const betterAuthClient = await createClient({
      server: {
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
    })

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)
    await executeFlow(betterAuthClient, eccVerifier, responseKeyStore)
    await betterAuthClient.deleteAccount()
  })

  it('recovers from loss', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()

    const responseKeyStore = new VerificationKeyStore()
    await responseKeyStore.add(await responseSigner.identity(), responseSigner)

    const authenticationKeyStore = new ServerAuthenticationKeyStore()
    const recoveryHashStore = new ServerRecoveryHashStore()

    const betterAuthClient = await createClient({
      server: {
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
        store: {
          authenticationKey: authenticationKeyStore,
          recoveryHash: recoveryHashStore,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
    })

    const recoveredBetterAuthClient = await createClient({
      server: {
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
        store: {
          authenticationKey: authenticationKeyStore,
          recoveryHash: recoveryHashStore,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
    })

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    const identity = await betterAuthClient.identity()
    const newRecoverySigner = new Secp256r1()
    const nextRecoverySigner = new Secp256r1()
    await newRecoverySigner.generate()
    await nextRecoverySigner.generate()
    const newRecoveryHash = await hasher.sum(await newRecoverySigner.public())
    const nextRecoveryHash = await hasher.sum(await nextRecoverySigner.public())

    await betterAuthClient.changeRecoveryKey(newRecoveryHash)
    await recoveredBetterAuthClient.recoverAccount(identity, newRecoverySigner, nextRecoveryHash)
    await executeFlow(recoveredBetterAuthClient, eccVerifier, responseKeyStore)
  })

  it('links another device', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()

    const responseKeyStore = new VerificationKeyStore()
    await responseKeyStore.add(await responseSigner.identity(), responseSigner)

    const authenticationKeyStore = new ServerAuthenticationKeyStore()

    const betterAuthClient = await createClient({
      server: {
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
        store: {
          authenticationKey: authenticationKeyStore,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
    })

    const linkedBetterAuthClient = await createClient({
      server: {
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
        store: {
          authenticationKey: authenticationKeyStore,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
    })

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

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

    await executeFlow(linkedBetterAuthClient, eccVerifier, responseKeyStore)

    // unlink the original device
    await linkedBetterAuthClient.unlinkDevice(await betterAuthClient.device())
  })

  it('rejects expired authentication challenges', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()

    const responseKeyStore = new VerificationKeyStore()
    await responseKeyStore.add(await responseSigner.identity(), responseSigner)

    const betterAuthClient = await createClient({
      server: {
        expiry: {
          authenticationChallengeLifetimeInSeconds: -5,
        },
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
    })

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    try {
      await executeFlow(betterAuthClient, eccVerifier, responseKeyStore)
      throw 'expected a failure'
    } catch (e: unknown) {
      expect(e).toBe('expired nonce')
    }
  })

  it('rejects expired refresh tokens', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()

    const responseKeyStore = new VerificationKeyStore()
    await responseKeyStore.add(await responseSigner.identity(), responseSigner)

    const betterAuthClient = await createClient({
      server: {
        expiry: {
          refreshLifetimeInHours: -1,
        },
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
    })

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    try {
      await executeFlow(betterAuthClient, eccVerifier, responseKeyStore)
      throw 'expected a failure'
    } catch (e: unknown) {
      expect(e).toBe('refresh has expired')
    }
  })

  it('rejects expired access tokens', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()

    const responseKeyStore = new VerificationKeyStore()
    await responseKeyStore.add(await responseSigner.identity(), responseSigner)

    const betterAuthClient = await createClient({
      server: {
        expiry: {
          accessLifetimeInMinutes: -1,
        },
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
    })

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    try {
      await executeFlow(betterAuthClient, eccVerifier, responseKeyStore)
      throw 'expected a failure'
    } catch (e: unknown) {
      expect(e).toBe('token expired')
    }
  })

  it('detects tampered access tokens', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()

    const responseKeyStore = new VerificationKeyStore()
    await responseKeyStore.add(await responseSigner.identity(), responseSigner)

    const accessTokenStore = new ClientValueStore()

    const betterAuthClient = await createClient({
      server: {
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
      accessTokenStore: accessTokenStore,
    })

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    await betterAuthClient.createSession()
    const token = await accessTokenStore.get()
    const signature = token.substring(0, 88)
    const bytes = Base64.decode(signature)
    const index = randomInt(64)
    bytes[2 + index] ^= 0xff
    const tamperedToken = Base64.encode(bytes) + token.substring(88)
    await accessTokenStore.store(tamperedToken)

    try {
      await testAccess(betterAuthClient, eccVerifier, responseKeyStore)
      throw 'expected a failure'
    } catch (e: unknown) {
      expect(e).toBe('invalid signature')
    }
  })

  it('detects mismatched access nonce', async () => {
    const hasher = new Hasher()

    const accessSigner = new Secp256r1()
    const responseSigner = new Secp256r1()

    await accessSigner.generate()
    await responseSigner.generate()

    const responseKeyStore = new VerificationKeyStore()
    await responseKeyStore.add(await responseSigner.identity(), responseSigner)

    const betterAuthClient = await createClient({
      server: {
        keys: {
          accessSigner: accessSigner,
          responseSigner: responseSigner,
        },
      },
      verifier: {
        expiry: {
          accessWindowInSeconds: 30,
        },
        keys: {
          // this would typically not be a signing key pair
          //  instead, a verification key (the interface contract) is required
          accessSigner: accessSigner,
        },
      },
      accessTokenStore: new ClientValueStore(),
    })

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    try {
      await betterAuthClient.createSession()
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
