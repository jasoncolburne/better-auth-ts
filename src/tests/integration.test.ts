import { describe, expect, it } from 'vitest'
import { BetterAuthClient } from '../api'
import { IAuthenticationPaths, INetwork, IVerificationKey, IVerifier } from '../interfaces'
import {
  ClientRotatingKeyStore,
  ClientValueStore,
  Hasher,
  Noncer,
  Rfc3339Nano,
  Secp256r1,
  Secp256r1Verifier,
} from './implementation'
import { ServerResponse } from '../messages'

const DEBUG_LOGGING = false

class Secp256r1VerificationKey implements IVerificationKey {
  private readonly secpVerifier: IVerifier

  constructor(private readonly publicKey: string) {
    this.secpVerifier = new Secp256r1Verifier()
  }

  async public(): Promise<string> {
    return this.publicKey
  }

  verifier(): IVerifier {
    return this.secpVerifier
  }

  async verify(message: string, signature: string): Promise<void> {
    return this.secpVerifier.verify(message, signature, this.publicKey)
  }
}

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

class Network implements INetwork {
  async sendRequest(path: string, message: string): Promise<string> {
    if (DEBUG_LOGGING) {
      console.log(message)
    }

    // eslint-disable-next-line no-undef
    const response = await fetch(`http://localhost:8080${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: message,
    })

    const reply = await response.text()

    if (DEBUG_LOGGING) {
      console.log(reply)
    }

    return reply
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
  responseVerificationKey: IVerificationKey
) {
  await betterAuthClient.rotateAuthenticationKey()
  await betterAuthClient.authenticate()
  await betterAuthClient.refreshAccessToken()

  await testAccess(betterAuthClient, eccVerifier, responseVerificationKey)
}

async function testAccess(
  betterAuthClient: BetterAuthClient,
  eccVerifier: IVerifier,
  responseVerificationKey: IVerificationKey
): Promise<void> {
  const message = {
    foo: 'bar',
    bar: 'foo',
  }
  const reply = await betterAuthClient.makeAccessRequest<IFakeRequest>('/foo/bar', message)
  const response = FakeResponse.parse(reply)

  await response.verify(eccVerifier, await responseVerificationKey.public())

  if (response.payload.response.wasFoo !== 'bar' || response.payload.response.wasBar !== 'foo') {
    throw 'invalid data returned'
  }
}

describe('integration', () => {
  it('completes auth flows', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const network = new Network()

    const responsePublicKey = await network.sendRequest('/key/response', '')
    const responseVerificationKey = new Secp256r1VerificationKey(responsePublicKey)

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseVerificationKey,
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: network,
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
    await executeFlow(betterAuthClient, eccVerifier, responseVerificationKey)
  })

  it('recovers from loss', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const network = new Network()

    const responsePublicKey = await network.sendRequest('/key/response', '')
    const responseVerificationKey = new Secp256r1VerificationKey(responsePublicKey)

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseVerificationKey,
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: network,
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
          response: responseVerificationKey,
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: network,
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
    await executeFlow(recoveredBetterAuthClient, eccVerifier, responseVerificationKey)
  })

  it('links another device', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const network = new Network()

    const responsePublicKey = await network.sendRequest('/key/response', '')
    const responseVerificationKey = new Secp256r1VerificationKey(responsePublicKey)

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseVerificationKey,
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: network,
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
          response: responseVerificationKey,
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: network,
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
    await executeFlow(linkedBetterAuthClient, eccVerifier, responseVerificationKey)
  })

  it('detects mismatched access nonce', async () => {
    const hasher = new Hasher()
    const noncer = new Noncer()

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const network = new Network()

    const responsePublicKey = await network.sendRequest('/key/response', '')
    const responseVerificationKey = new Secp256r1VerificationKey(responsePublicKey)

    const accessTokenStore = new ClientValueStore()
    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
        publicKey: {
          response: responseVerificationKey, // this would only be a public key in production
        },
      },
      encoding: {
        timestamper: new Rfc3339Nano(),
      },
      io: {
        network: network,
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
