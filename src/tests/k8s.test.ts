import { describe, it } from 'vitest'
import { BetterAuthClient } from '../api/index.js'
import {
  IAuthenticationPaths,
  INetwork,
  IVerificationKey,
  IVerificationKeyStore,
  IVerifier,
} from '../interfaces/index.js'
import {
  ClientRotatingKeyStore,
  ClientValueStore,
  Hasher,
  Noncer,
  Rfc3339Nano,
  Secp256r1,
  Secp256r1Verifier,
  VerificationKeyStore,
} from './implementation/index.js'
import { ServerResponse } from '../messages/index.js'

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
}

class Network implements INetwork {
  async sendRequest(path: string, message: string): Promise<string> {
    if (DEBUG_LOGGING) {
      console.log(message)
    }

    let subdomain = 'auth'

    if (path === '/foo/bar') {
      subdomain = 'app'
    }

    // eslint-disable-next-line no-undef
    const response = await fetch(`http://${subdomain}.better-auth.local${path}`, {
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
  serverName: string
}

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

  await response.verify(
    eccVerifier,
    await (await responseVerificationKeyStore.get(response.payload.access.serverIdentity)).public()
  )

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

    const responseVerificationKeyStore = new VerificationKeyStore()
    // eslint-disable-next-line no-undef
    const responseKeysResponse = await fetch('http://keys.better-auth.local/keys')
    const responseKeysObject = JSON.parse(await responseKeysResponse.text())
    const responseKeys = new Map<string, string>(Object.entries(responseKeysObject))

    responseKeys.forEach(async (publicKey, identity) => {
      const responseVerificationKey = new Secp256r1VerificationKey(publicKey)
      await responseVerificationKeyStore.add(identity, responseVerificationKey)
    })

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
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
          response: responseVerificationKeyStore,
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)
    await executeFlow(betterAuthClient, eccVerifier, responseVerificationKeyStore)
    await betterAuthClient.deleteAccount()
  })

  it('recovers from loss', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const network = new Network()

    const responseVerificationKeyStore = new VerificationKeyStore()
    // eslint-disable-next-line no-undef
    const responseKeysResponse = await fetch('http://keys.better-auth.local/keys')
    const responseKeysObject = JSON.parse(await responseKeysResponse.text())
    const responseKeys = new Map<string, string>(Object.entries(responseKeysObject))

    responseKeys.forEach(async (publicKey, identity) => {
      const responseVerificationKey = new Secp256r1VerificationKey(publicKey)
      await responseVerificationKeyStore.add(identity, responseVerificationKey)
    })

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
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
          response: responseVerificationKeyStore,
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
          response: responseVerificationKeyStore,
        },
        token: {
          access: new ClientValueStore(),
        },
      },
    })

    const recoveryHash = await hasher.sum(await recoverySigner.public())
    await betterAuthClient.createAccount(recoveryHash)

    const identity = await betterAuthClient.identity()
    const nextRecoverySigner = new Secp256r1()
    await nextRecoverySigner.generate()
    const nextRecoveryHash = await hasher.sum(await nextRecoverySigner.public())

    await recoveredBetterAuthClient.recoverAccount(identity, recoverySigner, nextRecoveryHash)
    await executeFlow(recoveredBetterAuthClient, eccVerifier, responseVerificationKeyStore)
  })

  it('links another device', async () => {
    const eccVerifier = new Secp256r1Verifier()
    const hasher = new Hasher()
    const noncer = new Noncer()

    const recoverySigner = new Secp256r1()
    await recoverySigner.generate()

    const network = new Network()

    const responseVerificationKeyStore = new VerificationKeyStore()
    // eslint-disable-next-line no-undef
    const responseKeysResponse = await fetch('http://keys.better-auth.local/keys')
    const responseKeysObject = JSON.parse(await responseKeysResponse.text())
    const responseKeys = new Map<string, string>(Object.entries(responseKeysObject))

    responseKeys.forEach(async (publicKey, identity) => {
      const responseVerificationKey = new Secp256r1VerificationKey(publicKey)
      await responseVerificationKeyStore.add(identity, responseVerificationKey)
    })

    const betterAuthClient = new BetterAuthClient({
      crypto: {
        hasher: hasher,
        noncer: noncer,
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
          response: responseVerificationKeyStore,
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
          response: responseVerificationKeyStore,
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

    await executeFlow(linkedBetterAuthClient, eccVerifier, responseVerificationKeyStore)

    // unlink the original device
    await linkedBetterAuthClient.unlinkDevice(await betterAuthClient.device())
  })
})
