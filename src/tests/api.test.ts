import { beforeAll, describe, it } from 'vitest'
import { BetterAuthClient, BetterAuthServer } from '../api'
import { INetwork } from '../interfaces'
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
import { Noncer } from './crypto/nonce'
import { Digester } from './crypto/digest'
import { Ed25519Verifier } from './crypto/ed25519'
import { KeyDeriver } from './crypto/keyDerivation'
import { Secp256r1, Secp256r1Verifier } from './crypto/secp256r1'
import {
  ClientRefreshNonceStore,
  ClientRotatingKeyStore,
  ClientSingleKeyStore,
  ClientValueStore,
} from './client.storage.mocks'

interface IMockAccessAttributes {
  permissionsByRole: object
}

class MockAccessAttributes implements IMockAccessAttributes {
  constructor(public permissionsByRole: object) {}
}

class MockNetworkServer implements INetwork {
  constructor(
    private readonly betterAuthServer: BetterAuthServer,
    private readonly attributes: IMockAccessAttributes
  ) {}

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
      default:
        throw 'unexpected message'
    }
  }
}

describe('api', () => {
  let betterAuthServer: BetterAuthServer
  let betterAuthClient: BetterAuthClient

  beforeAll(async () => {
    const responseSigner = new Secp256r1()
    const accessSigner = new Secp256r1()

    await responseSigner.generate()
    await accessSigner.generate()

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
          key: new Secp256r1Verifier(),
          passphrase: new Ed25519Verifier(),
        },
        nonce: new Noncer(),
        digest: new Digester(),
      }
    )

    const map = {
      admin: ['read', 'write'],
    }
    const attributes = new MockAccessAttributes(map)
    const mockNetworkServer = new MockNetworkServer(betterAuthServer, attributes)

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

  it('completes passphrase flow', async () => {
    const passphraseRegistrationMaterials =
      await betterAuthServer.generatePassphraseRegistrationMaterials()

    const passphrase = 'testPassphrase'
    await betterAuthClient.registerPassphraseAuthenticationKey(
      passphraseRegistrationMaterials,
      passphrase
    )
    await betterAuthClient.authenticateWithPassphrase(passphrase)
    await betterAuthClient.refreshAccessToken()
  }, 5000)

  it('completes key auth flow', async () => {
    const registrationMaterials = await betterAuthServer.generateRegistrationMaterials()

    await betterAuthClient.registerAuthenticationKey(registrationMaterials)
    await betterAuthClient.rotateAuthenticationKey()
    await betterAuthClient.authenticate()
    await betterAuthClient.refreshAccessToken()
  }, 5000)
})
