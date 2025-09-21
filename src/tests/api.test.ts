import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { BetterAuthClient, BetterAuthServer } from '../api'
import { INetwork } from '../interfaces'
import {
  ServerAuthenticationKeyStore,
  ServerAuthenticationNonceStore,
  ServerAuthenticationRegistrationTokenStore,
  ServerPassphraseAuthenticationKeyStore,
  ServerPassphraseRegistrationTokenStore,
  ServerRefreshKeyStore,
} from './storage.mock.test'
import { Noncer } from './crypto/nonce'
import { Digester } from './crypto/digest'

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
  const betterAuthServer = new BetterAuthServer(
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
        access: new ServerAccessNoneStore(),
      },
    },
    {
      keyPairs: {
        response: responseSigner,
        access: accessSigner,
      },
      verification: {
        key: keyVerifier,
        passphrase: passphraseVerifier,
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

  const betterAuthClient = new BetterAuthClient(
    {
      identifier: {
        account: accountIdentifierStore,
        device: deviceIdentifierStore,
        session: sessionIdentifierStore,
      },
      nonce: {
        refresh: refreshNonceStore,
      },
      token: {
        refresh: refreshTokenStore,
        access: accessTokenStore,
      },
      key: {
        authentication: authenticationKeyStore,
        refresh: refreshKeyStore,
        access: accessKeyStore,
      },
    },
    {
      digest: new Digester(),
      publicKeys: {
        response: responseKey,
      },
      keyDerivation: new KeyDeriver(),
      nonce: new Noncer(),
    },
    {
      network: mockNetworkServer,
    }
  )
})
