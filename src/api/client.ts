import {
  IClientRefreshNonceStore,
  IClientRotatingKeyStore,
  IClientSingleKeyStore,
  IClientValueStore,
  IDigester,
  IKeyDeriver,
  INetwork,
  ISalter,
  IVerificationKey,
} from '../interfaces'
import {
  BeginAuthenticationRequest,
  BeginAuthenticationResponse,
  BeginPassphraseAuthenticationRequest,
  BeginPassphraseAuthenticationResponse,
  CompleteAuthenticationRequest,
  CompleteAuthenticationResponse,
  CompletePassphraseAuthenticationRequest,
  PassphraseRegistrationMaterials,
  RefreshAccessTokenRequest,
  RefreshAccessTokenResponse,
  RegisterAuthenticationKeyRequest,
  RegisterAuthenticationKeyResponse,
  RegisterPassphraseAuthenticationKeyRequest,
  RegisterPassphraseAuthenticationKeyResponse,
  RegistrationMaterials,
  RotateAuthenticationKeyRequest,
  RotateAuthenticationKeyResponse,
} from '../messages'
import { SignableMessage } from '../messages/request'

export class BetterAuthClient {
  constructor(
    private readonly stores: {
      identifier: {
        account: IClientValueStore
        device: IClientValueStore
        session: IClientValueStore
      }
      nonce: {
        refresh: IClientRefreshNonceStore
      }
      token: {
        refresh: IClientValueStore
      }
      key: {
        authentication: IClientRotatingKeyStore
        refresh: IClientSingleKeyStore
        access: IClientSingleKeyStore
      }
    },
    private readonly crypto: {
      digest: IDigester
      publicKeys: {
        response: IVerificationKey
      }
      keyDerivation: IKeyDeriver
      nonce: ISalter
    },
    private readonly io: {
      network: INetwork
    }
  ) {
    if (!stores || !crypto || !io) {
      throw new Error('Invalid configuration')
    }
  }

  verifyResponse(response: SignableMessage, publicKeyDigest: string): boolean {
    const publicKey = this.crypto.publicKeys.response.public()
    const digest = this.crypto.digest.sum(publicKey)

    if (digest !== publicKeyDigest) {
      throw 'digest mismatch'
    }

    const verifier = this.crypto.publicKeys.response.verifier()

    return response.verify(verifier, publicKey)
  }

  registerAuthenticationKey(registrationMaterials: string): void {
    const materials = RegistrationMaterials.parse(registrationMaterials)
    if (!this.verifyResponse(materials, materials.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }

    const [currentAuthenticationPublicKey, nextAuthenticationPublicKeyDigest] =
      this.stores.key.authentication.initialize()

    const request = new RegisterAuthenticationKeyRequest({
      registration: {
        token: materials.payload.registration.token,
      },
      identification: {
        deviceId: this.stores.identifier.device.get(),
      },
      authentication: {
        publicKeys: {
          current: currentAuthenticationPublicKey,
          nextDigest: nextAuthenticationPublicKeyDigest,
        },
      },
    })

    request.sign(this.stores.key.authentication.signer())
    const message = request.serialize()
    const reply = this.io.network.sendRequest('/auth/key/register', message)

    const response = RegisterAuthenticationKeyResponse.parse(reply)
    if (!this.verifyResponse(response, response.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }

    this.stores.identifier.account.store(response.payload.identification.accountId)
  }

  registerPassphraseAuthenticationKey(
    passphraseRegistrationMaterials: string,
    passphrase: string
  ): void {
    const materials = PassphraseRegistrationMaterials.parse(passphraseRegistrationMaterials)
    if (!this.verifyResponse(materials, materials.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }

    const keyPair = this.crypto.keyDerivation.derive(
      passphrase,
      materials.payload.passphraseAuthentication.salt,
      materials.payload.passphraseAuthentication.parameters
    )

    const request = new RegisterPassphraseAuthenticationKeyRequest({
      registration: {
        token: materials.payload.registration.token,
      },
      passphraseAuthentication: {
        publicKey: keyPair.public(),
      },
    })

    request.sign(keyPair)
    const message = request.serialize()
    const reply = this.io.network.sendRequest('/auth/passphrase/register', message)

    const response = RegisterPassphraseAuthenticationKeyResponse.parse(reply)
    if (!this.verifyResponse(response, response.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }
  }

  rotateAuthenticationKey(): void {
    const [currentAuthenticationPublicKey, nextAuthenticationPublicKeyDigest] =
      this.stores.key.authentication.rotate()

    const request = new RotateAuthenticationKeyRequest({
      identification: {
        accountId: this.stores.identifier.account.get(),
        deviceId: this.stores.identifier.device.get(),
      },
      authentication: {
        publicKeys: {
          current: currentAuthenticationPublicKey,
          nextDigest: nextAuthenticationPublicKeyDigest,
        },
      },
    })

    request.sign(this.stores.key.authentication.signer())
    const message = request.serialize()
    const reply = this.io.network.sendRequest('/auth/key/rotate', message)

    const response = RotateAuthenticationKeyResponse.parse(reply)
    if (!this.verifyResponse(response, response.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }

    if (!response.payload.success) {
      throw 'response not marked successful'
    }
  }

  authenticate(): void {
    const beginRequest = new BeginAuthenticationRequest({
      identification: {
        accountId: this.stores.identifier.account.get(),
      },
    })

    const beginMessage = beginRequest.serialize()
    const beginReply = this.io.network.sendRequest('/auth/key/begin', beginMessage)

    const beginResponse = BeginAuthenticationResponse.parse(beginReply)
    if (!this.verifyResponse(beginResponse, beginResponse.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }

    const refreshPublicKey = this.stores.key.refresh.generate()
    const nextNonceDigest = this.stores.nonce.refresh.initialize()

    const completeRequest = new CompleteAuthenticationRequest({
      identification: {
        deviceId: this.stores.identifier.device.get(),
      },
      authentication: {
        nonce: beginResponse.payload.authentication.nonce,
      },
      refresh: {
        publicKey: refreshPublicKey,
        nonces: {
          nextDigest: nextNonceDigest,
        },
      },
    })

    completeRequest.sign(this.stores.key.refresh.signer())
    const completeMessage = completeRequest.serialize()
    const completeReply = this.io.network.sendRequest('/auth/key/complete', completeMessage)

    const completeResponse = CompleteAuthenticationResponse.parse(completeReply)
    if (!this.verifyResponse(completeResponse, completeResponse.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }

    this.stores.identifier.session.store(completeResponse.payload.refresh.sessionId)
  }

  authenticateWithPassphrase(passphrase: string): void {
    const beginRequest = new BeginPassphraseAuthenticationRequest({
      identification: {
        accountId: this.stores.identifier.account.get(),
      },
    })

    const beginMessage = beginRequest.serialize()
    const beginReply = this.io.network.sendRequest('/auth/passphrase/begin', beginMessage)

    const beginResponse = BeginPassphraseAuthenticationResponse.parse(beginReply)
    if (!this.verifyResponse(beginResponse, beginResponse.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }

    const keyPair = this.crypto.keyDerivation.derive(
      passphrase,
      beginResponse.payload.passphraseAuthentication.salt,
      beginResponse.payload.passphraseAuthentication.parameters
    )

    const refreshPublicKey = this.stores.key.refresh.generate()
    const nextNonceDigest = this.stores.nonce.refresh.initialize()

    const completeRequest = new CompletePassphraseAuthenticationRequest({
      passphraseAuthentication: {
        nonce: beginResponse.payload.passphraseAuthentication.nonce,
        publicKey: keyPair.public(),
      },
      refresh: {
        publicKey: refreshPublicKey,
        nonces: {
          nextDigest: nextNonceDigest,
        },
      },
    })

    completeRequest.sign(keyPair)
    const completeMessage = completeRequest.serialize()
    const completeReply = this.io.network.sendRequest('/auth/passphrase/complete', completeMessage)

    const completeResponse = CompleteAuthenticationResponse.parse(completeReply)
    if (!this.verifyResponse(completeResponse, completeResponse.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }

    this.stores.identifier.session.store(completeResponse.payload.refresh.sessionId)
  }

  refreshAccessToken(): void {
    const accessPublicKey = this.stores.key.access.generate()
    const [current, nextDigest] = this.stores.nonce.refresh.evolve()

    const request = new RefreshAccessTokenRequest({
      refresh: {
        sessionId: this.stores.identifier.session.get(),
        nonces: {
          current: current,
          nextDigest: nextDigest,
        },
      },
      access: {
        publicKey: accessPublicKey,
      },
    })

    request.sign(this.stores.key.refresh.signer())
    const message = request.serialize()
    const reply = this.io.network.sendRequest('/auth/refresh', message)

    const response = RefreshAccessTokenResponse.parse(reply)
    if (!this.verifyResponse(response, response.payload.publicKeyDigest)) {
      throw 'invalid signature'
    }

    this.stores.token.refresh.store(response.payload.access.token)
  }

  // makeRequest<T, R>(message: string): R {

  // }
}
