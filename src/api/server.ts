import {
  IDigester,
  ISalter,
  IServerAccessNonceStore,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerPassphraseAuthenticationKeyStore,
  IServerPassphraseRegistrationTokenStore,
  IServerRefreshKeyStore,
  IServerRefreshNonceStore,
  IServerRegistrationTokenStore,
  ISigningKey,
  IVerificationKey,
  IVerifier,
} from '../interfaces'
import {
  AccessRequest,
  AccessToken,
  BeginAuthenticationRequest,
  BeginAuthenticationResponse,
  BeginPassphraseAuthenticationRequest,
  BeginPassphraseAuthenticationResponse,
  CompleteAuthenticationRequest,
  CompleteAuthenticationResponse,
  CompletePassphraseAuthenticationRequest,
  CompletePassphraseAuthenticationResponse,
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
import { rfc3339Nano } from '../utils/time'

export class BetterAuthServer {
  constructor(
    private readonly stores: {
      registrationToken: {
        key: IServerRegistrationTokenStore
        passphrase: IServerPassphraseRegistrationTokenStore
      }
      key: {
        authentication: IServerAuthenticationKeyStore
        passphrase: IServerPassphraseAuthenticationKeyStore
        refresh: IServerRefreshKeyStore
      }
      nonce: {
        authentication: IServerAuthenticationNonceStore
        refresh: IServerRefreshNonceStore
        access: IServerAccessNonceStore
      }
    },
    private readonly crypto: {
      keyPairs: {
        response: ISigningKey
        access: ISigningKey
      }
      verification: {
        key: IVerifier
        passphrase: IVerifier
      }
      salt: ISalter
      digest: IDigester
    }
  ) {}

  private responsePublicKeyDigest(): string {
    const responsePublicKey = this.crypto.keyPairs.response.public()
    return this.crypto.digest.sum(responsePublicKey)
  }

  // registration

  generateRegistrationMaterials(): string {
    const token = this.stores.registrationToken.key.generate()

    const response = new RegistrationMaterials({
      registration: {
        token: token,
      },
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }

  generatePassphraseRegistrationMaterials(): string {
    const params = '$argon2id$v=19$m=262144,t=3,p=4$' // TODO remove magic
    const salt = this.crypto.salt.generate128()

    const token = this.stores.registrationToken.passphrase.generate(salt, params)

    const response = new PassphraseRegistrationMaterials({
      registration: {
        token: token,
      },
      passphraseAuthentication: {
        parameters: params,
        salt: salt,
      },
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }

  registerAuthenticationKey(message: string): string {
    const request = RegisterAuthenticationKeyRequest.parse(message)
    if (
      !request.verify(
        this.crypto.verification.key,
        request.payload.authentication.publicKeys.current
      )
    ) {
      throw 'invalid signature'
    }

    const token = request.payload.registration.token
    const accountId = this.stores.registrationToken.key.validate(token)

    this.stores.key.authentication.register(
      accountId,
      request.payload.identification.deviceId,
      request.payload.authentication.publicKeys.current,
      request.payload.authentication.publicKeys.nextDigest
    )

    this.stores.registrationToken.key.invalidate(token)

    const response = new RegisterAuthenticationKeyResponse({
      identification: {
        accountId: accountId,
      },
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }

  registerPassphraseAuthenticationKey(message: string): string {
    const request = RegisterPassphraseAuthenticationKeyRequest.parse(message)
    if (
      !request.verify(
        this.crypto.verification.passphrase,
        request.payload.passphraseAuthentication.publicKey
      )
    ) {
      throw 'invalid signature'
    }

    const token = request.payload.registration.token
    const [accountId, salt, parameters] = this.stores.registrationToken.passphrase.validate(token)
    const passphraseKeyDigest = this.crypto.digest.sum(
      request.payload.passphraseAuthentication.publicKey
    )

    this.stores.key.passphrase.register(accountId, passphraseKeyDigest, salt, parameters)

    this.stores.registrationToken.passphrase.invalidate(token)

    const response = new RegisterPassphraseAuthenticationKeyResponse({
      identification: {
        accountId: accountId,
      },
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }

  // rotation

  rotateAuthenticationKey(message: string): string {
    const request = RotateAuthenticationKeyRequest.parse(message)
    if (
      !request.verify(
        this.crypto.verification.key,
        request.payload.authentication.publicKeys.current
      )
    ) {
      throw 'invalid signature'
    }

    this.stores.key.authentication.rotate(
      request.payload.identification.accountId,
      request.payload.identification.deviceId,
      request.payload.authentication.publicKeys.current,
      request.payload.authentication.publicKeys.nextDigest
    )

    // this is replayable, and should be fixed but making it not fixed
    const response = new RotateAuthenticationKeyResponse({
      success: true,
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }

  // authentication

  beginAuthentication(message: string): string {
    const request = BeginAuthenticationRequest.parse(message)

    const nonce = this.stores.nonce.authentication.generate(
      request.payload.identification.accountId
    )

    const response = new BeginAuthenticationResponse({
      authentication: {
        nonce: nonce,
      },
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }

  completeAuthentication(message: string): string {
    const request = CompleteAuthenticationRequest.parse(message)
    const accountId = this.stores.nonce.authentication.validate(
      request.payload.authentication.nonce
    )

    const authenticationPublicKey = this.stores.key.authentication.public(
      accountId,
      request.payload.identification.deviceId
    )
    if (!request.verify(this.crypto.verification.key, authenticationPublicKey)) {
      throw 'invalid signature'
    }

    const sessionId = this.stores.key.refresh.create(accountId, request.payload.refresh.publicKey)
    this.stores.nonce.refresh.create(sessionId, request.payload.refresh.nonces.nextDigest)

    const response = new CompleteAuthenticationResponse({
      refresh: {
        sessionId: sessionId,
      },
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }

  beginPassphraseAuthentication(message: string): string {
    const request = BeginPassphraseAuthenticationRequest.parse(message)

    const nonce = this.stores.nonce.authentication.generate(
      request.payload.identification.accountId
    )
    const [salt, parameters] = this.stores.key.passphrase.getDerivationMaterials(
      request.payload.identification.accountId
    )

    const response = new BeginPassphraseAuthenticationResponse({
      passphraseAuthentication: {
        nonce: nonce,
        salt: salt,
        parameters: parameters,
      },
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }

  completePassphraseAuthentication(message: string): string {
    const request = CompletePassphraseAuthenticationRequest.parse(message)
    if (
      !request.verify(
        this.crypto.verification.passphrase,
        request.payload.passphraseAuthentication.publicKey
      )
    ) {
      throw 'invalid signature'
    }

    const accountId = this.stores.nonce.authentication.validate(
      request.payload.passphraseAuthentication.nonce
    )
    const publicKeyDigest = this.crypto.digest.sum(
      request.payload.passphraseAuthentication.publicKey
    )
    if (!this.stores.key.passphrase.verifyPublicKeyDigest(accountId, publicKeyDigest)) {
      throw 'invalid public key'
    }

    const sessionId = this.stores.key.refresh.create(accountId, request.payload.refresh.publicKey)
    this.stores.nonce.refresh.create(sessionId, request.payload.refresh.nonces.nextDigest)

    const response = new CompletePassphraseAuthenticationResponse({
      refresh: {
        sessionId: sessionId,
      },
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }

  // refresh

  refreshAccessToken<T>(message: string, attributes: T): string {
    const request = RefreshAccessTokenRequest.parse(message)

    const [accountId, refreshKey] = this.stores.key.refresh.get(request.payload.refresh.sessionId)
    if (!request.verify(this.crypto.verification.key, refreshKey)) {
      throw 'invalid signature'
    }

    this.stores.nonce.refresh.evolve(
      request.payload.refresh.nonces.current,
      request.payload.refresh.nonces.nextDigest
    )

    const now = new Date()
    const later = new Date(now)
    later.setMinutes(later.getMinutes() + 15)
    const issuedAt = rfc3339Nano(now)
    const expiry = rfc3339Nano(later)

    const accessToken = new AccessToken<T>(
      accountId,
      request.payload.access.publicKey,
      issuedAt,
      expiry,
      attributes
    )

    accessToken.sign(this.crypto.keyPairs.access)
    const token = accessToken.serialize()

    const response = new RefreshAccessTokenResponse({
      access: {
        token: token,
      },
      publicKeyDigest: this.responsePublicKeyDigest(),
    })

    response.sign(this.crypto.keyPairs.response)

    return response.serialize()
  }
}

export class AccessVerifier {
  constructor(
    private readonly stores: {
      accessNonce: IServerAccessNonceStore
    },
    private readonly crypto: {
      publicKeys: {
        access: IVerificationKey
      }
      verification: {
        key: IVerifier
      }
    }
  ) {}

  verify<T>(message: string): boolean {
    const request = AccessRequest.parse<T>(message)
    return request.verifyRequest(
      this.stores.accessNonce,
      this.crypto.verification.key,
      this.crypto.verification.key,
      this.crypto.publicKeys.access.public()
    )
  }
}
