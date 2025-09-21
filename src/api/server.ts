import {
  IDigester,
  ISalter,
  IServerAccessNonceStore,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerAuthenticationRegistrationTokenStore,
  IServerPassphraseAuthenticationKeyStore,
  IServerPassphraseRegistrationTokenStore,
  IServerRefreshKeyStore,
  IServerRefreshNonceStore,
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
      token: {
        registration: {
          key: IServerAuthenticationRegistrationTokenStore
          passphrase: IServerPassphraseRegistrationTokenStore
        }
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

  private async responsePublicKeyDigest(): Promise<string> {
    const responsePublicKey = this.crypto.keyPairs.response.public()
    return await this.crypto.digest.sum(responsePublicKey)
  }

  // registration

  async generateRegistrationMaterials(): Promise<string> {
    const token = await this.stores.token.registration.key.generate()

    const response = new RegistrationMaterials({
      registration: {
        token: token,
      },
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  async generatePassphraseRegistrationMaterials(): Promise<string> {
    const params = '$argon2id$v=19$m=262144,t=3,p=4$' // TODO remove magic
    const salt = await this.crypto.salt.generate128()

    const token = await this.stores.token.registration.passphrase.generate(salt, params)

    const response = new PassphraseRegistrationMaterials({
      registration: {
        token: token,
      },
      passphraseAuthentication: {
        parameters: params,
        salt: salt,
      },
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  async registerAuthenticationKey(message: string): Promise<string> {
    const request = RegisterAuthenticationKeyRequest.parse(message)
    if (
      !(await request.verify(
        this.crypto.verification.key,
        request.payload.authentication.publicKeys.current
      ))
    ) {
      throw 'invalid signature'
    }

    const token = request.payload.registration.token
    const accountId = await this.stores.token.registration.key.validate(token)

    await this.stores.key.authentication.register(
      accountId,
      request.payload.identification.deviceId,
      request.payload.authentication.publicKeys.current,
      request.payload.authentication.publicKeys.nextDigest
    )

    await this.stores.token.registration.key.invalidate(token)

    const response = new RegisterAuthenticationKeyResponse({
      identification: {
        accountId: accountId,
      },
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  async registerPassphraseAuthenticationKey(message: string): Promise<string> {
    const request = RegisterPassphraseAuthenticationKeyRequest.parse(message)
    if (
      !(await request.verify(
        this.crypto.verification.passphrase,
        request.payload.passphraseAuthentication.publicKey
      ))
    ) {
      throw 'invalid signature'
    }

    const token = request.payload.registration.token
    const [accountId, salt, parameters] =
      await this.stores.token.registration.passphrase.validate(token)
    const passphraseKeyDigest = await this.crypto.digest.sum(
      request.payload.passphraseAuthentication.publicKey
    )

    await this.stores.key.passphrase.register(accountId, passphraseKeyDigest, salt, parameters)

    await this.stores.token.registration.passphrase.invalidate(token)

    const response = new RegisterPassphraseAuthenticationKeyResponse({
      identification: {
        accountId: accountId,
      },
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  // rotation

  async rotateAuthenticationKey(message: string): Promise<string> {
    const request = RotateAuthenticationKeyRequest.parse(message)
    if (
      !(await request.verify(
        this.crypto.verification.key,
        request.payload.authentication.publicKeys.current
      ))
    ) {
      throw 'invalid signature'
    }

    await this.stores.key.authentication.rotate(
      request.payload.identification.accountId,
      request.payload.identification.deviceId,
      request.payload.authentication.publicKeys.current,
      request.payload.authentication.publicKeys.nextDigest
    )

    // this is replayable, and should be fixed but making it not fixed
    const response = new RotateAuthenticationKeyResponse({
      success: true,
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  // authentication

  async beginAuthentication(message: string): Promise<string> {
    const request = BeginAuthenticationRequest.parse(message)

    const nonce = await this.stores.nonce.authentication.generate(
      request.payload.identification.accountId
    )

    const response = new BeginAuthenticationResponse({
      authentication: {
        nonce: nonce,
      },
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  async completeAuthentication(message: string): Promise<string> {
    const request = CompleteAuthenticationRequest.parse(message)
    const accountId = await this.stores.nonce.authentication.validate(
      request.payload.authentication.nonce
    )

    const authenticationPublicKey = this.stores.key.authentication.public(
      accountId,
      request.payload.identification.deviceId
    )
    if (!(await request.verify(this.crypto.verification.key, authenticationPublicKey))) {
      throw 'invalid signature'
    }

    const sessionId = await this.stores.key.refresh.create(
      accountId,
      request.payload.refresh.publicKey
    )
    await this.stores.nonce.refresh.create(sessionId, request.payload.refresh.nonces.nextDigest)

    const response = new CompleteAuthenticationResponse({
      refresh: {
        sessionId: sessionId,
      },
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  async beginPassphraseAuthentication(message: string): Promise<string> {
    const request = BeginPassphraseAuthenticationRequest.parse(message)

    const nonce = await this.stores.nonce.authentication.generate(
      request.payload.identification.accountId
    )
    const [salt, parameters] = await this.stores.key.passphrase.getDerivationMaterials(
      request.payload.identification.accountId
    )

    const response = new BeginPassphraseAuthenticationResponse({
      passphraseAuthentication: {
        nonce: nonce,
        salt: salt,
        parameters: parameters,
      },
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  async completePassphraseAuthentication(message: string): Promise<string> {
    const request = CompletePassphraseAuthenticationRequest.parse(message)
    if (
      !(await request.verify(
        this.crypto.verification.passphrase,
        request.payload.passphraseAuthentication.publicKey
      ))
    ) {
      throw 'invalid signature'
    }

    const accountId = await this.stores.nonce.authentication.validate(
      request.payload.passphraseAuthentication.nonce
    )
    const publicKeyDigest = await this.crypto.digest.sum(
      request.payload.passphraseAuthentication.publicKey
    )
    if (!(await this.stores.key.passphrase.verifyPublicKeyDigest(accountId, publicKeyDigest))) {
      throw 'invalid public key'
    }

    const sessionId = await this.stores.key.refresh.create(
      accountId,
      request.payload.refresh.publicKey
    )
    await this.stores.nonce.refresh.create(sessionId, request.payload.refresh.nonces.nextDigest)

    const response = new CompletePassphraseAuthenticationResponse({
      refresh: {
        sessionId: sessionId,
      },
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  // refresh

  async refreshAccessToken<T>(message: string, attributes: T): Promise<string> {
    const request = RefreshAccessTokenRequest.parse(message)

    const [accountId, refreshKey] = await this.stores.key.refresh.get(
      request.payload.refresh.sessionId
    )
    if (!(await request.verify(this.crypto.verification.key, refreshKey))) {
      throw 'invalid signature'
    }

    await this.stores.nonce.refresh.evolve(
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

    await accessToken.sign(this.crypto.keyPairs.access)
    const token = await accessToken.serialize()

    const response = new RefreshAccessTokenResponse({
      access: {
        token: token,
      },
      publicKeyDigest: await this.responsePublicKeyDigest(),
    })

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
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

  async verify<T>(message: string): Promise<boolean> {
    const request = AccessRequest.parse<T>(message)
    return await request.verifyRequest(
      this.stores.accessNonce,
      this.crypto.verification.key,
      this.crypto.verification.key,
      this.crypto.publicKeys.access.public()
    )
  }
}
