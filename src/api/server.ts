import {
  IDigester,
  INoncer,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerRegistrationTokenStore,
  IServerTimeLockStore,
  ISigningKey,
  IVerificationKey,
  IVerifier,
} from '../interfaces'
import {
  AccessRequest,
  AccessToken,
  BeginAuthenticationRequest,
  BeginAuthenticationResponse,
  CompleteAuthenticationRequest,
  CompleteAuthenticationResponse,
  CreationContainer,
  CreationRequest,
  CreationResponse,
  RefreshAccessTokenRequest,
  RefreshAccessTokenResponse,
  RotateAuthenticationKeyRequest,
  RotateAuthenticationKeyResponse,
} from '../messages'
import { rfc3339Nano } from '../utils'

export class BetterAuthServer {
  constructor(
    private readonly stores: {
      registration: {
        token: IServerRegistrationTokenStore
      }
      authentication: {
        key: IServerAuthenticationKeyStore
        nonce: IServerAuthenticationNonceStore
      }
      access: {
        keyDigest: IServerTimeLockStore
      }
    },
    private readonly crypto: {
      keyPairs: {
        response: ISigningKey
        access: ISigningKey
      }
      verifier: IVerifier
      noncer: INoncer
      digester: IDigester
    },
    private readonly expiry: {
      accessInMinutes: number
      refreshInHours: number
    }
  ) {}

  private async responseKeyDigest(): Promise<string> {
    const responsePublicKey = await this.crypto.keyPairs.response.public()
    return await this.crypto.digester.sum(responsePublicKey)
  }

  // registration

  async generateCreationContainer(): Promise<string> {
    const token = await this.stores.registration.token.generate()

    const response = new CreationContainer(
      {
        registration: {
          token: token,
        },
      },
      await this.responseKeyDigest(),
      await this.crypto.noncer.generate128()
    )

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  async createAccount(message: string): Promise<string> {
    const request = CreationRequest.parse(message)
    if (
      !(await request.verify(
        this.crypto.verifier,
        request.payload.authentication.publicKeys.current
      ))
    ) {
      throw 'invalid signature'
    }

    const token = request.payload.registration.token
    const accountId = await this.stores.registration.token.validate(token)

    await this.stores.authentication.key.register(
      accountId,
      request.payload.identification.deviceId,
      request.payload.authentication.publicKeys.current,
      request.payload.authentication.publicKeys.nextDigest
    )

    await this.stores.registration.token.invalidate(token)

    const response = new CreationResponse(
      {
        identification: {
          accountId: accountId,
        },
      },
      await this.responseKeyDigest(),
      await this.crypto.noncer.generate128()
    )

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  // rotation

  async rotateAuthenticationKey(message: string): Promise<string> {
    const request = RotateAuthenticationKeyRequest.parse(message)
    if (
      !(await request.verify(
        this.crypto.verifier,
        request.payload.authentication.publicKeys.current
      ))
    ) {
      throw 'invalid signature'
    }

    await this.stores.authentication.key.rotate(
      request.payload.identification.accountId,
      request.payload.identification.deviceId,
      request.payload.authentication.publicKeys.current,
      request.payload.authentication.publicKeys.nextDigest
    )

    // this is replayable, and should be fixed but making it not fixed
    const response = new RotateAuthenticationKeyResponse(
      {},
      await this.responseKeyDigest(),
      await this.crypto.noncer.generate128()
    )

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  // authentication

  async beginAuthentication(message: string): Promise<string> {
    const request = BeginAuthenticationRequest.parse(message)

    const nonce = await this.stores.authentication.nonce.generate(
      request.payload.identification.accountId
    )

    const response = new BeginAuthenticationResponse(
      {
        authentication: {
          nonce: nonce,
        },
      },
      await this.responseKeyDigest(),
      await this.crypto.noncer.generate128()
    )

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  async completeAuthentication<T>(message: string, attributes: T): Promise<string> {
    const request = CompleteAuthenticationRequest.parse(message)
    const accountId = await this.stores.authentication.nonce.validate(
      request.payload.authentication.nonce
    )

    const authenticationPublicKey = await this.stores.authentication.key.public(
      accountId,
      request.payload.identification.deviceId
    )
    if (!(await request.verify(this.crypto.verifier, authenticationPublicKey))) {
      throw 'invalid signature'
    }

    const now = new Date()
    const later = new Date(now)
    later.setMinutes(later.getMinutes() + this.expiry.accessInMinutes)
    const issuedAt = rfc3339Nano(now)
    const expiry = rfc3339Nano(later)
    const evenLater = new Date(now)
    evenLater.setHours(evenLater.getHours() + this.expiry.refreshInHours)
    const refreshExpiry = rfc3339Nano(evenLater)

    const accessToken = new AccessToken<T>(
      accountId,
      request.payload.access.publicKeys.current,
      request.payload.access.publicKeys.nextDigest,
      issuedAt,
      expiry,
      refreshExpiry,
      attributes
    )

    await accessToken.sign(this.crypto.keyPairs.access)
    const token = await accessToken.serialize()

    const response = new CompleteAuthenticationResponse(
      {
        access: {
          token: token,
        },
      },
      await this.responseKeyDigest(),
      await this.crypto.noncer.generate128()
    )

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }

  // refresh

  async refreshAccessToken<T>(message: string): Promise<string> {
    const request = RefreshAccessTokenRequest.parse(message)
    if (!(await request.verify(this.crypto.verifier, request.payload.access.publicKeys.current))) {
      throw 'invalid signature'
    }

    const tokenString = request.payload.access.token
    const token = await AccessToken.parse<T>(tokenString)
    if (!token.verify(this.crypto.verifier, await this.crypto.keyPairs.access.public())) {
      throw 'invalid token signature'
    }

    const digest = await this.crypto.digester.sum(request.payload.access.publicKeys.current)
    if (digest !== token.nextDigest) {
      throw 'digest mismatch'
    }

    const now = new Date()
    const refreshExpiry = new Date(token.refreshExpiry)

    if (now > refreshExpiry) {
      throw 'refresh has expired'
    }

    await this.stores.access.keyDigest.reserve(digest)

    const later = new Date(now)
    later.setMinutes(later.getMinutes() + this.expiry.accessInMinutes)
    const issuedAt = rfc3339Nano(now)
    const expiry = rfc3339Nano(later)

    const accessToken = new AccessToken(
      token.accountId,
      request.payload.access.publicKeys.current,
      request.payload.access.publicKeys.nextDigest,
      issuedAt,
      expiry,
      token.refreshExpiry,
      token.attributes
    )

    await accessToken.sign(this.crypto.keyPairs.access)
    const serializedToken = await accessToken.serialize()

    const response = new RefreshAccessTokenResponse(
      {
        access: {
          token: serializedToken,
        },
      },
      await this.responseKeyDigest(),
      await this.crypto.noncer.generate128()
    )

    await response.sign(this.crypto.keyPairs.response)

    return await response.serialize()
  }
}

export class AccessVerifier {
  constructor(
    private readonly stores: {
      access: {
        nonce: IServerTimeLockStore
      }
    },
    private readonly crypto: {
      publicKeys: {
        access: IVerificationKey
      }
      verifier: IVerifier
    }
  ) {}

  async verify<T>(message: string): Promise<boolean> {
    const request = AccessRequest.parse<T>(message)
    return await request._verify<T>(
      this.stores.access.nonce,
      this.crypto.verifier,
      this.crypto.verifier,
      await this.crypto.publicKeys.access.public()
    )
  }
}
