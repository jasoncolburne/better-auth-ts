import {
  IDigester,
  INoncer,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerRecoveryDigestStore,
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
  CreationRequest,
  CreationResponse,
  LinkContainer,
  LinkDeviceRequest,
  LinkDeviceResponse,
  RefreshAccessTokenRequest,
  RefreshAccessTokenResponse,
  RotateAuthenticationKeyRequest,
  RotateAuthenticationKeyResponse,
} from '../messages'
import { RecoverAccountRequest, RecoverAccountResponse } from '../messages/recovery'
import { rfc3339Nano } from '../utils'

export class BetterAuthServer {
  constructor(
    private readonly args: {
      crypto: {
        digester: IDigester
        keyPairs: {
          response: ISigningKey
          access: ISigningKey
        }
        noncer: INoncer
        verifier: IVerifier
      }
      expiry: {
        accessInMinutes: number
        refreshInHours: number
      }
      store: {
        access: {
          keyDigest: IServerTimeLockStore
        }
        authentication: {
          key: IServerAuthenticationKeyStore
          nonce: IServerAuthenticationNonceStore
        }
        recovery: {
          key: IServerRecoveryDigestStore
        }
      }
    }
  ) {}

  // we fetch this every time since the keypair implementation may rotate behind the scenes
  private async responseKeyDigest(): Promise<string> {
    const responsePublicKey = await this.args.crypto.keyPairs.response.public()
    return await this.args.crypto.digester.sum(responsePublicKey)
  }

  // account creation

  async createAccount(message: string): Promise<string> {
    const request = CreationRequest.parse(message)
    if (
      !(await request.verify(
        this.args.crypto.verifier,
        request.payload.request.authentication.publicKey
      ))
    ) {
      throw 'invalid signature'
    }

    const identity = request.payload.request.authentication.identity

    await this.args.store.recovery.key.register(
      identity,
      request.payload.request.creation.recoveryDigest
    )

    await this.args.store.authentication.key.register(
      identity,
      request.payload.request.authentication.device,
      request.payload.request.authentication.publicKey,
      request.payload.request.authentication.rotationDigest
    )

    const response = new CreationResponse(
      {
        identification: {
          accountId: identity,
        },
      },
      await this.responseKeyDigest(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return await response.serialize()
  }

  // linking

  async linkDevice(message: string): Promise<string> {
    const request = LinkDeviceRequest.parse(message)

    const publicKey = await this.args.store.authentication.key.public(
      request.payload.request.authentication.identity,
      request.payload.request.authentication.device
    )

    if (!(await request.verify(this.args.crypto.verifier, publicKey))) {
      throw 'invalid signature'
    }

    const linkContainer = new LinkContainer(request.payload.request.link.payload)
    linkContainer.signature = request.payload.request.link.signature

    if (
      !linkContainer.verify(
        this.args.crypto.verifier,
        linkContainer.payload.authentication.publicKey
      )
    ) {
      throw 'invalid signature'
    }

    if (
      linkContainer.payload.authentication.identity !==
      request.payload.request.authentication.identity
    ) {
      throw 'mismatched identities'
    }

    await this.args.store.authentication.key.register(
      linkContainer.payload.authentication.identity,
      linkContainer.payload.authentication.device,
      linkContainer.payload.authentication.publicKey,
      linkContainer.payload.authentication.rotationDigest
    )

    const response = new LinkDeviceResponse(
      {},
      await this.responseKeyDigest(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return response.serialize()
  }

  // rotation

  async rotateAuthenticationKey(message: string): Promise<string> {
    const request = RotateAuthenticationKeyRequest.parse(message)
    if (
      !(await request.verify(
        this.args.crypto.verifier,
        request.payload.request.authentication.publicKey
      ))
    ) {
      throw 'invalid signature'
    }

    await this.args.store.authentication.key.rotate(
      request.payload.request.authentication.identity,
      request.payload.request.authentication.device,
      request.payload.request.authentication.publicKey,
      request.payload.request.authentication.rotationDigest
    )

    // this is replayable, and should be fixed but making it not fixed
    const response = new RotateAuthenticationKeyResponse(
      {},
      await this.responseKeyDigest(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return await response.serialize()
  }

  // authentication

  async beginAuthentication(message: string): Promise<string> {
    const request = BeginAuthenticationRequest.parse(message)

    const nonce = await this.args.store.authentication.nonce.generate(
      request.payload.request.authentication.identity
    )

    const response = new BeginAuthenticationResponse(
      {
        authentication: {
          nonce: nonce,
        },
      },
      await this.responseKeyDigest(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return await response.serialize()
  }

  async completeAuthentication<T>(message: string, attributes: T): Promise<string> {
    const request = CompleteAuthenticationRequest.parse(message)
    const accountId = await this.args.store.authentication.nonce.validate(
      request.payload.request.authentication.nonce
    )

    const authenticationPublicKey = await this.args.store.authentication.key.public(
      accountId,
      request.payload.request.authentication.device
    )
    if (!(await request.verify(this.args.crypto.verifier, authenticationPublicKey))) {
      throw 'invalid signature'
    }

    const now = new Date()
    const later = new Date(now)
    later.setMinutes(later.getMinutes() + this.args.expiry.accessInMinutes)
    const issuedAt = rfc3339Nano(now)
    const expiry = rfc3339Nano(later)
    const evenLater = new Date(now)
    evenLater.setHours(evenLater.getHours() + this.args.expiry.refreshInHours)
    const refreshExpiry = rfc3339Nano(evenLater)

    const accessToken = new AccessToken<T>(
      accountId,
      request.payload.request.access.publicKey,
      request.payload.request.access.rotationDigest,
      issuedAt,
      expiry,
      refreshExpiry,
      attributes
    )

    await accessToken.sign(this.args.crypto.keyPairs.access)
    const token = await accessToken.serialize()

    const response = new CompleteAuthenticationResponse(
      {
        access: {
          token: token,
        },
      },
      await this.responseKeyDigest(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return await response.serialize()
  }

  // refresh

  async refreshAccessToken<T>(message: string): Promise<string> {
    const request = RefreshAccessTokenRequest.parse(message)
    if (
      !(await request.verify(this.args.crypto.verifier, request.payload.request.access.publicKey))
    ) {
      throw 'invalid signature'
    }

    const tokenString = request.payload.request.access.token
    const token = await AccessToken.parse<T>(tokenString)
    if (!token.verify(this.args.crypto.verifier, await this.args.crypto.keyPairs.access.public())) {
      throw 'invalid token signature'
    }

    const digest = await this.args.crypto.digester.sum(request.payload.request.access.publicKey)
    if (digest !== token.rotationDigest) {
      throw 'digest mismatch'
    }

    const now = new Date()
    const refreshExpiry = new Date(token.refreshExpiry)

    if (now > refreshExpiry) {
      throw 'refresh has expired'
    }

    await this.args.store.access.keyDigest.reserve(digest)

    const later = new Date(now)
    later.setMinutes(later.getMinutes() + this.args.expiry.accessInMinutes)
    const issuedAt = rfc3339Nano(now)
    const expiry = rfc3339Nano(later)

    const accessToken = new AccessToken(
      token.identity,
      request.payload.request.access.publicKey,
      request.payload.request.access.rotationDigest,
      issuedAt,
      expiry,
      token.refreshExpiry,
      token.attributes
    )

    await accessToken.sign(this.args.crypto.keyPairs.access)
    const serializedToken = await accessToken.serialize()

    const response = new RefreshAccessTokenResponse(
      {
        access: {
          token: serializedToken,
        },
      },
      await this.responseKeyDigest(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return await response.serialize()
  }

  async recoverAccount(message: string): Promise<string> {
    const request = RecoverAccountRequest.parse(message)
    if (
      !(await request.verify(this.args.crypto.verifier, request.payload.request.recovery.publicKey))
    ) {
      throw 'invalid signature'
    }

    const digest = await this.args.crypto.digester.sum(request.payload.request.recovery.publicKey)
    await this.args.store.recovery.key.validate(
      request.payload.request.authentication.identity,
      digest
    )

    await this.args.store.authentication.key.register(
      request.payload.request.authentication.identity,
      request.payload.request.authentication.device,
      request.payload.request.authentication.publicKey,
      request.payload.request.authentication.rotationDigest
    )

    const response = new RecoverAccountResponse(
      {},
      await this.responseKeyDigest(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return await response.serialize()
  }
}

export class AccessVerifier {
  constructor(
    private readonly args: {
      crypto: {
        publicKey: {
          access: IVerificationKey
        }
        verifier: IVerifier
      }
      store: {
        access: {
          nonce: IServerTimeLockStore
        }
      }
    }
  ) {}

  async verify<T>(message: string): Promise<boolean> {
    const request = AccessRequest.parse<T>(message)
    return await request._verify<T>(
      this.args.store.access.nonce,
      this.args.crypto.verifier,
      this.args.crypto.verifier,
      await this.args.crypto.publicKey.access.public()
    )
  }
}
