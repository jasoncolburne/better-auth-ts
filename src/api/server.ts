import {
  IHasher,
  INoncer,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerRecoveryHashStore,
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
        hasher: IHasher
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
          keyHash: IServerTimeLockStore
        }
        authentication: {
          key: IServerAuthenticationKeyStore
          nonce: IServerAuthenticationNonceStore
        }
        recovery: {
          key: IServerRecoveryHashStore
        }
      }
    }
  ) {}

  // we fetch this every time since the keypair implementation may rotate behind the scenes
  private async responseKeyHash(): Promise<string> {
    const responsePublicKey = await this.args.crypto.keyPairs.response.public()
    return await this.args.crypto.hasher.sum(responsePublicKey)
  }

  // account creation

  async createAccount(message: string): Promise<string> {
    const request = CreationRequest.parse(message)
    await request.verify(
      this.args.crypto.verifier,
      request.payload.request.authentication.publicKey
    )

    const identity = request.payload.request.authentication.identity

    await this.args.store.recovery.key.register(
      identity,
      request.payload.request.authentication.recoveryHash
    )

    await this.args.store.authentication.key.register(
      identity,
      request.payload.request.authentication.device,
      request.payload.request.authentication.publicKey,
      request.payload.request.authentication.rotationHash,
      false
    )

    const response = new CreationResponse(
      {},
      await this.responseKeyHash(),
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

    await request.verify(this.args.crypto.verifier, publicKey)

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
      linkContainer.payload.authentication.rotationHash,
      true
    )

    const response = new LinkDeviceResponse(
      {},
      await this.responseKeyHash(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return response.serialize()
  }

  // rotation

  async rotateAuthenticationKey(message: string): Promise<string> {
    const request = RotateAuthenticationKeyRequest.parse(message)
    await request.verify(
      this.args.crypto.verifier,
      request.payload.request.authentication.publicKey
    )

    await this.args.store.authentication.key.rotate(
      request.payload.request.authentication.identity,
      request.payload.request.authentication.device,
      request.payload.request.authentication.publicKey,
      request.payload.request.authentication.rotationHash
    )

    // this is replayable, and should be fixed but making it not fixed
    const response = new RotateAuthenticationKeyResponse(
      {},
      await this.responseKeyHash(),
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
      await this.responseKeyHash(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return await response.serialize()
  }

  async completeAuthentication<T>(message: string, attributes: T): Promise<string> {
    const request = CompleteAuthenticationRequest.parse(message)
    const identity = await this.args.store.authentication.nonce.validate(
      request.payload.request.authentication.nonce
    )

    const authenticationPublicKey = await this.args.store.authentication.key.public(
      identity,
      request.payload.request.authentication.device
    )
    await request.verify(this.args.crypto.verifier, authenticationPublicKey)

    const now = new Date()
    const later = new Date(now)
    const evenLater = new Date(now)

    later.setMinutes(later.getMinutes() + this.args.expiry.accessInMinutes)
    evenLater.setHours(evenLater.getHours() + this.args.expiry.refreshInHours)

    const issuedAt = rfc3339Nano(now)
    const expiry = rfc3339Nano(later)
    const refreshExpiry = rfc3339Nano(evenLater)

    const accessToken = new AccessToken<T>(
      identity,
      request.payload.request.access.publicKey,
      request.payload.request.access.rotationHash,
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
      await this.responseKeyHash(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return await response.serialize()
  }

  // refresh

  async refreshAccessToken<T>(message: string): Promise<string> {
    const request = RefreshAccessTokenRequest.parse(message)
    await request.verify(this.args.crypto.verifier, request.payload.request.access.publicKey)

    const tokenString = request.payload.request.access.token
    const token = await AccessToken.parse<T>(
      tokenString,
      this.args.crypto.keyPairs.access.verifier().signatureLength
    )
    await token.verify(this.args.crypto.verifier, await this.args.crypto.keyPairs.access.public())

    const hash = await this.args.crypto.hasher.sum(request.payload.request.access.publicKey)
    if (hash !== token.rotationHash) {
      throw 'hash mismatch'
    }

    const now = new Date()
    const refreshExpiry = new Date(token.refreshExpiry)

    if (now > refreshExpiry) {
      throw 'refresh has expired'
    }

    await this.args.store.access.keyHash.reserve(hash)

    const later = new Date(now)
    later.setMinutes(later.getMinutes() + this.args.expiry.accessInMinutes)
    const issuedAt = rfc3339Nano(now)
    const expiry = rfc3339Nano(later)

    const accessToken = new AccessToken(
      token.identity,
      request.payload.request.access.publicKey,
      request.payload.request.access.rotationHash,
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
      await this.responseKeyHash(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPairs.response)

    return await response.serialize()
  }

  async recoverAccount(message: string): Promise<string> {
    const request = RecoverAccountRequest.parse(message)
    await request.verify(
      this.args.crypto.verifier,
      request.payload.request.authentication.recoveryKey
    )

    const hash = await this.args.crypto.hasher.sum(
      request.payload.request.authentication.recoveryKey
    )
    await this.args.store.recovery.key.validate(
      request.payload.request.authentication.identity,
      hash
    )

    await this.args.store.authentication.key.register(
      request.payload.request.authentication.identity,
      request.payload.request.authentication.device,
      request.payload.request.authentication.publicKey,
      request.payload.request.authentication.rotationHash,
      true
    )

    const response = new RecoverAccountResponse(
      {},
      await this.responseKeyHash(),
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

  async verify<T>(message: string): Promise<string> {
    const request = AccessRequest.parse<T>(message)
    return await request._verify<T>(
      this.args.store.access.nonce,
      this.args.crypto.verifier,
      this.args.crypto.verifier,
      await this.args.crypto.publicKey.access.public()
    )
  }
}
