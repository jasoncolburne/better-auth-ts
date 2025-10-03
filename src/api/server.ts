import {
  IHasher,
  IIdentityVerifier,
  INoncer,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerRecoveryHashStore,
  IServerTimeLockStore,
  ISigningKey,
  ITimestamper,
  ITokenEncoder,
  IVerificationKey,
  IVerifier,
} from '../interfaces'
import {
  AccessRequest,
  AccessToken,
  CreationRequest,
  CreationResponse,
  FinishAuthenticationRequest,
  FinishAuthenticationResponse,
  LinkContainer,
  LinkDeviceRequest,
  LinkDeviceResponse,
  RecoverAccountRequest,
  RecoverAccountResponse,
  RefreshAccessTokenRequest,
  RefreshAccessTokenResponse,
  RotateAuthenticationKeyRequest,
  RotateAuthenticationKeyResponse,
  StartAuthenticationRequest,
  StartAuthenticationResponse,
  UnlinkDeviceRequest,
  UnlinkDeviceResponse,
} from '../messages'

export class BetterAuthServer {
  constructor(
    private readonly args: {
      crypto: {
        hasher: IHasher
        keyPair: {
          response: ISigningKey
          access: ISigningKey
        }
        noncer: INoncer
        verifier: IVerifier
      }
      encoding: {
        identityVerifier: IIdentityVerifier
        timestamper: ITimestamper
        tokenEncoder: ITokenEncoder
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
          hash: IServerRecoveryHashStore
        }
      }
    }
  ) {}

  // we fetch this every time since the keypair implementation may rotate behind the scenes
  private async responseKeyHash(): Promise<string> {
    const responsePublicKey = await this.args.crypto.keyPair.response.public()
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

    await this.args.encoding.identityVerifier.verify(
      identity,
      request.payload.request.authentication.publicKey,
      request.payload.request.authentication.rotationHash,
      request.payload.request.authentication.recoveryHash
    )

    const deviceHash = await this.args.crypto.hasher.sum(
      request.payload.request.authentication.publicKey
    )

    if (deviceHash !== request.payload.request.authentication.device) {
      throw 'malformed device'
    }

    await this.args.store.recovery.hash.register(
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

    await response.sign(this.args.crypto.keyPair.response)

    return await response.serialize()
  }

  // linking

  async linkDevice(message: string): Promise<string> {
    const request = LinkDeviceRequest.parse(message)

    await request.verify(
      this.args.crypto.verifier,
      request.payload.request.authentication.publicKey
    )

    const linkContainer = new LinkContainer(request.payload.request.link.payload)
    linkContainer.signature = request.payload.request.link.signature

    await linkContainer.verify(
      this.args.crypto.verifier,
      linkContainer.payload.authentication.publicKey
    )

    if (
      linkContainer.payload.authentication.identity !==
      request.payload.request.authentication.identity
    ) {
      throw 'mismatched identities'
    }

    await this.args.store.authentication.key.rotate(
      request.payload.request.authentication.identity,
      request.payload.request.authentication.device,
      request.payload.request.authentication.publicKey,
      request.payload.request.authentication.rotationHash
    )

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

    await response.sign(this.args.crypto.keyPair.response)

    return response.serialize()
  }

  async unlinkDevice(message: string): Promise<string> {
    const request = UnlinkDeviceRequest.parse(message)

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

    await this.args.store.authentication.key.revokeDevice(
      request.payload.request.authentication.identity,
      request.payload.request.link.device
    )

    const response = new UnlinkDeviceResponse(
      {},
      await this.responseKeyHash(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)
    const reply = await response.serialize()

    return reply
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

    await response.sign(this.args.crypto.keyPair.response)

    return await response.serialize()
  }

  // authentication

  async startAuthentication(message: string): Promise<string> {
    const request = StartAuthenticationRequest.parse(message)

    const nonce = await this.args.store.authentication.nonce.generate(
      request.payload.request.authentication.identity
    )

    const response = new StartAuthenticationResponse(
      {
        authentication: {
          nonce: nonce,
        },
      },
      await this.responseKeyHash(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)

    return await response.serialize()
  }

  async finishAuthentication<T>(message: string, attributes: T): Promise<string> {
    const request = FinishAuthenticationRequest.parse(message)
    const identity = await this.args.store.authentication.nonce.validate(
      request.payload.request.authentication.nonce
    )

    const authenticationPublicKey = await this.args.store.authentication.key.public(
      identity,
      request.payload.request.authentication.device
    )
    await request.verify(this.args.crypto.verifier, authenticationPublicKey)

    const now = this.args.encoding.timestamper.now()
    const later = this.args.encoding.timestamper.parse(now)
    const evenLater = this.args.encoding.timestamper.parse(now)

    later.setMinutes(later.getMinutes() + this.args.expiry.accessInMinutes)
    evenLater.setHours(evenLater.getHours() + this.args.expiry.refreshInHours)

    const issuedAt = this.args.encoding.timestamper.format(now)
    const expiry = this.args.encoding.timestamper.format(later)
    const refreshExpiry = this.args.encoding.timestamper.format(evenLater)

    const accessToken = new AccessToken<T>(
      identity,
      request.payload.request.access.publicKey,
      request.payload.request.access.rotationHash,
      issuedAt,
      expiry,
      refreshExpiry,
      attributes
    )

    await accessToken.sign(this.args.crypto.keyPair.access)
    const token = await accessToken.serializeToken(this.args.encoding.tokenEncoder)

    const response = new FinishAuthenticationResponse(
      {
        access: {
          token: token,
        },
      },
      await this.responseKeyHash(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)

    return await response.serialize()
  }

  // refresh

  async refreshAccessToken<T>(message: string): Promise<string> {
    const request = RefreshAccessTokenRequest.parse(message)
    await request.verify(this.args.crypto.verifier, request.payload.request.access.publicKey)

    const tokenString = request.payload.request.access.token
    const token = await AccessToken.parse<T>(
      tokenString,
      this.args.crypto.keyPair.access.verifier().signatureLength,
      this.args.encoding.tokenEncoder
    )
    await token.verifyToken(
      this.args.crypto.verifier,
      await this.args.crypto.keyPair.access.public(),
      this.args.encoding.timestamper
    )

    const hash = await this.args.crypto.hasher.sum(request.payload.request.access.publicKey)
    if (hash !== token.rotationHash) {
      throw 'hash mismatch'
    }

    const now = this.args.encoding.timestamper.now()
    const refreshExpiry = this.args.encoding.timestamper.parse(token.refreshExpiry)

    if (now > refreshExpiry) {
      throw 'refresh has expired'
    }

    await this.args.store.access.keyHash.reserve(hash)

    const later = this.args.encoding.timestamper.parse(now)
    later.setMinutes(later.getMinutes() + this.args.expiry.accessInMinutes)
    const issuedAt = this.args.encoding.timestamper.format(now)
    const expiry = this.args.encoding.timestamper.format(later)

    const accessToken = new AccessToken(
      token.identity,
      request.payload.request.access.publicKey,
      request.payload.request.access.rotationHash,
      issuedAt,
      expiry,
      token.refreshExpiry,
      token.attributes
    )

    await accessToken.sign(this.args.crypto.keyPair.access)
    const serializedToken = await accessToken.serializeToken(this.args.encoding.tokenEncoder)

    const response = new RefreshAccessTokenResponse(
      {
        access: {
          token: serializedToken,
        },
      },
      await this.responseKeyHash(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)

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
    await this.args.store.recovery.hash.rotate(
      request.payload.request.authentication.identity,
      hash,
      request.payload.request.authentication.recoveryHash
    )

    await this.args.store.authentication.key.revokeDevices(
      request.payload.request.authentication.identity
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

    await response.sign(this.args.crypto.keyPair.response)

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
      encoding: {
        tokenEncoder: ITokenEncoder
        timestamper: ITimestamper
      }
      store: {
        access: {
          nonce: IServerTimeLockStore
        }
      }
    }
  ) {}

  async verify<T, U>(message: string): Promise<[string, U]> {
    const request = AccessRequest.parse<T>(message)
    return await request._verify<U>(
      this.args.store.access.nonce,
      this.args.crypto.verifier,
      this.args.crypto.publicKey.access.verifier(),
      await this.args.crypto.publicKey.access.public(),
      this.args.encoding.tokenEncoder,
      this.args.encoding.timestamper
    )
  }
}
