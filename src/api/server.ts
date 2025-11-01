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
  IVerificationKeyStore,
  IVerifier,
} from '../interfaces/index.js'
import {
  ExpiredTokenError,
  InvalidDeviceError,
  InvalidHashError,
  MismatchedIdentitiesError,
} from '../errors.js'
import {
  AccessRequest,
  AccessToken,
  ChangeRecoveryKeyRequest,
  ChangeRecoveryKeyResponse,
  CreateAccountRequest,
  CreateAccountResponse,
  CreateSessionRequest,
  CreateSessionResponse,
  DeleteAccountRequest,
  DeleteAccountResponse,
  LinkContainer,
  LinkDeviceRequest,
  LinkDeviceResponse,
  RecoverAccountRequest,
  RecoverAccountResponse,
  RefreshSessionRequest,
  RefreshSessionResponse,
  RequestSessionRequest,
  RequestSessionResponse,
  RotateDeviceRequest,
  RotateDeviceResponse,
  UnlinkDeviceRequest,
  UnlinkDeviceResponse,
} from '../messages/index.js'

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
          verificationKey: IVerificationKeyStore
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

  // account creation

  async createAccount(message: string): Promise<string> {
    const request = CreateAccountRequest.parse(message)
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

    const device = await this.args.crypto.hasher.sum(
      request.payload.request.authentication.publicKey +
        request.payload.request.authentication.rotationHash
    )

    if (device !== request.payload.request.authentication.device) {
      throw new InvalidDeviceError(request.payload.request.authentication.device, device)
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

    const response = new CreateAccountResponse(
      {},
      await this.args.crypto.keyPair.response.identity(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)

    return await response.serialize()
  }

  async deleteAccount(message: string): Promise<string> {
    const request = DeleteAccountRequest.parse(message)
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

    await this.args.store.authentication.key.deleteIdentity(
      request.payload.request.authentication.identity
    )

    const response = new DeleteAccountResponse(
      {},
      await this.args.crypto.keyPair.response.identity(),
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

    const device = await this.args.crypto.hasher.sum(
      request.payload.request.authentication.publicKey +
        request.payload.request.authentication.rotationHash
    )

    if (device !== request.payload.request.authentication.device) {
      throw new InvalidDeviceError(request.payload.request.authentication.device, device)
    }

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
      await this.args.crypto.keyPair.response.identity(),
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
      throw new MismatchedIdentitiesError(
        linkContainer.payload.authentication.identity,
        request.payload.request.authentication.identity
      )
    }

    const device = await this.args.crypto.hasher.sum(
      linkContainer.payload.authentication.publicKey +
        linkContainer.payload.authentication.rotationHash
    )

    if (device !== linkContainer.payload.authentication.device) {
      throw 'bad device derivation'
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
      await this.args.crypto.keyPair.response.identity(),
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
      await this.args.crypto.keyPair.response.identity(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)
    const reply = await response.serialize()

    return reply
  }

  // rotation

  async rotateDevice(message: string): Promise<string> {
    const request = RotateDeviceRequest.parse(message)
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
    const response = new RotateDeviceResponse(
      {},
      await this.args.crypto.keyPair.response.identity(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)

    return await response.serialize()
  }

  // authentication

  async requestSession(message: string): Promise<string> {
    const request = RequestSessionRequest.parse(message)

    const nonce = await this.args.store.authentication.nonce.generate(
      request.payload.request.authentication.identity
    )

    const response = new RequestSessionResponse(
      {
        authentication: {
          nonce: nonce,
        },
      },
      await this.args.crypto.keyPair.response.identity(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)

    return await response.serialize()
  }

  async createSession<T>(message: string, attributes: T): Promise<string> {
    const request = CreateSessionRequest.parse(message)
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
      await this.args.crypto.keyPair.access.identity(),
      request.payload.request.authentication.device,
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

    const response = new CreateSessionResponse(
      {
        access: {
          token: token,
        },
      },
      await this.args.crypto.keyPair.response.identity(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)

    return await response.serialize()
  }

  // refresh

  async refreshSession<T>(message: string): Promise<string> {
    const request = RefreshSessionRequest.parse(message)
    await request.verify(this.args.crypto.verifier, request.payload.request.access.publicKey)

    const tokenString = request.payload.request.access.token
    const token = await AccessToken.parse<T>(tokenString, this.args.encoding.tokenEncoder)

    const accessVerificationKey = await this.args.store.access.verificationKey.get(
      token.serverIdentity
    )
    await token.verifySignature(this.args.crypto.verifier, await accessVerificationKey.public())

    const hash = await this.args.crypto.hasher.sum(request.payload.request.access.publicKey)
    if (hash !== token.rotationHash) {
      throw new InvalidHashError(token.rotationHash, hash, 'rotation')
    }

    await this.args.store.authentication.key.ensureActive(token.identity, token.device)

    const now = this.args.encoding.timestamper.now()
    const refreshExpiry = this.args.encoding.timestamper.parse(token.refreshExpiry)

    if (now > refreshExpiry) {
      throw new ExpiredTokenError(
        token.refreshExpiry,
        this.args.encoding.timestamper.format(now),
        'refresh'
      )
    }

    await this.args.store.access.keyHash.reserve(hash)

    const later = this.args.encoding.timestamper.parse(now)
    later.setMinutes(later.getMinutes() + this.args.expiry.accessInMinutes)
    const issuedAt = this.args.encoding.timestamper.format(now)
    const expiry = this.args.encoding.timestamper.format(later)

    const accessToken = new AccessToken(
      await this.args.crypto.keyPair.access.identity(),
      token.device,
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

    const response = new RefreshSessionResponse(
      {
        access: {
          token: serializedToken,
        },
      },
      await this.args.crypto.keyPair.response.identity(),
      request.payload.access.nonce
    )

    await response.sign(this.args.crypto.keyPair.response)

    return await response.serialize()
  }

  async changeRecoveryKey(message: string): Promise<string> {
    const request = ChangeRecoveryKeyRequest.parse(message)
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

    await this.args.store.recovery.hash.change(
      request.payload.request.authentication.identity,
      request.payload.request.authentication.recoveryHash
    )

    // this is replayable, and should be fixed but making it not fixed
    const response = new ChangeRecoveryKeyResponse(
      {},
      await this.args.crypto.keyPair.response.identity(),
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
        verifier: IVerifier
      }
      encoding: {
        tokenEncoder: ITokenEncoder
        timestamper: ITimestamper
      }
      store: {
        access: {
          nonce: IServerTimeLockStore
          key: IVerificationKeyStore
        }
      }
    }
  ) {}

  async verify<T, U>(message: string): Promise<[T, AccessToken<U>, string]> {
    const request = AccessRequest.parse<T>(message)

    return [
      request.payload.request,
      await request._verify<U>(
        this.args.store.access.nonce,
        this.args.crypto.verifier,
        this.args.store.access.key,
        this.args.encoding.tokenEncoder,
        this.args.encoding.timestamper
      ),
      request.payload.access.nonce,
    ]
  }
}
