import {
  IAuthenticationPaths,
  IClientRotatingKeyStore,
  IClientValueStore,
  IHasher,
  INetwork,
  INoncer,
  ISigningKey,
  ITimestamper,
  IVerificationKeyStore,
} from '../interfaces'
import {
  AccessRequest,
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
  ScannableResponse,
  SignableMessage,
  StartAuthenticationRequest,
  StartAuthenticationResponse,
  UnlinkDeviceRequest,
  UnlinkDeviceResponse,
} from '../messages'

export class BetterAuthClient {
  constructor(
    private readonly args: {
      crypto: {
        hasher: IHasher
        noncer: INoncer
      }
      encoding: {
        timestamper: ITimestamper
      }
      io: {
        network: INetwork
      }
      paths: IAuthenticationPaths
      store: {
        identifier: {
          device: IClientValueStore
          identity: IClientValueStore
        }
        key: {
          access: IClientRotatingKeyStore
          authentication: IClientRotatingKeyStore
          response: IVerificationKeyStore
        }
        token: {
          access: IClientValueStore
        }
      }
    }
  ) {}

  async identity(): Promise<string> {
    return await this.args.store.identifier.identity.get()
  }

  async device(): Promise<string> {
    return await this.args.store.identifier.device.get()
  }

  private async verifyResponse(response: SignableMessage, serverIdentity: string): Promise<void> {
    const publicKey = await this.args.store.key.response.get(serverIdentity)
    const verifier = publicKey.verifier()

    await response.verify(verifier, await publicKey.public())
  }

  async createAccount(recoveryHash: string): Promise<void> {
    const [identity, publicKey, rotationHash] =
      await this.args.store.key.authentication.initialize(recoveryHash)
    const device = await this.args.crypto.hasher.sum(publicKey)

    const nonce = await this.args.crypto.noncer.generate128()

    const request = new CreationRequest(
      {
        authentication: {
          device: device,
          identity: identity,
          publicKey: publicKey,
          recoveryHash: recoveryHash,
          rotationHash: rotationHash,
        },
      },
      nonce
    )

    await request.sign(await this.args.store.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.account.create, message)

    const response = CreationResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.identifier.identity.store(identity)
    await this.args.store.identifier.device.store(device)
  }

  // happens on the new device
  async generateLinkContainer(identity: string): Promise<string> {
    const [, publicKey, rotationHash] = await this.args.store.key.authentication.initialize()
    const device = await this.args.crypto.hasher.sum(publicKey)

    await this.args.store.identifier.identity.store(identity)
    await this.args.store.identifier.device.store(device)

    const linkContainer = new LinkContainer({
      authentication: {
        device: device,
        identity: identity,
        publicKey: publicKey,
        rotationHash: rotationHash,
      },
    })

    await linkContainer.sign(await this.args.store.key.authentication.signer())

    return await linkContainer.serialize()
  }

  // happens on the existing device
  async linkDevice(linkContainer: string): Promise<void> {
    const container = LinkContainer.parse(linkContainer)
    const nonce = await this.args.crypto.noncer.generate128()
    const [publicKey, rotationHash] = await this.args.store.key.authentication.rotate()

    const request = new LinkDeviceRequest(
      {
        authentication: {
          device: await this.args.store.identifier.device.get(),
          identity: await this.args.store.identifier.identity.get(),
          publicKey: publicKey,
          rotationHash: rotationHash,
        },
        link: container,
      },
      nonce
    )

    await request.sign(await this.args.store.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.device.link, message)

    const response = LinkDeviceResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }
  }

  async unlinkDevice(device: string): Promise<void> {
    const nonce = await this.args.crypto.noncer.generate128()
    const [publicKey, rotationHash] = await this.args.store.key.authentication.rotate()

    let hash = rotationHash
    if (device === (await this.args.store.identifier.device.get())) {
      // if we know we are disabling the current device, hash again to prevent a rotation
      // through the standard means while allowing verification of the key should the need arise
      hash = await this.args.crypto.hasher.sum(rotationHash)
    }

    const request = new UnlinkDeviceRequest(
      {
        authentication: {
          device: await this.args.store.identifier.device.get(),
          identity: await this.args.store.identifier.identity.get(),
          publicKey: publicKey,
          rotationHash: hash,
        },
        link: {
          device: device,
        },
      },
      nonce
    )

    await request.sign(await this.args.store.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.device.unlink, message)

    const response = UnlinkDeviceResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }
  }

  async rotateAuthenticationKey(): Promise<void> {
    const [publicKey, rotationHash] = await this.args.store.key.authentication.rotate()
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new RotateAuthenticationKeyRequest(
      {
        authentication: {
          device: await this.args.store.identifier.device.get(),
          identity: await this.args.store.identifier.identity.get(),
          publicKey: publicKey,
          rotationHash: rotationHash,
        },
      },
      nonce
    )

    await request.sign(await this.args.store.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.device.rotate, message)

    const response = RotateAuthenticationKeyResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }
  }

  async authenticate(): Promise<void> {
    const startNonce = await this.args.crypto.noncer.generate128()

    const startRequest = new StartAuthenticationRequest({
      access: {
        nonce: startNonce,
      },
      request: {
        authentication: {
          identity: await this.args.store.identifier.identity.get(),
        },
      },
    })

    const startMessage = await startRequest.serialize()
    const startReply = await this.args.io.network.sendRequest(
      this.args.paths.session.request,
      startMessage
    )

    const startResponse = StartAuthenticationResponse.parse(startReply)
    await this.verifyResponse(startResponse, startResponse.payload.access.serverIdentity)

    if (startResponse.payload.access.nonce !== startNonce) {
      throw 'incorrect nonce'
    }

    const [, currentKey, nextKeyHash] = await this.args.store.key.access.initialize()
    const finishNonce = await this.args.crypto.noncer.generate128()

    const finishRequest = new FinishAuthenticationRequest(
      {
        access: {
          publicKey: currentKey,
          rotationHash: nextKeyHash,
        },
        authentication: {
          device: await this.args.store.identifier.device.get(),
          nonce: startResponse.payload.response.authentication.nonce,
        },
      },
      finishNonce
    )

    await finishRequest.sign(await this.args.store.key.authentication.signer())
    const finishMessage = await finishRequest.serialize()
    const finishReply = await this.args.io.network.sendRequest(
      this.args.paths.session.create,
      finishMessage
    )

    const finishResponse = FinishAuthenticationResponse.parse(finishReply)
    await this.verifyResponse(finishResponse, finishResponse.payload.access.serverIdentity)

    if (finishResponse.payload.access.nonce !== finishNonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.token.access.store(finishResponse.payload.response.access.token)
  }

  async refreshAccessToken(): Promise<void> {
    const [publicKey, rotationHash] = await this.args.store.key.access.rotate()
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new RefreshAccessTokenRequest(
      {
        access: {
          publicKey: publicKey,
          rotationHash: rotationHash,
          token: await this.args.store.token.access.get(),
        },
      },
      nonce
    )

    await request.sign(await this.args.store.key.access.signer())
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.session.refresh, message)

    const response = RefreshAccessTokenResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.token.access.store(response.payload.response.access.token)
  }

  async recoverAccount(
    identity: string,
    recoveryKey: ISigningKey,
    recoveryHash: string
  ): Promise<void> {
    const [, publicKey, rotationHash] = await this.args.store.key.authentication.initialize()
    const device = await this.args.crypto.hasher.sum(publicKey)
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new RecoverAccountRequest(
      {
        authentication: {
          device: device,
          identity: identity,
          publicKey: publicKey,
          recoveryHash: recoveryHash,
          recoveryKey: await recoveryKey.public(),
          rotationHash: rotationHash,
        },
      },
      nonce
    )

    await request.sign(recoveryKey)
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.account.recover, message)

    const response = RecoverAccountResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.identifier.identity.store(identity)
    await this.args.store.identifier.device.store(device)
  }

  async makeAccessRequest<T>(path: string, request: T): Promise<string> {
    const accessRequest = new AccessRequest<T>({
      access: {
        nonce: await this.args.crypto.noncer.generate128(),
        timestamp: this.args.encoding.timestamper.format(this.args.encoding.timestamper.now()),
        token: await this.args.store.token.access.get(),
      },
      request: request,
    })

    await accessRequest.sign(await this.args.store.key.access.signer())
    const message = await accessRequest.serialize()
    const reply = await this.args.io.network.sendRequest(path, message)
    const response = ScannableResponse.parse(reply)
    if (response.payload.access.nonce !== accessRequest.payload.access.nonce) {
      throw 'incorrect nonce'
    }

    return reply
  }
}
