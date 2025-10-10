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
  ScannableResponse,
  SignableMessage,
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
    const device = await this.args.crypto.hasher.sum(publicKey + rotationHash)

    const nonce = await this.args.crypto.noncer.generate128()

    const request = new CreateAccountRequest(
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

    const response = CreateAccountResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.identifier.identity.store(identity)
    await this.args.store.identifier.device.store(device)
  }

  async deleteAccount(): Promise<void> {
    const nonce = await this.args.crypto.noncer.generate128()
    const [signingKey, rotationHash] = await this.args.store.key.authentication.next()

    const request = new DeleteAccountRequest(
      {
        authentication: {
          device: await this.args.store.identifier.device.get(),
          identity: await this.args.store.identifier.identity.get(),
          publicKey: await signingKey.public(),
          rotationHash: rotationHash,
        },
      },
      nonce
    )

    await request.sign(signingKey)
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.account.delete, message)

    const response = DeleteAccountResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.key.authentication.rotate()
  }

  async recoverAccount(
    identity: string,
    recoveryKey: ISigningKey,
    recoveryHash: string
  ): Promise<void> {
    const [, publicKey, rotationHash] = await this.args.store.key.authentication.initialize()
    const device = await this.args.crypto.hasher.sum(publicKey + rotationHash)
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

  // happens on the new device
  async generateLinkContainer(identity: string): Promise<string> {
    const [, publicKey, rotationHash] = await this.args.store.key.authentication.initialize()
    const device = await this.args.crypto.hasher.sum(publicKey + rotationHash)

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
    const [signingKey, rotationHash] = await this.args.store.key.authentication.next()

    const request = new LinkDeviceRequest(
      {
        authentication: {
          device: await this.args.store.identifier.device.get(),
          identity: await this.args.store.identifier.identity.get(),
          publicKey: await signingKey.public(),
          rotationHash: rotationHash,
        },
        link: container,
      },
      nonce
    )

    await request.sign(signingKey)
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.device.link, message)

    const response = LinkDeviceResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.key.authentication.rotate()
  }

  async unlinkDevice(device: string): Promise<void> {
    const nonce = await this.args.crypto.noncer.generate128()
    const [signingKey, rotationHash] = await this.args.store.key.authentication.next()

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
          publicKey: await signingKey.public(),
          rotationHash: hash,
        },
        link: {
          device: device,
        },
      },
      nonce
    )

    await request.sign(signingKey)
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.device.unlink, message)

    const response = UnlinkDeviceResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.key.authentication.rotate()
  }

  async rotateDevice(): Promise<void> {
    const [signingKey, rotationHash] = await this.args.store.key.authentication.next()
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new RotateDeviceRequest(
      {
        authentication: {
          device: await this.args.store.identifier.device.get(),
          identity: await this.args.store.identifier.identity.get(),
          publicKey: await signingKey.public(),
          rotationHash: rotationHash,
        },
      },
      nonce
    )

    await request.sign(signingKey)
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.device.rotate, message)

    const response = RotateDeviceResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.key.authentication.rotate()
  }

  async createSession(): Promise<void> {
    const startNonce = await this.args.crypto.noncer.generate128()

    const startRequest = new RequestSessionRequest({
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

    const startResponse = RequestSessionResponse.parse(startReply)
    await this.verifyResponse(startResponse, startResponse.payload.access.serverIdentity)

    if (startResponse.payload.access.nonce !== startNonce) {
      throw 'incorrect nonce'
    }

    const [, publicKey, rotationHash] = await this.args.store.key.access.initialize()
    const finishNonce = await this.args.crypto.noncer.generate128()

    const finishRequest = new CreateSessionRequest(
      {
        access: {
          publicKey: publicKey,
          rotationHash: rotationHash,
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

    const finishResponse = CreateSessionResponse.parse(finishReply)
    await this.verifyResponse(finishResponse, finishResponse.payload.access.serverIdentity)

    if (finishResponse.payload.access.nonce !== finishNonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.token.access.store(finishResponse.payload.response.access.token)
  }

  async refreshSession(): Promise<void> {
    const [signingKey, rotationHash] = await this.args.store.key.access.next()
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new RefreshSessionRequest(
      {
        access: {
          publicKey: await signingKey.public(),
          rotationHash: rotationHash,
          token: await this.args.store.token.access.get(),
        },
      },
      nonce
    )

    await request.sign(signingKey)
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest(this.args.paths.session.refresh, message)

    const response = RefreshSessionResponse.parse(reply)
    await this.verifyResponse(response, response.payload.access.serverIdentity)

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.token.access.store(response.payload.response.access.token)
    await this.args.store.key.access.rotate()
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
