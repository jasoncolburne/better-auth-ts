import {
  IClientRotatingKeyStore,
  IClientValueStore,
  IDigester,
  INetwork,
  INoncer,
  ISigningKey,
  IVerificationKey,
} from '../interfaces'
import {
  AccessRequest,
  BeginAuthenticationRequest,
  BeginAuthenticationResponse,
  CompleteAuthenticationRequest,
  CompleteAuthenticationResponse,
  CreationRequest,
  CreationResponse,
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
} from '../messages'
import { rfc3339Nano } from '../utils'

export class BetterAuthClient {
  constructor(
    private readonly args: {
      crypto: {
        digester: IDigester
        noncer: INoncer
        publicKey: {
          response: IVerificationKey
        }
      }
      io: {
        network: INetwork
      }
      store: {
        identifier: {
          account: IClientValueStore
          device: IClientValueStore
        }
        key: {
          access: IClientRotatingKeyStore
          authentication: IClientRotatingKeyStore
        }
        token: {
          access: IClientValueStore
        }
      }
    }
  ) {}

  async accountId(): Promise<string> {
    return await this.args.store.identifier.account.get()
  }

  async deviceId(): Promise<string> {
    return await this.args.store.identifier.device.get()
  }

  private async verifyResponse(
    response: SignableMessage,
    publicKeyDigest: string
  ): Promise<boolean> {
    const publicKey = await this.args.crypto.publicKey.response.public()
    const digest = await this.args.crypto.digester.sum(publicKey)

    if (digest !== publicKeyDigest) {
      throw 'digest mismatch'
    }

    const verifier = this.args.crypto.publicKey.response.verifier()

    return await response.verify(verifier, publicKey)
  }

  async createAccount(accountId: string, recoveryDigest: string): Promise<void> {
    const [currentAuthenticationPublicKey, nextAuthenticationPublicKeyDigest] =
      await this.args.store.key.authentication.initialize()
    const deviceId = await this.args.crypto.digester.sum(currentAuthenticationPublicKey)
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new CreationRequest(
      {
        authentication: {
          device: deviceId,
          identity: accountId,
          publicKey: currentAuthenticationPublicKey,
          recoveryDigest: recoveryDigest,
          rotationDigest: nextAuthenticationPublicKeyDigest,
        },
      },
      nonce
    )

    await request.sign(await this.args.store.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest('/auth/creation/create', message)

    const response = CreationResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.identifier.account.store(accountId)
    await this.args.store.identifier.device.store(deviceId)
  }

  // happens on the new device
  // send account id by qr code or network from the existing device
  async generateLinkContainer(accountId: string): Promise<string> {
    const [current, rotationDigest] = await this.args.store.key.authentication.initialize()
    const deviceId = await this.args.crypto.digester.sum(current)

    await this.args.store.identifier.account.store(accountId)
    await this.args.store.identifier.device.store(deviceId)

    const linkContainer = new LinkContainer({
      authentication: {
        device: deviceId,
        identity: accountId,
        publicKey: current,
        rotationDigest: rotationDigest,
      },
    })

    await linkContainer.sign(await this.args.store.key.authentication.signer())

    return await linkContainer.serialize()
  }

  // happens on the existing device (share with qr code + camera)
  // use a 61x61 module layout and a 53x53 module code, centered on the new device, at something
  // like 244x244px (61*4x61*4)
  async linkDevice(linkContainer: string): Promise<void> {
    const container = LinkContainer.parse(linkContainer)
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new LinkDeviceRequest(
      {
        authentication: {
          device: await this.args.store.identifier.device.get(),
          identity: await this.args.store.identifier.account.get(),
        },
        link: container,
      },
      nonce
    )

    await request.sign(await this.args.store.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest('/auth/linking/link', message)

    const response = LinkDeviceResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }
  }

  async rotateAuthenticationKey(): Promise<void> {
    const [currentAuthenticationPublicKey, nextAuthenticationPublicKeyDigest] =
      await this.args.store.key.authentication.rotate()
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new RotateAuthenticationKeyRequest(
      {
        authentication: {
          device: await this.args.store.identifier.device.get(),
          identity: await this.args.store.identifier.account.get(),
          publicKey: currentAuthenticationPublicKey,
          rotationDigest: nextAuthenticationPublicKeyDigest,
        },
      },
      nonce
    )

    await request.sign(await this.args.store.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest('/auth/rotation/rotate', message)

    const response = RotateAuthenticationKeyResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }
  }

  async authenticate(): Promise<void> {
    const startNonce = await this.args.crypto.noncer.generate128()

    const startRequest = new BeginAuthenticationRequest({
      access: {
        nonce: startNonce,
      },
      request: {
        authentication: {
          identity: await this.args.store.identifier.account.get(),
        },
      },
    })

    const startMessage = await startRequest.serialize()
    const startReply = await this.args.io.network.sendRequest(
      '/auth/authentication/start',
      startMessage
    )

    const startResponse = BeginAuthenticationResponse.parse(startReply)
    if (
      !(await this.verifyResponse(startResponse, startResponse.payload.access.responseKeyDigest))
    ) {
      throw 'invalid signature'
    }

    if (startResponse.payload.access.nonce !== startNonce) {
      throw 'incorrect nonce'
    }

    const [currentKey, nextKeyDigest] = await this.args.store.key.access.initialize()
    const finishNonce = await this.args.crypto.noncer.generate128()

    const finishRequest = new CompleteAuthenticationRequest(
      {
        access: {
          publicKey: currentKey,
          rotationDigest: nextKeyDigest,
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
      '/auth/authentication/finish',
      finishMessage
    )

    const finishResponse = CompleteAuthenticationResponse.parse(finishReply)
    if (
      !(await this.verifyResponse(finishResponse, finishResponse.payload.access.responseKeyDigest))
    ) {
      throw 'invalid signature'
    }

    if (finishResponse.payload.access.nonce !== finishNonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.token.access.store(finishResponse.payload.response.access.token)
  }

  async refreshAccessToken(): Promise<void> {
    const [currentKey, nextKeyDigest] = await this.args.store.key.access.rotate()
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new RefreshAccessTokenRequest(
      {
        access: {
          publicKey: currentKey,
          rotationDigest: nextKeyDigest,
          token: await this.args.store.token.access.get(),
        },
      },
      nonce
    )

    await request.sign(await this.args.store.key.access.signer())
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest('/auth/refresh/refresh', message)

    const response = RefreshAccessTokenResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.token.access.store(response.payload.response.access.token)
  }

  async recoverAccount(accountId: string, recoveryKey: ISigningKey): Promise<void> {
    const [current, rotationDigest] = await this.args.store.key.authentication.initialize()
    const deviceId = await this.args.crypto.digester.sum(current)
    const nonce = await this.args.crypto.noncer.generate128()

    const request = new RecoverAccountRequest(
      {
        authentication: {
          device: deviceId,
          identity: accountId,
          publicKey: current,
          recoveryKey: await recoveryKey.public(),
          rotationDigest: rotationDigest,
        },
      },
      nonce
    )

    await request.sign(recoveryKey)
    const message = await request.serialize()
    const reply = await this.args.io.network.sendRequest('/auth/recovery/recover', message)

    const response = RecoverAccountResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.args.store.identifier.account.store(accountId)
    await this.args.store.identifier.device.store(deviceId)
  }

  async makeAccessRequest<T>(path: string, request: T): Promise<string> {
    const accessRequest = new AccessRequest<T>({
      access: {
        nonce: await this.args.crypto.noncer.generate128(),
        timestamp: rfc3339Nano(new Date()),
        token: await this.args.store.token.access.get(),
      },
      request: request,
    })

    await accessRequest.sign(await this.args.store.key.access.signer())
    const message = await accessRequest.serialize()
    const reply = await this.args.io.network.sendRequest(path, message)
    const response = ScannableResponse.parse(reply)
    if (response.payload.access.nonce !== accessRequest.payload.access.nonce) {
      throw 'invalid reply nonce'
    }

    return reply
  }
}
