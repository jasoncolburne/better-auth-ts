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
  CreationContainer,
  CreationRequest,
  CreationResponse,
  LinkContainer,
  LinkDeviceRequest,
  LinkDeviceResponse,
  RefreshAccessTokenRequest,
  RefreshAccessTokenResponse,
  RotateAuthenticationKeyRequest,
  RotateAuthenticationKeyResponse,
  ScannableResponse,
  SignableMessage,
} from '../messages'
import { RecoverAccountRequest, RecoverAccountResponse } from '../messages/recovery'
import { rfc3339Nano } from '../utils'

export class BetterAuthClient {
  constructor(
    private readonly crypto: {
      digester: IDigester
      noncer: INoncer
      publicKeys: {
        response: IVerificationKey
      }
    },
    private readonly io: {
      network: INetwork
    },
    private readonly stores: {
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
  ) {}

  async accountId(): Promise<string> {
    return await this.stores.identifier.account.get()
  }

  async deviceId(): Promise<string> {
    return await this.stores.identifier.device.get()
  }

  private async verifyResponse(
    response: SignableMessage,
    publicKeyDigest: string
  ): Promise<boolean> {
    const publicKey = await this.crypto.publicKeys.response.public()
    const digest = await this.crypto.digester.sum(publicKey)

    if (digest !== publicKeyDigest) {
      throw 'digest mismatch'
    }

    const verifier = this.crypto.publicKeys.response.verifier()

    return await response.verify(verifier, publicKey)
  }

  async createAccount(creationContainer: string, recoveryKeyDigest: string): Promise<void> {
    const materials = CreationContainer.parse(creationContainer)
    if (!(await this.verifyResponse(materials, materials.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    const [currentAuthenticationPublicKey, nextAuthenticationPublicKeyDigest] =
      await this.stores.key.authentication.initialize()
    const deviceId = await this.crypto.digester.sum(currentAuthenticationPublicKey)
    const nonce = await this.crypto.noncer.generate128()

    const request = new CreationRequest({
      access: {
        nonce: nonce,
      },
      authentication: {
        publicKeys: {
          current: currentAuthenticationPublicKey,
          nextDigest: nextAuthenticationPublicKeyDigest,
        },
      },
      creation: {
        token: materials.payload.response.creation.token,
        recoveryKeyDigest: recoveryKeyDigest,
      },
      identification: {
        deviceId: deviceId,
      },
    })

    await request.sign(await this.stores.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/create', message)

    const response = CreationResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.stores.identifier.account.store(response.payload.response.identification.accountId)
    await this.stores.identifier.device.store(deviceId)
  }

  // happens on the new device
  // send account id by qr code or network from the existing device
  async generateLinkContainer(accountId: string): Promise<string> {
    const [current, nextDigest] = await this.stores.key.authentication.initialize()
    const deviceId = await this.crypto.digester.sum(current)

    await this.stores.identifier.account.store(accountId)
    await this.stores.identifier.device.store(deviceId)

    const linkContainer = new LinkContainer({
      identification: {
        accountId: accountId,
        deviceId: deviceId,
      },
      publicKeys: {
        current: current,
        nextDigest: nextDigest,
      },
    })

    await linkContainer.sign(await this.stores.key.authentication.signer())

    return await linkContainer.serialize()
  }

  // happens on the existing device (share with qr code + camera)
  // use a 61x61 module layout and a 53x53 module code, centered on the new device, at 300x300px
  // for best results
  async linkDevice(linkContainer: string): Promise<void> {
    const container = LinkContainer.parse(linkContainer)
    const nonce = await this.crypto.noncer.generate128()

    const request = new LinkDeviceRequest({
      access: {
        nonce: nonce,
      },
      identification: {
        accountId: await this.stores.identifier.account.get(),
        deviceId: await this.stores.identifier.device.get(),
      },
      link: container,
    })

    await request.sign(await this.stores.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/link', message)

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
      await this.stores.key.authentication.rotate()
    const nonce = await this.crypto.noncer.generate128()

    const request = new RotateAuthenticationKeyRequest({
      access: {
        nonce: nonce,
      },
      identification: {
        accountId: await this.stores.identifier.account.get(),
        deviceId: await this.stores.identifier.device.get(),
      },
      authentication: {
        publicKeys: {
          current: currentAuthenticationPublicKey,
          nextDigest: nextAuthenticationPublicKeyDigest,
        },
      },
    })

    await request.sign(await this.stores.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/rotate', message)

    const response = RotateAuthenticationKeyResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }
  }

  async authenticate(): Promise<void> {
    const beginNonce = await this.crypto.noncer.generate128()

    const beginRequest = new BeginAuthenticationRequest({
      access: {
        nonce: beginNonce,
      },
      identification: {
        accountId: await this.stores.identifier.account.get(),
      },
    })

    const beginMessage = await beginRequest.serialize()
    const beginReply = await this.io.network.sendRequest('/auth/begin', beginMessage)

    const beginResponse = BeginAuthenticationResponse.parse(beginReply)
    if (
      !(await this.verifyResponse(beginResponse, beginResponse.payload.access.responseKeyDigest))
    ) {
      throw 'invalid signature'
    }

    if (beginResponse.payload.access.nonce !== beginNonce) {
      throw 'incorrect nonce'
    }

    const [currentKey, nextKeyDigest] = await this.stores.key.access.initialize()
    const completeNonce = await this.crypto.noncer.generate128()

    const completeRequest = new CompleteAuthenticationRequest({
      access: {
        nonce: completeNonce,
        publicKeys: {
          current: currentKey,
          nextDigest: nextKeyDigest,
        },
      },
      authentication: {
        nonce: beginResponse.payload.response.authentication.nonce,
      },
      identification: {
        deviceId: await this.stores.identifier.device.get(),
      },
    })

    await completeRequest.sign(await this.stores.key.authentication.signer())
    const completeMessage = await completeRequest.serialize()
    const completeReply = await this.io.network.sendRequest('/auth/complete', completeMessage)

    const completeResponse = CompleteAuthenticationResponse.parse(completeReply)
    if (
      !(await this.verifyResponse(
        completeResponse,
        completeResponse.payload.access.responseKeyDigest
      ))
    ) {
      throw 'invalid signature'
    }

    if (completeResponse.payload.access.nonce !== completeNonce) {
      throw 'incorrect nonce'
    }

    await this.stores.token.access.store(completeResponse.payload.response.access.token)
  }

  async refreshAccessToken(): Promise<void> {
    const [currentKey, nextKeyDigest] = await this.stores.key.access.rotate()
    const nonce = await this.crypto.noncer.generate128()

    const request = new RefreshAccessTokenRequest({
      access: {
        nonce: nonce,
        publicKeys: {
          current: currentKey,
          nextDigest: nextKeyDigest,
        },
        token: await this.stores.token.access.get(),
      },
    })

    await request.sign(await this.stores.key.access.signer())
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/refresh', message)

    const response = RefreshAccessTokenResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.stores.token.access.store(response.payload.response.access.token)
  }

  async recoverAccount(accountId: string, recoveryKey: ISigningKey): Promise<void> {
    const [current, nextDigest] = await this.stores.key.authentication.initialize()
    const deviceId = await this.crypto.digester.sum(current)
    const nonce = await this.crypto.noncer.generate128()

    const request = new RecoverAccountRequest({
      access: {
        nonce: nonce,
      },
      authentication: {
        publicKeys: {
          current: current,
          nextDigest: nextDigest,
        },
      },
      identification: {
        accountId: accountId,
        deviceId: deviceId,
      },
      recovery: {
        publicKey: await recoveryKey.public(),
      },
    })

    await request.sign(recoveryKey)
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/recover', message)

    const response = RecoverAccountResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    if (response.payload.access.nonce !== nonce) {
      throw 'incorrect nonce'
    }

    await this.stores.identifier.account.store(accountId)
    await this.stores.identifier.device.store(deviceId)
  }

  async makeAccessRequest<T>(path: string, request: T): Promise<string> {
    const accessRequest = new AccessRequest<T>({
      token: await this.stores.token.access.get(),
      access: {
        timestamp: rfc3339Nano(new Date()),
        nonce: await this.crypto.noncer.generate128(),
      },
      request: request,
    })

    await accessRequest.sign(await this.stores.key.access.signer())
    const message = await accessRequest.serialize()
    const reply = await this.io.network.sendRequest(path, message)
    const response = ScannableResponse.parse(reply)
    if (response.payload.access.nonce !== accessRequest.payload.access.nonce) {
      throw 'invalid reply nonce'
    }

    return reply
  }
}
