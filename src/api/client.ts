import {
  IClientRotatingKeyStore,
  IClientValueStore,
  IDigester,
  INetwork,
  INoncer,
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
  RefreshAccessTokenRequest,
  RefreshAccessTokenResponse,
  RotateAuthenticationKeyRequest,
  RotateAuthenticationKeyResponse,
  SignableMessage,
} from '../messages'
import { rfc3339Nano } from '../utils'

export class BetterAuthClient {
  constructor(
    private readonly stores: {
      identifier: {
        account: IClientValueStore
        device: IClientValueStore
      }
      token: {
        access: IClientValueStore
      }
      key: {
        authentication: IClientRotatingKeyStore
        access: IClientRotatingKeyStore
      }
    },
    private readonly crypto: {
      digest: IDigester
      publicKeys: {
        response: IVerificationKey
      }
      nonce: INoncer
    },
    private readonly io: {
      network: INetwork
    }
  ) {}

  private async verifyResponse(
    response: SignableMessage,
    publicKeyDigest: string
  ): Promise<boolean> {
    const publicKey = await this.crypto.publicKeys.response.public()
    const digest = await this.crypto.digest.sum(publicKey)

    if (digest !== publicKeyDigest) {
      throw 'digest mismatch'
    }

    const verifier = this.crypto.publicKeys.response.verifier()

    return await response.verify(verifier, publicKey)
  }

  async createAccount(registrationMaterials: string): Promise<void> {
    const materials = CreationContainer.parse(registrationMaterials)
    if (!(await this.verifyResponse(materials, materials.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    const [currentAuthenticationPublicKey, nextAuthenticationPublicKeyDigest] =
      await this.stores.key.authentication.initialize()
    const deviceId = await this.crypto.digest.sum(currentAuthenticationPublicKey)

    const request = new CreationRequest({
      registration: {
        token: materials.payload.response.registration.token,
      },
      identification: {
        deviceId: deviceId,
      },
      authentication: {
        publicKeys: {
          current: currentAuthenticationPublicKey,
          nextDigest: nextAuthenticationPublicKeyDigest,
        },
      },
    })

    await request.sign(this.stores.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/key/register', message)

    const response = CreationResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    await this.stores.identifier.account.store(response.payload.response.identification.accountId)
    await this.stores.identifier.device.store(deviceId)
  }

  async rotateAuthenticationKey(): Promise<void> {
    const [currentAuthenticationPublicKey, nextAuthenticationPublicKeyDigest] =
      await this.stores.key.authentication.rotate()

    const request = new RotateAuthenticationKeyRequest({
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

    await request.sign(this.stores.key.authentication.signer())
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/key/rotate', message)

    const response = RotateAuthenticationKeyResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }
  }

  async authenticate(): Promise<void> {
    const beginRequest = new BeginAuthenticationRequest({
      identification: {
        accountId: await this.stores.identifier.account.get(),
      },
    })

    const beginMessage = await beginRequest.serialize()
    const beginReply = await this.io.network.sendRequest('/auth/key/begin', beginMessage)

    const beginResponse = BeginAuthenticationResponse.parse(beginReply)
    if (
      !(await this.verifyResponse(beginResponse, beginResponse.payload.access.responseKeyDigest))
    ) {
      throw 'invalid signature'
    }

    const [currentKey, nextKeyDigest] = await this.stores.key.access.initialize()
    const completeRequest = new CompleteAuthenticationRequest({
      identification: {
        deviceId: await this.stores.identifier.device.get(),
      },
      authentication: {
        nonce: beginResponse.payload.response.authentication.nonce,
      },
      access: {
        publicKeys: {
          current: currentKey,
          nextDigest: nextKeyDigest,
        },
      },
    })

    await completeRequest.sign(this.stores.key.authentication.signer())
    const completeMessage = await completeRequest.serialize()
    const completeReply = await this.io.network.sendRequest('/auth/key/complete', completeMessage)

    const completeResponse = CompleteAuthenticationResponse.parse(completeReply)
    if (
      !(await this.verifyResponse(
        completeResponse,
        completeResponse.payload.access.responseKeyDigest
      ))
    ) {
      throw 'invalid signature'
    }

    await this.stores.token.access.store(completeResponse.payload.response.access.token)
  }

  async refreshAccessToken(): Promise<void> {
    const [currentKey, nextKeyDigest] = await this.stores.key.access.rotate()

    const request = new RefreshAccessTokenRequest({
      access: {
        token: await this.stores.token.access.get(),
        publicKeys: {
          current: currentKey,
          nextDigest: nextKeyDigest,
        },
      },
    })

    await request.sign(this.stores.key.access.signer())
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/refresh', message)

    const response = RefreshAccessTokenResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.responseKeyDigest))) {
      throw 'invalid signature'
    }

    await this.stores.token.access.store(response.payload.response.access.token)
  }

  async makeAccessRequest<T>(path: string, request: T): Promise<string> {
    const accessRequest = new AccessRequest<T>({
      token: await this.stores.token.access.get(),
      access: {
        timestamp: rfc3339Nano(new Date()),
        nonce: await this.crypto.nonce.generate128(),
      },
      request: request,
    })

    await accessRequest.sign(this.stores.key.access.signer())
    const message = await accessRequest.serialize()
    return await this.io.network.sendRequest(path, message)
  }
}
