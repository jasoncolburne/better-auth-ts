import {
  IClientRefreshNonceStore,
  IClientRotatingKeyStore,
  IClientSingleKeyStore,
  IClientValueStore,
  IDigester,
  IKeyDeriver,
  INetwork,
  ISalter,
  IVerificationKey,
} from '../interfaces'
import {
  AccessRequest,
  BeginAuthenticationRequest,
  BeginAuthenticationResponse,
  BeginPassphraseAuthenticationRequest,
  BeginPassphraseAuthenticationResponse,
  CompleteAuthenticationRequest,
  CompleteAuthenticationResponse,
  CompletePassphraseAuthenticationRequest,
  PassphraseRegistrationMaterials,
  RefreshAccessTokenRequest,
  RefreshAccessTokenResponse,
  RegisterAuthenticationKeyRequest,
  RegisterAuthenticationKeyResponse,
  RegisterPassphraseAuthenticationKeyRequest,
  RegisterPassphraseAuthenticationKeyResponse,
  RegistrationMaterials,
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
        session: IClientValueStore
      }
      nonce: {
        refresh: IClientRefreshNonceStore
      }
      token: {
        refresh: IClientValueStore
        access: IClientValueStore
      }
      key: {
        authentication: IClientRotatingKeyStore
        refresh: IClientSingleKeyStore
        access: IClientSingleKeyStore
      }
    },
    private readonly crypto: {
      digest: IDigester
      publicKeys: {
        response: IVerificationKey
      }
      keyDerivation: IKeyDeriver
      nonce: ISalter
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

  async registerAuthenticationKey(registrationMaterials: string): Promise<void> {
    const materials = RegistrationMaterials.parse(registrationMaterials)
    if (!(await this.verifyResponse(materials, materials.payload.access.publicKeyDigest))) {
      throw 'invalid signature'
    }

    const [currentAuthenticationPublicKey, nextAuthenticationPublicKeyDigest] =
      await this.stores.key.authentication.initialize()
    const deviceId = await this.crypto.digest.sum(currentAuthenticationPublicKey)

    const request = new RegisterAuthenticationKeyRequest({
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

    const response = RegisterAuthenticationKeyResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.publicKeyDigest))) {
      throw 'invalid signature'
    }

    await this.stores.identifier.account.store(response.payload.response.identification.accountId)
    await this.stores.identifier.device.store(deviceId)
  }

  async registerPassphraseAuthenticationKey(
    passphraseRegistrationMaterials: string,
    passphrase: string
  ): Promise<void> {
    const materials = PassphraseRegistrationMaterials.parse(passphraseRegistrationMaterials)
    if (!(await this.verifyResponse(materials, materials.payload.access.publicKeyDigest))) {
      throw 'invalid signature'
    }

    const keyPair = await this.crypto.keyDerivation.derive(
      passphrase,
      materials.payload.response.passphraseAuthentication.salt,
      materials.payload.response.passphraseAuthentication.parameters
    )

    const request = new RegisterPassphraseAuthenticationKeyRequest({
      registration: {
        token: materials.payload.response.registration.token,
      },
      passphraseAuthentication: {
        publicKey: await keyPair.public(),
      },
    })

    await request.sign(keyPair)
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/passphrase/register', message)

    const response = RegisterPassphraseAuthenticationKeyResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.publicKeyDigest))) {
      throw 'invalid signature'
    }

    await this.stores.identifier.account.store(response.payload.response.identification.accountId)
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
    if (!(await this.verifyResponse(response, response.payload.access.publicKeyDigest))) {
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
    if (!(await this.verifyResponse(beginResponse, beginResponse.payload.access.publicKeyDigest))) {
      throw 'invalid signature'
    }

    const refreshPublicKey = await this.stores.key.refresh.generate()
    const nextNonceDigest = await this.stores.nonce.refresh.initialize()

    const completeRequest = new CompleteAuthenticationRequest({
      identification: {
        deviceId: await this.stores.identifier.device.get(),
      },
      authentication: {
        nonce: beginResponse.payload.response.authentication.nonce,
      },
      refresh: {
        publicKey: refreshPublicKey,
        nonces: {
          nextDigest: nextNonceDigest,
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
        completeResponse.payload.access.publicKeyDigest
      ))
    ) {
      throw 'invalid signature'
    }

    await this.stores.identifier.session.store(completeResponse.payload.response.refresh.sessionId)
  }

  async authenticateWithPassphrase(passphrase: string): Promise<void> {
    const beginRequest = new BeginPassphraseAuthenticationRequest({
      identification: {
        accountId: await this.stores.identifier.account.get(),
      },
    })

    const beginMessage = await beginRequest.serialize()
    const beginReply = await this.io.network.sendRequest('/auth/passphrase/begin', beginMessage)

    const beginResponse = BeginPassphraseAuthenticationResponse.parse(beginReply)
    if (!(await this.verifyResponse(beginResponse, beginResponse.payload.access.publicKeyDigest))) {
      throw 'invalid signature'
    }

    const keyPair = await this.crypto.keyDerivation.derive(
      passphrase,
      beginResponse.payload.response.passphraseAuthentication.salt,
      beginResponse.payload.response.passphraseAuthentication.parameters
    )

    const refreshPublicKey = await this.stores.key.refresh.generate()
    const nextNonceDigest = await this.stores.nonce.refresh.initialize()

    const completeRequest = new CompletePassphraseAuthenticationRequest({
      passphraseAuthentication: {
        nonce: beginResponse.payload.response.passphraseAuthentication.nonce,
        publicKey: await keyPair.public(),
      },
      refresh: {
        publicKey: refreshPublicKey,
        nonces: {
          nextDigest: nextNonceDigest,
        },
      },
    })

    await completeRequest.sign(keyPair)
    const completeMessage = await completeRequest.serialize()
    const completeReply = await this.io.network.sendRequest(
      '/auth/passphrase/complete',
      completeMessage
    )

    const completeResponse = CompleteAuthenticationResponse.parse(completeReply)
    if (
      !(await this.verifyResponse(
        completeResponse,
        completeResponse.payload.access.publicKeyDigest
      ))
    ) {
      throw 'invalid signature'
    }

    await this.stores.identifier.session.store(completeResponse.payload.response.refresh.sessionId)
  }

  async refreshAccessToken(): Promise<void> {
    const accessPublicKey = await this.stores.key.access.generate()
    const [current, nextDigest] = await this.stores.nonce.refresh.evolve()

    const request = new RefreshAccessTokenRequest({
      refresh: {
        sessionId: await this.stores.identifier.session.get(),
        nonces: {
          current: current,
          nextDigest: nextDigest,
        },
      },
      access: {
        publicKey: accessPublicKey,
      },
    })

    await request.sign(this.stores.key.refresh.signer())
    const message = await request.serialize()
    const reply = await this.io.network.sendRequest('/auth/refresh', message)

    const response = RefreshAccessTokenResponse.parse(reply)
    if (!(await this.verifyResponse(response, response.payload.access.publicKeyDigest))) {
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
