import { SignableMessage } from './request'

interface IRotateAuthenticationKeyRequest {
  payload: {
    identification: {
      accountId: string
      deviceId: string
    }
    authentication: {
      publicKeys: {
        current: string
        nextDigest: string
      }
    }
  }
  signature?: string
}

export class RotateAuthenticationKeyRequest
  extends SignableMessage
  implements IRotateAuthenticationKeyRequest
{
  constructor(
    public payload: {
      identification: {
        accountId: string
        deviceId: string
      }
      authentication: {
        publicKeys: {
          current: string
          nextDigest: string
        }
      }
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify({
      identification: {
        accountId: this.payload.identification.accountId,
        deviceId: this.payload.identification.deviceId,
      },
      authentication: {
        publicKeys: {
          current: this.payload.authentication.publicKeys.current,
          nextDigest: this.payload.authentication.publicKeys.nextDigest,
        },
      },
    })
  }

  static parse(message: string): RotateAuthenticationKeyRequest {
    const json = JSON.parse(message)
    const result = new RotateAuthenticationKeyRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface IRotateAuthenticationKeyResponse {
  payload: {
    success: boolean
    publicKeyDigest: string
  }
  signature?: string
}

export class RotateAuthenticationKeyResponse
  extends SignableMessage
  implements IRotateAuthenticationKeyResponse
{
  constructor(
    public payload: {
      success: boolean
      publicKeyDigest: string
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify({
      success: this.payload.success,
      publicKeyDigest: this.payload.publicKeyDigest,
    })
  }

  static parse(message: string): RotateAuthenticationKeyResponse {
    const json = JSON.parse(message)
    const result = new RotateAuthenticationKeyResponse(json.payload)
    result.signature = json.signature

    return result
  }
}
