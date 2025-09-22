import { SignableMessage } from './message'
import { ServerResponse } from './response'

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
    return JSON.stringify(this.payload)
  }

  static parse(message: string): RotateAuthenticationKeyRequest {
    const json = JSON.parse(message)
    const result = new RotateAuthenticationKeyRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface IRotateAuthenticationKeyResponse {
  nonce: string
}

export class RotateAuthenticationKeyResponse extends ServerResponse<IRotateAuthenticationKeyResponse> {
  static parse(message: string): RotateAuthenticationKeyResponse {
    return ServerResponse._parse(message, RotateAuthenticationKeyResponse)
  }
}
