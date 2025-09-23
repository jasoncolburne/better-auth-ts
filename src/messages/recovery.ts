import { SignableMessage } from './message'
import { ServerResponse } from './response'

interface IRecoverAccountRequest {
  payload: {
    identification: {
      accountId: string
      deviceId: string
    }
    recovery: {
      publicKey: string
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

export class RecoverAccountRequest extends SignableMessage implements IRecoverAccountRequest {
  constructor(
    public payload: {
      identification: {
        accountId: string
        deviceId: string
      }
      recovery: {
        publicKey: string
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

  static parse(message: string): RecoverAccountRequest {
    const json = JSON.parse(message)
    const result = new RecoverAccountRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface IRecoverAccountResponse {}

export class RecoverAccountResponse extends ServerResponse<IRecoverAccountResponse> {
  static parse(message: string): RecoverAccountResponse {
    return ServerResponse._parse(message, RecoverAccountResponse)
  }
}
