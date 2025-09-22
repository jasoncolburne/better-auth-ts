import { SignableMessage } from './message'
import { ServerResponse } from './response'

interface IRefreshAccessTokenRequest {
  payload: {
    access: {
      token: string
      publicKeys: {
        current: string
        nextDigest: string
      }
    }
  }
  signature?: string
}

export class RefreshAccessTokenRequest
  extends SignableMessage
  implements IRefreshAccessTokenRequest
{
  constructor(
    public payload: {
      access: {
        token: string
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

  static parse(message: string): RefreshAccessTokenRequest {
    const json = JSON.parse(message)
    const result = new RefreshAccessTokenRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface IRefreshAccessTokenResponse {
  access: {
    token: string
  }
}

export class RefreshAccessTokenResponse extends ServerResponse<IRefreshAccessTokenResponse> {
  static parse(message: string): RefreshAccessTokenResponse {
    return ServerResponse._parse(message, RefreshAccessTokenResponse)
  }
}
