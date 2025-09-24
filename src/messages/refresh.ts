import { ClientRequest } from './request'
import { ServerResponse } from './response'

interface IRefreshAccessTokenRequest {
  access: {
    publicKeys: {
      current: string
      nextDigest: string
    }
    token: string
  }
}

export class RefreshAccessTokenRequest extends ClientRequest<IRefreshAccessTokenRequest> {
  static parse(message: string): RefreshAccessTokenRequest {
    return ClientRequest._parse(message, RefreshAccessTokenRequest)
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
