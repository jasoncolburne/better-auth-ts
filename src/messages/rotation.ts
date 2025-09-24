import { ClientRequest } from './request'
import { ServerResponse } from './response'

interface IRotateAuthenticationKeyRequest {
  authentication: {
    publicKeys: {
      current: string
      rotationDigest: string
    }
  }
  identification: {
    accountId: string
    deviceId: string
  }
}

export class RotateAuthenticationKeyRequest extends ClientRequest<IRotateAuthenticationKeyRequest> {
  static parse(message: string): RotateAuthenticationKeyRequest {
    return ClientRequest._parse(message, RotateAuthenticationKeyRequest)
  }
}

interface IRotateAuthenticationKeyResponse {}

export class RotateAuthenticationKeyResponse extends ServerResponse<IRotateAuthenticationKeyResponse> {
  static parse(message: string): RotateAuthenticationKeyResponse {
    return ServerResponse._parse(message, RotateAuthenticationKeyResponse)
  }
}
