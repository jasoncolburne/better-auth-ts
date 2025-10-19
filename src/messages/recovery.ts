import { ClientRequest } from './request.js'
import { ServerResponse } from './response.js'

export interface IChangeRecoveryKeyRequest {
  authentication: {
    device: string
    identity: string
    publicKey: string
    recoveryHash: string
    rotationHash: string
  }
}

export class ChangeRecoveryKeyRequest extends ClientRequest<IChangeRecoveryKeyRequest> {
  static parse(message: string): ChangeRecoveryKeyRequest {
    return ClientRequest._parse(message, ChangeRecoveryKeyRequest)
  }
}

interface IChangeRecoveryKeyResponse {}

export class ChangeRecoveryKeyResponse extends ServerResponse<IChangeRecoveryKeyResponse> {
  static parse(message: string): ChangeRecoveryKeyResponse {
    return ServerResponse._parse(message, ChangeRecoveryKeyResponse)
  }
}
