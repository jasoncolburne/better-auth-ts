import { ClientRequest } from './request'
import { ServerResponse } from './response'

export interface ICreationRequest {
  authentication: {
    device: string
    identity: string
    publicKey: string
    recoveryDigest: string
    rotationDigest: string
  }
}

export class CreationRequest extends ClientRequest<ICreationRequest> {
  static parse(message: string): CreationRequest {
    return ClientRequest._parse(message, CreationRequest)
  }
}

interface ICreationResponse {}

export class CreationResponse extends ServerResponse<ICreationResponse> {
  static parse(message: string): CreationResponse {
    return ServerResponse._parse(message, CreationResponse)
  }
}
