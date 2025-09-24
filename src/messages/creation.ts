import { ClientRequest } from './request'
import { ServerResponse } from './response'

interface ICreationContainer {
  creation: {
    token: string
  }
}

export class CreationContainer extends ServerResponse<ICreationContainer> {
  static parse(message: string): CreationContainer {
    return ServerResponse._parse(message, CreationContainer)
  }
}

export interface ICreationRequest {
  authentication: {
    publicKey: {
      current: string
      rotationDigest: string
    }
  }
  creation: {
    token: string
    recoveryDigest: string
  }
  identification: {
    deviceId: string
  }
}

export class CreationRequest extends ClientRequest<ICreationRequest> {
  static parse(message: string): CreationRequest {
    return ClientRequest._parse(message, CreationRequest)
  }
}

interface ICreationResponse {
  identification: {
    accountId: string
  }
}

export class CreationResponse extends ServerResponse<ICreationResponse> {
  static parse(message: string): CreationResponse {
    return ServerResponse._parse(message, CreationResponse)
  }
}
