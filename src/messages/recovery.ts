import { ClientRequest } from './request'
import { ServerResponse } from './response'

interface IRecoverAccountRequest {
  authentication: {
    device: string
    identity: string
    publicKey: string
    rotationDigest: string
  }
  recovery: {
    publicKey: string
  }
}

export class RecoverAccountRequest extends ClientRequest<IRecoverAccountRequest> {
  static parse(message: string): RecoverAccountRequest {
    return ClientRequest._parse(message, RecoverAccountRequest)
  }
}

interface IRecoverAccountResponse {}

export class RecoverAccountResponse extends ServerResponse<IRecoverAccountResponse> {
  static parse(message: string): RecoverAccountResponse {
    return ServerResponse._parse(message, RecoverAccountResponse)
  }
}
