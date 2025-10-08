import { ClientRequest } from './request'
import { ServerResponse } from './response'

export interface ICreateAccountRequest {
  authentication: {
    device: string
    identity: string
    publicKey: string
    recoveryHash: string
    rotationHash: string
  }
}

export class CreateAccountRequest extends ClientRequest<ICreateAccountRequest> {
  static parse(message: string): CreateAccountRequest {
    return ClientRequest._parse(message, CreateAccountRequest)
  }
}

interface ICreateAccountResponse {}

export class CreateAccountResponse extends ServerResponse<ICreateAccountResponse> {
  static parse(message: string): CreateAccountResponse {
    return ServerResponse._parse(message, CreateAccountResponse)
  }
}

interface IRecoverAccountRequest {
  authentication: {
    device: string
    identity: string
    publicKey: string
    recoveryHash: string
    recoveryKey: string
    rotationHash: string
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
