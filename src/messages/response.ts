import { SignableMessage } from './message'

interface IServerAccess {
  nonce: string
  responseKeyHash: string
}

interface IServerPayload<T> {
  access: IServerAccess
  response: T
}

interface IServerResponse<T> {
  payload: IServerPayload<T>
  signature?: string
}

export class ServerResponse<T> extends SignableMessage implements IServerResponse<T> {
  payload: IServerPayload<T>

  constructor(response: T, responseKeyHash: string, nonce: string) {
    super()

    const access: IServerAccess = {
      nonce: nonce,
      responseKeyHash: responseKeyHash,
    }

    this.payload = {
      access: access,
      response: response,
    }
  }

  static _parse<T, U extends ServerResponse<T>>(
    message: string,
    constructor: new (response: T, publicKeyHash: string, nonce: string) => U
  ): ServerResponse<T> {
    const json = JSON.parse(message) as IServerResponse<T>
    const result = new constructor(
      json.payload.response,
      json.payload.access.responseKeyHash,
      json.payload.access.nonce
    )
    result.signature = json.signature

    return result
  }
}

interface IScannableResponse {}

export class ScannableResponse extends ServerResponse<IScannableResponse> {
  static parse(message: string): ScannableResponse {
    return ServerResponse._parse(message, ScannableResponse)
  }
}
