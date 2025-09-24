import { SignableMessage } from './message'

interface IServerAccess {
  nonce: string
  responseKeyDigest: string
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

  constructor(response: T, responseKeyDigest: string, nonce: string) {
    super()

    const access: IServerAccess = {
      responseKeyDigest: responseKeyDigest,
      nonce: nonce,
    }

    // if (typeof nonce !== 'undefined') {
    //   access.nonce = nonce
    // }

    this.payload = {
      access: access,
      response: response,
    }
  }

  composePayload(): string {
    return JSON.stringify(this.payload)
  }

  static _parse<T, U extends ServerResponse<T>>(
    message: string,
    constructor: new (response: T, publicKeyDigest: string, nonce: string) => U
  ): ServerResponse<T> {
    const json = JSON.parse(message)
    const result = new constructor(
      json.payload.response,
      json.payload.access.responseKeyDigest,
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
