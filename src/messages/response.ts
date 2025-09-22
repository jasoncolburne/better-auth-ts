import { SignableMessage } from './message'

interface IServerAccess {
  publicKeyDigest: string
  nonce: string
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

  constructor(response: T, publicKeyDigest: string, nonce: string) {
    super()

    const access: IServerAccess = {
      publicKeyDigest: publicKeyDigest,
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
      json.payload.access.publicKeyDigest,
      json.payload.access.nonce
    )
    result.signature = json.signature

    return result
  }
}
