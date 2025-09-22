import { SignableMessage } from './message'

interface IServerPayload<T> {
  publicKeyDigest: string
  response: T
}

interface IServerResponse<T> {
  payload: IServerPayload<T>
  signature?: string
}

export class ServerResponse<T> extends SignableMessage implements IServerResponse<T> {
  payload: IServerPayload<T>

  constructor(response: T, publicKeyDigest: string) {
    super()

    this.payload = {
      publicKeyDigest: publicKeyDigest,
      response: response,
    }
  }

  composePayload(): string {
    return JSON.stringify(this.payload)
  }

  static _parse<T, U extends ServerResponse<T>>(
    message: string,
    constructor: new (response: T, publicKeyDigest: string) => U
  ): ServerResponse<T> {
    const json = JSON.parse(message)
    const result = new constructor(json.payload.response, json.payload.publicKeyDigest)
    result.signature = json.signature

    return result
  }
}
