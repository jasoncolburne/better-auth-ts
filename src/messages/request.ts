import { SignableMessage } from './message'

interface IClientAccess {
  nonce: string
}

interface IClientPayload<T> {
  access: IClientAccess
  request: T
}

interface IClientRequest<T> {
  payload: IClientPayload<T>
  signature?: string
}

export class ClientRequest<T> extends SignableMessage implements IClientRequest<T> {
  payload: IClientPayload<T>

  constructor(request: T, nonce: string) {
    super()

    const access: IClientAccess = {
      nonce: nonce,
    }

    this.payload = {
      access: access,
      request: request,
    }
  }

  static _parse<T, U extends ClientRequest<T>>(
    message: string,
    constructor: new (request: T, nonce: string) => U
  ): ClientRequest<T> {
    const json = JSON.parse(message) as ClientRequest<T>
    const result = new constructor(json.payload.request, json.payload.access.nonce)
    result.signature = json.signature

    return result
  }
}
