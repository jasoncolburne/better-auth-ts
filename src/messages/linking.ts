import { SignableMessage } from './message'
import { ServerResponse } from './response'

interface ILinkContainer {
  payload: {
    identification: {
      accountId: string
      deviceId: string
    }
    publicKeys: {
      current: string
      nextDigest: string
    }
  }
  signature?: string
}

export class LinkContainer extends SignableMessage implements ILinkContainer {
  constructor(
    public payload: {
      identification: {
        accountId: string
        deviceId: string
      }
      publicKeys: {
        current: string
        nextDigest: string
      }
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify(this.payload)
  }

  static parse(message: string): LinkContainer {
    const json = JSON.parse(message)
    const result = new LinkContainer(json.payload)
    result.signature = json.signature

    return result
  }
}

interface ILinkDeviceRequest {
  payload: {
    identification: {
      accountId: string
      deviceId: string
    }
    link: ILinkContainer
  }
  signature?: string
}

export class LinkDeviceRequest extends SignableMessage implements ILinkDeviceRequest {
  constructor(
    public payload: {
      identification: {
        accountId: string
        deviceId: string
      }
      link: ILinkContainer
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify(this.payload)
  }

  static parse(message: string): LinkDeviceRequest {
    const json = JSON.parse(message)
    const result = new LinkDeviceRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface ILinkDeviceResponse {}

export class LinkDeviceResponse extends ServerResponse<ILinkDeviceResponse> {
  static parse(message: string): LinkDeviceResponse {
    return ServerResponse._parse(message, LinkDeviceResponse)
  }
}
