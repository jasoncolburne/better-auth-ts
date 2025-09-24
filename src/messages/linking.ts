import { SignableMessage } from './message'
import { ClientRequest } from './request'
import { ServerResponse } from './response'

interface ILinkContainer {
  payload: {
    identification: {
      accountId: string
      deviceId: string
    }
    publicKey: {
      current: string
      rotationDigest: string
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
      publicKey: {
        current: string
        rotationDigest: string
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
  identification: {
    accountId: string
    deviceId: string
  }
  link: ILinkContainer
}

export class LinkDeviceRequest extends ClientRequest<ILinkDeviceRequest> {
  static parse(message: string): LinkDeviceRequest {
    return ClientRequest._parse(message, LinkDeviceRequest)
  }
}

interface ILinkDeviceResponse {}

export class LinkDeviceResponse extends ServerResponse<ILinkDeviceResponse> {
  static parse(message: string): LinkDeviceResponse {
    return ServerResponse._parse(message, LinkDeviceResponse)
  }
}
