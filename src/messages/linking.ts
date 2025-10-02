import { SignableMessage } from './message'
import { ClientRequest } from './request'
import { ServerResponse } from './response'

interface ILinkContainer {
  payload: {
    authentication: {
      device: string
      identity: string
      publicKey: string
      rotationHash: string
    }
  }
  signature?: string
}

export class LinkContainer extends SignableMessage implements ILinkContainer {
  constructor(
    public payload: {
      authentication: {
        device: string
        identity: string
        publicKey: string
        rotationHash: string
      }
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify(this.payload)
  }

  static parse(message: string): LinkContainer {
    const json = JSON.parse(message) as LinkContainer
    const result = new LinkContainer(json.payload)
    result.signature = json.signature

    return result
  }
}

interface ILinkDeviceRequest {
  authentication: {
    device: string
    identity: string
    publicKey: string
    rotationHash: string
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

interface IUnlinkDeviceRequest {
  authentication: {
    device: string
    identity: string
    publicKey: string
  }
}

export class UnlinkDeviceRequest extends ClientRequest<IUnlinkDeviceRequest> {
  static parse(message: string): UnlinkDeviceRequest {
    return ClientRequest._parse(message, UnlinkDeviceRequest)
  }
}

interface IUnlinkDeviceResponse {}

export class UnlinkDeviceResponse extends ServerResponse<IUnlinkDeviceResponse> {
  static parse(message: string): UnlinkDeviceResponse {
    return ServerResponse._parse(message, UnlinkDeviceResponse)
  }
}
