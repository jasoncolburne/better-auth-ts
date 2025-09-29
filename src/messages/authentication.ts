import { SerializableMessage } from './message'
import { ClientRequest } from './request'
import { ServerResponse } from './response'

interface IStartAuthenticationRequest {
  payload: {
    access: {
      nonce: string
    }
    request: {
      authentication: {
        identity: string
      }
    }
  }
}

export class StartAuthenticationRequest
  extends SerializableMessage
  implements IStartAuthenticationRequest
{
  constructor(
    public payload: {
      access: {
        nonce: string
      }
      request: {
        authentication: {
          identity: string
        }
      }
    }
  ) {
    super()
  }

  async serialize(): Promise<string> {
    return JSON.stringify({
      payload: this.payload,
    })
  }

  static parse(message: string): StartAuthenticationRequest {
    const json = JSON.parse(message) as StartAuthenticationRequest
    return new StartAuthenticationRequest(json.payload)
  }
}

interface IStartAuthenticationResponse {
  authentication: {
    nonce: string
  }
}

export class StartAuthenticationResponse extends ServerResponse<IStartAuthenticationResponse> {
  static parse(message: string): StartAuthenticationResponse {
    return ServerResponse._parse(message, StartAuthenticationResponse)
  }
}

interface IFinishAuthenticationRequest {
  access: {
    publicKey: string
    rotationHash: string
  }
  authentication: {
    device: string
    nonce: string
  }
}

export class FinishAuthenticationRequest extends ClientRequest<IFinishAuthenticationRequest> {
  static parse(message: string): FinishAuthenticationRequest {
    return ClientRequest._parse(message, FinishAuthenticationRequest)
  }
}

interface IFinishAuthenticationResponse {
  access: {
    token: string
  }
}

export class FinishAuthenticationResponse extends ServerResponse<IFinishAuthenticationResponse> {
  static parse(message: string): FinishAuthenticationResponse {
    return ServerResponse._parse(message, FinishAuthenticationResponse)
  }
}
