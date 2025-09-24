import { SerializableMessage } from './message'
import { ClientRequest } from './request'
import { ServerResponse } from './response'

interface IBeginAuthenticationRequest {
  payload: {
    access: {
      nonce: string
    }
    request: {
      identification: {
        accountId: string
      }
    }
  }
}

export class BeginAuthenticationRequest
  extends SerializableMessage
  implements IBeginAuthenticationRequest
{
  constructor(
    public payload: {
      access: {
        nonce: string
      }
      request: {
        identification: {
          accountId: string
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

  static parse(message: string): BeginAuthenticationRequest {
    const json = JSON.parse(message)
    return new BeginAuthenticationRequest(json.payload)
  }
}

interface IBeginAuthenticationResponse {
  authentication: {
    nonce: string
  }
}

export class BeginAuthenticationResponse extends ServerResponse<IBeginAuthenticationResponse> {
  static parse(message: string): BeginAuthenticationResponse {
    return ServerResponse._parse(message, BeginAuthenticationResponse)
  }
}

interface ICompleteAuthenticationRequest {
  access: {
    publicKeys: {
      current: string
      nextDigest: string
    }
  }
  authentication: {
    nonce: string
  }
  identification: {
    deviceId: string
  }
}

export class CompleteAuthenticationRequest extends ClientRequest<ICompleteAuthenticationRequest> {
  static parse(message: string): CompleteAuthenticationRequest {
    return ClientRequest._parse(message, CompleteAuthenticationRequest)
  }
}

interface ICompleteAuthenticationResponse {
  access: {
    token: string
  }
}

export class CompleteAuthenticationResponse extends ServerResponse<ICompleteAuthenticationResponse> {
  static parse(message: string): CompleteAuthenticationResponse {
    return ServerResponse._parse(message, CompleteAuthenticationResponse)
  }
}
