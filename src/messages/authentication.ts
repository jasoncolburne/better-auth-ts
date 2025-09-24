import { SerializableMessage, SignableMessage } from './message'
import { ServerResponse } from './response'

interface IBeginAuthenticationRequest {
  payload: {
    access: {
      nonce: string
    }
    identification: {
      accountId: string
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
      identification: {
        accountId: string
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
  payload: {
    access: {
      nonce: string
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
  signature?: string
}

export class CompleteAuthenticationRequest
  extends SignableMessage
  implements ICompleteAuthenticationRequest
{
  constructor(
    public payload: {
      access: {
        nonce: string
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
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify(this.payload)
  }

  static parse(message: string): CompleteAuthenticationRequest {
    const json = JSON.parse(message)
    const result = new CompleteAuthenticationRequest(json.payload)
    result.signature = json.signature

    return result
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
