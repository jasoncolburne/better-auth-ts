import { SerializableMessage } from './message.js'
import { ClientRequest } from './request.js'
import { ServerResponse } from './response.js'

// this request is unsigned, and differs from the others as a result
interface IRequestSessionRequest {
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

export class RequestSessionRequest extends SerializableMessage implements IRequestSessionRequest {
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

  static parse(message: string): RequestSessionRequest {
    const json = JSON.parse(message) as RequestSessionRequest
    return new RequestSessionRequest(json.payload)
  }
}

interface IRequestSessionResponse {
  authentication: {
    nonce: string
  }
}

export class RequestSessionResponse extends ServerResponse<IRequestSessionResponse> {
  static parse(message: string): RequestSessionResponse {
    return ServerResponse._parse(message, RequestSessionResponse)
  }
}

interface ICreateSessionRequest {
  access: {
    publicKey: string
    rotationHash: string
  }
  authentication: {
    device: string
    nonce: string
  }
}

export class CreateSessionRequest extends ClientRequest<ICreateSessionRequest> {
  static parse(message: string): CreateSessionRequest {
    return ClientRequest._parse(message, CreateSessionRequest)
  }
}

interface ICreateSessionResponse {
  access: {
    token: string
  }
}

export class CreateSessionResponse extends ServerResponse<ICreateSessionResponse> {
  static parse(message: string): CreateSessionResponse {
    return ServerResponse._parse(message, CreateSessionResponse)
  }
}

interface IRefreshSessionRequest {
  access: {
    publicKey: string
    rotationHash: string
    token: string
  }
}

export class RefreshSessionRequest extends ClientRequest<IRefreshSessionRequest> {
  static parse(message: string): RefreshSessionRequest {
    return ClientRequest._parse(message, RefreshSessionRequest)
  }
}

interface IRefreshSessionResponse {
  access: {
    token: string
  }
}

export class RefreshSessionResponse extends ServerResponse<IRefreshSessionResponse> {
  static parse(message: string): RefreshSessionResponse {
    return ServerResponse._parse(message, RefreshSessionResponse)
  }
}
