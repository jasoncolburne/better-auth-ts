import { SignableMessage } from './message'
import { ServerResponse } from './response'

interface ICreationContainer {
  creation: {
    token: string
  }
}

export class CreationContainer extends ServerResponse<ICreationContainer> {
  static parse(message: string): CreationContainer {
    return ServerResponse._parse(message, CreationContainer)
  }
}

export interface ICreationRequest {
  payload: {
    access: {
      nonce: string
    }
    authentication: {
      publicKeys: {
        current: string
        nextDigest: string
      }
    }
    creation: {
      token: string
      recoveryKeyDigest: string
    }
    identification: {
      deviceId: string
    }
  }
  signature?: string
}

export class CreationRequest extends SignableMessage implements ICreationRequest {
  constructor(
    public payload: {
      access: {
        nonce: string
      }
      authentication: {
        publicKeys: {
          current: string
          nextDigest: string
        }
      }
      creation: {
        token: string
        recoveryKeyDigest: string
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

  static parse(message: string): CreationRequest {
    const json = JSON.parse(message)
    const result = new CreationRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface ICreationResponse {
  identification: {
    accountId: string
  }
}

export class CreationResponse extends ServerResponse<ICreationResponse> {
  static parse(message: string): CreationResponse {
    return ServerResponse._parse(message, CreationResponse)
  }
}
