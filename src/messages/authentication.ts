import { SerializableMessage, SignableMessage } from './message'
import { ServerResponse } from './response'

interface IBeginAuthenticationRequest {
  payload: {
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
    identification: {
      deviceId: string
    }
    authentication: {
      nonce: string
    }
    refresh: {
      publicKey: string
      nonces: {
        nextDigest: string
      }
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
      identification: {
        deviceId: string
      }
      authentication: {
        nonce: string
      }
      refresh: {
        publicKey: string
        nonces: {
          nextDigest: string
        }
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
  refresh: {
    sessionId: string
  }
}

export class CompleteAuthenticationResponse extends ServerResponse<ICompleteAuthenticationResponse> {
  static parse(message: string): CompleteAuthenticationResponse {
    return ServerResponse._parse(message, CompleteAuthenticationResponse)
  }
}

interface IBeginPassphraseAuthenticationRequest {
  payload: {
    identification: {
      accountId: string
    }
  }
}

export class BeginPassphraseAuthenticationRequest
  extends SerializableMessage
  implements IBeginPassphraseAuthenticationRequest
{
  constructor(
    public payload: {
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

  static parse(message: string): BeginPassphraseAuthenticationRequest {
    const json = JSON.parse(message)
    return new BeginPassphraseAuthenticationRequest(json.payload)
  }
}

interface IBeginPassphraseAuthenticationResponse {
  passphraseAuthentication: {
    nonce: string
    parameters: string
    salt: string
  }
}

export class BeginPassphraseAuthenticationResponse extends ServerResponse<IBeginPassphraseAuthenticationResponse> {
  static parse(message: string): BeginPassphraseAuthenticationResponse {
    return ServerResponse._parse(message, BeginPassphraseAuthenticationResponse)
  }
}

interface ICompletePassphraseAuthenticationRequest {
  payload: {
    passphraseAuthentication: {
      nonce: string
      publicKey: string
    }
    refresh: {
      publicKey: string
      nonces: {
        nextDigest: string
      }
    }
  }
  signature?: string
}

export class CompletePassphraseAuthenticationRequest
  extends SignableMessage
  implements ICompletePassphraseAuthenticationRequest
{
  constructor(
    public payload: {
      passphraseAuthentication: {
        nonce: string
        publicKey: string
      }
      refresh: {
        publicKey: string
        nonces: {
          nextDigest: string
        }
      }
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify(this.payload)
  }

  static parse(message: string): CompletePassphraseAuthenticationRequest {
    const json = JSON.parse(message)
    const result = new CompletePassphraseAuthenticationRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface ICompletePassphraseAuthenticationResponse {
  refresh: {
    sessionId: string
  }
}

export class CompletePassphraseAuthenticationResponse extends ServerResponse<ICompletePassphraseAuthenticationResponse> {
  static parse(message: string): CompletePassphraseAuthenticationResponse {
    return ServerResponse._parse(message, CompletePassphraseAuthenticationResponse)
  }
}
