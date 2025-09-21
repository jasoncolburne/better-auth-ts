import { SerializableMessage, SignableMessage } from './request'

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
      payload: {
        identification: {
          accountId: this.payload.identification.accountId,
        },
      },
    })
  }

  static parse(message: string): BeginAuthenticationRequest {
    const json = JSON.parse(message)
    return new BeginAuthenticationRequest(json.payload)
  }
}

interface IBeginAuthenticationResponse {
  payload: {
    authentication: {
      nonce: string
    }
    publicKeyDigest: string
  }
  signature?: string
}

export class BeginAuthenticationResponse
  extends SignableMessage
  implements IBeginAuthenticationResponse
{
  constructor(
    public payload: {
      authentication: {
        nonce: string
      }
      publicKeyDigest: string
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify({
      authentication: {
        nonce: this.payload.authentication.nonce,
      },
      publicKeyDigest: this.payload.publicKeyDigest,
    })
  }

  static parse(message: string): BeginAuthenticationResponse {
    const json = JSON.parse(message)
    const result = new BeginAuthenticationResponse(json.payload)
    result.signature = json.signature

    return result
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
    return JSON.stringify({
      identification: {
        deviceId: this.payload.identification.deviceId,
      },
      authentication: {
        nonce: this.payload.authentication.nonce,
      },
      refresh: {
        publicKey: this.payload.refresh.publicKey,
        nonces: {
          nextDigest: this.payload.refresh.nonces.nextDigest,
        },
      },
    })
  }

  static parse(message: string): CompleteAuthenticationRequest {
    const json = JSON.parse(message)
    const result = new CompleteAuthenticationRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface ICompleteAuthenticationResponse {
  payload: {
    refresh: {
      sessionId: string
    }
    publicKeyDigest: string
  }
  signature?: string
}

export class CompleteAuthenticationResponse
  extends SignableMessage
  implements ICompleteAuthenticationResponse
{
  constructor(
    public payload: {
      refresh: {
        sessionId: string
      }
      publicKeyDigest: string
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify({
      refresh: {
        sessionId: this.payload.refresh.sessionId,
      },
      publicKeyDigest: this.payload.publicKeyDigest,
    })
  }

  static parse(message: string): CompleteAuthenticationResponse {
    const json = JSON.parse(message)
    const result = new CompleteAuthenticationResponse(json.payload)
    result.signature = json.signature

    return result
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
      payload: {
        identification: {
          accountId: this.payload.identification.accountId,
        },
      },
    })
  }

  static parse(message: string): BeginPassphraseAuthenticationRequest {
    const json = JSON.parse(message)
    return new BeginPassphraseAuthenticationRequest(json.payload)
  }
}

interface IBeginPassphraseAuthenticationResponse {
  payload: {
    passphraseAuthentication: {
      nonce: string
      parameters: string
      salt: string
    }
    publicKeyDigest: string
  }
  signature?: string
}

export class BeginPassphraseAuthenticationResponse
  extends SignableMessage
  implements IBeginPassphraseAuthenticationResponse
{
  constructor(
    public payload: {
      passphraseAuthentication: {
        nonce: string
        parameters: string
        salt: string
      }
      publicKeyDigest: string
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify({
      passphraseAuthentication: {
        nonce: this.payload.passphraseAuthentication.nonce,
        parameters: this.payload.passphraseAuthentication.parameters,
        salt: this.payload.passphraseAuthentication.salt,
      },
      publicKeyDigest: this.payload.publicKeyDigest,
    })
  }

  static parse(message: string): BeginPassphraseAuthenticationResponse {
    const json = JSON.parse(message)
    const result = new BeginPassphraseAuthenticationResponse(json.payload)
    result.signature = json.signature

    return result
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
    return JSON.stringify({
      passphraseAuthentication: {
        nonce: this.payload.passphraseAuthentication.nonce,
        publicKey: this.payload.passphraseAuthentication.publicKey,
      },
      refresh: {
        publicKey: this.payload.refresh.publicKey,
        nonces: {
          nextDigest: this.payload.refresh.nonces.nextDigest,
        },
      },
    })
  }

  static parse(message: string): CompletePassphraseAuthenticationRequest {
    const json = JSON.parse(message)
    const result = new CompletePassphraseAuthenticationRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface ICompletePassphraseAuthenticationResponse {
  payload: {
    refresh: {
      sessionId: string
    }
    publicKeyDigest: string
  }
  signature?: string
}

export class CompletePassphraseAuthenticationResponse
  extends SignableMessage
  implements ICompletePassphraseAuthenticationResponse
{
  constructor(
    public payload: {
      refresh: {
        sessionId: string
      }
      publicKeyDigest: string
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify({
      refresh: {
        sessionId: this.payload.refresh.sessionId,
      },
      publicKeyDigest: this.payload.publicKeyDigest,
    })
  }

  static parse(message: string): CompletePassphraseAuthenticationResponse {
    const json = JSON.parse(message)
    const result = new CompletePassphraseAuthenticationResponse(json.payload)
    result.signature = json.signature

    return result
  }
}
