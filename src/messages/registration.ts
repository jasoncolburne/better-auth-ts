import { SignableMessage } from './message'
import { ServerResponse } from './response'

interface IRegistrationMaterials {
  registration: {
    token: string
  }
}

export class RegistrationMaterials extends ServerResponse<IRegistrationMaterials> {
  static parse(message: string): RegistrationMaterials {
    return ServerResponse._parse(message, RegistrationMaterials)
  }
}

export interface IPassphraseRegistrationMaterials {
  registration: {
    token: string
  }
  passphraseAuthentication: {
    parameters: string
    salt: string
  }
}

export class PassphraseRegistrationMaterials extends ServerResponse<IPassphraseRegistrationMaterials> {
  static parse(message: string): PassphraseRegistrationMaterials {
    return ServerResponse._parse(message, PassphraseRegistrationMaterials)
  }
}

export interface IRegisterAuthenticationKeyRequest {
  payload: {
    registration: {
      token: string
    }
    identification: {
      deviceId: string
    }
    authentication: {
      publicKeys: {
        current: string
        nextDigest: string
      }
    }
  }
  signature?: string
}

export class RegisterAuthenticationKeyRequest
  extends SignableMessage
  implements IRegisterAuthenticationKeyRequest
{
  constructor(
    public payload: {
      registration: {
        token: string
      }
      identification: {
        deviceId: string
      }
      authentication: {
        publicKeys: {
          current: string
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

  static parse(message: string): RegisterAuthenticationKeyRequest {
    const json = JSON.parse(message)
    const result = new RegisterAuthenticationKeyRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface IRegisterAuthenticationKeyResponse {
  identification: {
    accountId: string
  }
}

export class RegisterAuthenticationKeyResponse extends ServerResponse<IRegisterAuthenticationKeyResponse> {
  static parse(message: string): RegisterAuthenticationKeyResponse {
    return ServerResponse._parse(message, RegisterAuthenticationKeyResponse)
  }
}

interface IRegisterPassphraseAuthenticationKeyRequest {
  payload: {
    registration: {
      token: string
    }
    passphraseAuthentication: {
      publicKey: string
    }
  }
  signature?: string
}

export class RegisterPassphraseAuthenticationKeyRequest
  extends SignableMessage
  implements IRegisterPassphraseAuthenticationKeyRequest
{
  constructor(
    public payload: {
      registration: {
        token: string
      }
      passphraseAuthentication: {
        publicKey: string
      }
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify(this.payload)
  }

  static parse(message: string): RegisterPassphraseAuthenticationKeyRequest {
    const json = JSON.parse(message)
    const result = new RegisterPassphraseAuthenticationKeyRequest(json.payload)
    result.signature = json.signature

    return result
  }
}

interface IRegisterPassphraseAuthenticationKeyResponse {
  identification: {
    accountId: string
  }
}

export class RegisterPassphraseAuthenticationKeyResponse extends ServerResponse<IRegisterPassphraseAuthenticationKeyResponse> {
  static parse(message: string): RegisterPassphraseAuthenticationKeyResponse {
    return ServerResponse._parse(message, RegisterPassphraseAuthenticationKeyResponse)
  }
}
