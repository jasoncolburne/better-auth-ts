import { SignableMessage } from "./request";

interface IRegistrationMaterials {
    payload: {
        registration: {
            token: string
        }
        publicKeyDigest: string
    },
    signature?: string
}

export class RegistrationMaterials extends SignableMessage implements IRegistrationMaterials {
    constructor(
        public payload: {
            registration: {
                token: string
            }
            publicKeyDigest: string
        }
    ) {
        super()
    }

    composePayload(): string {
        return JSON.stringify({
            "registration": {
                "token": this.payload.registration.token
            }, 
            "publicKeyDigest": this.payload.publicKeyDigest
        })
    }

    static parse(message: string): RegistrationMaterials {
        const json = JSON.parse(message);
        const result = new RegistrationMaterials(json.payload);
        result.signature = json.signature;

        return result;
    }
}

export interface IPassphraseRegistrationMaterials {
    payload: {
        registration: {
            token: string
        }
        passphraseAuthentication: {
            parameters: string,
            salt: string
        }
        publicKeyDigest: string
    },
    signature?: string
}

export class PassphraseRegistrationMaterials extends SignableMessage implements IPassphraseRegistrationMaterials {
    constructor(
        public payload: {
            registration: {
                token: string
            }
            passphraseAuthentication: {
                parameters: string,
                salt: string
            },
            publicKeyDigest: string
        }
    ) {
        super();
    }

    composePayload(): string {
        return JSON.stringify({
            "registration": {
                "token": this.payload.registration.token
            },
            "passphraseAuthentication": {
                "parameters": this.payload.passphraseAuthentication.parameters,
                "salt": this.payload.passphraseAuthentication.salt
            },
            "publicKeyDigest": this.payload.publicKeyDigest
        })
    }

    static parse(message: string): PassphraseRegistrationMaterials {
        const json = JSON.parse(message);
        const result = new PassphraseRegistrationMaterials(json.payload);
        result.signature = json.signature;

        return result;
    }
}

export interface IRegisterAuthenticationKeyRequest {
    payload: {
        registration: {
            token: string
        },
        identification: {
            deviceId: string
        },
        authentication: {
            publicKeys: {
                current: string,
                nextDigest: string
            }
        }
    },
    signature?: string
}

export class RegisterAuthenticationKeyRequest extends SignableMessage implements IRegisterAuthenticationKeyRequest {
    constructor(
        public payload: {
            registration: {
                token: string
            },
            identification: {
                deviceId: string
            },
            authentication: {
                publicKeys: {
                    current: string,
                    nextDigest: string
                }
            }
        }
    ) {
        super();
    }

    composePayload(): string {
        return JSON.stringify({
            "registration": {
                "token": this.payload.registration.token
            },
            "identification": {
                "deviceId": this.payload.identification.deviceId
            },
            "authentication": {
                "publicKeys": {
                    "current": this.payload.authentication.publicKeys.current,
                    "nextDigest": this.payload.authentication.publicKeys.nextDigest
                }
            },
        })
    }

    static parse(message: string): RegisterAuthenticationKeyRequest {
        const json = JSON.parse(message);
        const result = new RegisterAuthenticationKeyRequest(json.payload);
        result.signature = json.signature;

        return result;
    }
}

interface IRegisterAuthenticationKeyResponse {
    payload: {
        identification: {
            accountId: string
        },
        publicKeyDigest: string
    },
    signature?: string
}

export class RegisterAuthenticationKeyResponse extends SignableMessage implements IRegisterAuthenticationKeyResponse {
    constructor(
        public payload: {
            identification: {
                accountId: string
            },
            publicKeyDigest: string
        }
    ) {
        super();
    }

    composePayload(): string {
        return JSON.stringify({
            "identification": {
                "accountId": this.payload.identification.accountId
            },
            "publicKeyDigest": this.payload.publicKeyDigest
        })
    }

    static parse(message: string): RegisterAuthenticationKeyResponse {
        const json = JSON.parse(message);
        const result = new RegisterAuthenticationKeyResponse(json.payload);
        result.signature = json.signature;

        return result;
    }
}


interface IRegisterPassphraseAuthenticationKeyRequest {
    payload: {
        registration: {
            token: string
        },
        passphraseAuthentication: {
            publicKey: string
        }
    }
    signature?: string
}

export class RegisterPassphraseAuthenticationKeyRequest extends SignableMessage implements IRegisterPassphraseAuthenticationKeyRequest {
    constructor(
        public payload: {
            registration: {
                token: string
            },
            passphraseAuthentication: {
                publicKey: string
            }
        }
    ) {
        super();
    }

    composePayload(): string {
        return JSON.stringify({
            "registration": {
                "token": this.payload.registration.token
            },
            "passphraseAuthentication": {
                "publicKey": this.payload.passphraseAuthentication.publicKey
            }
        })
    }

    static parse(message: string): RegisterPassphraseAuthenticationKeyRequest {
        const json = JSON.parse(message);
        const result = new RegisterPassphraseAuthenticationKeyRequest(json.payload);
        result.signature = json.signature;

        return result;
    }
}

interface IRegisterPassphraseAuthenticationKeyResponse {
    payload: {
        identification: {
            accountId: string
        },
        publicKeyDigest: string
    },
    signature?: string
}

export class RegisterPassphraseAuthenticationKeyResponse extends SignableMessage implements IRegisterPassphraseAuthenticationKeyResponse {
    constructor(
        public payload: {
            identification: {
                accountId: string
            },
            publicKeyDigest: string
        }
    ) {
        super();
    }

    composePayload(): string {
        return JSON.stringify({
            "identification": {
                "accountId": this.payload.identification.accountId
            },
            "publicKeyDigest": this.payload.publicKeyDigest
        });
    }

    static parse(message: string): RegisterPassphraseAuthenticationKeyResponse {
        const json = JSON.parse(message);
        const result = new RegisterPassphraseAuthenticationKeyResponse(json.payload);
        result.signature = json.signature;

        return result;
    }
}
