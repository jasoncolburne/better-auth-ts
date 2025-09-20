import { SignableMessage } from "./request";

interface IRefreshAccessTokenRequest {
    payload: {
        refresh: {
            sessionId: string,
            nonces: {
                current: string,
                nextDigest: string
            }
        },
        access: {
            publicKey: string
        }
    },
    signature?: string
}

export class RefreshAccessTokenRequest extends SignableMessage implements IRefreshAccessTokenRequest {
    constructor(
        public payload: {
            refresh: {
                sessionId: string,
                nonces: {
                    current: string,
                    nextDigest: string
                }
            },
            access: {
                publicKey: string
            }
        }
    ) {
        super();
    }

    composePayload(): string {
        return JSON.stringify({
            "refresh": {
                "sessionId": this.payload.refresh.sessionId,
                "nonces": {
                    "current": this.payload.refresh.nonces.current,
                    "nextDigest": this.payload.refresh.nonces.nextDigest
                }
            }, 
            "access": {
                "publicKey": this.payload.access.publicKey
            }
        })
    }

    static parse(message: string): RefreshAccessTokenRequest {
        const json = JSON.parse(message);
        const result = new RefreshAccessTokenRequest(json.payload);
        result.signature = json.signature;

        return result;
    }
}

interface IRefreshAccessTokenResponse {
    payload: {
        access: {
            token: string
        },
        publicKeyDigest: string
    },
    signature?: string
}

export class RefreshAccessTokenResponse extends SignableMessage implements IRefreshAccessTokenResponse {    
    constructor(
        public payload: {
            access: {
                token: string
            },
            publicKeyDigest: string
        }
    ) {
        super();
    }

    composePayload(): string {
        return JSON.stringify({
            "access": {
                "token": this.payload.access.token,
            },
            "publicKeyDigest": this.payload.publicKeyDigest
        })
    }

    static parse(message: string): RefreshAccessTokenResponse {
        const json = JSON.parse(message);
        const result = new RefreshAccessTokenResponse(json.payload);
        result.signature = json.signature;

        return result;
    }
}
