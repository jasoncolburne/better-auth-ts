import Pako from "pako";
import { IVerifier } from "../interfaces/crypto"
import { Base64 } from "../utils/base64";
import { SignableMessage } from "./request";
import { IAccessNonceStore } from "../interfaces/storage";

export interface IAccessToken {
    accountId: string,
    publicKey: string,
    issuedAt: string,
    expiry: string,
    attributes: Map<string, any>,
}

export class AccessToken extends SignableMessage implements IAccessToken {
    constructor(
        public accountId: string,
        public publicKey: string,
        public issuedAt: string,
        public expiry: string,
        public attributes: Map<string, any>,
    ) {
        super();
    }

    static parse(
        message: string,
    ): AccessToken {
        const signature = message.substring(0, 88);
        var rest = message.substring(88);

        while (rest.length % 4 != 0) {
            rest += "=";
        }

        const compressedToken = Base64.decode(message);
        const tokenBytes = Pako.inflate(compressedToken);

        const decoder = new TextDecoder('utf-8');
        const tokenString = decoder.decode(tokenBytes);

        const json = JSON.parse(tokenString);
        const result = new AccessToken(
            json.accountId,
            json.publicKey,
            json.issuedAt,
            json.expiry,
            json.attributes
        );

        result.signature = json.signature;

        return result;
    }

    composePayload(): string {
        return JSON.stringify({
           "accountId": this.accountId,
           "publicKey": this.publicKey,
           "issuedAt": this.issuedAt,
           "expiry": this.expiry,
           "attributes": this.attributes 
        });
    }

    serialize(): string {
        const encoder = new TextEncoder();
        const tokenBytes = encoder.encode(this.composePayload());
        const compressedToken = Pako.deflate(tokenBytes);
        const token = Base64.encode(compressedToken).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
        
        return this.signature + token;
    }

    verify(verifier: IVerifier, publicKey: string): boolean {
        if (!super.verify(verifier, publicKey)) {
            return false;
        }

        const now = Date.now();
        const issuedAt = new Date(this.issuedAt!).getTime();
        const expiry = new Date(this.expiry!).getTime();

        if (now < issuedAt) {
            return false;
        }

        if (now > expiry) {
            return false;
        }

        return true;
    }
}

export interface IAccess {
    timestamp: string,
    nonce: string
}

export interface IAccessRequest<T> {
    token: string,
    payload: {
        access: IAccess,
        request: T,
    }
    signature?: string
}

export class AccessRequest<T> extends SignableMessage implements IAccessRequest<T> {
    constructor(
        public token:string,
        public payload: {
            access: {
                timestamp: string,
                nonce: string
            },
            request: T
        }
    ) {
        super();
    }

    composePayload(): string {
        return JSON.stringify({
            "token": this.token,
            "payload": {
                "access": {
                    "timestamp": this.payload.access.timestamp,
                    "nonce": this.payload.access.nonce
                },
                "request": this.payload.request
            } 
        });
    }

    verifyRequest(nonceStore: IAccessNonceStore, verifier: IVerifier, tokenVerifier: IVerifier, serverAccessPublicKey: string): boolean {
        const accessToken = AccessToken.parse(this.token);

        if (!accessToken.verify(tokenVerifier, serverAccessPublicKey)) {
            return false;
        }

        if (!super.verify(verifier, accessToken.publicKey)) {
            return false;
        }

        const now = Date.now();
        const accessTime = new Date(this.payload.access.timestamp).getTime();

        if (now > accessTime + 30000) {
            return false;
        }

        if (now < accessTime) {
            return false;
        }

        if (!nonceStore.reserve(this.payload.access.nonce)) {
            return false;
        }

        return true;
    }

    static parse<T>(message: string): AccessRequest<T> {
        const json = JSON.parse(message);
        const result = new AccessRequest<T>(json.token, json.payload);
        result.signature = json.signature;

        return result;
    }
}