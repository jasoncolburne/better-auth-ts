import { IVerifier } from '../interfaces/crypto'
import { Base64 } from '../utils/base64'
import { SignableMessage } from './request'
import { IServerAccessNonceStore } from '../interfaces/storage'

import { TextDecoder, TextEncoder } from 'util'
import { Gzip } from '../utils/gzip'

export interface IAccessToken<T> {
  accountId: string
  publicKey: string
  issuedAt: string
  expiry: string
  attributes: T
}

export class AccessToken<T> extends SignableMessage implements IAccessToken<T> {
  constructor(
    public accountId: string,
    public publicKey: string,
    public issuedAt: string,
    public expiry: string,
    public attributes: T
  ) {
    super()
  }

  static async parse<T>(message: string): Promise<AccessToken<T>> {
    const signature = message.substring(0, 88)
    let rest = message.substring(88)

    while (rest.length % 4 !== 0) {
      rest += '='
    }

    const compressedToken = Base64.decode(message)
    const tokenBytes = await Gzip.inflate(compressedToken)

    const decoder = new TextDecoder('utf-8')
    const tokenString = decoder.decode(tokenBytes)

    const json = JSON.parse(tokenString)
    const result = new AccessToken(
      json.accountId,
      json.publicKey,
      json.issuedAt,
      json.expiry,
      json.attributes
    )

    result.signature = signature

    return result
  }

  composePayload(): string {
    return JSON.stringify({
      accountId: this.accountId,
      publicKey: this.publicKey,
      issuedAt: this.issuedAt,
      expiry: this.expiry,
      attributes: this.attributes,
    })
  }

  async serialize(): Promise<string> {
    const encoder = new TextEncoder()
    const tokenBytes = encoder.encode(this.composePayload())
    const compressedToken = await Gzip.deflate(tokenBytes)
    const token = Base64.encode(compressedToken)
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '')

    return this.signature + token
  }

  async verify(verifier: IVerifier, publicKey: string): Promise<boolean> {
    if (!(await super.verify(verifier, publicKey))) {
      return false
    }

    const now = Date.now()
    const issuedAt = new Date(this.issuedAt!).getTime()
    const expiry = new Date(this.expiry!).getTime()

    if (now < issuedAt) {
      return false
    }

    if (now > expiry) {
      return false
    }

    return true
  }
}

export interface IAccessRequest<T> {
  token: string
  payload: {
    access: {
      timestamp: string
      nonce: string
    }
    request: T
  }
  signature?: string
}

export class AccessRequest<T> extends SignableMessage implements IAccessRequest<T> {
  constructor(
    public token: string,
    public payload: {
      access: {
        timestamp: string
        nonce: string
      }
      request: T
    }
  ) {
    super()
  }

  composePayload(): string {
    return JSON.stringify({
      token: this.token,
      payload: {
        access: {
          timestamp: this.payload.access.timestamp,
          nonce: this.payload.access.nonce,
        },
        request: this.payload.request,
      },
    })
  }

  async verifyRequest(
    nonceStore: IServerAccessNonceStore,
    verifier: IVerifier,
    tokenVerifier: IVerifier,
    serverAccessPublicKey: string
  ): Promise<boolean> {
    const accessToken = await AccessToken.parse(this.token)

    if (!(await accessToken.verify(tokenVerifier, serverAccessPublicKey))) {
      return false
    }

    if (!(await super.verify(verifier, accessToken.publicKey))) {
      return false
    }

    const now = Date.now()
    const accessTime = new Date(this.payload.access.timestamp).getTime()

    if (now > accessTime + 30000) {
      return false
    }

    if (now < accessTime) {
      return false
    }

    if (!(await nonceStore.reserve(this.payload.access.nonce))) {
      return false
    }

    return true
  }

  static parse<T>(message: string): AccessRequest<T> {
    const json = JSON.parse(message)
    const result = new AccessRequest<T>(json.token, json.payload)
    result.signature = json.signature

    return result
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function isAccessRequest<T>(obj: any): obj is AccessRequest<T> {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    typeof obj.token === 'string' &&
    obj.payload !== null &&
    typeof obj.payload === 'object' &&
    obj.payload.access !== null &&
    typeof obj.payload.access === 'object' &&
    typeof obj.payload.access.timestamp === 'string' &&
    typeof obj.payload.access.nonce === 'string' &&
    typeof obj.signature === 'string'
  )
}
