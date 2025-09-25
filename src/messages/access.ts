import { IServerTimeLockStore, IVerifier } from '../interfaces'
import { Base64, Gzip } from '../utils'
import { SignableMessage } from './message'

import { TextDecoder, TextEncoder } from 'util'

export interface IAccessToken<T> {
  identity: string
  publicKey: string
  rotationHash: string
  issuedAt: string
  expiry: string
  refreshExpiry: string
  attributes: T
}

export class AccessToken<T> extends SignableMessage implements IAccessToken<T> {
  constructor(
    public identity: string,
    public publicKey: string,
    public rotationHash: string,
    public issuedAt: string,
    public expiry: string,
    public refreshExpiry: string,
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

    const compressedToken = Base64.decode(rest)
    const tokenBytes = await Gzip.inflate(compressedToken)

    const decoder = new TextDecoder('utf-8')
    const tokenString = decoder.decode(tokenBytes)

    const json = JSON.parse(tokenString) as IAccessToken<T>
    const result = new AccessToken<T>(
      json.identity,
      json.publicKey,
      json.rotationHash,
      json.issuedAt,
      json.expiry,
      json.refreshExpiry,
      json.attributes
    )

    result.signature = signature

    return result
  }

  composePayload(): string {
    return JSON.stringify({
      identity: this.identity,
      publicKey: this.publicKey,
      rotationHash: this.rotationHash,
      issuedAt: this.issuedAt,
      expiry: this.expiry,
      refreshExpiry: this.refreshExpiry,
      attributes: this.attributes,
    })
  }

  async serialize(): Promise<string> {
    const encoder = new TextEncoder()
    const tokenBytes = encoder.encode(this.composePayload())
    const compressedToken = await Gzip.deflate(tokenBytes)
    const token = Base64.encode(compressedToken).replaceAll('=', '')

    return this.signature + token
  }

  async verify(verifier: IVerifier, publicKey: string): Promise<void> {
    await super.verify(verifier, publicKey)

    const now = new Date()
    const issuedAt = new Date(this.issuedAt)
    const expiry = new Date(this.expiry)

    if (now < issuedAt) {
      throw 'token from future'
    }

    if (now > expiry) {
      throw 'token expired'
    }
  }
}

export interface IAccessRequest<T> {
  payload: {
    access: {
      nonce: string
      timestamp: string
      token: string
    }
    request: T
  }
  signature?: string
}

export class AccessRequest<T> extends SignableMessage implements IAccessRequest<T> {
  constructor(
    public payload: {
      access: {
        nonce: string
        timestamp: string
        token: string
      }
      request: T
    }
  ) {
    super()
  }

  async _verify<T>(
    nonceStore: IServerTimeLockStore,
    verifier: IVerifier,
    tokenVerifier: IVerifier,
    serverAccessPublicKey: string
  ): Promise<string> {
    const accessToken = await AccessToken.parse<T>(this.payload.access.token)

    await accessToken.verify(tokenVerifier, serverAccessPublicKey)
    await super.verify(verifier, accessToken.publicKey)

    const now = new Date()
    const accessTime = new Date(this.payload.access.timestamp)
    const expiry = new Date(accessTime)
    expiry.setSeconds(expiry.getSeconds() + nonceStore.lifetimeInSeconds)

    if (now > expiry) {
      throw 'stale request'
    }

    if (now < accessTime) {
      throw 'request from future'
    }

    await nonceStore.reserve(this.payload.access.nonce)

    return accessToken.identity
  }

  static parse<T>(message: string): AccessRequest<T> {
    const json = JSON.parse(message)
    const result = new AccessRequest<T>(json.payload)
    result.signature = json.signature

    return result
  }
}
