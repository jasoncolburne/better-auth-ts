import { IServerTimeLockStore, IVerifier } from '../interfaces'
import { Base64, Gzip } from '../utils'
import { SignableMessage } from './message'

import { TextDecoder, TextEncoder } from 'util'

export interface IAccessToken<T> {
  accountId: string
  publicKey: string
  rotationDigest: string
  issuedAt: string
  expiry: string
  refreshExpiry: string
  attributes: T
}

export class AccessToken<T> extends SignableMessage implements IAccessToken<T> {
  constructor(
    public accountId: string,
    public publicKey: string,
    public rotationDigest: string,
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

    const json = JSON.parse(tokenString)
    const result = new AccessToken<T>(
      json.accountId,
      json.publicKey,
      json.rotationDigest,
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
      accountId: this.accountId,
      publicKey: this.publicKey,
      rotationDigest: this.rotationDigest,
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

  async verify(verifier: IVerifier, publicKey: string): Promise<boolean> {
    if (!(await super.verify(verifier, publicKey))) {
      return false
    }

    const now = new Date()
    const issuedAt = new Date(this.issuedAt)
    const expiry = new Date(this.expiry)

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
  payload: {
    access: {
      timestamp: string
      nonce: string
    }
    request: T
    token: string
  }
  signature?: string
}

export class AccessRequest<T> extends SignableMessage implements IAccessRequest<T> {
  constructor(
    public payload: {
      access: {
        timestamp: string
        nonce: string
      }
      request: T
      token: string
    }
  ) {
    super()
  }

  async _verify<T>(
    nonceStore: IServerTimeLockStore,
    verifier: IVerifier,
    tokenVerifier: IVerifier,
    serverAccessPublicKey: string
  ): Promise<boolean> {
    const accessToken = await AccessToken.parse<T>(this.payload.token)

    if (!(await accessToken.verify(tokenVerifier, serverAccessPublicKey))) {
      return false
    }

    if (!(await super.verify(verifier, accessToken.publicKey))) {
      return false
    }

    const now = new Date()
    const accessTime = new Date(this.payload.access.timestamp)
    const expiry = new Date(accessTime)
    expiry.setSeconds(expiry.getSeconds() + nonceStore.lifetimeInSeconds)

    if (now > expiry) {
      return false
    }

    if (now < accessTime) {
      return false
    }

    await nonceStore.reserve(this.payload.access.nonce)

    return true
  }

  static parse<T>(message: string): AccessRequest<T> {
    const json = JSON.parse(message)
    const result = new AccessRequest<T>(json.payload)
    result.signature = json.signature

    return result
  }
}
