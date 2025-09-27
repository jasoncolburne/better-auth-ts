import { IServerTimeLockStore, ITimestamper, ITokenEncoder, IVerifier } from '../interfaces'
import { SignableMessage } from './message'

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

  static async parse<T>(
    message: string,
    publicKeyLength: number,
    tokenEncoder: ITokenEncoder
  ): Promise<AccessToken<T>> {
    const signature = message.substring(0, publicKeyLength)
    let rest = message.substring(publicKeyLength)

    const tokenString = await tokenEncoder.decode(rest)

    const json = JSON.parse(tokenString) as IAccessToken<T>
    const token = new AccessToken<T>(
      json.identity,
      json.publicKey,
      json.rotationHash,
      json.issuedAt,
      json.expiry,
      json.refreshExpiry,
      json.attributes
    )

    token.signature = signature

    return token
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

  async serializeToken(tokenEncoder: ITokenEncoder): Promise<string> {
    if (typeof this.signature === 'undefined') {
      throw 'missing signature'
    }

    const token = await tokenEncoder.encode(this.composePayload())
    return this.signature + token
  }

  async verifyToken(
    verifier: IVerifier,
    publicKey: string,
    timestamper: ITimestamper
  ): Promise<void> {
    await super.verify(verifier, publicKey)

    const now = timestamper.now()
    const issuedAt = timestamper.parse(this.issuedAt)
    const expiry = timestamper.parse(this.expiry)

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
    serverAccessPublicKey: string,
    tokenEncoder: ITokenEncoder,
    timestamper: ITimestamper
  ): Promise<string> {
    const accessToken = await AccessToken.parse<T>(
      this.payload.access.token,
      tokenVerifier.signatureLength,
      tokenEncoder
    )

    await accessToken.verifyToken(tokenVerifier, serverAccessPublicKey, timestamper)
    await super.verify(verifier, accessToken.publicKey)

    const now = timestamper.now()
    const accessTime = timestamper.parse(this.payload.access.timestamp)
    const expiry = timestamper.parse(accessTime)
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
