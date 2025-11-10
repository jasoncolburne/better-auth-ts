import {
  IServerTimeLockStore,
  ITimestamper,
  ITokenEncoder,
  IVerificationKeyStore,
  IVerifier,
} from '../interfaces/index.js'
import { SignableMessage } from './message.js'
import {
  ExpiredTokenError,
  FutureRequestError,
  FutureTokenError,
  InvalidMessageError,
  StaleRequestError,
} from '../errors.js'
import { safeJsonParse } from '../utils/parse.js'

export interface IAccessToken<T> {
  serverIdentity: string
  device: string
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
    public serverIdentity: string,
    public device: string,
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

  static async parse<T>(message: string, tokenEncoder: ITokenEncoder): Promise<AccessToken<T>> {
    const publicKeyLength = await tokenEncoder.signatureLength(message)

    const signature = message.substring(0, publicKeyLength)
    let rest = message.substring(publicKeyLength)

    const tokenString = await tokenEncoder.decode(rest)

    const json = safeJsonParse<IAccessToken<T>>(tokenString, 'AccessToken')
    const token = new AccessToken<T>(
      json.serverIdentity,
      json.device,
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
      serverIdentity: this.serverIdentity,
      device: this.device,
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
      throw new InvalidMessageError('signature', 'signature is missing')
    }

    const token = await tokenEncoder.encode(this.composePayload())
    return this.signature + token
  }

  async verifySignature(verifier: IVerifier, publicKey: string): Promise<void> {
    await super.verify(verifier, publicKey)
  }

  async verifyTokenForAccess(
    verifier: IVerifier,
    publicKey: string,
    timestamper: ITimestamper
  ): Promise<void> {
    await this.verifySignature(verifier, publicKey)

    const now = timestamper.now()
    const issuedAt = timestamper.parse(this.issuedAt)
    const expiry = timestamper.parse(this.expiry)

    if (now < issuedAt) {
      throw new FutureTokenError(
        this.issuedAt,
        timestamper.format(now),
        issuedAt.getTime() - now.getTime()
      )
    }

    if (now > expiry) {
      throw new ExpiredTokenError(this.expiry, timestamper.format(now), 'access')
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
    accessKeyStore: IVerificationKeyStore,
    tokenEncoder: ITokenEncoder,
    timestamper: ITimestamper
  ): Promise<AccessToken<T>> {
    const accessToken = await AccessToken.parse<T>(this.payload.access.token, tokenEncoder)

    const accessKey = await accessKeyStore.get(accessToken.serverIdentity)

    await accessToken.verifyTokenForAccess(
      accessKey.verifier(),
      await accessKey.public(),
      timestamper
    )
    await super.verify(verifier, accessToken.publicKey)

    const now = timestamper.now()
    const accessTime = timestamper.parse(this.payload.access.timestamp)
    const expiry = timestamper.parse(accessTime)
    expiry.setSeconds(expiry.getSeconds() + nonceStore.lifetimeInSeconds)

    if (now > expiry) {
      throw new StaleRequestError(
        this.payload.access.timestamp,
        timestamper.format(now),
        nonceStore.lifetimeInSeconds
      )
    }

    if (now < accessTime) {
      throw new FutureRequestError(
        this.payload.access.timestamp,
        timestamper.format(now),
        accessTime.getTime() - now.getTime()
      )
    }

    await nonceStore.reserve(this.payload.access.nonce)

    return accessToken
  }

  static parse<T>(message: string): AccessRequest<T> {
    const json = safeJsonParse<IAccessRequest<T>>(message, 'AccessRequest')
    const result = new AccessRequest<T>(json.payload)
    result.signature = json.signature

    return result
  }
}
