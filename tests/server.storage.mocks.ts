import {
  IDigester,
  INoncer,
  IServerTimeLockStore,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerCreationTokenStore,
  IServerRecoveryDigestStore,
} from '../src/interfaces'
import { Noncer } from './crypto/nonce'
import { Digester } from './crypto/digest'

export class ServerCreationTokenStore
  implements IServerCreationTokenStore
{
  private readonly dataByToken: Map<string, string>
  private readonly tokenExpirations: Map<string, Date>
  private readonly digester: IDigester
  private readonly noncer: INoncer

  constructor(public readonly lifetimeInMinutes: number) {
    this.dataByToken = new Map<string, string>()
    this.tokenExpirations = new Map<string, Date>()
    this.digester = new Digester()
    this.noncer = new Noncer()
  }

  async generate(): Promise<string> {
    let saltyNonce = await this.noncer.generate128()
    const accountId = await this.digester.sum(saltyNonce)
    saltyNonce = await this.noncer.generate128()
    const token = await this.digester.sum(saltyNonce)

    const expiration = new Date()
    expiration.setMinutes(expiration.getMinutes() + this.lifetimeInMinutes)
    this.dataByToken.set(token, accountId)
    this.tokenExpirations.set(token, expiration)

    return token
  }

  async validate(token: string): Promise<string> {
    const expiration = this.tokenExpirations.get(token)
    const accountId = this.dataByToken.get(token)

    if (typeof accountId === 'undefined' || typeof expiration === 'undefined') {
      throw 'invalid token'
    }

    const now = new Date()
    if (now > expiration) {
      throw 'expired token'
    }

    return accountId
  }

  async invalidate(token: string): Promise<void> {
    this.dataByToken.delete(token)
    this.tokenExpirations.delete(token)
  }
}

export class ServerAuthenticationKeyStore implements IServerAuthenticationKeyStore {
  private readonly dataByToken: Map<string, [string, string]>
  private readonly digester: IDigester

  constructor() {
    this.dataByToken = new Map<string, [string, string]>()
    this.digester = new Digester()
  }

  async register(
    accountId: string,
    deviceId: string,
    current: string,
    rotationDigest: string
  ): Promise<void> {
    this.dataByToken.set(accountId + deviceId, [current, rotationDigest])
  }

  async rotate(
    accountId: string,
    deviceId: string,
    current: string,
    rotationDigest: string
  ): Promise<void> {
    const bundle = this.dataByToken.get(accountId + deviceId)

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    const cesrDigest = await this.digester.sum(current)

    if (bundle[1] !== cesrDigest) {
      throw 'invalid forward secret'
    }

    this.dataByToken.set(accountId + deviceId, [current, rotationDigest])
  }

  async public(accountId: string, deviceId: string): Promise<string> {
    const bundle = this.dataByToken.get(accountId + deviceId)

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    return bundle[0]
  }
}

export class ServerRecoveryDigestStore implements IServerRecoveryDigestStore {
  private readonly dataByAccount: Map<string, string>

  constructor() {
    this.dataByAccount = new Map<string, string>()
  }

  async register(accountId: string, digest: string): Promise<void> {
    this.dataByAccount.set(accountId, digest)
  }

  async validate(accountId: string, digest: string): Promise<void> {
    const stored = this.dataByAccount.get(accountId)

    if (typeof stored === 'undefined') {
      throw 'not found'
    }

    if (stored !== digest) {
      throw 'incorrect digest'
    }
  }

}

export class ServerAuthenticationNonceStore implements IServerAuthenticationNonceStore {
  private readonly dataByNonce: Map<string, string>
  private readonly nonceExpirations: Map<string, Date>
  private readonly noncer: INoncer

  constructor(public readonly lifetimeInSeconds: number) {
    this.dataByNonce = new Map<string, string>()
    this.nonceExpirations = new Map<string, Date>()
    this.noncer = new Noncer()
  }

  async generate(accountId: string): Promise<string> {
    const expiration = new Date()
    expiration.setSeconds(expiration.getSeconds() + this.lifetimeInSeconds)

    const nonce = await this.noncer.generate128()
    this.dataByNonce.set(nonce, accountId)
    this.nonceExpirations.set(nonce, expiration)

    return nonce
  }

  async validate(nonce: string): Promise<string> {
    const accountId = this.dataByNonce.get(nonce)
    const expiration = this.nonceExpirations.get(nonce)

    if (typeof accountId === 'undefined' || typeof expiration === 'undefined') {
      throw 'not found'
    }

    const now = new Date()

    if (now > expiration) { 
      throw 'expired nonce'
    }

    return accountId
  }
}

export class ServerTimeLockStore implements IServerTimeLockStore {
  private readonly nonces: Map<string, Date>

  constructor(public readonly lifetimeInSeconds: number) {
    this.nonces = new Map<string, Date>()
  }

  async reserve(value: string): Promise<void> {
    const validAt = this.nonces.get(value)

    if (typeof validAt !== 'undefined') {
      const now = new Date()
      if (now < validAt) {
        throw 'value reserved too recently'
      }
    }

    const newValidAt = new Date()
    newValidAt.setSeconds(newValidAt.getSeconds() + this.lifetimeInSeconds)

    this.nonces.set(value, newValidAt)
  }
}
