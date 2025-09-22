import {
  IDigester,
  INoncer,
  IServerAccessNonceStore,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerRegistrationTokenStore,
  IServerPassphraseAuthenticationKeyStore,
  IServerPassphraseRegistrationTokenStore,
  IServerRefreshKeyStore,
  IServerRefreshNonceStore,
} from '../src/interfaces'
import { Noncer } from './crypto/nonce'
import { Digester } from './crypto/digest'

export class ServerAuthenticationRegistrationTokenStore
  implements IServerRegistrationTokenStore
{
  private readonly dataByToken: Map<string, string>
  private readonly digester: IDigester
  private readonly noncer: INoncer

  constructor() {
    this.dataByToken = new Map<string, string>()
    this.digester = new Digester()
    this.noncer = new Noncer()
  }

  async generate(): Promise<string> {
    let saltyNonce = await this.noncer.generate128()
    const accountId = await this.digester.sum(saltyNonce)
    saltyNonce = await this.noncer.generate128()
    const token = await this.digester.sum(saltyNonce)

    this.dataByToken.set(token, accountId)

    return token
  }

  async validate(token: string): Promise<string> {
    const accountId = this.dataByToken.get(token)

    if (typeof accountId === 'undefined') {
      throw 'invalid token'
    }

    return accountId
  }

  async invalidate(token: string): Promise<void> {
    this.dataByToken.delete(token)
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
    nextDigest: string
  ): Promise<void> {
    this.dataByToken.set(accountId + deviceId, [current, nextDigest])
  }

  async rotate(
    accountId: string,
    deviceId: string,
    current: string,
    nextDigest: string
  ): Promise<void> {
    const bundle = this.dataByToken.get(accountId + deviceId)

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    const cesrDigest = await this.digester.sum(current)

    if (bundle[1] !== cesrDigest) {
      throw 'invalid forward secret'
    }

    this.dataByToken.set(accountId + deviceId, [current, nextDigest])
  }

  public(accountId: string, deviceId: string): string {
    const bundle = this.dataByToken.get(accountId + deviceId)

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    return bundle[0]
  }
}

export class ServerAuthenticationNonceStore implements IServerAuthenticationNonceStore {
  private readonly dataByNonce: Map<string, string>
  private readonly noncer: INoncer

  constructor() {
    this.dataByNonce = new Map<string, string>()
    this.noncer = new Noncer()
  }

  async generate(accountId: string): Promise<string> {
    const nonce = await this.noncer.generate128()
    this.dataByNonce.set(nonce, accountId)

    return nonce
  }

  async validate(nonce: string): Promise<string> {
    const accountId = this.dataByNonce.get(nonce)

    if (typeof accountId === 'undefined') {
      throw 'not found'
    }

    return accountId
  }
}

export class ServerAccessNonceStore implements IServerAccessNonceStore {
  private readonly accountIdsByNonce: Map<string, string>

  constructor() {
    this.accountIdsByNonce = new Map<string, string>()
  }

  async reserve(accountId: string, nonce: string): Promise<void> {
    const stored = this.accountIdsByNonce.get(nonce)

    if (typeof stored !== 'undefined') {
      throw 'already used'
    }

    this.accountIdsByNonce.set(nonce, accountId)
  }
}
