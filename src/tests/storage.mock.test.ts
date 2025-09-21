import {
  ISalter,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerAuthenticationRegistrationTokenStore,
  IServerPassphraseAuthenticationKeyStore,
  IServerPassphraseRegistrationTokenStore,
  IServerRefreshKeyStore,
} from '../interfaces'
import { Blake3 } from './crypto/blake3'
import { getEntropy } from './crypto/entropy'
import { TextEncoder } from 'util'
import { Noncer } from './crypto/nonce'

export class ServerAuthenticationRegistrationTokenStore
  implements IServerAuthenticationRegistrationTokenStore
{
  private readonly dataByToken: Map<string, string>

  constructor() {
    this.dataByToken = new Map<string, string>()
  }

  async generate(): Promise<string> {
    let entropy = await getEntropy(32)
    const accountId = await Blake3.cesrDigest(entropy)
    entropy = await getEntropy(32)
    const token = await Blake3.cesrDigest(entropy)

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

export class ServerPassphraseRegistrationTokenStore
  implements IServerPassphraseRegistrationTokenStore
{
  private readonly dataByToken: Map<string, [string, string, string]>

  constructor() {
    this.dataByToken = new Map<string, [string, string, string]>()
  }

  async generate(salt: string, parameters: string): Promise<string> {
    const e1 = await getEntropy(32)
    const accountId = await Blake3.cesrDigest(e1)
    const e2 = await getEntropy(32)
    const token = await Blake3.cesrDigest(e2)

    this.dataByToken.set(token, [accountId, salt, parameters])

    return token
  }

  async validate(token: string): Promise<[string, string, string]> {
    const bundle = this.dataByToken.get(token)

    if (typeof bundle === 'undefined') {
      throw 'invalid token'
    }

    return bundle
  }

  async invalidate(token: string): Promise<void> {
    this.dataByToken.delete(token)
  }
}

export class ServerAuthenticationKeyStore implements IServerAuthenticationKeyStore {
  private readonly dataByToken: Map<[string, string], [string, string]>

  constructor() {
    this.dataByToken = new Map<[string, string], [string, string]>()
  }

  async register(
    accountId: string,
    deviceId: string,
    current: string,
    nextDigest: string
  ): Promise<void> {
    this.dataByToken.set([accountId, deviceId], [current, nextDigest])
  }

  async rotate(
    accountId: string,
    deviceId: string,
    current: string,
    nextDigest: string
  ): Promise<void> {
    const bundle = this.dataByToken.get([accountId, deviceId])

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    const encoder = new TextEncoder()
    const bytes = encoder.encode(current)
    const cesrDigest = await Blake3.cesrDigest(bytes)

    if (bundle[1] !== cesrDigest) {
      throw 'invalid forward secret'
    }

    this.dataByToken.set([accountId, deviceId], [current, nextDigest])
  }

  public(accountId: string, deviceId: string): string {
    const bundle = this.dataByToken.get([accountId, deviceId])

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    return bundle[0]
  }
}

export class ServerPassphraseAuthenticationKeyStore
  implements IServerPassphraseAuthenticationKeyStore
{
  private readonly dataByToken: Map<string, [string, string, string]>

  constructor() {
    this.dataByToken = new Map<string, [string, string, string]>()
  }

  async register(
    accountId: string,
    publicKeyDigest: string,
    salt: string,
    parameters: string
  ): Promise<void> {
    const bundle = this.dataByToken.get(accountId)

    if (typeof bundle !== 'undefined') {
      throw 'already registered'
    }

    this.dataByToken.set(accountId, [publicKeyDigest, salt, parameters])
  }

  async getDerivationMaterials(accountId: string): Promise<[string, string]> {
    const bundle = this.dataByToken.get(accountId)

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    return [bundle[1], bundle[2]]
  }

  async verifyPublicKeyDigest(accountId: string, publicKeyDigest: string): Promise<boolean> {
    const bundle = this.dataByToken.get(accountId)

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    return bundle[0] === publicKeyDigest
  }
}

export class ServerRefreshKeyStore implements IServerRefreshKeyStore {
  private readonly dataBySessionId: Map<string, [string, string]>

  constructor() {
    this.dataBySessionId = new Map<string, [string, string]>()
  }

  async create(accountId: string, publicKey: string): Promise<string> {
    const entropy = await getEntropy(32)
    const sessionId = await Blake3.cesrDigest(entropy)

    this.dataBySessionId.set(sessionId, [accountId, publicKey])

    return sessionId
  }

  async get(sessionId: string): Promise<[string, string]> {
    const bundle = this.dataBySessionId.get(sessionId)

    if (typeof bundle === 'undefined') {
      throw 'invalid sessionId'
    }

    return bundle
  }
}

export class ServerAuthenticationNonceStore implements IServerAuthenticationNonceStore {
  private readonly dataByNonce: Map<string, string>
  private readonly noncer: ISalter

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
