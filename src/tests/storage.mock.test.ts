import {
  IServerAuthenticationKeyStore,
  IServerAuthenticationRegistrationTokenStore,
  IServerPassphraseAuthenticationKeyStore,
  IServerPassphraseRegistrationTokenStore,
} from '../interfaces'
import { Blake3 } from './crypto/blake3'
import { getEntropy } from './crypto/entropy'
import { TextEncoder } from 'util'

export class ServerAuthenticationRegistrationTokenStore
  implements IServerAuthenticationRegistrationTokenStore
{
  private readonly dataByToken: Map<string, string>

  constructor() {
    this.dataByToken = new Map<string, string>()
  }

  async generate(): Promise<string> {
    const e1 = await getEntropy(32)
    const accountId = await Blake3.cesrDigest(e1)
    const e2 = await getEntropy(32)
    const token = await Blake3.cesrDigest(e2)

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
