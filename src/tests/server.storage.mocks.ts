import {
  IHasher,
  INoncer,
  IServerAuthenticationKeyStore,
  IServerAuthenticationNonceStore,
  IServerRecoveryHashStore,
  IServerTimeLockStore,
} from '../interfaces'
import { Noncer } from './crypto/nonce'
import { Hasher } from './crypto/hash'

export class ServerAuthenticationKeyStore implements IServerAuthenticationKeyStore {
  private readonly dataByToken: Map<string, [string, string]>
  private readonly hasher: IHasher
  private readonly identities: Set<string>

  constructor() {
    this.dataByToken = new Map<string, [string, string]>()
    this.hasher = new Hasher()
    this.identities = new Set<string>()
  }

  async register(
    identity: string,
    device: string,
    current: string,
    rotationHash: string,
    existingIdentity: boolean
  ): Promise<void> {
    const hasIdentity = this.identities.has(identity)

    if (!existingIdentity && hasIdentity) {
      throw 'identity already registered'
    }

    if (existingIdentity && !hasIdentity) {
      throw 'identity not found'
    }

    const bundle = this.dataByToken.get(identity + device)

    if (typeof bundle !== 'undefined') {
      throw 'already exists'
    }

    this.identities.add(identity)
    this.dataByToken.set(identity + device, [current, rotationHash])
  }

  async rotate(
    identity: string,
    device: string,
    current: string,
    rotationHash: string
  ): Promise<void> {
    const bundle = this.dataByToken.get(identity + device)

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    const cesrHash = await this.hasher.sum(current)

    if (bundle[1] !== cesrHash) {
      throw 'invalid forward secret'
    }

    this.dataByToken.set(identity + device, [current, rotationHash])
  }

  async public(identity: string, device: string): Promise<string> {
    const bundle = this.dataByToken.get(identity + device)

    if (typeof bundle === 'undefined') {
      throw 'not found'
    }

    return bundle[0]
  }
}

export class ServerRecoveryHashStore implements IServerRecoveryHashStore {
  private readonly dataByAccount: Map<string, string>

  constructor() {
    this.dataByAccount = new Map<string, string>()
  }

  async register(identity: string, hash: string): Promise<void> {
    this.dataByAccount.set(identity, hash)
  }

  async validate(identity: string, hash: string): Promise<void> {
    const stored = this.dataByAccount.get(identity)

    if (typeof stored === 'undefined') {
      throw 'not found'
    }

    if (stored !== hash) {
      throw 'incorrect hash'
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

  async generate(identity: string): Promise<string> {
    const expiration = new Date()
    expiration.setSeconds(expiration.getSeconds() + this.lifetimeInSeconds)

    const nonce = await this.noncer.generate128()
    this.dataByNonce.set(nonce, identity)
    this.nonceExpirations.set(nonce, expiration)

    return nonce
  }

  async validate(nonce: string): Promise<string> {
    const identity = this.dataByNonce.get(nonce)
    const expiration = this.nonceExpirations.get(nonce)

    if (typeof identity === 'undefined' || typeof expiration === 'undefined') {
      throw 'not found'
    }

    const now = new Date()

    if (now > expiration) {
      throw 'expired nonce'
    }

    return identity
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
