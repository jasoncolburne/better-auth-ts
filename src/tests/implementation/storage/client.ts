import {
  IClientRotatingKeyStore,
  IClientValueStore,
  IHasher,
  ISigningKey,
  IVerificationKey,
  IVerificationKeyStore,
} from '../../../interfaces'
import { Hasher } from '../crypto/hash'
import { Secp256r1 } from '../crypto/secp256r1'

export class ClientRotatingKeyStore implements IClientRotatingKeyStore {
  private current?: ISigningKey
  private next?: ISigningKey
  private readonly hasher: IHasher

  constructor() {
    this.hasher = new Hasher()
  }

  async initialize(extraData?: string): Promise<[string, string, string]> {
    const current = new Secp256r1()
    const next = new Secp256r1()

    await current.generate()
    await next.generate()

    this.current = current
    this.next = next

    let suffix = ''
    if (typeof extraData !== 'undefined') {
      suffix = extraData
    }

    const publicKey = await current.public()
    const rotationHash = await this.hasher.sum(await next.public())
    const identity = await this.hasher.sum(publicKey + rotationHash + suffix)

    return [identity, publicKey, rotationHash]
  }

  async rotate(): Promise<[string, string]> {
    if (typeof this.next === 'undefined') {
      throw 'call initialize() first'
    }

    const next = new Secp256r1()
    await next.generate()

    this.current = this.next
    this.next = next

    const rotationHash = await this.hasher.sum(await next.public())

    return [await this.current.public(), rotationHash]
  }

  async signer(): Promise<ISigningKey> {
    if (typeof this.current === 'undefined') {
      throw 'call initialize() first'
    }

    return this.current
  }
}

export class ClientValueStore implements IClientValueStore {
  private value?: string

  async store(value: string): Promise<void> {
    this.value = value
  }

  async get(): Promise<string> {
    if (typeof this.value === 'undefined') {
      throw 'nothing to get'
    }

    return this.value
  }
}

export class ClientVerificationKeyStore implements IVerificationKeyStore {
  private readonly keysByIdentity: Map<string, IVerificationKey>

  constructor() {
    this.keysByIdentity = new Map()
  }

  async add(identity: string, key: IVerificationKey): Promise<void> {
    this.keysByIdentity.set(identity, key)
  }

  async get(identity: string): Promise<IVerificationKey> {
    const key = this.keysByIdentity.get(identity)

    if (typeof key === 'undefined') {
      throw 'not found'
    }

    return key
  }
}
