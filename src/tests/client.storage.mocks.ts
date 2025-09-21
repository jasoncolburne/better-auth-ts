import {
  IClientRefreshNonceStore,
  IClientRotatingKeyStore,
  IClientSingleKeyStore,
  IClientValueStore,
  IDigester,
  ISalter,
  ISigningKey,
} from '../interfaces'
import { Digester } from './crypto/digest'
import { Noncer } from './crypto/nonce'
import { Secp256r1 } from './crypto/secp256r1'

export class ClientSingleKeyStore implements IClientSingleKeyStore {
  private key?: ISigningKey

  async generate(): Promise<string> {
    const key = new Secp256r1()
    await key.generate()

    this.key = key

    return await key.public()
  }

  signer(): ISigningKey {
    if (typeof this.key === 'undefined') {
      throw 'no key'
    }

    return this.key
  }
}

export class ClientRotatingKeyStore implements IClientRotatingKeyStore {
  private current?: ISigningKey
  private next?: ISigningKey
  private readonly digester: IDigester

  constructor() {
    this.digester = new Digester()
  }

  async initialize(): Promise<[string, string]> {
    const current = new Secp256r1()
    const next = new Secp256r1()

    await current.generate()
    await next.generate()

    this.current = current
    this.next = next

    const nextDigest = await this.digester.sum(await next.public())

    return [await current.public(), nextDigest]
  }

  async rotate(): Promise<[string, string]> {
    if (typeof this.next === 'undefined') {
      throw 'call initialize() first'
    }

    const next = new Secp256r1()
    await next.generate()

    this.current = this.next
    this.next = next

    const nextDigest = await this.digester.sum(await next.public())

    return [await this.current.public(), nextDigest]
  }

  signer(): ISigningKey {
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

export class ClientRefreshNonceStore implements IClientRefreshNonceStore {
  private current?: string
  private next?: string
  private readonly noncer: ISalter
  private readonly digester: IDigester

  constructor() {
    this.noncer = new Noncer()
    this.digester = new Digester()
  }

  async initialize(): Promise<string> {
    this.next = await this.noncer.generate128()
    const nextDigest = await this.digester.sum(this.next)

    return nextDigest
  }

  async evolve(): Promise<[string, string]> {
    if (typeof this.next === 'undefined') {
      throw 'must call initialize first'
    }

    this.current = this.next
    this.next = await this.noncer.generate128()
    const nextDigest = await this.digester.sum(this.next)

    return [this.current, nextDigest]
  }
}
