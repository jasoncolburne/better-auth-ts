import {
  IClientRotatingKeyStore,
  IClientValueStore,
  IDigester,
  ISigningKey,
} from '../src/interfaces'
import { Digester } from './crypto/digest'
import { Secp256r1 } from './crypto/secp256r1'

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

    const rotationDigest = await this.digester.sum(await next.public())

    return [await current.public(), rotationDigest]
  }

  async rotate(): Promise<[string, string]> {
    if (typeof this.next === 'undefined') {
      throw 'call initialize() first'
    }

    const next = new Secp256r1()
    await next.generate()

    this.current = this.next
    this.next = next

    const rotationDigest = await this.digester.sum(await next.public())

    return [await this.current.public(), rotationDigest]
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
