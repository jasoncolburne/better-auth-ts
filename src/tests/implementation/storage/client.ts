import {
  IClientRotatingKeyStore,
  IClientValueStore,
  IHasher,
  ISigningKey,
} from '../../../interfaces/index.js'
import { InvalidStateTransitionError, NotFoundError } from '../../../errors.js'
import { Hasher } from '../crypto/hash.js'
import { Secp256r1 } from '../crypto/secp256r1.js'

export class ClientRotatingKeyStore implements IClientRotatingKeyStore {
  private currentKey?: ISigningKey
  private nextKey?: ISigningKey
  private futureKey?: ISigningKey
  private readonly hasher: IHasher

  constructor() {
    this.hasher = new Hasher()
  }

  async initialize(extraData?: string): Promise<[string, string, string]> {
    const current = new Secp256r1()
    const next = new Secp256r1()

    await current.generate()
    await next.generate()

    this.currentKey = current
    this.nextKey = next

    let suffix = ''
    if (typeof extraData !== 'undefined') {
      suffix = extraData
    }

    const publicKey = await current.public()
    const rotationHash = await this.hasher.sum(await next.public())
    const identity = await this.hasher.sum(publicKey + rotationHash + suffix)

    return [identity, publicKey, rotationHash]
  }

  async next(): Promise<[ISigningKey, string]> {
    if (typeof this.nextKey === 'undefined') {
      throw new InvalidStateTransitionError('signer', 'must call initialize() first')
    }

    if (typeof this.futureKey === 'undefined') {
      const key = new Secp256r1()
      await key.generate()
      this.futureKey = key
    }

    const rotationHash = await this.hasher.sum(await this.futureKey!.public())

    return [this.nextKey!, rotationHash]
  }

  async rotate(): Promise<void> {
    if (typeof this.nextKey === 'undefined') {
      throw new InvalidStateTransitionError('signer', 'must call initialize() first')
    }

    if (typeof this.futureKey === 'undefined') {
      throw new InvalidStateTransitionError('rotate', 'must call next() first')
    }

    this.currentKey = this.nextKey
    this.nextKey = this.futureKey
    this.futureKey = undefined
  }

  async signer(): Promise<ISigningKey> {
    if (typeof this.currentKey === 'undefined') {
      throw new InvalidStateTransitionError('signer', 'must call initialize() first')
    }

    return this.currentKey
  }
}

export class ClientValueStore implements IClientValueStore {
  private value?: string

  async store(value: string): Promise<void> {
    this.value = value
  }

  async get(): Promise<string> {
    if (typeof this.value === 'undefined') {
      throw new NotFoundError('value')
    }

    return this.value
  }
}
