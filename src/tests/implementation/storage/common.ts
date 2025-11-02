import { IVerificationKey, IVerificationKeyStore } from '../../../interfaces/index.js'
// Using vanilla errors for test implementations from '../../../errors.js'

export class VerificationKeyStore implements IVerificationKeyStore {
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
      throw new Error('Verification key not found')
    }

    return key
  }
}
