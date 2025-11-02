import { IHasher, IIdentityVerifier } from '../../../interfaces/index.js'
import { InvalidIdentityError } from '../../../errors.js'
import { Hasher } from '../crypto/index.js'

export class IdentityVerifier implements IIdentityVerifier {
  hasher: IHasher

  constructor() {
    this.hasher = new Hasher()
  }

  async verify(
    identity: string,
    publicKey: string,
    rotationHash: string,
    extraData?: string
  ): Promise<void> {
    let suffix = ''
    if (typeof extraData !== 'undefined') {
      suffix = extraData
    }

    const identityHash = await this.hasher.sum(publicKey + rotationHash + suffix)
    if (identityHash !== identity) {
      throw new InvalidIdentityError(identity, `hash(${publicKey.substring(0, 8)}... + ${rotationHash.substring(0, 8)}... + ${suffix}) = ${identityHash.substring(0, 16)}...`)
    }
  }
}
