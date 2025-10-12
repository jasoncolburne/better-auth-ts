import { IHasher, IIdentityVerifier } from '../../../interfaces/index.js'
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
      throw 'could not verify identity'
    }
  }
}
