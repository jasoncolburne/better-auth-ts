import { IKeyDeriver, ISigningKey } from '../../src/interfaces'
import { Base64 } from '../../src/utils/base64'
import { Argon2 } from './argon2'
import { Ed25519 } from './ed25519'

export class KeyDeriver implements IKeyDeriver {
  private readonly argon2: Argon2

  constructor() {
    this.argon2 = new Argon2()
  }

  async derive(passphrase: string, salt: string, parameters: string): Promise<ISigningKey> {
    const saltBytes = Base64.decode(salt).subarray(2)
    const keyBytes = await this.argon2.derive(passphrase, saltBytes, parameters)
    return new Ed25519(keyBytes)
  }
}
