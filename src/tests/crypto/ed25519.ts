import { KeyPair } from 'libsodium-wrappers'
import { sodium } from './sodium'
import { ISigningKey, IVerifier } from '../../interfaces'
import { Base64 } from '../../utils/base64'
import { setTimeout } from 'timers/promises'

export class Ed25519Verifier implements IVerifier {
  async verify(message: string, signature: string, publicKey: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      void setTimeout(0, () => {
        try {
          const publicKeyBytes = Base64.decode(publicKey).subarray(1)
          const signatureBytes = Base64.decode(signature).subarray(2)

          const valid = sodium.crypto_sign_verify_detached(signatureBytes, message, publicKeyBytes)
          resolve(valid)
        } catch (error) {
          reject(error)
        }
      })
    })
  }
}

export class Ed25519 implements ISigningKey {
  private readonly keyPair: KeyPair
  private readonly _verifier: IVerifier

  constructor(public seed: Uint8Array) {
    this.keyPair = sodium.crypto_sign_seed_keypair(seed)
    this._verifier = new Ed25519Verifier()
  }

  async sign(message: string): Promise<string> {
    return new Promise((resolve, reject) => {
      void setTimeout(0, () => {
        try {
          const signature = sodium.crypto_sign_detached(message, this.keyPair.privateKey)

          const padded = new Uint8Array([0, 0, ...signature])
          const base64 = Base64.encode(padded)

          resolve(`0B${base64.substring(2)}`)
        } catch (error) {
          reject(error)
        }
      })
    })
  }

  public(): string {
    const padded = new Uint8Array([0, ...this.keyPair.publicKey])
    const base64 = Base64.encode(padded)

    return `B${base64.substring(1)}`
  }

  verifier(): IVerifier {
    return this._verifier
  }

  verify(message: string, signature: string): Promise<boolean> {
    return this._verifier.verify(message, signature, this.public())
  }
}
