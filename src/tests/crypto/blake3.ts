import { blake3 } from '@noble/hashes/blake3'
import { setTimeout } from 'timers/promises'
import { Base64 } from '../../utils/base64'

export class Blake3 {
  static async cesrDigest(bytes: Uint8Array): Promise<string> {
    const digest = new Uint8Array([0, ...(await Blake3.sum256(bytes))])
    const base64 = Base64.encode(digest)
    return `E${base64.substring(1)}`
  }

  static async sum256(bytes: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      void setTimeout(0, () => {
        try {
          const result = blake3(bytes)
          resolve(result)
        } catch (error) {
          reject(error)
        }
      })
    })
  }
}
