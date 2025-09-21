import { blake3 } from '@noble/hashes/blake3'
import { setTimeout } from 'timers/promises'

export class Blake3 {
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
