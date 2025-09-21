import { blake3 } from '@noble/hashes/blake3'

export class Blake3 {
  static async sum256(bytes: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(
      (() => {
        const result = blake3(bytes)
        return result
      })()
    )
  }
}
