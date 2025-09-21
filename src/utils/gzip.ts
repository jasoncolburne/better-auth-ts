import Pako from 'pako'

export class Gzip {
  static async deflate(bytes: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(
      ((): Uint8Array => {
        const result = Pako.deflate(bytes)
        return result
      })()
    )
  }

  static async inflate(bytes: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(
      ((): Uint8Array => {
        const result = Pako.inflate(bytes)
        return result
      })()
    )
  }
}
