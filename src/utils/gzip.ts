import Pako from 'pako'

export class Gzip {
  static async deflate(bytes: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(
      ((): Uint8Array => {
        const result = Pako.deflateRaw(bytes)
        return result
      })()
    )
  }

  static async inflate(bytes: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(
      ((): Uint8Array => {
        const result = Pako.inflateRaw(bytes)
        return result
      })()
    )
  }
}
