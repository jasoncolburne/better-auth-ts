export class Base64 {
  private static readonly encoder = new TextEncoder()
  private static readonly decoder = new TextDecoder()

  static encode(data: Uint8Array): string {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(data).toString('base64')
    } else {
      const binary = String.fromCharCode(...data)
      return btoa(binary)
    }
  }

  static decode(base64: string): Uint8Array {
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(base64, 'base64'))
    } else {
      const binary = atob(base64)
      return new Uint8Array(binary.split('').map(c => c.charCodeAt(0)))
    }
  }

  static encodeString(str: string): string {
    const data = this.encoder.encode(str)
    return this.encode(data)
  }

  static decodeString(base64: string): string {
    const data = this.decode(base64)
    return this.decoder.decode(data)
  }
}
