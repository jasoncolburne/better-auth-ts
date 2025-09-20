import { TextDecoder, TextEncoder } from 'util'

export class Base64 {
  private static readonly encoder = new TextEncoder()
  private static readonly decoder = new TextDecoder()

  static encode(data: Uint8Array): string {
    let b64: string

    if (typeof Buffer !== 'undefined') {
      b64 = Buffer.from(data).toString('base64')
    } else {
      const binary = String.fromCharCode(...data)
      b64 = globalThis.btoa(binary).replaceAll('/', '_').replaceAll('+', '-')
    }

    return b64
  }

  static decode(base64: string): Uint8Array {
    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(base64, 'base64'))
    } else {
      const binary = globalThis.atob(base64)
      return new Uint8Array(binary.split('').map(c => c.charCodeAt(0)))
    }
  }
}
