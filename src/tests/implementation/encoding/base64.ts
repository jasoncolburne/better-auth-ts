export class Base64 {
  private static readonly encoder = new TextEncoder()
  private static readonly decoder = new TextDecoder()

  static encode(data: Uint8Array): string {
    let base64: string

    if (typeof Buffer !== 'undefined') {
      base64 = Buffer.from(data).toString('base64')
    } else {
      const binary = String.fromCharCode(...data)
      base64 = btoa(binary)
    }

    return base64.replaceAll('/', '_').replaceAll('+', '-')
  }

  static decode(base64: string): Uint8Array<ArrayBuffer> {
    // Normalize URL-safe Base64 to standard Base64
    const normalized = base64
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .padEnd(Math.ceil(base64.length / 4) * 4, '=')

    if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(normalized, 'base64'))
    } else {
      const binary = atob(normalized)
      return new Uint8Array(binary.split('').map(c => c.charCodeAt(0)))
    }
  }
}
