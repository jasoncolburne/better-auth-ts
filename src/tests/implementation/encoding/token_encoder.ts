import { ITokenEncoder } from '../../../interfaces/index.js'
import { Base64 } from './base64.js'

export class TokenEncoder implements ITokenEncoder {
  async signatureLength(token: string): Promise<number> {
    if (token.length < 2) {
      throw 'token too short'
    }

    if (!token.startsWith('0I')) {
      throw 'incorrect token format'
    }

    return 88
  }

  async encode(object: string): Promise<string> {
    const encoder = new TextEncoder()
    const tokenBytes = encoder.encode(object)

    const cs = new CompressionStream('gzip')
    const compressedStream = new Blob([tokenBytes]).stream().pipeThrough(cs)
    const compressedBuffer = await new Response(compressedStream).arrayBuffer()
    const compressedToken = new Uint8Array(compressedBuffer)

    const token = Base64.encode(compressedToken).replaceAll('=', '')
    return token
  }

  async decode(rawToken: string): Promise<string> {
    let token = rawToken
    while (token.length % 4 !== 0) {
      token += '='
    }

    const compressedToken = Base64.decode(token)
    const ds = new DecompressionStream('gzip')
    const decompressedStream = new Blob([compressedToken]).stream().pipeThrough(ds)
    const decompressedBuffer = await new Response(decompressedStream).arrayBuffer()
    const objectBytes = new Uint8Array(decompressedBuffer)
    const decoder = new TextDecoder('utf-8')
    const objectString = decoder.decode(objectBytes)
    return objectString
  }
}
