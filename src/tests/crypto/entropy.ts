import { webcrypto } from 'crypto'

export async function getEntropy(length: number): Promise<Uint8Array> {
  return Promise.resolve(
    (() => {
      const bytes = new Uint8Array(length)
      return webcrypto.getRandomValues(bytes)
    })()
  )
}
