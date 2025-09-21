import 'crypto'

import { setTimeout } from 'timers/promises'

// Cross-platform secure random bytes function
export async function getEntropy(length: number): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    void setTimeout(0, () => {
      try {
        const bytes = new Uint8Array(length)
        globalThis.crypto.getRandomValues(bytes)
        resolve(bytes)
      } catch (error) {
        reject(error)
      }
    })
  })
}
