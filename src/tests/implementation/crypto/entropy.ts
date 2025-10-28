export async function getEntropy(length: number): Promise<Uint8Array> {
  const bytes = new Uint8Array(length)
  return crypto.getRandomValues(bytes)
}
