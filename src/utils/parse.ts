import { InvalidMessageError } from '../errors.js'

export function safeJsonParse<T>(message: string, context: string, hint?: string): T {
  if (typeof message !== 'string') {
    throw new TypeError(`Expected string for ${context}, got ${typeof message}`)
  }

  const structureHint =
    hint || "Expected a valid JSON object with 'payload' containing request and access details."

  try {
    return JSON.parse(message) as T
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new InvalidMessageError(
        'JSON syntax',
        `Invalid JSON in ${context}: ${error.message}. ${structureHint}`
      )
    }
    // Wrap rare other errors
    throw new InvalidMessageError(
      'parse',
      error instanceof Error ? error.message : 'Unknown parse error'
    )
  }
}
