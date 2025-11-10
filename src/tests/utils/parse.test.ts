import { describe, expect, it, vi } from 'vitest'
import { safeJsonParse } from '../../utils/parse.js'
import { InvalidMessageError } from '../../errors.js'

describe('safeJsonParse', () => {
  it('parses valid JSON correctly', () => {
    const validJson = '{"payload": {"request": {}, "access": {"nonce": "abc"}}}'
    const result = safeJsonParse(validJson, 'TestMessage')
    expect(result).toEqual({ payload: { request: {}, access: { nonce: 'abc' } } })
  })

  it('throws InvalidMessageError on SyntaxError with context and generic hint', () => {
    const invalidJson = '{invalid: json}'
    expect(() => safeJsonParse(invalidJson, 'TestMessage')).toThrowError(InvalidMessageError)
    expect(() => safeJsonParse(invalidJson, 'TestMessage')).toThrow(/Invalid JSON in TestMessage/)
    expect(() => safeJsonParse(invalidJson, 'TestMessage')).toThrow(
      /Expected a valid JSON object with 'payload' containing request and access details./
    )
  })

  it('uses custom hint if provided', () => {
    const invalidJson = '{invalid: json}'
    const customHint = 'Expected custom structure'
    expect(() => safeJsonParse(invalidJson, 'TestMessage', customHint)).toThrowError(
      InvalidMessageError
    )
    expect(() => safeJsonParse(invalidJson, 'TestMessage', customHint)).toThrow(customHint)
  })

  it('throws TypeError for non-string input', () => {
    expect(() => safeJsonParse(null as any, 'TestMessage')).toThrow(TypeError)
    expect(() => safeJsonParse(123 as any, 'TestMessage')).toThrow(TypeError)
  })

  it('wraps other errors in InvalidMessageError', () => {
    const mockError = new Error('Other error')
    vi.spyOn(JSON, 'parse').mockImplementation(() => {
      throw mockError
    })
    expect(() => safeJsonParse('{}', 'TestMessage')).toThrowError(InvalidMessageError)
    vi.restoreAllMocks()
  })
})
