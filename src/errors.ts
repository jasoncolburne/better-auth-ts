/**
 * Better Auth Error Classes
 *
 * Standardized error types for all Better Auth operations.
 * See ERRORS.md in the root repository for complete specification.
 */

export class BetterAuthError extends Error {
  readonly code: string
  readonly context?: Record<string, unknown>

  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message)
    this.name = this.constructor.name
    this.code = code
    this.context = context
    Object.setPrototypeOf(this, new.target.prototype) // Restore prototype chain
  }

  toJSON(): Record<string, unknown> {
    return {
      error: {
        code: this.code,
        message: this.message,
        context: this.context,
      },
    }
  }
}

// ============================================================================
// Validation Errors
// ============================================================================

export class InvalidMessageError extends BetterAuthError {
  constructor(field?: string, details?: string) {
    super(
      field
        ? `Message structure is invalid: ${field}${details ? ` (${details})` : ''}`
        : 'Message structure is invalid or malformed',
      'BA101',
      { field, details }
    )
  }
}

export class InvalidIdentityError extends BetterAuthError {
  constructor(provided?: string, details?: string) {
    super('Identity verification failed', 'BA102', { provided, details })
  }
}

export class InvalidDeviceError extends BetterAuthError {
  constructor(provided?: string, calculated?: string) {
    super('Device hash does not match hash(publicKey || rotationHash)', 'BA103', {
      provided,
      calculated,
    })
  }
}

export class InvalidHashError extends BetterAuthError {
  constructor(expected?: string, actual?: string, hashType?: string) {
    super('Hash validation failed', 'BA104', { expected, actual, hashType })
  }
}

// ============================================================================
// Cryptographic Errors
// ============================================================================

export class IncorrectNonceError extends BetterAuthError {
  constructor(expected?: string, actual?: string) {
    super('Response nonce does not match request nonce', 'BA203', {
      expected: expected?.substring(0, 16) + '...',
      actual: actual?.substring(0, 16) + '...',
    })
  }
}

// ============================================================================
// Authentication/Authorization Errors
// ============================================================================

export class MismatchedIdentitiesError extends BetterAuthError {
  constructor(linkContainerIdentity?: string, requestIdentity?: string) {
    super('Link container identity does not match request identity', 'BA302', {
      linkContainerIdentity,
      requestIdentity,
    })
  }
}

// ============================================================================
// Token Errors
// ============================================================================

export class ExpiredTokenError extends BetterAuthError {
  constructor(expiryTime?: string, currentTime?: string, tokenType?: 'access' | 'refresh') {
    super('Token has expired', 'BA401', { expiryTime, currentTime, tokenType })
  }
}

export class FutureTokenError extends BetterAuthError {
  constructor(issuedAt?: string, currentTime?: string, timeDifference?: number) {
    super('Token issued_at timestamp is in the future', 'BA403', {
      issuedAt,
      currentTime,
      timeDifference,
    })
  }
}

// ============================================================================
// Temporal Errors
// ============================================================================

export class StaleRequestError extends BetterAuthError {
  constructor(requestTimestamp?: string, currentTime?: string, maximumAge?: number) {
    super('Request timestamp is too old', 'BA501', {
      requestTimestamp,
      currentTime,
      maximumAge,
    })
  }
}

export class FutureRequestError extends BetterAuthError {
  constructor(requestTimestamp?: string, currentTime?: string, timeDifference?: number) {
    super('Request timestamp is in the future', 'BA502', {
      requestTimestamp,
      currentTime,
      timeDifference,
    })
  }
}
