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
      field ? `Message structure is invalid: ${field}${details ? ` (${details})` : ''}` : 'Message structure is invalid or malformed',
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

export class SignatureVerificationError extends BetterAuthError {
  constructor(publicKey?: string, signedData?: string) {
    super('Signature verification failed', 'BA201', { publicKey, signedData })
  }
}

export class NonceError extends BetterAuthError {
  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message, code, context)
  }
}

export class IncorrectNonceError extends NonceError {
  constructor(expected?: string, actual?: string) {
    super('Response nonce does not match request nonce', 'BA203', {
      expected: expected?.substring(0, 16) + '...',
      actual: actual?.substring(0, 16) + '...',
    })
  }
}

export class ExpiredNonceError extends NonceError {
  constructor(nonceTimestamp?: string, currentTime?: string, expirationWindow?: string) {
    super('Authentication challenge has expired', 'BA204', {
      nonceTimestamp,
      currentTime,
      expirationWindow,
    })
  }
}

export class NonceReplayError extends NonceError {
  constructor(nonce?: string, previousUsageTimestamp?: string) {
    super('Nonce has already been used (replay attack detected)', 'BA205', {
      nonce: nonce?.substring(0, 16) + '...',
      previousUsageTimestamp,
    })
  }
}

// ============================================================================
// Authentication/Authorization Errors
// ============================================================================

export class AuthenticationError extends BetterAuthError {
  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message, code, context)
  }
}

export class MismatchedIdentitiesError extends AuthenticationError {
  constructor(linkContainerIdentity?: string, requestIdentity?: string) {
    super('Link container identity does not match request identity', 'BA302', {
      linkContainerIdentity,
      requestIdentity,
    })
  }
}

export class PermissionDeniedError extends BetterAuthError {
  constructor(requiredPermissions?: string[], actualPermissions?: string[], operation?: string) {
    super('Insufficient permissions for requested operation', 'BA303', {
      requiredPermissions,
      actualPermissions,
      operation,
    })
  }
}

// ============================================================================
// Token Errors
// ============================================================================

export class TokenError extends BetterAuthError {
  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message, code, context)
  }
}

export class ExpiredTokenError extends TokenError {
  constructor(expiryTime?: string, currentTime?: string, tokenType?: 'access' | 'refresh') {
    super('Token has expired', 'BA401', { expiryTime, currentTime, tokenType })
  }
}

export class InvalidTokenError extends TokenError {
  constructor(details?: string) {
    super('Token structure or format is invalid', 'BA402', { details })
  }
}

export class FutureTokenError extends TokenError {
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

export class TemporalError extends BetterAuthError {
  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message, code, context)
  }
}

export class StaleRequestError extends TemporalError {
  constructor(requestTimestamp?: string, currentTime?: string, maximumAge?: number) {
    super('Request timestamp is too old', 'BA501', {
      requestTimestamp,
      currentTime,
      maximumAge,
    })
  }
}

export class FutureRequestError extends TemporalError {
  constructor(requestTimestamp?: string, currentTime?: string, timeDifference?: number) {
    super('Request timestamp is in the future', 'BA502', {
      requestTimestamp,
      currentTime,
      timeDifference,
    })
  }
}

export class ClockSkewError extends TemporalError {
  constructor(clientTime?: string, serverTime?: string, timeDifference?: number, maxTolerance?: number) {
    super('Client and server clock difference exceeds tolerance', 'BA503', {
      clientTime,
      serverTime,
      timeDifference,
      maxTolerance,
    })
  }
}

// ============================================================================
// Storage Errors
// ============================================================================

export class StorageError extends BetterAuthError {
  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message, code, context)
  }
}

export class NotFoundError extends StorageError {
  constructor(resourceType?: string, resourceIdentifier?: string) {
    super(
      `Resource not found${resourceType ? `: ${resourceType}` : ''}`,
      'BA601',
      { resourceType, resourceIdentifier }
    )
  }
}

export class AlreadyExistsError extends StorageError {
  constructor(resourceType?: string, resourceIdentifier?: string) {
    super(
      `Resource already exists${resourceType ? `: ${resourceType}` : ''}`,
      'BA602',
      { resourceType, resourceIdentifier }
    )
  }
}

export class StorageUnavailableError extends StorageError {
  constructor(backendType?: string, connectionDetails?: string, backendError?: string) {
    super('Storage backend is unavailable', 'BA603', {
      backendType,
      connectionDetails,
      backendError,
    })
  }
}

export class StorageCorruptionError extends StorageError {
  constructor(resourceType?: string, resourceIdentifier?: string, corruptionDetails?: string) {
    super('Stored data is corrupted or invalid', 'BA604', {
      resourceType,
      resourceIdentifier,
      corruptionDetails,
    })
  }
}

// ============================================================================
// Encoding Errors
// ============================================================================

export class EncodingError extends BetterAuthError {
  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message, code, context)
  }
}

export class SerializationError extends EncodingError {
  constructor(messageType?: string, format?: string, details?: string) {
    super('Failed to serialize message', 'BA701', { messageType, format, details })
  }
}

export class DeserializationError extends EncodingError {
  constructor(messageType?: string, rawData?: string, details?: string) {
    super('Failed to deserialize message', 'BA702', {
      messageType,
      rawData: rawData?.substring(0, 100) + '...',
      details,
    })
  }
}

export class CompressionError extends EncodingError {
  constructor(operation?: 'compress' | 'decompress', dataSize?: number, details?: string) {
    super('Failed to compress or decompress data', 'BA703', {
      operation,
      dataSize,
      details,
    })
  }
}

// ============================================================================
// Network Errors (Client-Only)
// ============================================================================

export class NetworkError extends BetterAuthError {
  constructor(message: string, code: string, context?: Record<string, unknown>) {
    super(message, code, context)
  }
}

export class ConnectionError extends NetworkError {
  constructor(serverUrl?: string, details?: string) {
    super('Failed to connect to server', 'BA801', { serverUrl, details })
  }
}

export class TimeoutError extends NetworkError {
  constructor(timeoutDuration?: number, endpoint?: string) {
    super('Request timed out', 'BA802', { timeoutDuration, endpoint })
  }
}

export class ProtocolError extends NetworkError {
  constructor(httpStatusCode?: number, details?: string) {
    super('Invalid HTTP response or protocol violation', 'BA803', {
      httpStatusCode,
      details,
    })
  }
}

// ============================================================================
// Protocol Errors
// ============================================================================

export class InvalidStateError extends BetterAuthError {
  constructor(currentState?: string, attemptedOperation?: string, requiredState?: string) {
    super('Operation not allowed in current state', 'BA901', {
      currentState,
      attemptedOperation,
      requiredState,
    })
  }
}

export class RotationError extends BetterAuthError {
  constructor(rotationType?: 'access' | 'authentication', details?: string) {
    super('Key rotation failed', 'BA902', { rotationType, details })
  }
}

export class RecoveryError extends BetterAuthError {
  constructor(details?: string) {
    super('Account recovery failed', 'BA903', { details })
  }
}

export class DeviceRevokedError extends BetterAuthError {
  constructor(deviceIdentifier?: string, revocationTimestamp?: string) {
    super('Device has been revoked', 'BA904', {
      deviceIdentifier,
      revocationTimestamp,
    })
  }
}

export class IdentityDeletedError extends BetterAuthError {
  constructor(identityIdentifier?: string, deletionTimestamp?: string) {
    super('Identity has been deleted', 'BA905', {
      identityIdentifier,
      deletionTimestamp,
    })
  }
}

// ============================================================================
// Specialized Errors (for specific operations)
// ============================================================================

export class InvalidForwardSecretError extends InvalidHashError {
  constructor(provided?: string, expected?: string) {
    super(expected, provided, 'forward-secret')
    this.message = 'Invalid forward secret (rotation hash mismatch)'
  }
}

export class RecoveryHashMismatchError extends InvalidHashError {
  constructor(provided?: string, expected?: string) {
    super(expected, provided, 'recovery')
    this.message = 'Recovery key hash does not match stored hash'
  }
}

export class DuplicateIdentityError extends AlreadyExistsError {
  constructor(identity?: string) {
    super('identity', identity)
    this.message = 'Identity already registered'
  }
}

export class DuplicateDeviceError extends AlreadyExistsError {
  constructor(device?: string) {
    super('device', device)
    this.message = 'Device already exists'
  }
}

export class InvalidRecoveryKeyError extends AuthenticationError {
  constructor(details?: string) {
    super('Recovery key verification failed', 'BA301', { details })
  }
}

export class ValueReservedError extends StorageError {
  constructor(value?: string, reservedUntil?: string) {
    super('Value is currently reserved', 'BA604', { value, reservedUntil })
    this.message = 'Value reserved too recently'
  }
}

export class InvalidStateTransitionError extends InvalidStateError {
  constructor(operation?: string, reason?: string) {
    const msg = `Invalid state transition: ${operation} ${reason ? `(${reason})` : ''}`
    super(undefined, operation, undefined)
    Object.defineProperty(this, 'message', { value: msg, writable: true })
    Object.defineProperty(this, 'context', { value: { operation, reason }, writable: true })
  }
}
