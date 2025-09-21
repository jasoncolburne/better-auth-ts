import _sodium from 'libsodium-wrappers'

await _sodium.ready

export const sodium = _sodium
