import _sodium from 'libsodium-wrappers-sumo'

await _sodium.ready

export const sodium = _sodium
