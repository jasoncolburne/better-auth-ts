import { describe, it } from 'vitest'
import { Secp256r1, TokenEncoder } from './implementation/index.js'
import { AccessToken } from '../messages/index.js'
import { InvalidTokenError } from '../errors.js'

interface IMockAccessAttributes {
  permissionsByRole: object
}

class MockAccessAttributes implements IMockAccessAttributes {
  constructor(public permissionsByRole: object) {}
}

describe('tokens', () => {
  it('can be encoded and decoded', async () => {
    const tokenEncoder = new TokenEncoder()

    const tempTokenString =
      '0IAGTf0y29Ra-8cjCnXS8NlImAi4_KZfaxgr_5iAux1CLoOZ7d5tvFktxb8Xc6pU2pYQkMw0V75fwP537N9dToIyH4sIAAAAAAACA22PXY-iMBSG_wvX203rUBHuOgIDasQ1jC5uNobaKkU-TFtAZ-J_nzoXu8nOnsuT93k_3i3FZc9lzHijhb5ZnoUIiUl_mNkp0isAWHpgCzKMWSaghJvE309VxifT6_no3Nh1G1jfLMZ7ceCGDYJhvIoDqXySVCAcPdfc2VFYlHG-TabDa0leu1NE56Byc8OJv6lB0taqqFx5jGadHfUiTU9OHYrFXp17FmKIdpfMZk80ileGvHS0Eoc5_1P4jVIM1qW92Qb-7keC6-HlxZH-Yjm-Coxilm1Q2-AV3dPO4LLVuRZtE-WqeISHIZDEGWe125Z-BnVHxc9NuQZk3c-XziyS5-2ybt6OpyJ51Faq44xoQ47gCAMEAZykaORh17PR9wnG8PN2RsuvFyFv_yifPGR_UUp-lFwVwRfATSH8n3WutRS001xZ3rt14bI2xcwo9XxbtxV_PHNWi8byfhnznBlkkEJz6_f9fv8A44o2TvkBAAA'

    const tempKey = new Secp256r1()
    await tempKey.generate()

    const tempToken = await AccessToken.parse<MockAccessAttributes>(tempTokenString, tokenEncoder)
    const newToken = new AccessToken<MockAccessAttributes>(
      tempToken.serverIdentity,
      tempToken.device,
      tempToken.identity,
      tempToken.publicKey,
      tempToken.rotationHash,
      tempToken.issuedAt,
      tempToken.expiry,
      tempToken.refreshExpiry,
      tempToken.attributes
    )

    await newToken.sign(tempKey)
    const tokenString = await newToken.serializeToken(tokenEncoder)

    const token = await AccessToken.parse<MockAccessAttributes>(tokenString, tokenEncoder)

    if (token.serverIdentity !== '1AAIAvcJ4T1tP--dTcdLAw6dYi0r0VOD_CsYe8Cxkf7ydxWE') {
      throw new InvalidTokenError('bad server identity')
    }

    if (token.device !== 'EEw6PIErsDAOl-F2Bme7Zb0hjIaWOCwUjAUugHbK-l9a') {
      throw new InvalidTokenError('bad device')
    }

    if (token.identity !== 'EOomshl9rfHJu4HviTTg7mFiL_skvdF501ZpY4d3bHIP') {
      throw new InvalidTokenError('bad identity')
    }

    if (token.publicKey !== '1AAIAzbb5-Rj4VWEDZQO5mwGG7rDLN6xi51IdYV1on5Pb_bu') {
      throw new InvalidTokenError('bad public key')
    }

    if (token.rotationHash !== 'EFF-rA76Ym9ojDY0tubiXVjR-ARvKN7JHrkWNmnzfghO') {
      throw new InvalidTokenError('bad rotation hash')
    }

    if (token.issuedAt !== '2025-10-08T12:59:41.855000000Z') {
      throw new InvalidTokenError('bad issued at')
    }

    if (token.expiry !== '2025-10-08T13:14:41.855000000Z') {
      throw new InvalidTokenError('bad expiry')
    }

    if (token.refreshExpiry !== '2025-10-09T00:59:41.855000000Z') {
      throw new InvalidTokenError('bad refresh expiry')
    }

    if (
      JSON.stringify(token.attributes.permissionsByRole) !==
      JSON.stringify({
        admin: ['read', 'write'],
      })
    ) {
      throw new InvalidTokenError('bad attributes')
    }
  })
})
