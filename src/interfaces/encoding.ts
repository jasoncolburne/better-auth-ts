export interface ITimestamper {
  format(when: Date): string
  parse(when: string | Date): Date
  now(): Date
}

export interface ITokenEncoder {
  encode(object: string): Promise<string>
  decode(rawToken: string): Promise<string>
  signatureLength(token: string): Promise<number>
}

export interface IIdentityVerifier {
  verify(
    identity: string,
    publicKey: string,
    rotationHash: string,
    extraData?: string
  ): Promise<void>
}
