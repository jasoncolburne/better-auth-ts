export interface ITimestamper {
  format(when: Date): string
  parse(when: string | Date): Date
  now(): Date
}

export interface ITokenizer {
  encode(object: string): Promise<string>
  decode(rawToken: string): Promise<string>
}
