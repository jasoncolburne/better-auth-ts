import { ITimestamper } from '../../../interfaces'

export class Rfc3339Nano implements ITimestamper {
  format(when: Date): string {
    const isoString = when.toISOString()
    return isoString.replace('Z', '000000Z')
  }

  parse(when: string | Date): Date {
    return new Date(when)
  }

  now(): Date {
    return new Date()
  }
}
