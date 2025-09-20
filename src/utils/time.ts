function rfc3339Nano(when: Date): string {
  const isoString = when.toISOString()
  return isoString.replace('Z', '000000Z')
}
