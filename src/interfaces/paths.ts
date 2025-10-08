export interface IAuthenticationPaths {
  account: {
    create: string
    recover: string
  }
  session: {
    request: string
    connect: string
    refresh: string
  }
  device: {
    rotate: string
    link: string
    unlink: string
  }
}
