export interface IAuthenticationPaths {
  account: {
    create: string
    recover: string
    delete: string
  }
  session: {
    request: string
    create: string
    refresh: string
  }
  device: {
    rotate: string
    link: string
    unlink: string
  }
}
