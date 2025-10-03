export interface IAuthenticationPaths {
  account: {
    create: string
  }
  authenticate: {
    start: string
    finish: string
  }
  rotate: {
    authentication: string
    access: string
    link: string
    unlink: string
    recover: string
  }
}
