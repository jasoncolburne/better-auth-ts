export interface IAuthenticationPaths {
  authenticate: {
    start: string
    finish: string
  }
  register: {
    create: string
    link: string
    recover: string
  }
  rotate: {
    authentication: string
    access: string
  }
}
