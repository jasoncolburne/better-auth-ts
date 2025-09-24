export interface INetwork {
  sendRequest(path: string, message: string): Promise<string>
}
