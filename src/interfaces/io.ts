export interface INetwork {
  // returns the network response
  sendRequest(path: string, message: string): Promise<string>
}
