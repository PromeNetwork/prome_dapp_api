export class HttpSuccess {
  private readonly data;
  private readonly status;
  private readonly code;
  constructor(data: string | Record<string, any> | any[], status = 200) {
    this.data = data;
    this.status = status;
    this.code = 0;
  }
}
