export class AuthenticationError extends Error {
  constructor(
    message: string,
    public status: number = 401,
  ) {
    super(message);
  }
}
