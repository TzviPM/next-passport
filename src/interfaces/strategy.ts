import {NextResponse} from 'next/server';

export interface Failure {
  challenge?: string;
  status?: number;
}

interface FailFunction {
  (status: number): Promise<void>;
  (challenge: string, status: number): Promise<void>;
}

export abstract class Strategy<U> {
  constructor(public readonly name: string) {}

  /**
   * Authenticate `user`, with optional `info`.
   *
   * Strategies should call this function to successfully authenticate a
   * user.  `user` should be an object supplied by the application after it
   * has been given an opportunity to verify credentials.  `info` is an
   * optional argument containing additional user information.  This is
   * useful for third-party authentication strategies to pass profile
   * details.
   */
  public success!: (user: U, info: Object) => Promise<NextResponse>;

  /**
   * Fail authentication, with optional `challenge` and `status`, defaulting
   * to 401.
   *
   * Strategies should call this function to fail an authentication attempt.
   */
  public fail!: FailFunction;

  /**
   * Redirect to `url` with optional `status`, defaulting to 302.
   *
   * Strategies should call this function to redirect the user (via their
   * user agent) to a third-party website for authentication.
   */
  public redirect!: (url: string, status: number) => Promise<NextResponse>;

  /**
   * Pass without making a success or fail decision.
   *
   * Under most circumstances, Strategies should not need to call this
   * function.  It exists primarily to allow previous authentication state
   * to be restored, for example from an HTTP session.
   */
  public pass!: () => Promise<NextResponse>;

  /**
   * Internal error while performing authentication.
   *
   * Strategies should call this function when an internal error occurs
   * during the process of performing authentication; for example, if the
   * user directory is not available.
   */
  public error!: (err: Error) => Promise<NextResponse>;

  abstract authenticate(options?: AuthenticateOptions): Promise<NextResponse>;
}

export interface AuthenticateOptions {
  /**
   * After successful login, redirect to given URL
   */
  successRedirect?: string;

  /**
   * True to store success message in session.messages, or a string to use as override message for success.
   */
  successMessage?: boolean | string;

  /**
   * True to flash success messages or a string to use as a flash message for success (overrides any from the strategy itself).
   */
  successFlash?: boolean | string;

  /**
   * After failed login, redirect to given URL
   */
  failureRedirect?: string;

  /**
   * True to store failure message in session.messages, or a string to use as override message for failure.
   */
  failureMessage?: boolean | string;

  /**
   * True to flash failure messages or a string to use as a flash message for failures (overrides any from the strategy itself).
   */
  failureFlash?: boolean | string;

  /**
   * If true, the failureFlash option is not used for flash messages and remains available for your application to use.
   */
  failWithError?: boolean;

  /**
   * URL to redirect to if a user fails to log in, defaults to `successRedirect`
   */
  successReturnToOrRedirect?: string;
}
