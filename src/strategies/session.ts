import {Strategy} from '../interfaces/strategy';
import {DeserializeUser} from '../interfaces/user';
import {SessionOptions} from '../interfaces/session';
import {getSession} from '../utils/session';
import {NextResponse} from 'next/server';

/**
 * This `Strategy` authenticates HTTP requests based on the contents
 * of session data.
 *
 * The login session must have been previously initiated, typically upon the
 * user interactively logging in using a HTML form.  During session initiation,
 * the logged-in user's information is persisted to the session so that it can
 * be restored on subsequent requests.
 *
 * Note that this strategy merely restores the authentication state from the
 * session, it does not authenticate the session itself.  Authenticating the
 * underlying session is assumed to have been done by the middleware
 * implementing session support.  This is typically accomplished by setting a
 * signed cookie, and verifying the signature of that cookie on incoming
 * requests.
 *
 * Session support is provided by {@link https://github.com/vvo/iron-session `vvo/iron-session`}.
 */
export class SessionStrategy<U, SU> extends Strategy<U> {
  constructor(
    private _sessionOptions: SessionOptions,
    private _deserializeUser: DeserializeUser<U, SU>,
  ) {
    super('session');
  }

  async getSession() {
    return getSession<SU>(this._sessionOptions);
  }

  /**
   * Authenticate request based on current session data.
   *
   * When login session data is present in the session, that data will be used to
   * restore login state across requests by calling the deserialize user
   * function.
   */
  async authenticate(): Promise<NextResponse> {
    const session = await this.getSession();
    const sessionUser = session.user;

    if (!sessionUser) {
      return this.pass();
    }

    try {
      const user = await this._deserializeUser(sessionUser);
      if (!user) {
        delete session.user;
        await session.save();
      }
      return this.pass();
    } catch (err) {
      return this.error(err as Error);
    }
  }
}
