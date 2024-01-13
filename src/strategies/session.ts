import type {IncomingMessage} from 'node:http';

import {Strategy} from '../interfaces/strategy';
import {
  ManagedRequest as SessionRequest,
  SessionOptions,
} from '../interfaces/session';
import {DeserializeUser, User} from '../interfaces/user';
import {pause} from '../utils/pause';

export interface AuthenticateOptions {
  pauseStream?: boolean;
}

export type ManagedRequest<U extends string = 'user'> = SessionRequest & {
  _userProperty?: U;
} & {
  [key in U]: User;
};

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
 * In {@link https://expressjs.com/ Express}-based apps, session support is
 * commonly provided by {@link https://github.com/expressjs/session `express-session`}
 * or {@link https://github.com/expressjs/cookie-session `cookie-session`}.
 *
 * @param {Object} [options]
 * @param {string} [options.key='passport'] - Determines what property ("key") on
 *          the session data where login session data is located.  The login
 *          session is stored and read from `req.session[key]`.
 * @param {function} deserializeUser - Function which deserializes user.
 */
export class SessionStrategy extends Strategy {
  private readonly _key: string;
  private readonly _deserializeUser: DeserializeUser;

  constructor(deserializeUser: DeserializeUser);
  constructor(options: SessionOptions, deserializeUser: DeserializeUser);
  constructor(
    optionsOrDeserialize: SessionOptions | DeserializeUser = {},
    deserializeUser?: DeserializeUser,
  ) {
    super('session');
    let options!: SessionOptions;
    if (typeof optionsOrDeserialize == 'function') {
      deserializeUser = optionsOrDeserialize;
      options = {};
    } else {
      options = optionsOrDeserialize;
    }

    this._key = options.key ?? 'passport';
    this._deserializeUser = deserializeUser!;
  }

  /**
   * Authenticate request based on current session data.
   *
   * When login session data is present in the session, that data will be used to
   * restore login state across across requests by calling the deserialize user
   * function.
   *
   * If login session data is not present, the request will be passed to the next
   * middleware, rather than failing authentication - which is the behavior of
   * most other strategies.  This deviation allows session authentication to be
   * performed at the application-level, rather than the individual route level,
   * while allowing both authenticated and unauthenticated requests and rendering
   * responses accordingly.  Routes that require authentication will need to guard
   * that condition.
   *
   * This function is protected, and should not be called directly.  Instead,
   * use `passport.authenticate()` middleware and specify the {@link SessionStrategy#name `name`}
   * of this strategy and any options.
   *
   * @protected
   * @param {http.IncomingMessage} req - The Node.js {@link https://nodejs.org/api/http.html#class-httpincomingmessage `IncomingMessage`}
   *          object.
   * @param {Object} [options]
   * @param {boolean} [options.pauseStream=false] - When `true`, data events on
   *          the request will be paused, and then resumed after the asynchronous
   *          `deserializeUser` function has completed.  This is only necessary in
   *          cases where later middleware in the stack are listening for events,
   *          and ensures that those events are not missed.
   *
   * @example
   * passport.authenticate('session');
   */
  authenticate(req: ManagedRequest, options: AuthenticateOptions = {}) {
    if (!req.session) {
      return this.error(
        new Error(
          'Login sessions require session support. Did you forget to use `express-session` middleware?',
        ),
      );
    }
    options = options || {};

    let sessionUser: any;
    if (req.session[this._key]) {
      sessionUser = req.session[this._key].user;
    }

    if (sessionUser || sessionUser === 0) {
      // NOTE: Stream pausing is desirable in the case where later middleware is
      //       listening for events emitted from request.  For discussion on the
      //       matter, refer to: https://github.com/TzviPM/next-passport/pull/106

      var paused = options.pauseStream ? pause(req as IncomingMessage) : null;
      this._deserializeUser(sessionUser, req, (err, user) => {
        if (err) {
          return this.error(err);
        }
        if (!user) {
          delete req.session[this._key].user;
        } else {
          var property = req._userProperty ?? 'user';
          req[property] = user;
        }
        this.pass();
        if (paused) {
          paused.resume();
        }
      });
    } else {
      this.pass();
    }
  }
}
