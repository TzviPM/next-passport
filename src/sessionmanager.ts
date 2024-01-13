import {
  LoginOptions,
  ManagedRequest,
  SessionOptions,
} from './interfaces/session';
import {SerializeUser, User} from './interfaces/user';

export interface ErrorCallback {
  (err?: Error): void;
}

export class SessionManager {
  private _key: string;
  private _serializeUser?: SerializeUser;

  constructor(serializeUser: SerializeUser);
  constructor(options: SessionOptions, serializeUser: SerializeUser);
  constructor(
    optionsOrSerialize: SessionOptions | SerializeUser,
    serialize?: SerializeUser,
  ) {
    let options!: SessionOptions;
    if (typeof optionsOrSerialize == 'function') {
      serialize = optionsOrSerialize;
      options = {};
    } else {
      options = optionsOrSerialize;
    }

    this._key = options.key ?? 'passport';
    this._serializeUser = serialize;
  }

  logIn(req: ManagedRequest, user: User, cb: ErrorCallback): void;
  logIn(
    req: ManagedRequest,
    user: User,
    options: LoginOptions,
    cb: ErrorCallback,
  ): void;
  logIn(
    req: ManagedRequest,
    user: User,
    optionsOrCb: LoginOptions | ErrorCallback = {},
    cb?: ErrorCallback,
  ) {
    let options!: LoginOptions;
    if (typeof optionsOrCb == 'function') {
      cb = options as ErrorCallback;
      options = {};
    }

    if (!req.session) {
      return cb?.(
        new Error(
          'Login sessions require session support. Did you forget to use `express-session` middleware?',
        ),
      );
    }

    var prevSession = req.session;

    // regenerate the session, which is good practice to help
    // guard against forms of session fixation
    req.session.regenerate((err?: Error) => {
      if (err) {
        return cb?.(err);
      }

      this._serializeUser?.(user, req, (err, obj) => {
        if (err) {
          return cb?.(err);
        }
        if (options.keepSessionInfo) {
          Object.assign(req.session, prevSession);
        }
        if (!req.session[this._key]) {
          req.session[this._key] = {};
        }
        // store user information in session, typically a user id
        req.session[this._key].user = obj;
        // save the session before redirection to ensure page
        // load does not happen before session is saved
        req.session.save((err?: Error) => {
          if (err) {
            return cb?.(err);
          }
          cb?.();
        });
      });
    });
  }

  logOut(req: ManagedRequest, options: LoginOptions, cb: ErrorCallback) {
    if (typeof options == 'function') {
      cb = options;
      options = {};
    }
    options = options || {};

    if (!req.session) {
      return cb?.(
        new Error(
          'Login sessions require session support. Did you forget to use `express-session` middleware?',
        ),
      );
    }

    // clear the user from the session object and save.
    // this will ensure that re-using the old session id
    // does not have a logged in user
    if (req.session[this._key]) {
      delete req.session[this._key].user;
    }
    var prevSession = req.session;

    req.session.save((err?: Error) => {
      if (err) {
        return cb(err);
      }

      // regenerate the session, which is good practice to help
      // guard against forms of session fixation
      req.session.regenerate((err?: Error) => {
        if (err) {
          return cb(err);
        }
        if (options.keepSessionInfo) {
          Object.assign(req.session, prevSession);
        }
        cb();
      });
    });
  }

  setFlash(name: string, message: string): void {
    return;
  }

  getFlash(name: string): string | undefined {
    return;
  }
}
