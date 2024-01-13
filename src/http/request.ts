import {IncomingMessage} from 'node:http';
import {User} from '../interfaces/user';
import {ErrorCallback, SessionManager} from '../sessionmanager';
import {LoginOptions} from '../interfaces/session';

export class IncomingMessageExt extends IncomingMessage {
  _userProperty?: string;
  _sessionManager?: SessionManager;

  [key: string]: any;

  /**
   * Initiate a login session for `user`.
   *
   * Options:
   *   - `session`  Save login state in session, defaults to _true_
   *
   * Examples:
   *
   *     req.logIn(user, { session: false });
   *
   *     req.logIn(user, function(err) {
   *       if (err) { throw err; }
   *       // session saved
   *     });
   */
  logIn(user: User, options: LoginOptions, done: (err?: Error) => void) {
    if (typeof options == 'function') {
      done = options;
      options = {};
    }
    options = options || {};

    var property = this._userProperty || 'user';
    var session = options.session ?? true;

    this[property] = user;
    if (session && this._sessionManager) {
      if (typeof done != 'function') {
        throw new Error('req#login requires a callback function');
      }

      this._sessionManager.logIn(this, user, options, err => {
        if (err) {
          this[property] = null;
          return done(err);
        }
        done();
      });
    } else {
      done && done();
    }
  }

  /**
   * Terminate an existing login session.
   */
  logOut(options: LoginOptions, done: ErrorCallback) {
    if (typeof options == 'function') {
      done = options;
      options = {};
    }
    options = options || {};

    var property = this._userProperty || 'user';

    this[property] = null;
    if (this._sessionManager) {
      if (typeof done != 'function') {
        throw new Error('req#logout requires a callback function');
      }

      this._sessionManager.logOut(this, options, done);
    } else {
      done && done();
    }
  }

  /**
   * Test if request is authenticated.
   */
  isAuthenticated(): boolean {
    var property = this._userProperty || 'user';
    return this[property] ? true : false;
  }

  /**
   * Test if request is unauthenticated.
   */
  isUnauthenticated(): boolean {
    return !this.isAuthenticated();
  }

  /**
   * Sets a flash message on the session
   */
  flash(type: string, msg: string): void {
    if (this._sessionManager) {
      this._sessionManager.setFlash(type, msg);
    }
  }
}
