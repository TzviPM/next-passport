import * as http from 'node:http';

import {IncomingMessageExt} from '../http/request';
import {AuthenticationError} from '../errors/authenticationerror';
import {Authenticator} from '../authenticator';
import {User} from '../interfaces/user';
import {Failure, Strategy} from '../interfaces/strategy';
import {MiddlewareFunction, PassportRequest} from './types';
import {ResponseType} from '../interfaces/http';
/**
 * Module dependencies.
 */
// var http = require('http'),

export type StrategySpecifier = Strategy | string | Array<Strategy | string>;

export interface AuthenticateOptions {
  /**
   * Save login state in session, defaults to _true_
   */
  session?: boolean;

  /**
   * After successful login, redirect to given URL
   */
  successRedirect?: string;

  /**
   * True to store success message in req.session.messages, or a string to use as override message for success.
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
   * True to store failure message in req.session.messages, or a string to use as override message for failure.
   */
  failureMessage?: boolean | string;

  /**
   * True to flash failure messages or a string to use as a flash message for failures (overrides any from the strategy itself).
   */
  failureFlash?: boolean | string;

  /**
   * Assign the object provided by the verify callback to given property
   */
  assignProperty?: string;

  /**
   * If true, the failureFlash option is not used for flash messages and remains available for your application to use.
   */
  failWithError?: boolean;

  /**
   * If false, the req.authInfo property is not populated.
   */
  authInfo?: boolean;

  /**
   * URL to redirect to if a user fails to log in, defaults to `successRedirect`
   */
  successReturnToOrRedirect?: string;
}

/**
 * The signature of a callback supplied to `authenticate`.
 *
 * `user` will be set to the
 * authenticated user on a successful authentication attempt, or `false`
 * otherwise.
 *
 * An optional `info` argument will be passed, containing additional
 * details provided by the strategy's verify callback - this could be information about
 * a successful authentication or a challenge message for a failed authentication.
 *
 * An optional `status` argument will be passed when authentication fails - this could
 * be a HTTP response code for a remote authentication failure or similar.
 *
 * For example:
 *
 * app.get('/protected', function(req, res, next) {
 *   passport.authenticate('local', function(err, user, info, status) {
 *     if (err) { return next(err) }
 *     if (!user) { return res.redirect('/signin') }
 *     res.redirect('/account');
 *   })(req, res, next);
 * });
 */
export interface AuthenticateCallback {
  (err: Error | null, user?: User | false, info?: any, status?: any): void;
}

/**
 * Authenticates requests.
 *
 * Applies the `name`ed strategy (or strategies) to the incoming request, in
 * order to authenticate the request.  If authentication is successful, the user
 * will be logged in and populated at `req.user` and a session will be
 * established by default.  If authentication fails, an unauthorized response
 * will be sent.
 *
 * An optional `callback` can be supplied to allow the application to override
 * the default manner in which authentication attempts are handled.
 *
 * Note that if a callback is supplied, it becomes the application's
 * responsibility to log-in the user, establish a session, and otherwise perform
 * the desired operations.
 *
 * Examples:
 *
 *     passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' });
 *
 *     passport.authenticate('basic', { session: false });
 *
 *     passport.authenticate('twitter');
 */

function authenticate(
  passport: Authenticator,
  name: StrategySpecifier,
  callback?: AuthenticateCallback,
): MiddlewareFunction;
function authenticate(
  passport: Authenticator,
  name: StrategySpecifier,
  options: AuthenticateOptions,
  callback?: AuthenticateCallback,
): MiddlewareFunction;
function authenticate(
  passport: Authenticator,
  name: StrategySpecifier,
  optionsOrCallback?: AuthenticateOptions | AuthenticateCallback,
  callback?: AuthenticateCallback,
): MiddlewareFunction {
  let options!: AuthenticateOptions;
  if (typeof optionsOrCallback == 'function') {
    callback = optionsOrCallback;
  } else if (optionsOrCallback) {
    options = optionsOrCallback;
  }
  options ??= {};

  var multi = true;

  // Cast `name` to an array, allowing authentication to pass through a chain of
  // strategies.  The first strategy to succeed, redirect, or error will halt
  // the chain.  Authentication failures will proceed through each strategy in
  // series, ultimately failing if all strategies fail.
  //
  // This is typically used on API endpoints to allow clients to authenticate
  // using their preferred choice of Basic, Digest, token-based schemes, etc.
  // It is not feasible to construct a chain of multiple strategies that involve
  // redirection (for example both Facebook and Twitter), since the first one to
  // redirect will halt the chain.
  if (!Array.isArray(name)) {
    name = [name];
    multi = false;
  }

  return function authenticate(req, res, next) {
    req.login = req.logIn = req.logIn || IncomingMessageExt.prototype.logIn;
    req.logout = req.logOut = req.logOut || IncomingMessageExt.prototype.logOut;
    req.isAuthenticated =
      req.isAuthenticated || IncomingMessageExt.prototype.isAuthenticated;
    req.isUnauthenticated =
      req.isUnauthenticated || IncomingMessageExt.prototype.isUnauthenticated;
    req.flash = req.flash || IncomingMessageExt.prototype.flash;

    req._sessionManager = passport._sessionManager;

    // accumulator for failures from each strategy in the chain
    var failures: Failure[] = [];

    function allFailed() {
      if (callback) {
        if (!multi) {
          return callback(
            null,
            false,
            failures[0].challenge,
            failures[0].status,
          );
        } else {
          var challenges = failures.map(function (f) {
            return f.challenge;
          });
          var statuses = failures.map(function (f) {
            return f.status;
          });
          return callback(null, false, challenges, statuses);
        }
      }

      // Strategies are ordered by priority.  For the purpose of flashing a
      // message, the first failure will be displayed.
      let failure = failures[0] || {};
      let msg: string | undefined;

      if (options.failureFlash) {
        msg =
          typeof options.failureFlash == 'string'
            ? options.failureFlash
            : failure.challenge;
        if (typeof msg == 'string') {
          req.flash?.('error', msg);
        }
      }
      if (options.failureMessage) {
        msg =
          typeof options.failureMessage == 'string'
            ? options.failureMessage
            : failure.challenge;
        if (typeof msg == 'string') {
          req.session.messages ??= [];
          req.session.messages.push(msg);
        }
      }
      if (options.failureRedirect) {
        return res.redirect(options.failureRedirect);
      }

      // When failure handling is not delegated to the application, the default
      // is to respond with 401 Unauthorized.  Note that the WWW-Authenticate
      // header will be set according to the strategies in use (see
      // actions#fail).  If multiple strategies failed, each of their challenges
      // will be included in the response.
      let rchallenge = [];
      let rstatus;

      for (const failure of failures) {
        const {challenge, status} = failure;

        rstatus ||= status;
        if (typeof challenge == 'string') {
          rchallenge.push(challenge);
        }
      }

      res.statusCode = rstatus ?? 401;
      if (res.statusCode == 401 && rchallenge.length) {
        res.setHeader('WWW-Authenticate', rchallenge);
      }
      if (options.failWithError) {
        return next(
          new AuthenticationError(http.STATUS_CODES[res.statusCode]!, rstatus),
        );
      }
      res.end(http.STATUS_CODES[res.statusCode]);
    }

    const names = name as Array<Strategy | string>;

    function attempt(i: number) {
      var layer = names[i];
      // If no more strategies exist in the chain, authentication has failed.
      if (!layer) {
        return allFailed();
      }

      // Get the strategy, which will be used as prototype from which to create
      // a new instance.  Action functions will then be bound to the strategy
      // within the context of the HTTP request/response pair.
      let strategy: Strategy;
      let prototype: Strategy | undefined;
      if (isStrategy(layer)) {
        strategy = layer;
      } else {
        prototype = passport._strategy(layer);
        if (!prototype) {
          return next(
            new Error('Unknown authentication strategy "' + layer + '"'),
          );
        }

        strategy = Object.create(prototype);
      }

      // ----- BEGIN STRATEGY AUGMENTATION -----
      // Augment the new strategy instance with action functions.  These action
      // functions are bound via closure the the request/response pair.  The end
      // goal of the strategy is to invoke *one* of these action methods, in
      // order to indicate successful or failed authentication, redirect to a
      // third-party identity provider, etc.

      augmentStrategy(
        strategy,
        callback,
        options,
        req,
        passport,
        next,
        res,
        failures,
        () => attempt(i + 1),
      );

      // ----- END STRATEGY AUGMENTATION -----

      strategy.authenticate(req, options);
    }

    attempt(0);
  };
}

function augmentStrategy(
  strategy: Strategy,
  callback: AuthenticateCallback | undefined,
  options: AuthenticateOptions,
  req: PassportRequest,
  passport: Authenticator,
  next: (err?: Error | undefined) => void,
  res: ResponseType,
  failures: Failure[],
  attemptNext: () => void,
) {
  strategy.success = function (user, info) {
    if (callback) {
      return callback(null, user, info);
    }

    info ??= '';

    if (options.successFlash) {
      let msg =
        typeof options.successFlash === 'string' ? options.successFlash : info;
      if (typeof msg == 'string') {
        req.flash?.('success', msg);
      }
    }
    if (options.successMessage) {
      let msg =
        typeof options.successMessage === 'string'
          ? options.successMessage
          : info;
      if (typeof msg == 'string') {
        req.session.messages ??= [];
        req.session.messages.push(msg);
      }
    }
    if (options.assignProperty) {
      req[options.assignProperty] = user;
      if (options.authInfo !== false) {
        passport.transformAuthInfo(info, req, function (err, tinfo) {
          if (err) {
            return next(err);
          }
          req.authInfo = tinfo;
          next();
        });
      } else {
        next();
      }
      return;
    }

    req.logIn?.(user, options, function (err) {
      if (err) {
        return next(err);
      }

      function complete() {
        if (options.successReturnToOrRedirect) {
          var url = options.successReturnToOrRedirect;
          if (req.session && req.session.returnTo) {
            url = req.session.returnTo;
            delete req.session.returnTo;
          }
          return res.redirect(url);
        }
        if (options.successRedirect) {
          return res.redirect(options.successRedirect);
        }
        next();
      }

      if (options.authInfo !== false) {
        passport.transformAuthInfo(info, req, function (err, tinfo) {
          if (err) {
            return next(err);
          }
          req.authInfo = tinfo;
          complete();
        });
      } else {
        complete();
      }
    });
  };

  /**
   * Fail authentication, with optional `challenge` and `status`, defaulting
   * to 401.
   *
   * Strategies should call this function to fail an authentication attempt.
   *
   * @param {String} challenge
   * @param {Number} status
   * @api public
   */
  strategy.fail = function (
    challengeOrStatus: string | number,
    status?: number,
  ) {
    let challenge: string | undefined;
    if (typeof challengeOrStatus == 'number') {
      status = challengeOrStatus;
    } else {
      challenge = challengeOrStatus;
    }

    // push this failure into the accumulator and attempt authentication
    // using the next strategy
    failures.push({challenge, status});
    attemptNext();
  };

  /**
   * Redirect to `url` with optional `status`, defaulting to 302.
   *
   * Strategies should call this function to redirect the user (via their
   * user agent) to a third-party website for authentication.
   *
   * @param {String} url
   * @param {Number} status
   * @api public
   */
  strategy.redirect = function (url, status) {
    // NOTE: Do not use `res.redirect` from Express, because it can't decide
    //       what it wants.
    //
    //       Express 2.x: res.redirect(url, status)
    //       Express 3.x: res.redirect(status, url) -OR- res.redirect(url, status)
    //         - as of 3.14.0, deprecated warnings are issued if res.redirect(url, status)
    //           is used
    //       Express 4.x: res.redirect(status, url)
    //         - all versions (as of 4.8.7) continue to accept res.redirect(url, status)
    //           but issue deprecated versions
    res.statusCode = status || 302;
    res.setHeader('Location', url);
    res.setHeader('Content-Length', '0');
    res.end();
  };

  /**
   * Pass without making a success or fail decision.
   *
   * Under most circumstances, Strategies should not need to call this
   * function.  It exists primarily to allow previous authentication state
   * to be restored, for example from an HTTP session.
   *
   * @api public
   */
  strategy.pass = function () {
    next();
  };

  /**
   * Internal error while performing authentication.
   *
   * Strategies should call this function when an internal error occurs
   * during the process of performing authentication; for example, if the
   * user directory is not available.
   *
   * @param {Error} err
   * @api public
   */
  strategy.error = function (err) {
    if (callback) {
      return callback(err);
    }

    next(err);
  };
}

function isStrategy(specifier: Strategy | string): specifier is Strategy {
  return typeof (specifier as Strategy).authenticate == 'function';
}

export {authenticate};
