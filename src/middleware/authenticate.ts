// import * as http from 'node:http';

import {NextResponse} from 'next/server';
import type {NextRequest} from 'next/server';

import {Authenticator} from '../authenticator';
import {AuthenticateOptions, Failure, Strategy} from '../interfaces/strategy';
import {MiddlewareFunction} from './types';
import {FlashType} from '../interfaces/session';
import {AuthenticationError} from '../errors/authenticationerror';
/**
 * Module dependencies.
 */
// var http = require('http'),

export type StrategySpecifier<U> =
  | Strategy<U>
  | string
  | Array<Strategy<U> | string>;

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
export interface AuthenticateCallback<U> {
  (
    err: Error | null,
    user?: U | false,
    info?: any,
    status?: any,
  ): Promise<NextResponse>;
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

function authenticate<U, SU>(
  passport: Authenticator<U, SU>,
  name: StrategySpecifier<U>,
  _options?: AuthenticateOptions,
  callback?: AuthenticateCallback<U>,
): MiddlewareFunction {
  const options = _options ?? {};

  let multi = true;

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

  return function authenticate(req, event) {
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
          passport._sessionManager.setFlash(FlashType.ERROR, msg);
        }
      }
      if (options.failureMessage) {
        msg =
          typeof options.failureMessage == 'string'
            ? options.failureMessage
            : failure.challenge;
        if (typeof msg == 'string') {
          passport._sessionManager.setMessage(msg);
        }
      }
      if (options.failureRedirect) {
        return NextResponse.redirect(options.failureRedirect);
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

      const statusCode = rstatus ?? 401;
      let headers = {};
      if (statusCode === 401 && rchallenge.length) {
        headers = {
          headers: {
            'WWW-Authenticate': rchallenge,
          },
        };
      }

      if (options.failWithError) {
        throw new AuthenticationError(String(statusCode), rstatus);
      }
      return new NextResponse(undefined, {
        status: statusCode,
        ...headers,
      });
    }

    const names = name as Array<Strategy<U> | string>;

    async function attempt(i: number) {
      var layer = names[i];
      // If no more strategies exist in the chain, authentication has failed.
      if (!layer) {
        return allFailed();
      }

      // Get the strategy, which will be used as prototype from which to create
      // a new instance.  Action functions will then be bound to the strategy
      // within the context of the HTTP request/response pair.
      let strategy: Strategy<U>;
      let prototype: Strategy<U> | undefined;
      if (isStrategy(layer)) {
        strategy = layer;
      } else {
        prototype = passport._strategy(layer);
        if (!prototype) {
          throw new Error('Unknown authentication strategy "' + layer + '"');
        }

        strategy = Object.create(prototype);
      }

      augmentStrategy(
        strategy,
        callback,
        options,
        req,
        passport,
        failures,
        () => attempt(i + 1),
      );

      const result = await strategy.authenticate(options);
      return result;
    }

    let res!: NextResponse;

    const promise = attempt(0).then(result => (res = result));

    event.waitUntil(promise);

    return res;
  };
}

/**
 *
 * Augment the new strategy instance with action functions.  These
 * action functions are bound via closure the the request/response
 * pair. The endgoal of the strategy is to invoke *one* of these
 * action methods, in order to indicate successful or failed
 * authentication, redirect to a third-party identity provider, etc.
 */
function augmentStrategy<U, SU>(
  strategy: Strategy<U>,
  callback: AuthenticateCallback<U> | undefined,
  options: AuthenticateOptions,
  req: NextRequest,
  passport: Authenticator<U, SU>,
  failures: Failure[],
  attemptNext: () => void,
) {
  strategy.success = async function (user, info) {
    if (callback) {
      return callback(null, user, info);
    }

    info ??= '';

    if (options.successFlash) {
      let msg =
        typeof options.successFlash === 'string' ? options.successFlash : info;
      if (typeof msg == 'string') {
        await passport._sessionManager.setFlash(FlashType.SUCCESS, msg);
      }
    }
    if (options.successMessage) {
      let msg =
        typeof options.successMessage === 'string'
          ? options.successMessage
          : info;
      if (typeof msg == 'string') {
        await passport._sessionManager.setMessage(msg);
      }
    }

    await passport._sessionManager.logIn(user);

    if (options.successReturnToOrRedirect) {
      var url = options.successReturnToOrRedirect;
      const returnTo = await passport._sessionManager.pluckReturnTo();
      if (returnTo) {
        url = returnTo;
      }
      return NextResponse.redirect(url);
    }
    if (options.successRedirect) {
      return NextResponse.redirect(options.successRedirect);
    }
    return NextResponse.next();
  };

  strategy.fail = async function (
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

  strategy.redirect = async function (url, status) {
    const statusCode = status || 302;
    return NextResponse.redirect(url, {
      status: statusCode,
      headers: {
        'Content-Length': '0',
        Location: url,
      },
    });
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
  strategy.pass = async function () {
    return NextResponse.next();
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
  strategy.error = async function (err) {
    if (callback) {
      return callback(err);
    }

    throw err;
  };
}

function isStrategy<U>(
  specifier: Strategy<U> | string,
): specifier is Strategy<U> {
  return typeof (specifier as Strategy<U>).authenticate == 'function';
}

export {authenticate};
