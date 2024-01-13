import {connectFramework} from './framework/connect';
import {Strategy} from './interfaces/strategy';
import {
  DeserializeUser,
  DeserializeUserCallback,
  SerializeUser,
  SerializeUserCallback,
  SerializedUser,
  User,
} from './interfaces/user';
import {
  AuthenticateCallback,
  AuthenticateOptions,
  StrategySpecifier,
} from './middleware/authenticate';
import {InitializeOptions} from './middleware/initialize';
import {PassportRequest} from './middleware/types';
import {SessionManager} from './sessionmanager';
import {SessionStrategy} from './strategies/session';

type ConnectFW = ReturnType<typeof connectFramework>;

interface Framework {
  initialize: ConnectFW['initialize'];
  authenticate: ConnectFW['authenticate'];
  authorize?: ConnectFW['authenticate'];
}

type DefaultInfo = Object;

interface InfoTransformerCallback<T = DefaultInfo> {
  (err?: Error | null, info?: T): void;
}

interface InfoTransformer<T = DefaultInfo, A = T> {
  /**
   * synchronous
   */
  (info: T): A;
  /**
   * async with callback
   */
  (info: T, done: InfoTransformerCallback<A>): void;
  /**
   * async with `req` and callback
   */
  (info: T, req: PassportRequest, done: InfoTransformerCallback<A>): void;
}

export class Authenticator {
  private _key: string;
  private _strategies: {
    [key: string]: Strategy;
  };
  private _serializers: SerializeUser<PassportRequest>[];
  private _deserializers: DeserializeUser<PassportRequest>[];
  private _infoTransformers: InfoTransformer[];
  private _framework!: Framework;
  public _sessionManager!: SessionManager;

  constructor() {
    this._key = 'passport';
    this._strategies = {};
    this._serializers = [];
    this._deserializers = [];
    this._infoTransformers = [];

    this.init();
  }

  /**
   * Initialize authenticator.
   *
   * Initializes the `Authenticator` instance by creating the default `{@link SessionManager}`,
   * {@link Authenticator#use `use()`}'ing the default `{@link SessionStrategy}`, and
   * adapting it to work as {@link https://github.com/senchalabs/connect#readme Connect}-style
   * middleware, which is also compatible with {@link https://expressjs.com/ Express}.
   *
   * @private
   */
  private init() {
    this.framework(connectFramework());
    this.use(
      new SessionStrategy({key: this._key}, this.deserializeUser.bind(this)),
    );
    this._sessionManager = new SessionManager(
      {key: this._key},
      this.serializeUser.bind(this),
    );
  }

  /**
   * Register a strategy for later use when authenticating requests.  The name
   * with which the strategy is registered is passed to {@link Authenticator#authenticate `authenticate()`}.
   *
   * @example <caption>Register strategy.</caption>
   * passport.use(new GoogleStrategy(...));
   *
   * @example <caption>Register strategy and override name.</caption>
   * passport.use('password', new LocalStrategy(function(username, password, cb) {
   *   // ...
   * }));
   */
  use(name: string, strategy: Strategy): this;
  use(strategy: Strategy): this;
  use(nameOrStrategy: Strategy | string, strategy?: Strategy): this {
    let name!: string;
    if (!strategy) {
      strategy = nameOrStrategy as Strategy;
      name = strategy.name;
    } else {
      name = nameOrStrategy as string;
    }

    this._strategies[name] = strategy;
    return this;
  }

  /**
   * Deregister a strategy that was previously registered with the given name.
   *
   * In a typical application, the necessary authentication strategies are
   * registered when initializing the app and, once registered, are always
   * available.  As such, it is typically not necessary to call this function.
   *
   * @public
   * @param {string} name - Name of the strategy.
   * @returns {this}
   *
   * @example
   * passport.unuse('acme');
   */
  unuse(name: string) {
    delete this._strategies[name];
    return this;
  }

  /**
   * Adapt this `Authenticator` to work with a specific framework.
   *
   * By default, Passport works as {@link https://github.com/senchalabs/connect#readme Connect}-style
   * middleware, which makes it compatible with {@link https://expressjs.com/ Express}.
   * For any app built using Express, there is no need to call this function.
   *
   * @public
   * @param {Object} fw
   * @returns {this}
   */
  framework(fw: Framework) {
    this._framework = fw;
    return this;
  }

  /**
   * Create initialization middleware.
   *
   * Returns middleware that initializes Passport to authenticate requests.
   *
   * As of v0.6.x, it is typically no longer necessary to use this middleware.  It
   * exists for compatiblity with apps built using previous versions of Passport,
   * in which this middleware was necessary.
   *
   * The primary exception to the above guidance is when using strategies that
   * depend directly on `passport@0.4.x` or earlier.  These earlier versions of
   * Passport monkeypatch Node.js `http.IncomingMessage` in a way that expects
   * certain Passport-specific properties to be available.  This middleware
   * provides a compatibility layer for this situation.
   *
   * @public
   * @param {Object} [options]
   * @param {string} [options.userProperty='user'] - Determines what property on
   *          `req` will be set to the authenticated user object.
   * @param {boolean} [options.compat=true] - When `true`, enables a compatibility
   *          layer for packages that depend on `passport@0.4.x` or earlier.
   * @returns {function}
   *
   * @example
   * app.use(passport.initialize());
   */
  initialize(options: InitializeOptions) {
    options = options || {};
    return this._framework.initialize(this, options);
  }

  /**
   * Create authentication middleware.
   *
   * Returns middleware that authenticates the request by applying the given
   * strategy (or strategies).
   *
   * Examples:
   *
   *     passport.authenticate('local', function(err, user) {
   *       if (!user) { return res.redirect('/login'); }
   *       res.end('Authenticated!');
   *     })(req, res);
   *
   * @public
   *
   * @example <caption>Authenticate username and password submitted via HTML form.</caption>
   * app.get('/login/password', passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' }));
   *
   * @example <caption>Authenticate bearer token used to access an API resource.</caption>
   * app.get('/api/resource', passport.authenticate('bearer', { session: false }));
   */
  authenticate(
    strategy: string | string[] | Strategy,
    options: AuthenticateOptions,
    callback?: AuthenticateCallback,
  ) {
    return this._framework.authenticate(this, strategy, options, callback);
  }

  /**
   * Create third-party service authorization middleware.
   *
   * Returns middleware that will authorize a connection to a third-party service.
   *
   * This middleware is identical to using {@link Authenticator#authenticate `authenticate()`}
   * middleware with the `assignProperty` option set to `'account'`.  This is
   * useful when a user is already authenticated (for example, using a username
   * and password) and they want to connect their account with a third-party
   * service.
   *
   * In this scenario, the user's third-party account will be set at
   * `req.account`, and the existing `req.user` and login session data will be
   * be left unmodified.  A route handler can then link the third-party account to
   * the existing local account.
   *
   * All arguments to this function behave identically to those accepted by
   * `{@link Authenticator#authenticate}`.
   *
   * @public
   * @param {string|string[]|Strategy} strategy
   * @param {Object} [options]
   * @param {function} [callback]
   * @returns {function}
   *
   * @example
   * app.get('/oauth/callback/twitter', passport.authorize('twitter'));
   */
  authorize(
    strategy: string | string[] | Strategy,
    options: AuthenticateOptions,
    callback: AuthenticateCallback,
  ) {
    options = options || {};
    options.assignProperty = 'account';

    let fn = this._framework.authorize || this._framework.authenticate;
    return fn(this, strategy, options, callback);
  }

  /**
   * Middleware that will restore login state from a session.
   *
   * Web applications typically use sessions to maintain login state between
   * requests.  For example, a user will authenticate by entering credentials into
   * a form which is submitted to the server.  If the credentials are valid, a
   * login session is established by setting a cookie containing a session
   * identifier in the user's web browser.  The web browser will send this cookie
   * in subsequent requests to the server, allowing a session to be maintained.
   *
   * If sessions are being utilized, and a login session has been established,
   * this middleware will populate `req.user` with the current user.
   *
   * Note that sessions are not strictly required for Passport to operate.
   * However, as a general rule, most web applications will make use of sessions.
   * An exception to this rule would be an API server, which expects each HTTP
   * request to provide credentials in an Authorization header.
   *
   * Examples:
   *
   *     app.use(connect.cookieParser());
   *     app.use(connect.session({ secret: 'keyboard cat' }));
   *     app.use(passport.initialize());
   *     app.use(passport.session());
   *
   * Options:
   *   - `pauseStream`      Pause the request stream before deserializing the user
   *                        object from the session.  Defaults to _false_.  Should
   *                        be set to true in cases where middleware consuming the
   *                        request body is configured after passport and the
   *                        deserializeUser method is asynchronous.
   *
   * @param {Object} options
   * @return {Function} middleware
   * @api public
   */
  session(options: AuthenticateOptions) {
    return this.authenticate('session', options);
  }

  /**
   * Registers a function used to serialize user objects into the session.
   *
   * Examples:
   *
   *     passport.serializeUser(function(user, done) {
   *       done(null, user.id);
   *     });
   *
   * @api public
   */
  serializeUser(
    fn: SerializeUser | User,
    req?: PassportRequest | SerializeUserCallback,
    done?: SerializeUserCallback,
  ) {
    if (typeof fn === 'function') {
      return this._serializers.push(fn as SerializeUser);
    }

    // private implementation that traverses the chain of serializers, attempting
    // to serialize a user
    let user = fn;

    // For backwards compatibility
    if (typeof req === 'function') {
      done = req;
      req = undefined;
    }

    let stack = this._serializers;

    function pass(i: number, err?: Error | 'pass', obj?: SerializedUser) {
      // serializers use 'pass' as an error to skip processing
      if ('pass' === err) {
        err = undefined;
      }
      // an error or serialized object was obtained, done
      if (err || obj || obj === 0) {
        return done!(err, obj);
      }

      let layer = stack[i];
      if (!layer) {
        return done!(new Error('Failed to serialize user into session'));
      }

      function serialized(e?: Error | 'pass', o?: SerializeUser) {
        pass(i + 1, e, o);
      }

      try {
        let arity = layer.length;
        if (arity == 3) {
          layer(user, req as PassportRequest, serialized);
        } else {
          layer(user, serialized);
        }
      } catch (e) {
        return done!(e as Error);
      }
    }

    pass(0);
  }

  /**
   * Registers a function used to deserialize user objects out of the session.
   *
   * Examples:
   *
   *     passport.deserializeUser(function(id, done) {
   *       User.findById(id, function (err, user) {
   *         done(err, user);
   *       });
   *     });
   *
   * @api public
   */
  deserializeUser(
    fn?: DeserializeUser<PassportRequest> | SerializedUser,
    req?: PassportRequest | DeserializeUserCallback,
    done?: DeserializeUserCallback,
  ): User | undefined {
    if (typeof fn === 'function') {
      this._deserializers.push(fn);
      return;
    }

    // private implementation that traverses the chain of deserializers,
    // attempting to deserialize a user
    let obj = fn;

    // For backwards compatibility
    if (typeof req === 'function') {
      done = req;
      req = undefined;
    }

    let stack = this._deserializers;
    const pass = (i: number, err?: Error | null | 'pass', user?: User) => {
      // deserializers use 'pass' as an error to skip processing
      if ('pass' === err) {
        err = undefined;
      }
      // an error or deserialized user was obtained, done
      if (err || user) {
        return done!(err, user);
      }
      // a valid user existed when establishing the session, but that user has
      // since been removed
      if (user === null || user === false) {
        return done!(null, false);
      }

      let layer = stack[i];
      if (!layer) {
        return done!(new Error('Failed to deserialize user out of session'));
      }

      function deserialized(err?: Error | null | 'pass', user?: User) {
        pass(i + 1, err, user);
      }

      try {
        let arity = layer.length;
        if (arity == 3) {
          layer(obj, req as PassportRequest, deserialized);
        } else {
          layer(obj, deserialized);
        }
      } catch (e) {
        return done!(e as Error);
      }
    };

    pass(0);
  }

  /**
   * Registers a function used to transform auth info.
   *
   * In some circumstances authorization details are contained in authentication
   * credentials or loaded as part of verification.
   *
   * For example, when using bearer tokens for API authentication, the tokens may
   * encode (either directly or indirectly in a database), details such as scope
   * of access or the client to which the token was issued.
   *
   * Such authorization details should be enforced separately from authentication.
   * Because Passport deals only with the latter, this is the responsiblity of
   * middleware or routes further along the chain.  However, it is not optimal to
   * decode the same data or execute the same database query later.  To avoid
   * this, Passport accepts optional `info` along with the authenticated `user`
   * in a strategy's `success()` action.  This info is set at `req.authInfo`,
   * where said later middlware or routes can access it.
   *
   * Optionally, applications can register transforms to proccess this info,
   * which take effect prior to `req.authInfo` being set.  This is useful, for
   * example, when the info contains a client ID.  The transform can load the
   * client from the database and include the instance in the transformed info,
   * allowing the full set of client properties to be convieniently accessed.
   *
   * If no transforms are registered, `info` supplied by the strategy will be left
   * unmodified.
   *
   * Examples:
   *
   *     passport.transformAuthInfo(function(info, done) {
   *       Client.findById(info.clientID, function (err, client) {
   *         info.client = client;
   *         done(err, info);
   *       });
   *     });
   *
   * @api public
   */
  transformAuthInfo(
    fn: InfoTransformer | DefaultInfo,
    req?: PassportRequest,
    done?: InfoTransformerCallback,
  ) {
    if (isTransformer(fn)) {
      return this._infoTransformers.push(fn);
    }

    // private implementation that traverses the chain of transformers,
    // attempting to transform auth info
    let info = fn;

    // For backwards compatibility
    if (typeof req === 'function') {
      done = req;
      req = undefined;
    }

    let stack = this._infoTransformers;
    function pass(i: number, err?: Error | 'pass' | null, tinfo?: any) {
      // transformers use 'pass' as an error to skip processing
      if ('pass' === err) {
        err = undefined;
      }
      // an error or transformed info was obtained, done
      if (err || tinfo) {
        return done!(err, tinfo);
      }

      let layer = stack[i];
      if (!layer) {
        // if no transformers are registered (or they all pass), the default
        // behavior is to use the un-transformed info as-is
        return done!(null, info);
      }

      function transformed(e?: Error | 'pass' | null, t?: any) {
        pass(i + 1, e, t);
      }

      try {
        let arity = layer.length;
        if (arity == 1) {
          // sync
          let t = layer(info);
          transformed(null, t);
        } else if (arity == 3) {
          layer(info, req as PassportRequest, transformed);
        } else {
          layer(info, transformed);
        }
      } catch (e) {
        return done!(e as Error);
      }
    }

    pass(0);
  }

  /**
   * Return strategy with given `name`.
   */
  _strategy(name: string): Strategy {
    return this._strategies[name];
  }
}
function isTransformer<T, A>(
  fn?: T | InfoTransformer<T, A>,
): fn is InfoTransformer<T, A> {
  return typeof fn === 'function';
}
