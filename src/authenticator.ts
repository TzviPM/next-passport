import {SessionOptions} from './interfaces/session';
import {AuthenticateOptions, Strategy} from './interfaces/strategy';
import {DeserializeUser, SerializeUser} from './interfaces/user';
import {AuthenticateCallback, authenticate} from './middleware/authenticate';
import {SessionManager} from './sessionmanager';
import {SessionStrategy} from './strategies/session';

type DefaultInfo = Object;

interface InfoTransformer<T = DefaultInfo, A = T> {
  (info: T): Promise<A>;
}

export class Authenticator<U, SU> {
  private _strategies: {
    [key: string]: Strategy<U>;
  } = {};
  private _serializers: SerializeUser<U, SU>[] = [];
  private _deserializers: DeserializeUser<U, SU>[] = [];
  private _infoTransformers: InfoTransformer[] = [];
  public _sessionManager!: SessionManager<U, SU>;

  constructor(private _sessionOptions: SessionOptions) {
    this.use(
      new SessionStrategy(
        this._sessionOptions,
        this.deserializeUser.bind(this),
      ),
    );

    this._sessionManager = new SessionManager(
      _sessionOptions,
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
  use(name: string, strategy: Strategy<U>): this;
  use(strategy: Strategy<U>): this;
  use(nameOrStrategy: Strategy<U> | string, strategy?: Strategy<U>): this {
    let name!: string;
    if (!strategy) {
      strategy = nameOrStrategy as Strategy<U>;
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
    strategy: string | string[] | Strategy<U>,
    options: AuthenticateOptions,
    callback?: AuthenticateCallback<U>,
  ) {
    return authenticate(this, strategy, options, callback);
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
  async serializeUser(fn: SerializeUser<U, SU> | U): Promise<SU | undefined> {
    if (typeof fn === 'function') {
      this._serializers.push(fn as SerializeUser<U, SU>);
      return;
    }

    // private implementation that traverses the chain of serializers, attempting
    // to serialize a user
    let user = fn;

    return new Promise((resolve, reject) => {
      const pass = (i: number, err?: Error | 'pass', obj?: SU) => {
        // serializers use 'pass' as an error to skip processing
        if ('pass' === err) {
          err = undefined;
        }

        if (err) {
          return reject(err);
        }
        if (obj || obj === 0) {
          return resolve(obj);
        }

        let layer = this._serializers[i];
        if (!layer) {
          return reject(new Error('Failed to serialize user into session'));
        }

        layer(user).then(
          o => pass(i + 1, undefined, o),
          e => pass(i + 1, e),
        );
      };

      pass(0);
    });
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
  async deserializeUser(
    fn?: DeserializeUser<U, SU> | SU,
  ): Promise<U | false | undefined> {
    if (typeof fn === 'function') {
      this._deserializers.push(fn as DeserializeUser<U, SU>);
      return;
    }

    // private implementation that traverses the chain of deserializers,
    // attempting to deserialize a user
    let obj = fn as SU;

    return new Promise((resolve, reject) => {
      const pass = (i: number, err?: Error | null | 'pass', user?: U) => {
        // deserializers use 'pass' as an error to skip processing
        if ('pass' === err) {
          err = undefined;
        }
        // an error or deserialized user was obtained, done
        if (err) {
          return reject(err);
        }
        if (user) {
          return resolve(user);
        }
        // a valid user existed when establishing the session, but that user has
        // since been removed
        if (user === null || user === false) {
          return resolve(false);
        }

        let layer = this._deserializers[i];
        if (!layer) {
          return reject(new Error('Failed to deserialize user out of session'));
        }

        layer(obj).then(
          u => pass(i + 1, null, u),
          e => pass(i + 1, e),
        );
      };

      pass(0);
    });
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
  async transformAuthInfo(fn: InfoTransformer | DefaultInfo): Promise<any> {
    if (isTransformer(fn)) {
      this._infoTransformers.push(fn);
      return;
    }

    // private implementation that traverses the chain of transformers,
    // attempting to transform auth info
    let info = fn;

    return new Promise((resolve, reject) => {
      const pass = (
        i: number,
        err?: Error | 'pass' | null,
        tinfo?: DefaultInfo,
      ) => {
        // transformers use 'pass' as an error to skip processing
        if ('pass' === err) {
          err = undefined;
        }
        // an error or transformed info was obtained, done
        if (err) {
          return reject(err);
        }
        if (tinfo) {
          return resolve(tinfo);
        }

        let layer = this._infoTransformers[i];
        if (!layer) {
          // if no transformers are registered (or they all pass), the default
          // behavior is to use the un-transformed info as-is
          return resolve(info);
        }

        layer(info).then(
          ti => pass(i + 1, null, ti),
          e => pass(i + 1, e),
        );
      };

      pass(0);
    });
  }

  /**
   * Return strategy with given `name`.
   */
  _strategy(name: string): Strategy<U> {
    return this._strategies[name];
  }
}

function isTransformer<T, A>(
  fn?: T | InfoTransformer<T, A>,
): fn is InfoTransformer<T, A> {
  return typeof fn === 'function';
}
