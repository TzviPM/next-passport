import {authenticate} from '../middleware/authenticate';
import {initialize} from '../middleware/initialize';

/**
 * Framework support for Connect/Express.
 *
 * This module provides support for using Passport with Express.  It exposes
 * middleware that conform to the `fn(req, res, next)` signature.
 */
export function connectFramework() {
  return {
    initialize,
    authenticate,
  };
}
