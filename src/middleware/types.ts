import {IncomingMessageExt} from '../http/request';
import {RequestType, ResponseType} from '../interfaces/http';
import {Session} from '../interfaces/session';
import {SessionManager} from '../sessionmanager';

export interface MiddlewareFunction {
  (req: PassportRequest, res: ResponseType, next: (err?: Error) => void): void;
}

export type PassportRequest = RequestType & {
  login?: IncomingMessageExt['logIn'];
  logIn?: IncomingMessageExt['logIn'];
  logout?: IncomingMessageExt['logOut'];
  logOut?: IncomingMessageExt['logOut'];
  isAuthenticated?: IncomingMessageExt['isAuthenticated'];
  isUnauthenticated?: IncomingMessageExt['isUnauthenticated'];
  flash?: IncomingMessageExt['flash'];
  session?: Session;
  _userProperty?: string;
  _sessionManager?: SessionManager;
};
