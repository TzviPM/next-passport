import {cookies} from 'next/headers';
import {SessionData, SessionOptions} from '../interfaces/session';
import {IronSession, getIronSession} from 'iron-session';

export const DEFAULT_COOKIE_NAME = 'session';

export async function getSession<SU>(
  options: SessionOptions,
): Promise<IronSession<SessionData<SU>>> {
  return getIronSession(cookies(), {
    password: options.secret,
    cookieName: options.cookieName ?? DEFAULT_COOKIE_NAME,
  });
}
