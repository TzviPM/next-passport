import {FlashType, SessionOptions} from './interfaces/session';
import {SerializeUser} from './interfaces/user';
import {getSession} from './utils/session';

export class SessionManager<U, SU> {
  constructor(
    private _sessionOptions: SessionOptions,
    private _serializeUser?: SerializeUser<U, SU>,
  ) {}

  async getSession() {
    return getSession<SU>(this._sessionOptions);
  }

  async logIn(user: U): Promise<void> {
    const session = await this.getSession();
    const userDto = await this._serializeUser?.(user);
    session.user = userDto;
    await session.save();
  }

  async logOut(): Promise<void> {
    const session = await this.getSession();

    // clear the user from the session object and save.
    // this will ensure that re-using the old session id
    // does not have a logged in user
    delete session.user;
    await session.save();

    // destroy the session
    session.destroy();
  }

  async setFlash(name: FlashType, message: string): Promise<void> {
    const session = await this.getSession();
    session.flash ??= {};
    session.flash[name] = message;
    await session.save();
  }

  async getFlash(name: FlashType): Promise<string | undefined> {
    const session = await this.getSession();
    return session.flash?.[name];
  }

  async setMessage(message: string): Promise<void> {
    const session = await this.getSession();
    session.messages ??= [];
    session.messages.push(message);
    await session.save();
  }

  async getMessages(): Promise<string[]> {
    const session = await this.getSession();
    return session.messages ?? [];
  }

  async isAuthenticated(): Promise<boolean> {
    return !(await this.isUnauthenticated());
  }

  async isUnauthenticated(): Promise<boolean> {
    const session = await this.getSession();
    return session.user === undefined;
  }

  async pluckReturnTo(): Promise<string | undefined> {
    const session = await this.getSession();
    const returnTo = session.returnTo;
    delete session.returnTo;
    await session.save();
    return returnTo;
  }
}
