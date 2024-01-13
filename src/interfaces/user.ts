import {RequestType} from './http';

export type User = {};

export type SerializedUser = any;

export interface SerializeUserCallback {
  (err?: Error, obj?: any): void;
}

export interface SerializeUser<T extends RequestType = RequestType> {
  (user: User, req?: T, cb?: SerializeUserCallback): SerializedUser;
  (user: User, cb?: SerializeUserCallback): SerializedUser;
}

export interface DeserializeUserCallback {
  (err?: Error | null, user?: User): void;
}

export interface DeserializeUser<T extends RequestType = RequestType> {
  (
    serialized: SerializedUser,
    req?: T,
    cb?: DeserializeUserCallback,
  ): User | undefined;
  (serialized: SerializedUser, cb?: DeserializeUserCallback): User | undefined;
  (
    serialized: SerializedUser,
    reqOrCb?: T | DeserializeUserCallback,
    cb?: DeserializeUserCallback,
  ): User | undefined;
}
