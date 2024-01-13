import {RequestType} from './http';

export interface SessionOptions {
  key?: string;
}

export type Session = any;

export type ManagedRequest = RequestType & {
  session?: Session;
};

export interface LoginOptions {
  session?: boolean;
  keepSessionInfo?: boolean;
}
