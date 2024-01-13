import type {IncomingMessage, ServerResponse} from 'node:http';

export type RequestType = (IncomingMessage | Request) & {
  [key: string]: any;
};
export type ResponseType = (Response & ServerResponse) & {
  statusCode?: number;
  redirect(url: string): void;
  setHeader(name: string, value: any): void;
};
