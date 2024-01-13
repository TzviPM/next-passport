import type {IncomingMessage, ServerResponse} from 'node:http';

export type RequestType = IncomingMessage | Request;
export type ResponseType = Response & ServerResponse;
