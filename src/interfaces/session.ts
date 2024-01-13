export interface SessionOptions {
  secret: string;
  cookieName?: string;
}

export enum FlashType {
  ERROR = 'error',
  SUCCESS = 'success',
  INFO = 'info',
}

export interface SessionData<SU> {
  user?: SU;
  flash?: {
    [FlashType.ERROR]?: string;
    [FlashType.SUCCESS]?: string;
    [FlashType.INFO]?: string;
  };
  messages?: string[];
  returnTo?: string;
}
