import type {NextFetchEvent, NextRequest, NextResponse} from 'next/server';

export interface MiddlewareFunction {
  (req: NextRequest, event: NextFetchEvent): Response | NextResponse | void;
}
