import type {Readable} from 'node:stream';

type Data = any;
type Encoding = any;
type EventType = 'data' | 'end';
type Event = [EventType, Data, Encoding];

export function pause(req: Readable) {
  let events: Event[] = [];

  function onData(data: Data, encoding: Encoding): void {
    events.push(['data', data, encoding]);
  }

  function onEnd(data: Data, encoding: Encoding): void {
    events.push(['end', data, encoding]);
  }

  req.on('data', onData);
  req.on('end', onEnd);

  function end() {
    req.removeListener('data', onData);
    req.removeListener('end', onEnd);
  }

  function resume() {
    end();
    for (let i = 0, len = events.length; i < len; ++i) {
      req.emit.apply(req, events[i]);
    }
  }

  return {end, resume};
}
