// Freeze "now" for the verifier: Date() with no args, Date.now()
export function freezeDate(unixSeconds) {
  if (unixSeconds === undefined || unixSeconds === null) return;
  const frozenMs = Number(unixSeconds) * 1000;
  const RealDate = Date;
  class FrozenDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) { super(frozenMs); } else { super(...args); }
    }
    static now() { return frozenMs; }
  }
  globalThis.Date = FrozenDate;
}
