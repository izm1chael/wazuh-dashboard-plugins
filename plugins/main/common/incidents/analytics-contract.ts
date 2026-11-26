export interface AnalyticsWindowQuery { policy_id: string; policy_version: number; from: string; until: string }
export type AnalyticsStatus = AnalyticsWindowQuery & { run_id: string } & (
  { state: 'not_recorded' } |
  { state: 'reserved' | 'completed'; finding_count: number; group_count: number; below_threshold: number;
    actor: string; reserved_at: string; completed_at: string | null }
);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DAY = 86400000;
const fail = (): never => { throw new Error('Invalid analytics window or receipt'); };
function time(value: unknown, fractional = false): number {
  if (typeof value !== 'string' || !(fractional ?
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/ :
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/).test(value)) return fail();
  const at = Date.parse(value);
  if (!Number.isFinite(at) || new Date(at).toISOString().slice(0, 19) !== value.slice(0, 19) ||
      at < Date.UTC(2000, 0, 1) || at > Date.UTC(2100, 0, 1)) return fail();
  return at;
}
function integer(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}
function exact(obj: object, keys: string[]): boolean {
  return Object.keys(obj).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(obj, key));
}
export function validateWindow(input: AnalyticsWindowQuery): AnalyticsWindowQuery {
  if (!input || !exact(input, ['policy_id', 'policy_version', 'from', 'until']) ||
      typeof input.policy_id !== 'string' || !UUID.test(input.policy_id) || !integer(input.policy_version, 1, 2147483647)) return fail();
  const from = time(input.from), until = time(input.until);
  if (from >= until || until - from > DAY) return fail();
  return { policy_id: input.policy_id, policy_version: input.policy_version, from: input.from, until: input.until };
}
export function validateAnalyticsStatus(status: AnalyticsStatus, query: AnalyticsWindowQuery): AnalyticsStatus {
  if (!status || typeof status.run_id !== 'string' || !/^[a-f0-9]{64}$/.test(status.run_id) ||
      status.policy_id !== query.policy_id || status.policy_version !== query.policy_version ||
      status.from !== query.from || status.until !== query.until) return fail();
  const keys = ['run_id', 'policy_id', 'policy_version', 'from', 'until', 'state'];
  if (status.state === 'not_recorded') {
    if (!exact(status, keys)) return fail();
    return status;
  }
  if ((status.state !== 'reserved' && status.state !== 'completed') ||
      !exact(status, [...keys, 'finding_count', 'group_count', 'below_threshold', 'actor', 'reserved_at', 'completed_at']) ||
      !integer(status.finding_count, 0, 100) || !integer(status.group_count, 0, 20) ||
      !integer(status.below_threshold, 0, status.finding_count) ||
      status.group_count * 2 > status.finding_count - status.below_threshold ||
      (status.group_count === 0) !== (status.finding_count === status.below_threshold) ||
      typeof status.actor !== 'string' || !status.actor.trim() || status.actor.length > 1024 ||
      /[\x00-\x1f\x7f-\x9f]/.test(status.actor)) return fail();
  const reserved = time(status.reserved_at, true);
  if (reserved < time(query.until) || (status.state === 'reserved' && status.completed_at !== null) ||
      (status.state === 'completed' && (status.completed_at === null || time(status.completed_at, true) < reserved))) return fail();
  return status;
}
/** Explicit operator-supplied schedule. Missing receipts do not prove a policy was enabled. */
export function healthWindows(policy: string, version: number, minutes: number, until: string, count: number): AnalyticsWindowQuery[] {
  if (!integer(minutes, 5, 1440) || !integer(count, 1, 10)) return fail();
  const end = time(until), size = minutes * 60000;
  if (end % size !== 0) return fail();
  const iso = (at: number) => new Date(at).toISOString().replace('.000Z', 'Z');
  return Array.from({ length: count }, (_, i) => validateWindow({ policy_id: policy, policy_version: version,
    from: iso(end - (i + 1) * size), until: iso(end - i * size) }));
}
export function latestSettledWindow(minutes: number, now: number): string {
  if (!integer(minutes, 5, 1440) || !Number.isFinite(now)) return fail();
  const size = minutes * 60000;
  return new Date(Math.floor((now - 120000) / size) * size).toISOString().replace('.000Z', 'Z');
}
