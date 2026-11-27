/** Read-only projection of core Management.health_snapshot v1.
 * Authenticated server must enforce the environment scope before returning it.
 */
export type LastRun = {
  observed_at: number;
  completed_version: number;
  outcome: string;
  acknowledged_pages: number;
  acknowledged_events: number;
  pending: boolean;
};

export type ScheduledSource = {
  instance: string;
  dataset: string;
  revision: string;
  interval: number;
  state: 'draft' | 'ready' | 'paused' | 'review' | 'revoked';
  version: number;
  due: number;
  claim_expiry: number | null;
  status: string;
  last_run: LastRun | null;
};

export type SchedulerSnapshot = {
  schema_version: 1;
  environment: string;
  observed_at: number;
  delivery_boundary: 'local_spool';
  coverage: 'unknown';
  native_delivery_qualified: false;
  sources: ScheduledSource[];
};

const ident = /^[A-Za-z0-9_.:-]{1,128}$/;
const sha = /^[a-f0-9]{64}$/;
const states = ['draft', 'ready', 'paused', 'review', 'revoked'];
const outcomes = ['complete', 'idle', 'budget_exhausted', 'provider_error',
  'invalid_provider_page', 'delivery_unknown', 'delivery_unconfirmed'];

function shape(value: unknown, keys: string[]): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

function int(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}

function parseRun(value: unknown, version: number, now: number): LastRun | null {
  if (!shape(value, ['observed_at', 'completed_version', 'outcome', 'acknowledged_pages',
    'acknowledged_events', 'pending'])) return null;
  if (!int(value.observed_at, 0, now) || !int(value.completed_version, 0, version) ||
      !int(value.acknowledged_pages, 0, 100) ||
      !int(value.acknowledged_events, 0, value.acknowledged_pages * 100) ||
      typeof value.outcome !== 'string' || !outcomes.includes(value.outcome) ||
      value.pending !== ['delivery_unknown', 'delivery_unconfirmed'].includes(value.outcome)) return null;
  return value as LastRun;
}

export function parseSchedulerSnapshot(value: unknown, environment: string): SchedulerSnapshot | null {
  if (!shape(value, ['schema_version', 'environment', 'observed_at', 'delivery_boundary',
    'coverage', 'native_delivery_qualified', 'sources']) ||
      value.schema_version !== 1 || value.environment !== environment || !ident.test(environment) ||
      value.delivery_boundary !== 'local_spool' || value.coverage !== 'unknown' ||
      value.native_delivery_qualified !== false || !int(value.observed_at) ||
      !Array.isArray(value.sources) || value.sources.length > 128) return null;
  const now = value.observed_at;
  const seen = new Set<string>();
  for (const candidate of value.sources) {
    if (!shape(candidate, ['instance', 'dataset', 'revision', 'interval', 'state',
      'version', 'due', 'claim_expiry', 'status', 'last_run'])) return null;
    const row = candidate;
    if (typeof row.instance !== 'string' || !ident.test(row.instance) ||
        typeof row.dataset !== 'string' || !ident.test(row.dataset) ||
        typeof row.revision !== 'string' || !sha.test(row.revision) ||
        !int(row.interval, 60, 86400) || !int(row.version) || !int(row.due) ||
        typeof row.state !== 'string' || !states.includes(row.state) ||
        (row.claim_expiry !== null && !int(row.claim_expiry))) return null;
    const key = JSON.stringify([row.instance, row.dataset]);
    if (seen.has(key)) return null;
    seen.add(key);
    const run = row.last_run === null ? null : parseRun(row.last_run, row.version, now);
    if (row.last_run !== null && !run) return null;
    let expected: string;
    if (row.claim_expiry !== null) {
      if (row.state !== 'ready') return null;
      expected = now >= row.claim_expiry ? 'expired_claim' : 'collecting';
    } else if (row.state !== 'ready') {
      expected = row.state;
    } else if (!run || run.completed_version !== row.version) {
      expected = 'not_observed';
    } else {
      expected = now - row.due > row.interval ? 'overdue' : 'local_observation';
    }
    if (row.status !== expected) return null;
  }
  return value as SchedulerSnapshot;
}
