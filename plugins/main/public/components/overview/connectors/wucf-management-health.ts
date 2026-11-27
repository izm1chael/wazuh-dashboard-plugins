/** Read-only lab snapshot validation. Server-side authorization remains mandatory. */
export type RunObservation = {
  observed_at: number;
  completed_version: number;
  outcome: string;
  acknowledged_pages: number;
  acknowledged_events: number;
  pending: boolean;
};

export type SourceHealth = {
  instance: string;
  dataset: string;
  revision: string;
  interval: number;
  state: string;
  version: number;
  due: number;
  claim_expiry: number | null;
  status: string;
  last_run: RunObservation | null;
};

export type ManagementHealth = {
  schema_version: 1;
  environment: string;
  observed_at: number;
  delivery_boundary: 'local_spool';
  coverage: 'unknown';
  native_delivery_qualified: false;
  sources: SourceHealth[];
};

const id = /^[A-Za-z0-9_.:-]{1,128}$/;
const rev = /^[a-f0-9]{64}$/;
const states = ['draft', 'ready', 'paused', 'review', 'revoked'];
const outcomes = ['complete', 'idle', 'budget_exhausted', 'provider_error',
  'invalid_provider_page', 'delivery_unknown', 'delivery_unconfirmed'];

function exact(value: unknown, keys: string[]): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const x = value as Record<string, unknown>;
  return Object.keys(x).length === keys.length && keys.every(k => Object.prototype.hasOwnProperty.call(x, k)) ? x : null;
}

function whole(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
}

function identifier(value: unknown): value is string {
  return typeof value === 'string' && id.test(value);
}

function parseRun(value: unknown, now: number, version: number): RunObservation | null {
  const x = exact(value, ['observed_at', 'completed_version', 'outcome', 'acknowledged_pages', 'acknowledged_events', 'pending']);
  if (!x || !whole(x.observed_at, 0, now) || !whole(x.completed_version, 1, version) ||
      typeof x.outcome !== 'string' || !outcomes.includes(x.outcome) ||
      !whole(x.acknowledged_pages, 0, 100) || !whole(x.acknowledged_events, 0, x.acknowledged_pages * 100) ||
      x.pending !== ['delivery_unknown', 'delivery_unconfirmed'].includes(x.outcome)) return null;
  return x as unknown as RunObservation;
}

export function parseManagementHealth(value: unknown, environment: string): ManagementHealth | null {
  const x = exact(value, ['schema_version', 'environment', 'observed_at', 'delivery_boundary', 'coverage', 'native_delivery_qualified', 'sources']);
  if (!x || x.schema_version !== 1 || !identifier(environment) || x.environment !== environment ||
      !whole(x.observed_at, 0, Number.MAX_SAFE_INTEGER - 86400) || x.delivery_boundary !== 'local_spool' ||
      x.coverage !== 'unknown' || x.native_delivery_qualified !== false || !Array.isArray(x.sources) || x.sources.length > 128) return null;
  const now = x.observed_at;
  const seen = new Set<string>();
  let claims = 0;
  for (const item of x.sources) {
    const s = exact(item, ['instance', 'dataset', 'revision', 'interval', 'state', 'version', 'due', 'claim_expiry', 'status', 'last_run']);
    if (!s || !identifier(s.instance) || !identifier(s.dataset) || typeof s.revision !== 'string' || !rev.test(s.revision) ||
        !whole(s.interval, 60, 86400) || !whole(s.version) || !whole(s.due) ||
        typeof s.state !== 'string' || !states.includes(s.state) || (s.claim_expiry !== null && !whole(s.claim_expiry))) return null;
    const key = JSON.stringify([s.instance, s.dataset]);
    if (seen.has(key)) return null;
    seen.add(key);
    const run = s.last_run === null ? null : parseRun(s.last_run, now, s.version);
    if (s.last_run !== null && run === null) return null;
    let status: string;
    if (s.claim_expiry !== null) {
      if (++claims > 1 || s.state !== 'ready') return null;
      status = now >= s.claim_expiry ? 'expired_claim' : 'collecting';
    } else if (s.state !== 'ready') status = s.state;
    else if (!run || run.completed_version !== s.version) status = 'not_observed';
    else {
      if (!['complete', 'idle', 'budget_exhausted'].includes(run.outcome)) return null;
      status = now - s.due > s.interval ? 'overdue' : 'local_observation';
    }
    if (s.status !== status) return null;
  }
  return x as unknown as ManagementHealth;
}

export function statusLabel(status: string): string {
  const labels: Record<string, string> = {
    draft: 'Draft', ready: 'Ready', paused: 'Paused', review: 'Review required', revoked: 'Revoked',
    collecting: 'Collecting locally', expired_claim: 'Expired worker reservation', not_observed: 'Not observed',
    overdue: 'Collection overdue', local_observation: 'Local run recorded',
  };
  return Object.prototype.hasOwnProperty.call(labels, status) ? labels[status] : 'Unknown';
}
