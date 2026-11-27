import { Health, parseHealth } from './wucf-model';

export type SourceIdentity = {
  environment: string;
  instance: string;
  provider: string;
  dataset: string;
  revision: string;
  intervalSeconds: number;
};

export type Assessment = {
  state: 'unknown' | 'stale' | 'collection_error' | 'delivery_blocked' |
    'local_events_observed' | 'no_events_observed';
  observation: Health | null;
  nativeQualified: false;
  coverage: 'unknown';
};

const unknown = (): Assessment => ({
  state: 'unknown', observation: null, nativeQualified: false, coverage: 'unknown',
});

/**
 * Derive presentation only, never an authorization decision or WADE
 * coverage claim. A revision mismatch invalidates old health observations.
 * The supplied server scope must already be authenticated and authorized.
 */
export function assessHealth(value: unknown, source: SourceIdentity, nowMs: number): Assessment {
  if (!Number.isFinite(nowMs) || !Number.isInteger(source.intervalSeconds) ||
      source.intervalSeconds < 60 || source.intervalSeconds > 86400) return unknown();
  const row = parseHealth(value, source.environment);
  if (!row || row.instance !== source.instance || row.provider !== source.provider ||
      row.dataset !== source.dataset || row.revision !== source.revision) return unknown();
  const age = nowMs - Date.parse(row.observed_at);
  // Future observations are not silently treated as fresh.
  if (age < 0) return unknown();
  const common = { observation: row, nativeQualified: false as const, coverage: 'unknown' as const };
  if (age > Math.max(300, source.intervalSeconds * 3) * 1000) {
    return { ...common, state: 'stale' };
  }
  if (row.state === 'delivery_blocked' || row.state === 'collection_error') {
    return { ...common, state: row.state };
  }
  return { ...common, state: row.acknowledged_events > 0 ?
    'local_events_observed' : 'no_events_observed' };
}
