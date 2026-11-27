/**
 * WUCF read-only onboarding candidate. No server route or authorization claim.
 * Data must arrive from an authenticated, scope-authorizing server.
 */
export type Dataset = {
  provider: string;
  dataset: string;
  label: string;
  credentialKind: string;
  permissions: readonly string[];
};

export const catalogue: readonly Dataset[] = [
  { provider: 'entra', dataset: 'signins', label: 'Entra sign-ins', credentialKind: 'OAuth client', permissions: ['AuditLog.Read.All'] },
  { provider: 'entra', dataset: 'directory_audit', label: 'Entra directory audit', credentialKind: 'OAuth client', permissions: ['AuditLog.Read.All'] },
  { provider: 'm365', dataset: 'audit', label: 'Microsoft 365 audit', credentialKind: 'OAuth client', permissions: ['ActivityFeed.Read'] },
  { provider: 'azure', dataset: 'activity', label: 'Azure Activity', credentialKind: 'OAuth client', permissions: ['Monitoring Reader (scope review required)'] },
  { provider: 'aws', dataset: 'cloudtrail', label: 'AWS CloudTrail', credentialKind: 'AWS role', permissions: ['s3:GetObject', 'sqs:ReceiveMessage', 'sqs:DeleteMessage'] },
  { provider: 'google_workspace', dataset: 'audit', label: 'Google Workspace audit', credentialKind: 'Delegated Google identity', permissions: ['admin.reports.audit.readonly (full scope required)'] },
];

export function findDatasets(search: string): readonly Dataset[] {
  const term = search.trim().toLowerCase().slice(0, 128);
  return catalogue.filter(item =>
    [item.provider, item.dataset, item.label].some(value => value.toLowerCase().includes(term)),
  );
}

export type Preview = {
  provider: string;
  dataset: string;
  interval_seconds: number;
  activation_supported: false;
};

export function preview(dataset: Dataset, interval: string): Preview | null {
  if (!catalogue.some(item => item.provider === dataset.provider && item.dataset === dataset.dataset)) return null;
  if (!/^[0-9]{1,5}$/.test(interval)) return null;
  const seconds = Number(interval);
  if (seconds < 60 || seconds > 86400) return null;
  return { provider: dataset.provider, dataset: dataset.dataset, interval_seconds: seconds, activation_supported: false };
}

export type Health = {
  schema_version: 1;
  environment: string;
  instance: string;
  dataset: string;
  provider: string;
  revision: string;
  observed_at: string;
  state: string;
  execution_status: string;
  acknowledged_pages: number;
  acknowledged_events: number;
  pending: boolean;
  delivery_boundary: 'unqualified_adapter' | 'local_spool';
  coverage: 'unknown';
  native_delivery_qualified: false;
};

const fields = [
  'schema_version', 'environment', 'instance', 'dataset', 'provider', 'revision',
  'observed_at', 'state', 'execution_status', 'acknowledged_pages',
  'acknowledged_events', 'pending', 'delivery_boundary', 'coverage', 'native_delivery_qualified',
];
const id = /^[A-Za-z0-9_.:-]{1,128}$/;
const statuses = [
  'complete', 'idle', 'budget_exhausted', 'provider_error',
  'invalid_provider_page', 'delivery_unknown', 'delivery_unconfirmed',
];

export function parseHealth(value: unknown, environment: string): Health | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (Object.keys(row).length !== fields.length || fields.some(key => !Object.prototype.hasOwnProperty.call(row, key))) return null;
  if (row.schema_version !== 1 || row.environment !== environment || row.coverage !== 'unknown' || row.native_delivery_qualified !== false) return null;
  for (const key of ['environment', 'instance', 'dataset', 'provider']) {
    if (typeof row[key] !== 'string' || !id.test(row[key] as string)) return null;
  }
  if (row.delivery_boundary !== 'unqualified_adapter' && row.delivery_boundary !== 'local_spool') return null;
  if (!catalogue.some(item => item.provider === row.provider && item.dataset === row.dataset)) return null;
  if (typeof row.revision !== 'string' || !/^[a-f0-9]{64}$/.test(row.revision)) return null;
  if (typeof row.observed_at !== 'string' || row.observed_at.length > 40 || !/(Z|[+-]00:00)$/.test(row.observed_at) || !Number.isFinite(Date.parse(row.observed_at))) return null;
  if (typeof row.execution_status !== 'string' || !statuses.includes(row.execution_status)) return null;
  const pages = row.acknowledged_pages;
  const events = row.acknowledged_events;
  if (typeof pages !== 'number' || !Number.isInteger(pages) || pages < 0 || pages > 100 ||
      typeof events !== 'number' || !Number.isInteger(events) || events < 0 || events > pages * 100) return null;
  const blocked = ['delivery_unknown', 'delivery_unconfirmed'].includes(row.execution_status);
  const error = ['provider_error', 'invalid_provider_page'].includes(row.execution_status);
  const state = blocked ? 'delivery_blocked' : error ? 'collection_error' : events ? 'events_acknowledged' : 'no_events_observed';
  if (row.pending !== blocked || row.state !== state) return null;
  // All returned keys are allowlisted; unknown fields including secrets fail.
  return row as Health;
}
