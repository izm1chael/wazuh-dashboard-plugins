import { EVIDENCE_TYPES, RELATION_TYPES, CollaborationPage } from './contracts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const TAG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const text = (value: unknown, max: number): value is string =>
  typeof value === 'string' && value.length <= max && !!value.trim() && !/[\x00-\x1f\x7f-\x9f]/.test(value);
const date = (value: unknown): value is string => text(value, 64) && Number.isFinite(Date.parse(value));
const fail = (): never => { throw new Error('Invalid investigation register projection'); };
const exact = (row: object, keys: string[]) =>
  Object.keys(row).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(row, key));

export function validateTags(raw: unknown): string[] {
  if (!Array.isArray(raw) || raw.length > 25 || raw.some(tag => typeof tag !== 'string' || !TAG.test(tag)) ||
      new Set(raw).size !== raw.length) return fail();
  return [...raw].sort();
}

function validId(value: unknown, incident: string, revision: number): boolean {
  if (!text(value, 64) || !value.startsWith(incident + ':')) return false;
  const n = Number(value.slice(incident.length + 1));
  return Number.isSafeInteger(n) && n > 0 && n <= revision && value === incident + ':' + n;
}

/** Both fields are absent on older indexers. A partial or malformed projection is not accepted. */
export function validateInvestigationRegister(page: CollaborationPage, incident: string): void {
  if (page.incident_relations === undefined && page.evidence_register === undefined) return;
  const relations = page.incident_relations, evidence = page.evidence_register;
  if (!Array.isArray(relations) || relations.length > 50 || !Array.isArray(evidence) || evidence.length > 50) return fail();
  const ids = new Set<string>(), targets = new Set<string>(), identities = new Set<string>();
  for (const row of relations) {
    if (!row || !exact(row, ['id', 'target_id', 'type', 'reason', 'recorded_by', 'recorded_at']) ||
        !validId(row.id, incident, page.observed_revision) || ids.has(row.id) ||
        typeof row.target_id !== 'string' || !UUID.test(row.target_id) || row.target_id === incident || targets.has(row.target_id) ||
        !RELATION_TYPES.includes(row.type) || !text(row.reason, 1024) || !text(row.recorded_by, 1024) || !date(row.recorded_at)) return fail();
    ids.add(row.id); targets.add(row.target_id);
  }
  for (const row of evidence) {
    if (!row || !exact(row, ['id', 'type', 'label', 'sha256', 'custody_reference', 'recorded_by', 'recorded_at',
        'origin', 'state', 'withdrawn_by', 'withdrawn_at', 'withdrawal_reason']) ||
        !validId(row.id, incident, page.observed_revision) || ids.has(row.id) || !EVIDENCE_TYPES.includes(row.type) ||
        typeof row.sha256 !== 'string' || !SHA256.test(row.sha256) || !text(row.label, 256) || !text(row.custody_reference, 256) ||
        !text(row.recorded_by, 1024) || !date(row.recorded_at) || row.origin !== 'analyst_attested_external_artifact') return fail();
    const identity = JSON.stringify([row.sha256, row.custody_reference]);
    if (identities.has(identity)) return fail();
    ids.add(row.id); identities.add(identity);
    if (row.state === 'recorded') {
      if (row.withdrawn_by !== null || row.withdrawn_at !== null || row.withdrawal_reason !== null) return fail();
    } else if (row.state === 'withdrawn') {
      if (!text(row.withdrawn_by, 1024) || !date(row.withdrawn_at) ||
          Date.parse(row.withdrawn_at) < Date.parse(row.recorded_at) || !text(row.withdrawal_reason, 1024)) return fail();
    } else return fail();
  }
}
