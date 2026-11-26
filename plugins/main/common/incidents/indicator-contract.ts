import { HuntField, validHuntValue } from './hunt-contract';
import type { Tlp } from './contracts';

export const INDICATOR_TYPES = ['ipv4', 'domain', 'md5', 'sha1', 'sha256'] as const;
export const INDICATOR_TLP = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'] as const;
export type IndicatorType = typeof INDICATOR_TYPES[number];
export type IndicatorState = 'active' | 'pending' | 'expired' | 'revoked';
export interface IndicatorInput {
  type: IndicatorType; value: string; source: string; external_id: string | null; confidence: number; tlp: Tlp;
  valid_from: string; valid_until: string;
}
export interface Indicator extends IndicatorInput {
  id: string; created_by: string; created_at: string; created_revision: number;
  revoked_by: string | null; revoked_at: string | null; revoked_revision: number | null; revocation_reason: string | null;
  state: IndicatorState;
}
export interface IndicatorCatalog { revision: number; observed_at: string; indicators: Indicator[] }
export interface CatalogMutation { revision: number; changed: number }
export const MAX_INDICATORS = 200, MAX_IMPORT = 20;
const DAY = 86400000;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STIX_ID = /^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const inputKeys = ['type', 'value', 'source', 'external_id', 'confidence', 'tlp', 'valid_from', 'valid_until'];
const outputKeys = [...inputKeys, 'id', 'created_by', 'created_at', 'created_revision', 'revoked_by', 'revoked_at', 'revoked_revision', 'revocation_reason', 'state'];
const fail = (): never => { throw new Error('Invalid indicator catalog data'); };
export const safeText = (value: unknown, max: number): value is string =>
  typeof value === 'string' && !!value.trim() && value === value.trim() && value.length <= max && !/[\x00-\x1f\x7f-\x9f]/.test(value);
const exact = (obj: object, keys: string[]) => Object.keys(obj).length === keys.length && keys.every(k => Object.prototype.hasOwnProperty.call(obj, k));
export function timestamp(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value)) return fail();
  const at = Date.parse(value);
  if (!Number.isFinite(at) || new Date(at).toISOString().slice(0, 19) !== value.slice(0, 19) ||
      at < Date.UTC(2000, 0, 1) || at > Date.UTC(2100, 0, 1)) return fail();
  return at;
}
export function huntFields(type: IndicatorType): HuntField[] {
  switch (type) {
    case 'ipv4': return ['source.ip', 'destination.ip', 'host.ip'];
    case 'domain': return ['dns.question.name'];
    case 'md5': return ['file.hash.md5'];
    case 'sha1': return ['file.hash.sha1'];
    case 'sha256': return ['file.hash.sha256'];
  }
}
export function canonicalValue(type: IndicatorType, value: unknown): string {
  if (!safeText(value, 253)) return fail();
  if (type === 'domain') {
    const lower = value.toLowerCase();
    if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(lower) ||
        /^[0-9.]+$/.test(lower)) return fail();
    return lower;
  }
  const field = huntFields(type)?.[0];
  if (!field || !validHuntValue(field, value)) return fail();
  return value.toLowerCase();
}
export function validateIndicator(input: IndicatorInput): IndicatorInput {
  if (!input || !exact(input, inputKeys) || !INDICATOR_TYPES.includes(input.type) || !safeText(input.source, 256) ||
      (input.external_id !== null && (typeof input.external_id !== 'string' || !STIX_ID.test(input.external_id))) ||
      !Number.isInteger(input.confidence) || input.confidence < 0 || input.confidence > 100 || !INDICATOR_TLP.includes(input.tlp)) return fail();
  const start = timestamp(input.valid_from), end = timestamp(input.valid_until);
  if (start >= end || end - start > 366 * DAY) return fail();
  return { type: input.type, value: canonicalValue(input.type, input.value), source: input.source,
    external_id: input.external_id, confidence: input.confidence, tlp: input.tlp, valid_from: input.valid_from, valid_until: input.valid_until };
}
export function validateBatch(items: IndicatorInput[]): IndicatorInput[] {
  if (!Array.isArray(items) || !items.length || items.length > MAX_IMPORT) return fail();
  const validated = items.map(validateIndicator);
  const ids = validated.filter(row => row.external_id !== null).map(row => row.external_id);
  if (new Set(validated.map(row => row.type + ':' + row.value)).size !== validated.length || new Set(ids).size !== ids.length) return fail();
  return validated;
}
const revision = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 2147483647;
export function validateCatalog(body: IndicatorCatalog): IndicatorCatalog {
  if (!body || !exact(body, ['revision', 'observed_at', 'indicators']) || !revision(body.revision) ||
      !Array.isArray(body.indicators) || body.indicators.length > MAX_INDICATORS || (body.revision === 0) !== !body.indicators.length) return fail();
  const now = timestamp(body.observed_at), ids = new Set<string>(), external = new Set<string>(), previous = new Map<string, Indicator>();
  for (const row of body.indicators) {
    if (!row || !exact(row, outputKeys) || typeof row.id !== 'string' || !UUID.test(row.id) || ids.has(row.id) ||
        !safeText(row.created_by, 1024) || !revision(row.created_revision) || row.created_revision < 1 || row.created_revision > body.revision) return fail();
    const input = validateIndicator({ type: row.type, value: row.value, source: row.source, external_id: row.external_id,
      confidence: row.confidence, tlp: row.tlp, valid_from: row.valid_from, valid_until: row.valid_until });
    if (input.value !== row.value || (row.external_id !== null && external.has(row.external_id))) return fail();
    const created = timestamp(row.created_at), key = row.type + ':' + row.value;
    const prior = previous.get(key);
    if (prior && (created < timestamp(prior.created_at) ||
        (created < timestamp(prior.valid_until) && (prior.revoked_at === null || created < timestamp(prior.revoked_at))))) return fail();
    if (row.revoked_at === null) {
      if (row.revoked_by !== null || row.revoked_revision !== null || row.revocation_reason !== null) return fail();
    } else {
      if (timestamp(row.revoked_at) < created || !safeText(row.revoked_by, 1024) || !safeText(row.revocation_reason, 1024) ||
          !revision(row.revoked_revision) || row.revoked_revision <= row.created_revision || row.revoked_revision > body.revision) return fail();
    }
    const expected = row.revoked_at !== null ? 'revoked' : now >= timestamp(row.valid_until) ? 'expired' :
      now < timestamp(row.valid_from) ? 'pending' : 'active';
    if (row.state !== expected) return fail();
    ids.add(row.id); previous.set(key, row); if (row.external_id !== null) external.add(row.external_id);
  }
  return body;
}
export function validateMutation(body: CatalogMutation, expected: number, changed: number): CatalogMutation {
  if (!body || !exact(body, ['revision', 'changed']) || !revision(expected) || body.revision !== expected + 1 ||
      !revision(body.revision) || body.changed !== changed || !Number.isInteger(changed) || changed < 1 || changed > MAX_IMPORT) return fail();
  return body;
}
