import { Indicator, IndicatorInput, IndicatorType, MAX_IMPORT, UUID, timestamp, validateBatch, validateIndicator } from './indicator-contract';
import type { Tlp } from './contracts';

/** Narrow STIX 2.1 Indicator subset. No marking, extension, relationship or complex-pattern downgrade. */
const PATTERN: Record<IndicatorType, string> = {
  ipv4: 'ipv4-addr:value', domain: 'domain-name:value', md5: 'file:hashes.MD5',
  sha1: "file:hashes.'SHA-1'", sha256: "file:hashes.'SHA-256'",
};
const ALLOWED = new Set(['type', 'spec_version', 'id', 'created', 'modified', 'pattern', 'pattern_type',
  'pattern_version', 'valid_from', 'valid_until', 'confidence', 'revoked', 'name', 'description', 'labels', 'indicator_types']);
const fail = (): never => { throw new Error('Unsupported or malformed STIX indicator bundle'); };
type Obj = Record<string, unknown>;
function object(value: unknown): Obj {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
  return value as Obj;
}

/** JSON.parse validates syntax; scan its source as well because it silently accepts duplicate keys. */
function parseUnique(raw: string): unknown {
  if (typeof raw !== 'string' || raw.length > 65536) return fail();
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch (_) { return fail(); }
  let pos = 0, nodes = 0;
  const skip = () => { while (pos < raw.length && /\s/.test(raw[pos])) pos++; };
  function str(): string {
    const token = /"(?:[^"\\]|\\.)*"/y;
    token.lastIndex = pos;
    const match = token.exec(raw);
    if (!match) return fail();
    pos = token.lastIndex;
    return JSON.parse(match[0]) as string;
  }
  function walk(depth: number) {
    if (depth > 16 || ++nodes > 4096) return fail();
    skip();
    if (raw[pos] === '{') {
      pos++; skip(); const keys = new Set<string>();
      if (raw[pos] === '}') { pos++; return; }
      while (true) {
        skip(); const key = str();
        if (keys.has(key)) return fail();
        keys.add(key); skip(); if (raw[pos++] !== ':') return fail();
        walk(depth + 1); skip();
        if (raw[pos] === '}') { pos++; return; }
        if (raw[pos++] !== ',') return fail();
      }
    } else if (raw[pos] === '[') {
      pos++; skip(); if (raw[pos] === ']') { pos++; return; }
      while (true) {
        walk(depth + 1); skip();
        if (raw[pos] === ']') { pos++; return; }
        if (raw[pos++] !== ',') return fail();
      }
    } else if (raw[pos] === '"') str();
    else { while (pos < raw.length && !/[\s,\]}]/.test(raw[pos])) pos++; }
  }
  walk(0); skip(); if (pos !== raw.length) return fail();
  return parsed;
}
function parsePattern(pattern: unknown): { type: IndicatorType; value: string } {
  if (typeof pattern !== 'string' || pattern.length > 512) return fail();
  const match = /^\[\s*(ipv4-addr:value|domain-name:value|file:hashes\.(?:MD5|'MD5'|'SHA-1'|'SHA-256'))\s*=\s*'([a-zA-Z0-9.-]+)'\s*\]$/.exec(pattern);
  if (!match) return fail();
  const path = match[1] === "file:hashes.'MD5'" ? PATTERN.md5 : match[1];
  const type = (Object.keys(PATTERN) as IndicatorType[]).find(key => PATTERN[key] === path);
  if (!type) return fail();
  return { type, value: match[2] };
}
export function importStix(raw: string, source: string, tlp: Tlp): IndicatorInput[] {
  const bundle = object(parseUnique(raw));
  if (Object.keys(bundle).length !== 3 || bundle.type !== 'bundle' ||
      typeof bundle.id !== 'string' || !bundle.id.startsWith('bundle--') || !UUID.test(bundle.id.slice(8)) ||
      !Array.isArray(bundle.objects) || !bundle.objects.length || bundle.objects.length > MAX_IMPORT) return fail();
  return validateBatch(bundle.objects.map(value => {
    const row = object(value);
    if (Object.keys(row).some(key => !ALLOWED.has(key)) || row.type !== 'indicator' || row.spec_version !== '2.1' ||
        row.pattern_type !== 'stix' || (row.pattern_version !== undefined && row.pattern_version !== '2.1') ||
        (row.revoked !== undefined && row.revoked !== false) || typeof row.id !== 'string' || !row.id.startsWith('indicator--') ||
        !UUID.test(row.id.slice(11)) || timestamp(row.modified) < timestamp(row.created)) return fail();
    for (const field of ['name', 'description']) if (row[field] !== undefined && typeof row[field] !== 'string') return fail();
    for (const field of ['labels', 'indicator_types']) {
      const v = row[field];
      if (v !== undefined && (!Array.isArray(v) || v.some(item => typeof item !== 'string'))) return fail();
    }
    const pattern = parsePattern(row.pattern);
    return validateIndicator({ ...pattern, source, tlp, external_id: row.id, confidence: row.confidence as number,
      valid_from: row.valid_from as string, valid_until: row.valid_until as string });
  }));
}

/** Local export only. The UI does not send the bundle anywhere; read permission is still the actual access boundary. */
export function exportStix(rows: Indicator[], bundleId: string, observedAt: string) {
  const now = timestamp(observedAt);
  if (!UUID.test(bundleId) || !rows.length || rows.length > MAX_IMPORT || new Set(rows.map(row => row.id)).size !== rows.length) return fail();
  const objects = rows.map(row => {
    const definition = validateIndicator({ type: row.type, value: row.value, source: row.source, external_id: row.external_id,
      confidence: row.confidence, tlp: row.tlp, valid_from: row.valid_from, valid_until: row.valid_until });
    if (!UUID.test(row.id) || row.tlp !== 'TLP:CLEAR' || row.state !== 'active' || row.revoked_at !== null ||
        now < timestamp(row.valid_from) || now >= timestamp(row.valid_until)) return fail();
    const created = new Date(timestamp(row.created_at)).toISOString();
    return { type: 'indicator', spec_version: '2.1', id: 'indicator--' + row.id,
      created, modified: created, pattern_type: 'stix', pattern_version: '2.1',
      pattern: '[' + PATTERN[definition.type] + " = '" + definition.value + "']",
      valid_from: new Date(timestamp(definition.valid_from)).toISOString(),
      valid_until: new Date(timestamp(definition.valid_until)).toISOString(), confidence: definition.confidence };
  });
  return { type: 'bundle', id: 'bundle--' + bundleId, objects };
}
