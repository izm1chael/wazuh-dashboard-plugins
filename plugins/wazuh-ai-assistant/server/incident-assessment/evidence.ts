/** No free text, raw IDs, dates, notes, entity values or source payloads enter the provider digest. */
const STATUSES = ['new', 'triaging', 'active', 'closed'];
const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'];
const PRIORITIES = ['low', 'medium', 'high', 'urgent'];
const ENTITY_KINDS = ['agent_id', 'agent_name', 'host_id', 'host', 'host_ip', 'source_ip', 'destination_ip',
  'user', 'user_id', 'user_domain', 'domain', 'hash'];
export const PAGE_SIZE = 5;
export const ACTIONS = ['review_detection', 'review_entities', 'review_attack_techniques', 'review_chronology',
  'retrieve_missing_evidence', 'assess_business_impact', 'review_containment_options', 'review_classification'] as const;
export type Action = typeof ACTIONS[number];
export interface Fact { ref: string; kind: string; value: string | number | boolean | string[] }
export interface AssessmentDigest { facts: Fact[]; scope: 'first_finding_page' | 'expanded_linked_findings'; complete_link_coverage: boolean }
type Obj = Record<string, unknown>;
const object = (value: unknown): Obj => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid incident evidence');
  return value as Obj;
};
const count = (value: unknown, max: number): number => {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > max) throw new Error('Invalid evidence count');
  return value;
};
const choice = (value: unknown, allowed: string[]): string => {
  if (typeof value !== 'string' || !allowed.includes(value)) throw new Error('Invalid evidence enum');
  return value;
};
const array = (value: unknown, max: number): unknown[] => {
  if (!Array.isArray(value) || value.length > max) throw new Error('Invalid evidence array');
  return value;
};
export function checkedSummary(raw: unknown, id: string, revision: number, allowedTlp: readonly string[]): Obj {
  const summary = object(object(raw).incident);
  if (summary.id !== id || summary.revision !== revision ||
      typeof summary.tlp !== 'string' || !['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER'].includes(summary.tlp) ||
      !allowedTlp.includes(summary.tlp)) throw new Error('Incident revision or disclosure policy mismatch');
  return summary;
}

export function buildDigest(summary: Obj, rawPage: unknown, offset = 0): AssessmentDigest {
  const page = object(rawPage);
  const total = count(summary.finding_count, 1000);
  const refs = array(page.findings, PAGE_SIZE).map(object);
  const observations = array(page.observations, PAGE_SIZE).map(object);
  const unavailable = count(page.unavailable_count, PAGE_SIZE);
  const sampled = Math.min(total - offset, PAGE_SIZE);
  if (offset < 0 || offset > total) throw new Error('Invalid finding offset');
  if (page.revision !== summary.revision || refs.length !== observations.length ||
      refs.length + unavailable !== sampled ||
      (total > offset + PAGE_SIZE ? page.next_offset !== offset + PAGE_SIZE : page.next_offset !== undefined)) {
    throw new Error('Incomplete or stale finding page');
  }
  const seen = new Set<string>();
  const facts: Fact[] = [];
  const add = (kind: string, value: Fact['value']) => facts.push({ ref: 'F' + (facts.length + 1), kind, value });
  add('status', choice(summary.status, STATUSES));
  add('severity', choice(summary.severity, SEVERITIES));
  add('priority', choice(summary.priority, PRIORITIES));
  add('assigned', typeof summary.owner === 'string' && summary.owner.length > 0);
  add('linked_findings', total);
  add('visible_sample', refs.length);
  add('unavailable_sample', unavailable);
  add('uninspected_links', total - sampled);
  for (const [n, row] of observations.entries()) {
    const ref = refs[n];
    if (typeof ref.index !== 'string' || typeof ref.document_id !== 'string' ||
        ref.index !== row.index || ref.document_id !== row.document_id) throw new Error('Finding identity mismatch');
    const key = JSON.stringify([ref.index, ref.document_id]);
    if (seen.has(key)) throw new Error('Duplicate finding evidence');
    seen.add(key);
    // Only catalog-shaped IDs survive; values, timestamps, rule labels and source references never do.
    const techniques = array(row.techniques, 96).filter((v): v is string => typeof v === 'string' && /^T[0-9]{4}(\.[0-9]{3})?$/.test(v));
    const tactics = array(row.tactics, 48).filter((v): v is string => typeof v === 'string' && /^TA[0-9]{4}$/.test(v));
    const kinds = array(row.entities, 240).map(object).map(entity => entity.kind)
      .filter((v): v is string => typeof v === 'string' && ENTITY_KINDS.includes(v));
    add('sample_' + (offset + n + 1) + '_exact_rule_present', typeof row.wazuh_rule_id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(row.wazuh_rule_id));
    add('sample_' + (offset + n + 1) + '_techniques', [...new Set(techniques)].sort().slice(0, 12));
    add('sample_' + (offset + n + 1) + '_tactics', [...new Set(tactics)].sort().slice(0, 12));
    add('sample_' + (offset + n + 1) + '_entity_kinds', [...new Set(kinds)].sort());
    add('sample_' + (offset + n + 1) + '_timestamp_present', typeof row.timestamp === 'string' && Number.isFinite(Date.parse(row.timestamp)));
  }
  const digest: AssessmentDigest = { facts, scope: 'first_finding_page', complete_link_coverage: total === refs.length };
  if (JSON.stringify(digest).length > 6000) throw new Error('Incident evidence exceeds provider budget');
  return digest;
}

export interface Recommendation { action: Action; evidence_refs: string[] }
export function parseRecommendations(raw: string, digest: AssessmentDigest): Recommendation[] {
  if (raw.length > 4096) throw new Error('Assessment output exceeded limit');
  const body = object(JSON.parse(raw));
  if (Object.keys(body).length !== 1 || !Array.isArray(body.recommendations) ||
      body.recommendations.length < 1 || body.recommendations.length > 5) throw new Error('Invalid assessment output');
  const known = new Set(digest.facts.map(fact => fact.ref));
  const actions = new Set<string>();
  return body.recommendations.map(value => {
    const row = object(value);
    if (Object.keys(row).length !== 2 || typeof row.action !== 'string' ||
        !ACTIONS.includes(row.action as Action) || actions.has(row.action) ||
        !Array.isArray(row.evidence_refs) || row.evidence_refs.length < 1 || row.evidence_refs.length > 4 ||
        row.evidence_refs.some(ref => typeof ref !== 'string' || !known.has(ref)) ||
        new Set(row.evidence_refs).size !== row.evidence_refs.length) throw new Error('Invalid recommendation reference');
    actions.add(row.action);
    return { action: row.action as Action, evidence_refs: row.evidence_refs as string[] };
  });
}
