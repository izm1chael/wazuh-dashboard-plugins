import { AssessmentDigest, buildDigest, Fact, PAGE_SIZE, parseRecommendations } from './evidence';

export const HYPOTHESES = ['insufficient_evidence', 'possible_true_positive', 'possible_benign_positive', 'possible_false_positive'] as const;
export const TUNING = ['compare_benign_baseline', 'review_rule_scope', 'review_threshold_or_window', 'review_duplicate_grouping', 'replay_positive_and_negative_tests'] as const;
export type Probe = { kind: 'more_linked_findings' } | { kind: 'rule_prevalence'; sample: number } | { kind: 'rule_history'; sample: number };
type Obj = Record<string, unknown>;
const object = (v: unknown): Obj => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('Invalid agentic response');
  return v as Obj;
};
export function exactRule(rawPage: unknown, sample: number): string | undefined {
  const rows = object(rawPage).observations;
  if (!Array.isArray(rows) || !Number.isInteger(sample) || sample < 1 || sample > rows.length) return undefined;
  const rule = object(rows[sample - 1]).wazuh_rule_id;
  return typeof rule === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(rule) ? rule : undefined;
}

export function exactRuleUuid(rawPage: unknown, sample: number): string | undefined {
  const rows = object(rawPage).observations;
  if (!Array.isArray(rows) || !Number.isInteger(sample) || sample < 1 || sample > rows.length) return undefined;
  const rule = object(rows[sample - 1]).wazuh_rule_uuid;
  return typeof rule === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(rule) ? rule : undefined;
}

export function parsePlan(raw: string, firstPage: unknown, hasMore: boolean, historyEnabled = false): Probe[] {
  const body = object(JSON.parse(raw));
  if (Object.keys(body).length !== 1 || !Array.isArray(body.probes) || body.probes.length > 2) throw new Error('Invalid probe plan');
  const seen = new Set<string>();
  return body.probes.map(value => {
    const row = object(value);
    if (typeof row.kind !== 'string' || seen.has(row.kind)) throw new Error('Duplicate probe');
    seen.add(row.kind);
    if (row.kind === 'more_linked_findings' && Object.keys(row).length === 1 && hasMore) return { kind: row.kind };
    if (row.kind === 'rule_prevalence' && Object.keys(row).length === 2 && typeof row.sample === 'number' &&
        exactRule(firstPage, row.sample)) return { kind: row.kind, sample: row.sample };
    if (historyEnabled && row.kind === 'rule_history' && Object.keys(row).length === 2 && typeof row.sample === 'number' &&
        exactRuleUuid(firstPage, row.sample)) return { kind: row.kind, sample: row.sample };
    throw new Error('Unavailable or unauthorized probe shape');
  });
}

function append(digest: AssessmentDigest, kind: string, value: Fact['value']) {
  digest.facts.push({ ref: 'F' + (digest.facts.length + 1), kind, value });
  if (JSON.stringify(digest).length > 6000) throw new Error('Expanded evidence exceeded budget');
}

export function addLinkedPage(digest: AssessmentDigest, summary: Obj, raw: unknown): void {
  const second = buildDigest(summary, raw, PAGE_SIZE);
  const read = (name: string) => Number(second.facts.find(fact => fact.kind === name)?.value);
  const visible = read('visible_sample'), unavailable = read('unavailable_sample');
  append(digest, 'additional_visible_findings', visible);
  append(digest, 'additional_unavailable_findings', unavailable);
  const union = (suffix: string) => [...new Set(second.facts.filter(f => f.kind.endsWith(suffix))
    .flatMap(f => Array.isArray(f.value) ? f.value : []))].sort().slice(0, 12);
  append(digest, 'additional_techniques_sample', union('_techniques'));
  append(digest, 'additional_tactics_sample', union('_tactics'));
  append(digest, 'additional_entity_kinds_sample', union('_entity_kinds'));
  const total = Number(summary.finding_count);
  append(digest, 'remaining_uninspected_links', Math.max(0, total - 2 * PAGE_SIZE));
  digest.scope = 'expanded_linked_findings';
  digest.complete_link_coverage = total === visible + Number(digest.facts.find(f => f.kind === 'visible_sample')?.value);
}

export function prevalenceQuery(rule: string, until: Date) {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(rule) || !Number.isFinite(until.getTime())) throw new Error('Invalid prevalence input');
  return { index: 'wazuh-findings-v5*', allow_partial_search_results: false, body: {
    size: 0, track_total_hits: 10000, timeout: '10s',
    query: { bool: { filter: [{ term: { 'wazuh.rule.id': rule } },
      { range: { '@timestamp': { gte: new Date(until.getTime() - 86400000).toISOString(), lt: until.toISOString() } } }] } },
  } };
}

export function addPrevalence(digest: AssessmentDigest, sample: number, raw: unknown): void {
  const body = object(raw), shards = object(body._shards), hits = object(body.hits), total = object(hits.total);
  if (body.timed_out !== false || body.terminated_early === true || shards.failed !== 0 ||
      typeof shards.total !== 'number' || shards.total < 1 ||
      typeof total.value !== 'number' || !Number.isSafeInteger(total.value) || total.value < 0 || total.value > 10000 ||
      !['eq', 'gte'].includes(String(total.relation))) throw new Error('Incomplete prevalence response');
  append(digest, 'rule_prevalence_sample_number', sample);
  append(digest, 'caller_visible_rule_findings_last_24h', total.value);
  append(digest, 'rule_prevalence_is_lower_bound', total.relation === 'gte');
}

export function parseAgenticResult(raw: string, digest: AssessmentDigest) {
  const body = object(JSON.parse(raw));
  if (Object.keys(body).length !== 3 || !('recommendations' in body) || !('hypothesis' in body) || !('tuning' in body)) throw new Error('Invalid agentic assessment');
  const known = new Set(digest.facts.map(fact => fact.ref));
  function cited(value: unknown, options: readonly string[]) {
    const row = object(value);
    if (Object.keys(row).length !== 2 || typeof row.action !== 'string' || !options.includes(row.action) ||
        !Array.isArray(row.evidence_refs) || row.evidence_refs.length < 1 || row.evidence_refs.length > 4 ||
        row.evidence_refs.some(ref => typeof ref !== 'string' || !known.has(ref)) ||
        new Set(row.evidence_refs).size !== row.evidence_refs.length) throw new Error('Invalid cited hypothesis or tuning proposal');
    return { action: row.action, evidence_refs: row.evidence_refs as string[] };
  }
  if (!Array.isArray(body.tuning) || body.tuning.length > 3) throw new Error('Invalid tuning list');
  const tuning = body.tuning.map(row => cited(row, TUNING));
  if (new Set(tuning.map(row => row.action)).size !== tuning.length) throw new Error('Duplicate tuning proposal');
  return { recommendations: parseRecommendations(JSON.stringify({ recommendations: body.recommendations }), digest),
    hypothesis: cited(body.hypothesis, HYPOTHESES), tuning };
}
