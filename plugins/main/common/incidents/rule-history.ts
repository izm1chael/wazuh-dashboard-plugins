import type { Classification, FindingPage, IncidentSummary } from './contracts';

export const RULE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const HISTORY_CASE_LIMIT = 10;
export const HISTORY_FINDING_LIMIT = 5;
export const CLASSIFICATIONS = ['true_positive', 'benign_positive', 'false_positive', 'undetermined', 'duplicate'] as const;
export interface HistorySample { summary: IncidentSummary; page: FindingPage }
export interface RuleHistory {
  scope: 'recently_updated_currently_closed_sample';
  rule_uuid: string; observed_revision: number; more_closed_incidents: boolean; scanned_incidents: number;
  matched_incidents: number; complete_nonmatches: number; uncertain_nonmatches: number;
  matched_with_partial_coverage: number; classifications: Record<Classification, number>; unknown_classification: number;
  visible_findings: number; unavailable_findings: number; uninspected_links: number; missing_rule_identity: number;
}

/** Validate the actual page boundary, including unavailable references, not just visible rows. */
export function inspectPage(summary: IncidentSummary, page: FindingPage, limit: number) {
  const total = summary.finding_count;
  if (!Number.isSafeInteger(total) || total < 0 || total > 1000 || page.revision !== summary.revision ||
      !Array.isArray(page.findings) || !Array.isArray(page.observations) ||
      page.observations.length !== page.findings.length || !Number.isSafeInteger(page.unavailable_count) ||
      page.unavailable_count < 0 || page.findings.length + page.unavailable_count !== Math.min(total, limit) ||
      (total > limit ? page.next_offset !== limit : page.next_offset !== undefined)) throw new Error('Incomplete or stale finding sample');
  const seen = new Set<string>();
  const rules: string[] = [];
  let missing = 0;
  for (const [n, ref] of page.findings.entries()) {
    const row = page.observations[n];
    const key = JSON.stringify([ref.index, ref.document_id]);
    if (seen.has(key) || row.index !== ref.index || row.document_id !== ref.document_id) throw new Error('Invalid finding identity');
    seen.add(key);
    if (typeof row.wazuh_rule_uuid === 'string' && RULE_UUID.test(row.wazuh_rule_uuid)) rules.push(row.wazuh_rule_uuid);
    else missing++;
  }
  return { rules, missing, visible: page.findings.length, unavailable: page.unavailable_count, uninspected: Math.max(0, total - limit) };
}

export function summarizeRuleHistory(rule: string, revision: number, samples: HistorySample[], more: boolean): RuleHistory {
  if (!RULE_UUID.test(rule) || !Number.isSafeInteger(revision) || revision < 1 ||
      samples.length > HISTORY_CASE_LIMIT || typeof more !== 'boolean') throw new Error('Invalid history scope');
  const report: RuleHistory = {
    scope: 'recently_updated_currently_closed_sample', rule_uuid: rule, observed_revision: revision,
    more_closed_incidents: more, scanned_incidents: samples.length,
    matched_incidents: 0, complete_nonmatches: 0, uncertain_nonmatches: 0, matched_with_partial_coverage: 0,
    classifications: { true_positive: 0, benign_positive: 0, false_positive: 0, undetermined: 0, duplicate: 0 },
    unknown_classification: 0, visible_findings: 0, unavailable_findings: 0, uninspected_links: 0, missing_rule_identity: 0,
  };
  const seen = new Set<string>();
  for (const { summary, page } of samples) {
    if (summary.status !== 'closed' || seen.has(summary.id)) throw new Error('Invalid closed sample');
    seen.add(summary.id);
    const facts = inspectPage(summary, page, HISTORY_FINDING_LIMIT);
    const partial = facts.missing + facts.unavailable + facts.uninspected > 0;
    report.visible_findings += facts.visible; report.unavailable_findings += facts.unavailable;
    report.uninspected_links += facts.uninspected; report.missing_rule_identity += facts.missing;
    if (facts.rules.includes(rule)) {
      report.matched_incidents++;
      if (partial) report.matched_with_partial_coverage++;
      const classification = summary.closure?.classification;
      if (classification && CLASSIFICATIONS.includes(classification)) report.classifications[classification]++;
      else report.unknown_classification++;
    } else if (partial) report.uncertain_nonmatches++;
    else report.complete_nonmatches++;
  }
  return report;
}
