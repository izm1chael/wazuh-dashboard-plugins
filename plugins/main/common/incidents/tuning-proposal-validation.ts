import type { CollaborationPage, TuningReplayReceipt, TuningProposal } from './contracts';
import { RULE_UUID } from './rule-history';
export const TUNING_TYPES = ['compare_benign_baseline', 'review_rule_scope', 'review_threshold_or_window', 'review_duplicate_grouping', 'replay_positive_and_negative_tests'] as const;
export const SHA256 = /^[a-f0-9]{64}$/;
export const PROPOSAL_ROWS = 1000;
const fields = ['total', 'malicious', 'benign', 'unknown', 'unknown_changed', 'baseline_tp', 'candidate_tp',
  'baseline_fp', 'candidate_fp', 'lost_malicious', 'gained_malicious', 'removed_benign', 'added_benign'] as const;
const text = (value: unknown, max: number) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
const time = (value: unknown) => typeof value === 'string' && Number.isFinite(Date.parse(value));
export function validReplay(row: TuningReplayReceipt): boolean {
  if (!row || Object.keys(row).length !== fields.length + 2 ||
      typeof row.fixture_sha256 !== 'string' || !SHA256.test(row.fixture_sha256) ||
      !fields.every(field => Number.isSafeInteger(row[field]) && row[field] >= 0 && row[field] <= PROPOSAL_ROWS)) return false;
  const { total, malicious: m, benign: b, unknown: u, unknown_changed: uc, baseline_tp: bt, candidate_tp: ct,
    baseline_fp: bf, candidate_fp: cf, lost_malicious: lost, gained_malicious: gained, removed_benign: removed, added_benign: added } = row;
  return total >= 1 && total === m + b + u && uc <= u && bt <= m && ct <= m && bf <= b && cf <= b &&
    lost <= bt && lost <= m - ct && gained <= m - bt && gained <= ct && ct === bt - lost + gained &&
    removed <= bf && removed <= b - cf && added <= b - bf && added <= cf && cf === bf - removed + added &&
    row.gate === (m >= 10 && b >= 10 && u === 0 && lost === 0 && added === 0 && removed > 0 ? 'eligible_for_human_review' : 'blocked');
}
const proposalFields = ['id','rule_uuid','baseline_sha256','candidate_sha256','type','reason','replay','state',
  'proposed_by','proposed_at','decided_by','decided_at','decision_reason','evidence_origin'];
function validProposal(row: TuningProposal, incidentId: string, revision: number): boolean {
  if (!row || Object.keys(row).length !== proposalFields.length || Object.keys(row).some(key => !proposalFields.includes(key)) ||
      typeof row.id !== 'string' || !row.id.startsWith(incidentId + ':') ||
      !/^[1-9][0-9]*$/.test(row.id.slice(incidentId.length + 1)) || Number(row.id.slice(incidentId.length + 1)) > revision ||
      typeof row.rule_uuid !== 'string' || !RULE_UUID.test(row.rule_uuid) ||
      typeof row.baseline_sha256 !== 'string' || !SHA256.test(row.baseline_sha256) ||
      typeof row.candidate_sha256 !== 'string' || !SHA256.test(row.candidate_sha256) || row.baseline_sha256 === row.candidate_sha256 ||
      !TUNING_TYPES.includes(row.type) || !text(row.reason, 2048) || !text(row.proposed_by, 1024) || !time(row.proposed_at) ||
      row.evidence_origin !== 'analyst_supplied_paired_holdout' || !validReplay(row.replay)) return false;
  if (row.state === 'proposed') return row.decided_by === null && row.decided_at === null && row.decision_reason === null;
  return ['accepted_for_review', 'rejected', 'withdrawn'].includes(row.state) &&
    text(row.decided_by, 1024) && time(row.decided_at) && Date.parse(row.decided_at!) >= Date.parse(row.proposed_at) &&
    text(row.decision_reason, 2048) && (row.state === 'withdrawn' || row.decided_by !== row.proposed_by) &&
    (row.state !== 'accepted_for_review' || row.replay.gate === 'eligible_for_human_review');
}
export function validateTuningProposals(page: CollaborationPage, id: string): void {
  if (page.tuning_proposals === undefined) return;
  if (!Array.isArray(page.tuning_proposals) || page.tuning_proposals.length > 25 ||
      !page.tuning_proposals.every(row => validProposal(row, id, page.observed_revision)) ||
      new Set(page.tuning_proposals.map(row => row.id)).size !== page.tuning_proposals.length) {
    throw new Error('Invalid tuning proposal projection');
  }
}
