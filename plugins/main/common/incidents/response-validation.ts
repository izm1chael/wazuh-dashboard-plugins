import type { IncidentResponsePage, IncidentResponseRecord } from './contracts';

export const RESPONSE_INTENTS = ['investigate_endpoint', 'review_containment', 'review_indicator_block', 'collect_evidence'] as const;
export const RESPONSE_OUTCOMES = ['completed', 'failed', 'not_performed'] as const;
const fields = ['id', 'type', 'scope', 'reason', 'state', 'requested_by', 'requested_at', 'decided_by', 'decided_at',
  'decision_reason', 'finalized_by', 'finalized_at', 'final_reason', 'execution_verified'];
const text = (value: unknown, max: number) => typeof value === 'string' && value.trim().length > 0 && value.length <= max;
const time = (value: unknown) => typeof value === 'string' && Number.isFinite(Date.parse(value));
function valid(row: IncidentResponseRecord, id: string, revision: number): boolean {
  if (!row || Object.keys(row).length !== fields.length || Object.keys(row).some(key => !fields.includes(key)) ||
      !RESPONSE_INTENTS.includes(row.type) || typeof row.id !== 'string' || !row.id.startsWith(id + ':') ||
      !/^[1-9][0-9]*$/.test(row.id.slice(id.length + 1)) || Number(row.id.slice(id.length + 1)) > revision ||
      row.execution_verified !== false || !text(row.scope, 512) || !text(row.reason, 2048) ||
      !text(row.requested_by, 1024) || !time(row.requested_at)) return false;
  const noDecision = row.decided_by === null && row.decided_at === null && row.decision_reason === null;
  const decision = text(row.decided_by, 1024) && row.decided_by !== row.requested_by && time(row.decided_at) &&
    text(row.decision_reason, 2048) && Date.parse(row.decided_at!) >= Date.parse(row.requested_at);
  const noFinal = row.finalized_by === null && row.finalized_at === null && row.final_reason === null;
  const final = text(row.finalized_by, 1024) && time(row.finalized_at) && text(row.final_reason, 2048) &&
    Date.parse(row.finalized_at!) >= Date.parse(row.decided_at ?? row.requested_at);
  switch (row.state) {
    case 'requested': return noDecision && noFinal;
    case 'approved':
    case 'rejected': return decision && noFinal;
    case 'cancelled': return (noDecision || decision) && final;
    case 'reported_completed':
    case 'reported_failed':
    case 'reported_not_performed': return decision && final;
    default: return false;
  }
}
export function validateResponsePage(body: IncidentResponsePage, id: string): void {
  if (!body || body.mode !== 'manual_tracking_only' || typeof body.activity_pending !== 'boolean' ||
      !Number.isSafeInteger(body.observed_revision) || body.observed_revision < 1 ||
      !Array.isArray(body.responses) || body.responses.length > 50 ||
      !body.responses.every(row => valid(row, id, body.observed_revision)) ||
      new Set(body.responses.map(row => row.id)).size !== body.responses.length) {
    throw new Error('Invalid incident response projection');
  }
}
