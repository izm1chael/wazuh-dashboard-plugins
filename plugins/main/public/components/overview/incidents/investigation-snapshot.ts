import type { ActivityPage, FindingObservation, FindingPage, IncidentActivity, IncidentSummary } from '../../../../common/incidents/contracts';

export const INVESTIGATION_PAGE_BUDGET = 4;
type Reader = {
  findings(id: string, offset: number, revision: number): Promise<FindingPage>;
  activity(id: string, before: number): Promise<ActivityPage>;
  get(id: string): Promise<IncidentSummary>;
};
export type TimelineRow = {
  key: string; at: string | null; source: 'finding' | 'activity'; label: string; detail: string;
};
export interface InvestigationSnapshot {
  revision: number; positions: number; unavailable: number; unscanned: number;
  observations: FindingObservation[]; events: IncidentActivity[];
  activityPending: boolean; activityCapped: boolean; missingAuditRevisions: number;
  rows: TimelineRow[];
}
const key = (r: { index: string; document_id: string }) => JSON.stringify([r.index, r.document_id]);
const fail = () => { throw new Error('Investigation response changed or is inconsistent'); };
const integer = (n: number) => Number.isSafeInteger(n) && n >= 0;
const time = (value: string | null) => value === null ? NaN : Date.parse(value);

export function buildTimeline(observations: FindingObservation[], events: IncidentActivity[]): TimelineRow[] {
  const rows: TimelineRow[] = [
    ...observations.map(f => ({
      key: 'finding:' + key(f), at: f.timestamp, source: 'finding' as const,
      label: f.rule_title || f.rule_id || 'Linked finding',
      detail: f.index + ' / ' + f.document_id,
    })),
    ...events.map(e => ({
      key: 'activity:' + e.id, at: e.at, source: 'activity' as const,
      label: e.kind.replace(/_/g, ' '), detail: e.actor + ' · revision ' + e.revision,
    })),
  ];
  return rows.sort((a, b) => {
    const x = time(a.at), y = time(b.at);
    if (Number.isFinite(x) !== Number.isFinite(y)) return Number.isFinite(x) ? -1 : 1;
    return (Number.isFinite(x) ? x - y : 0) || a.key.localeCompare(b.key);
  });
}

/** On-demand current-user reads only. Bounded by four pages per source, no retries or direct index reads.
 * Revision checks detect aggregate changes, not atomic source ACL or retention snapshots.
 */
export async function loadInvestigation(api: Reader, incident: IncidentSummary,
    cancelled: () => boolean = () => false): Promise<InvestigationSnapshot> {
  const { id, revision, finding_count: total } = incident;
  if (!integer(total) || total > 1000 || !integer(revision) || revision < 1) fail();
  const check = () => { if (cancelled()) fail(); };
  const observations: FindingObservation[] = [], events: IncidentActivity[] = [];
  const seen = new Set<string>(), audit = new Set<number>();
  let positions = 0, unavailable = 0, activityPending = false, activityCapped = false;
  for (let page = 0; page < INVESTIGATION_PAGE_BUDGET; page++) {
    check();
    const result = await api.findings(id, positions, revision);
    check();
    if (result.revision !== revision || !Array.isArray(result.findings) ||
        !Array.isArray(result.observations) || !integer(result.unavailable_count)) fail();
    const observed = result.observations!;
    const count = result.findings.length + result.unavailable_count;
    if (count > 25 || count !== Math.min(25, total - positions) || observed.length !== result.findings.length) fail();
    const refs = new Set(result.findings.map(key));
    if (refs.size !== result.findings.length) fail();
    for (const f of observed) {
      const k = key(f);
      if (!refs.delete(k) || seen.has(k) || !Array.isArray(f.entities) ||
          !Array.isArray(f.techniques) || !Array.isArray(f.tactics)) fail();
      seen.add(k); observations.push(f);
    }
    positions += count;
    unavailable += result.unavailable_count;
    if (positions === total) {
      if (result.next_offset !== undefined) fail();
      break;
    }
    if (result.next_offset !== positions || count === 0) fail();
  }
  let before = 0, previous = revision + 1;
  for (let page = 0; page < INVESTIGATION_PAGE_BUDGET; page++) {
    check();
    const result = await api.activity(id, before);
    check();
    if (result.observed_revision !== revision || !Array.isArray(result.events) ||
        result.events.length > 50 || typeof result.activity_pending !== 'boolean') fail();
    activityPending = activityPending || result.activity_pending;
    for (const e of result.events) {
      if (e.incident_id !== id || e.id !== id + ':' + e.revision || !integer(e.revision) ||
          e.revision < 1 || e.revision >= previous || audit.has(e.revision)) fail();
      previous = e.revision; audit.add(e.revision); events.push(e);
    }
    if (result.next_before === undefined) break;
    if (!result.events.length || result.next_before !== previous) fail();
    before = result.next_before;
    if (page === INVESTIGATION_PAGE_BUDGET - 1) activityCapped = true;
  }
  check();
  const latest = await api.get(id);
  check();
  if (latest.id !== id || latest.revision !== revision || latest.finding_count !== total) fail();
  const expected = activityCapped ? revision - previous + 1 : revision;
  return { revision, positions, unavailable, unscanned: total - positions, observations, events,
    activityPending, activityCapped, missingAuditRevisions: expected - events.length,
    rows: buildTimeline(observations, events) };
}
