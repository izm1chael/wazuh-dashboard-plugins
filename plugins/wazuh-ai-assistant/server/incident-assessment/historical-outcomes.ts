import { AssessmentDigest, buildDigest, checkedSummary, PAGE_SIZE } from './evidence';
import { exactRuleUuid } from './agentic';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const LIMIT = 5;
type Obj = Record<string, unknown>;
const object = (value: unknown): Obj => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid history evidence');
  return value as Obj;
};
interface Reader {
  list(): Promise<unknown>;
  detail(id: string): Promise<unknown>;
  findings(id: string, revision: number): Promise<unknown>;
}
interface Source { id: string; revision: number }
export interface HistoricalOutcome {
  sample: number; scanned: number; matched: number; truePositive: number; benignPositive: number;
  falsePositive: number; otherClassification: number; partialOrUncertain: number; sources: Source[];
}

/** No historical incident identifier, raw finding or restricted-label count enters the model digest. */
export async function collectHistoricalOutcomes(reader: Reader, currentId: string, rule: string, sample: number,
    allowedTlp: readonly string[], check: () => void): Promise<HistoricalOutcome> {
  if (!UUID.test(rule) || !Number.isSafeInteger(sample) || sample < 1 || sample > PAGE_SIZE) throw new Error('Invalid history rule');
  check();
  const queue = object(await reader.list());
  if (!Array.isArray(queue.incidents) || queue.incidents.length > LIMIT + 1) throw new Error('Invalid closed queue');
  const report: HistoricalOutcome = { sample, scanned: 0, matched: 0, truePositive: 0, benignPositive: 0,
    falsePositive: 0, otherClassification: 0, partialOrUncertain: 0, sources: [] };
  const seen = new Set<string>();
  for (const raw of queue.incidents) {
    const row = object(raw);
    if (typeof row.id !== 'string' || !UUID.test(row.id) || seen.has(row.id)) throw new Error('Invalid history identity');
    seen.add(row.id);
    if (row.id === currentId || typeof row.tlp !== 'string' || !allowedTlp.includes(row.tlp) ||
        !['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER'].includes(row.tlp)) continue;
    if (report.scanned >= LIMIT) break;
    if (typeof row.revision !== 'number' || !Number.isSafeInteger(row.revision) || row.revision < 1) throw new Error('Invalid history revision');
    const id = row.id, revision = row.revision;
    check();
    const summary = checkedSummary(await reader.detail(id), id, revision, allowedTlp);
    if (summary.status !== 'closed') throw new Error('History incident changed');
    check();
    const page = await reader.findings(id, revision);
    const digest = buildDigest(summary, page);
    const observations = object(page).observations as unknown[];
    const identities = observations.map((_, n) => exactRuleUuid(page, n + 1));
    report.scanned++;
    report.sources.push({ id, revision });
    if (!digest.complete_link_coverage || identities.some(value => value === undefined)) report.partialOrUncertain++;
    if (!identities.includes(rule)) continue;
    report.matched++;
    const classification = summary.closure && typeof summary.closure === 'object' ? object(summary.closure).classification : undefined;
    if (classification === 'true_positive') report.truePositive++;
    else if (classification === 'benign_positive') report.benignPositive++;
    else if (classification === 'false_positive') report.falsePositive++;
    else report.otherClassification++;
  }
  return report;
}

export async function recheckHistoricalSources(reader: Reader, history: HistoricalOutcome, allowedTlp: readonly string[], check: () => void) {
  for (const source of history.sources) {
    check();
    const summary = checkedSummary(await reader.detail(source.id), source.id, source.revision, allowedTlp);
    if (summary.status !== 'closed') throw new Error('History incident changed');
  }
}

export function appendHistoricalFacts(digest: AssessmentDigest, history: HistoricalOutcome): void {
  const values: Array<[string, number]> = [
    ['history_rule_sample_number', history.sample],
    ['history_disclosure_eligible_closed_cases_sampled', history.scanned],
    ['history_exact_rule_matched_closed_cases', history.matched],
    ['history_matching_incidents_true_positive', history.truePositive],
    ['history_matching_incidents_benign_positive', history.benignPositive],
    ['history_matching_incidents_false_positive', history.falsePositive],
    ['history_matching_incidents_other_or_unknown', history.otherClassification],
    ['history_cases_with_partial_or_uncertain_coverage', history.partialOrUncertain],
  ];
  for (const [kind, value] of values) digest.facts.push({ ref: 'F' + (digest.facts.length + 1), kind, value });
  if (digest.facts.length > 56 || JSON.stringify(digest).length > 6000) throw new Error('History evidence exceeds budget');
}
