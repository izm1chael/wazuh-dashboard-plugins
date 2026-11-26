import type { IndexerIncidentClient } from './indexer-incident-client';
import { HISTORY_CASE_LIMIT, HISTORY_FINDING_LIMIT, RULE_UUID, inspectPage, summarizeRuleHistory } from '../../../common/incidents/rule-history';

/** Read-only current-user comparison; intentionally small and not a historical as-of reconstruction. */
export async function ruleHistory(client: Pick<IndexerIncidentClient, 'get' | 'list' | 'findings'>,
    id: string, revision: number, rule: string, checkBudget: () => void) {
  if (!RULE_UUID.test(rule) || !Number.isSafeInteger(revision) || revision < 1) throw { statusCode: 400 };
  checkBudget();
  const current = await client.get(id);
  if (current.revision !== revision) throw { statusCode: 409 };
  const currentPage = await client.findings(id, 0, revision, 25);
  if (!inspectPage(current, currentPage, 25).rules.includes(rule)) throw { statusCode: 403 };
  checkBudget();
  // The same incident is excluded; one additional row allows a full ten-case sample if present.
  const queue = await client.list({ queue: 'closed', limit: HISTORY_CASE_LIMIT + 1 });
  const candidates = queue.incidents.filter(item => item.id !== id);
  const samples = [];
  for (const summary of candidates.slice(0, HISTORY_CASE_LIMIT)) {
    checkBudget();
    const page = await client.findings(summary.id, 0, summary.revision, HISTORY_FINDING_LIMIT);
    samples.push({ summary, page });
  }
  checkBudget();
  if ((await client.get(id)).revision !== revision) throw { statusCode: 409 };
  return summarizeRuleHistory(rule, revision, samples, candidates.length > HISTORY_CASE_LIMIT || queue.next !== undefined);
}
