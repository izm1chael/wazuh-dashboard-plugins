import { IncidentDomainError, SEVERITIES, Severity } from './incident-domain';
import { validateIncidentId } from './incident-id';

export type IncidentQueue = 'open' | 'new' | 'triaging' | 'active' | 'unassigned' | 'closed' | 'all';
export interface IncidentPage {
  incidents: Array<Omit<import('./incident-domain').Incident, 'pending_activity'>>;
  next?: [string, string];
}

export interface IncidentQuery {
  queue?: IncidentQueue;
  severity?: Severity;
  owner?: string;
  search?: string;
  limit?: number;
  after?: [string, string];
}

const QUEUES = ['open', 'new', 'triaging', 'active', 'unassigned', 'closed', 'all'] as const;

function invalid(message: string): never {
  throw new IncidentDomainError('invalid', message);
}

/** Fixed query builder: no arbitrary DSL, index, fields or script from clients.
 * Live search_after pagination is deterministic for unchanged data, not a
 * point-in-time snapshot. A concurrent update can move a record across pages. */
export function buildIncidentQuery(input: IncidentQuery): Record<string, unknown> {
  const queue = input.queue === undefined ? 'open' : input.queue;
  if (!QUEUES.includes(queue)) return invalid('Invalid incident queue');
  const limit = input.limit === undefined ? 50 : input.limit;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) return invalid('Limit must be 1 to 100');
  const filter: object[] = [];
  const mustNot: object[] = [];
  const must: object[] = [];
  if (queue === 'open' || queue === 'unassigned') {
    filter.push({ terms: { status: ['new', 'triaging', 'active'] } });
  } else if (queue !== 'all') {
    filter.push({ term: { status: queue } });
  }
  if (queue === 'unassigned') mustNot.push({ exists: { field: 'owner' } });
  if (input.owner !== undefined) {
    if (typeof input.owner !== 'string' || !input.owner.trim() || input.owner.length > 1024) {
      return invalid('Invalid owner');
    }
    filter.push({ term: { owner: input.owner } });
  }
  if (input.severity !== undefined) {
    if (!SEVERITIES.includes(input.severity)) return invalid('Invalid severity');
    filter.push({ term: { severity: input.severity } });
  }
  if (input.search !== undefined) {
    if (typeof input.search !== 'string' || input.search.length > 1024) return invalid('Invalid search');
    if (input.search.trim()) {
      must.push({ multi_match: { query: input.search.trim(), fields: ['title^3', 'description', 'id'], operator: 'and' } });
    }
  }
  if (input.after !== undefined) {
    if (!Array.isArray(input.after) || input.after.length !== 2 ||
        typeof input.after[0] !== 'string' || !Number.isFinite(Date.parse(input.after[0])) ||
        new Date(input.after[0]).toISOString() !== input.after[0]) return invalid('Invalid cursor');
    validateIncidentId(input.after[1]);
  }
  return {
    size: limit + 1,
    track_total_hits: false,
    _source: { excludes: ['pending_activity'] },
    query: { bool: { filter, must_not: mustNot, must } },
    sort: [{ updated_at: { order: 'desc', format: 'strict_date_time' } }, { id: 'asc' }],
    ...(input.after === undefined ? {} : { search_after: input.after }),
  };
}
