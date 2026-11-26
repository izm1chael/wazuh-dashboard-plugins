import { isDeepStrictEqual } from 'util';
import { Activity, Incident, IncidentDomainError } from './incident-domain';
import { buildIncidentQuery, IncidentPage, IncidentQuery } from './incident-query';
import { validateIncidentId } from './incident-id';

export const INCIDENT_INDEX = 'wazuh-cases-v1';
export const ACTIVITY_INDEX = 'wazuh-case-activity-v1';

/**
 * Internal transport adapter only. Must be supplied by a trusted, authorised
 * service, never exposed as an arbitrary client transport proxy.
 */
export interface IncidentTransport {
  request<T>(params: {
    method: 'GET' | 'PUT';
    path: string;
    querystring?: Record<string, string | number>;
    body?: unknown;
  }): Promise<{ body: T }>;
}

export interface VersionedIncident {
  record: Incident;
  seqNo: number;
  primaryTerm: number;
}

interface Document<T> {
  _source: T;
  _seq_no: number;
  _primary_term: number;
}

interface WriteResult {
  _seq_no: number;
  _primary_term: number;
}

function version(record: Incident, result: WriteResult): VersionedIncident {
  if (!Number.isSafeInteger(result._seq_no) || result._seq_no < 0 ||
      !Number.isSafeInteger(result._primary_term) || result._primary_term < 1) {
    throw new Error('Missing incident concurrency metadata');
  }
  return { record, seqNo: result._seq_no, primaryTerm: result._primary_term };
}

function status(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const candidate = error as { statusCode?: number; meta?: { statusCode?: number } };
  return candidate.meta?.statusCode ?? candidate.statusCode;
}

function documentPath(index: string, operation: '_doc' | '_create', id: string): string {
  return '/' + index + '/' + operation + '/' + encodeURIComponent(id);
}

/**
 * A logical incident mutation is committed with its pending event in a single
 * document write. Activity delivery is a separate recoverable step.
 * Do not present a delivery failure as a rolled-back incident mutation.
 */
export class IncidentStore {
  constructor(private readonly transport: IncidentTransport) {}

  async list(query: IncidentQuery): Promise<IncidentPage> {
    const body = buildIncidentQuery(query);
    const limit = query.limit ?? 50;
    const response = await this.transport.request<{
      timed_out?: boolean;
      _shards?: { failed: number };
      hits: { hits: Array<{ _source: Incident; sort: [string, string] }> };
    }>({
      method: 'GET',
      path: '/' + INCIDENT_INDEX + '/_search',
      querystring: { allow_partial_search_results: 'false' },
      body,
    });
    if (response.body.timed_out || response.body._shards?.failed) {
      throw new Error('Incomplete incident queue search');
    }
    const hits = response.body.hits.hits;
    const selected = hits.slice(0, limit);
    const incidents = selected.map(hit => {
      validateIncidentId(hit._source.id);
      // Enforce projection locally as well as in the search request.
      const { pending_activity, ...incident } = hit._source;
      return incident;
    });
    const next = hits.length > limit ? selected[selected.length - 1].sort : undefined;
    if (next !== undefined) buildIncidentQuery({ ...query, after: next });
    return { incidents, ...(next === undefined ? {} : { next }) };
  }

  async get(id: string): Promise<VersionedIncident> {
    const { body } = await this.transport.request<Document<Incident>>({
      method: 'GET', path: documentPath(INCIDENT_INDEX, '_doc', id),
    });
    if (!body._source || body._source.id !== id) throw new Error('Invalid incident document');
    return version(body._source, body);
  }

  async create(record: Incident): Promise<VersionedIncident> {
    if (record.revision !== 1 || !record.pending_activity ||
        record.pending_activity.id !== record.id + ':1') {
      throw new IncidentDomainError('invalid', 'Initial activity is required');
    }
    const { body } = await this.transport.request<WriteResult>({
      method: 'PUT', path: documentPath(INCIDENT_INDEX, '_create', record.id),
      querystring: { refresh: 'wait_for' }, body: record,
    });
    return version(record, body);
  }

  async commit(previous: VersionedIncident, record: Incident): Promise<VersionedIncident> {
    if (previous.record.pending_activity !== null ||
        record.id !== previous.record.id ||
        record.revision !== previous.record.revision + 1 ||
        !record.pending_activity ||
        record.pending_activity.id !== record.id + ':' + record.revision ||
        record.pending_activity.incident_id !== record.id ||
        record.pending_activity.revision !== record.revision) {
      throw new IncidentDomainError('conflict', 'Invalid incident mutation or pending activity');
    }
    return this.replace(previous, record);
  }

  private async replace(previous: VersionedIncident, record: Incident): Promise<VersionedIncident> {
    try {
      const { body } = await this.transport.request<WriteResult>({
        method: 'PUT', path: documentPath(INCIDENT_INDEX, '_doc', record.id),
        querystring: { if_seq_no: previous.seqNo, if_primary_term: previous.primaryTerm, refresh: 'wait_for' },
        body: record,
      });
      return version(record, body);
    } catch (error) {
      if (status(error) === 409) throw new IncidentDomainError('conflict', 'Incident changed; reload before retrying');
      throw error;
    }
  }

  /**
   * Create-only activity delivery. On replay a conflict is accepted only if
   * the persisted event is identical. Acknowledgement is itself a CAS; a
   * conflicting acknowledgement never overwrites a newer incident.
   */
  async deliverPending(previous: VersionedIncident): Promise<VersionedIncident> {
    const event = previous.record.pending_activity;
    if (event === null) return previous;
    if (event.incident_id !== previous.record.id ||
        event.revision !== previous.record.revision ||
        event.id !== previous.record.id + ':' + previous.record.revision) {
      throw new Error('Invalid pending activity identity');
    }
    try {
      await this.transport.request<WriteResult>({
        method: 'PUT', path: documentPath(ACTIVITY_INDEX, '_create', event.id),
        querystring: { refresh: 'wait_for' }, body: event,
      });
    } catch (error) {
      if (status(error) !== 409) throw error;
      const { body } = await this.transport.request<Document<Activity>>({
        method: 'GET', path: documentPath(ACTIVITY_INDEX, '_doc', event.id),
      });
      if (!isDeepStrictEqual(body._source, event)) {
        throw new Error('Activity identity collision: refusing acknowledgement');
      }
    }
    return this.replace(previous, { ...previous.record, pending_activity: null });
  }
}
