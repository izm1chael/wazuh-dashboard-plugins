import { CreateIncident, Classification, Incident, Priority, Severity, Tlp } from './incident-domain';
import { validateIncidentId } from './incident-id';

/** Production routes must bind this transport to asCurrentUser, never an internal
 * administrator client. The indexer is the authority for permissions and state. */
export interface CurrentUserIncidentTransport {
  request<T>(params: {
    method: 'POST' | 'GET';
    path: string;
    querystring?: Record<string, string | number>;
    body?: object;
  }): Promise<{ body: T }>;
}

export type IndexerIncidentCommand =
  | { kind: 'assign-self' | 'unassign' | 'start-triage' | 'activate' }
  | { kind: 'edit'; title?: string; description?: string; severity?: Severity; priority?: Priority; tlp?: Tlp }
  | { kind: 'close'; classification: Classification; reason: string }
  | { kind: 'reopen'; reason: string }
  | { kind: 'attach-finding' | 'detach-finding'; index: string; document_id: string };

export type IncidentSummary = Omit<Incident, 'pending_activity'> & { finding_count: number };
export type Queue = 'open' | 'new' | 'triaging' | 'active' | 'closed' | 'unassigned' | 'all';
export interface QueueCursor { time: number; id: string }
export interface QueueQuery {
  queue?: Queue;
  severity?: Severity;
  owner?: string;
  search?: string;
  limit?: number;
  after?: QueueCursor;
}
export interface QueuePage { incidents: IncidentSummary[]; next?: QueueCursor }

export interface IndexerIncidentResult {
  incident: IncidentSummary;
  activity_delivery: 'delivered' | 'pending';
  replayed: boolean;
}

const ROOT = '/_plugins/_setup/incidents';

function commandBody(command: IndexerIncidentCommand): object {
  switch (command.kind) {
    case 'assign-self':
    case 'unassign':
    case 'start-triage':
    case 'activate':
      return {};
    case 'edit':
      return {
        ...(command.title === undefined ? {} : { title: command.title }),
        ...(command.description === undefined ? {} : { description: command.description }),
        ...(command.severity === undefined ? {} : { severity: command.severity }),
        ...(command.priority === undefined ? {} : { priority: command.priority }),
        ...(command.tlp === undefined ? {} : { tlp: command.tlp }),
      };
    case 'close':
      return { classification: command.classification, reason: command.reason };
    case 'reopen':
      return { reason: command.reason };
    case 'attach-finding':
    case 'detach-finding':
      return { index: command.index, document_id: command.document_id };
    default:
      throw new Error('Unknown incident command');
  }
}

/**
 * Staged dashboard adapter for the dedicated indexer write API. No arbitrary
 * path, identity, grant, index or activity payload may be supplied by the UI.
 * Network errors can represent ambiguous writes; never retry automatically.
 */
export class IndexerIncidentClient {
  constructor(private readonly transport: CurrentUserIncidentTransport) {}

  async list(query: QueueQuery = {}): Promise<QueuePage> {
    const limit = query.limit ?? 50;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('Invalid queue limit');
    if (query.after !== undefined) validateCursor(query.after);
    const { body } = await this.transport.request<QueuePage>({
      method: 'GET', path: ROOT,
      querystring: {
        queue: query.queue ?? 'open', limit,
        ...(query.severity === undefined ? {} : { severity: query.severity }),
        ...(query.owner === undefined ? {} : { owner: query.owner }),
        ...(query.search === undefined ? {} : { search: query.search }),
        ...(query.after === undefined ? {} : { after_time: query.after.time, after_id: query.after.id }),
      },
    });
    if (!body || !Array.isArray(body.incidents) || body.incidents.length > limit) throw new Error('Invalid incident page');
    body.incidents.forEach(summary => validateSummary(summary));
    if (body.next !== undefined) validateCursor(body.next);
    return body;
  }

  async get(id: string): Promise<IncidentSummary> {
    validateIncidentId(id);
    const { body } = await this.transport.request<{ incident: IncidentSummary }>({
      method: 'GET', path: ROOT + '/' + encodeURIComponent(id),
    });
    if (!body) throw new Error('Invalid incident detail');
    validateSummary(body.incident, id);
    return body.incident;
  }

  async create(input: CreateIncident, requestId: string): Promise<IndexerIncidentResult> {
    validateIncidentId(requestId);
    const { body } = await this.transport.request<IndexerIncidentResult>({
      method: 'POST', path: ROOT,
      body: {
        request_id: requestId,
        title: input.title,
        severity: input.severity,
        ...(input.description === undefined ? {} : { description: input.description }),
        ...(input.priority === undefined ? {} : { priority: input.priority }),
        ...(input.tlp === undefined ? {} : { tlp: input.tlp }),
      },
    });
    const result = validateResult(body);
    if (!result.replayed && result.incident.revision !== 1) throw new Error('Invalid new incident revision');
    return result;
  }

  async command(id: string, revision: number, command: IndexerIncidentCommand): Promise<IndexerIncidentResult> {
    validateIncidentId(id);
    if (!Number.isSafeInteger(revision) || revision < 1 || revision > 2147483647) {
      throw new Error('Invalid incident revision');
    }
    const payload = commandBody(command);
    const { body } = await this.transport.request<IndexerIncidentResult>({
      method: 'POST', path: ROOT + '/' + encodeURIComponent(id) + '/' + command.kind,
      querystring: { expected_revision: revision }, body: payload,
    });
    return validateResult(body, id, revision + 1);
  }
}

function validateResult(body: IndexerIncidentResult, id?: string, revision?: number): IndexerIncidentResult {
  if (!body || !body.incident || !['pending', 'delivered'].includes(body.activity_delivery) || typeof body.replayed !== 'boolean') {
    throw new Error('Invalid incident mutation response; reload before retrying');
  }
  validateSummary(body.incident, id, revision);
  return body;
}

function validateCursor(cursor: QueueCursor): void {
  if (!cursor || !Number.isSafeInteger(cursor.time)) throw new Error('Invalid queue cursor');
  validateIncidentId(cursor.id);
}

function validateSummary(incident: IncidentSummary, id?: string, revision?: number): void {
  if (!incident) throw new Error('Invalid incident projection');
  validateIncidentId(incident.id);
  if (!Number.isSafeInteger(incident.revision) || incident.revision < 1 ||
      (revision !== undefined && incident.revision !== revision) ||
      (id !== undefined && incident.id !== id) ||
      !Number.isSafeInteger(incident.finding_count) || incident.finding_count < 0 ||
      Object.prototype.hasOwnProperty.call(incident, 'pending_activity') ||
      Object.prototype.hasOwnProperty.call(incident, 'findings') ||
      Object.prototype.hasOwnProperty.call(incident, 'create_request_hash')) {
    throw new Error('Invalid incident projection; reload before retrying');
  }
}
