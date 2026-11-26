import { CreateIncident, Classification, Incident, Priority, Severity, Tlp } from './incident-domain';
import { validateIncidentId } from './incident-id';

/** Production routes must bind this transport to asCurrentUser, never an internal
 * administrator client. The indexer is the authority for permissions and state. */
export interface CurrentUserIncidentTransport {
  request<T>(params: {
    method: 'POST';
    path: string;
    querystring?: Record<string, number>;
    body: object;
  }): Promise<{ body: T }>;
}

export type IndexerIncidentCommand =
  | { kind: 'assign-self' | 'unassign' | 'start-triage' | 'activate' }
  | { kind: 'edit'; title?: string; description?: string; severity?: Severity; priority?: Priority; tlp?: Tlp }
  | { kind: 'close'; classification: Classification; reason: string }
  | { kind: 'reopen'; reason: string }
  | { kind: 'attach-finding' | 'detach-finding'; index: string; document_id: string };

export type IncidentSummary = Omit<Incident, 'pending_activity'> & { finding_count: number };
export interface IndexerIncidentResult {
  incident: IncidentSummary;
  activity_delivery: 'delivered' | 'pending';
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

  async create(input: CreateIncident): Promise<IndexerIncidentResult> {
    const { body } = await this.transport.request<IndexerIncidentResult>({
      method: 'POST', path: ROOT,
      body: {
        title: input.title,
        severity: input.severity,
        ...(input.description === undefined ? {} : { description: input.description }),
        ...(input.priority === undefined ? {} : { priority: input.priority }),
        ...(input.tlp === undefined ? {} : { tlp: input.tlp }),
      },
    });
    return validateResult(body);
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
  if (!body || !body.incident || !['pending', 'delivered'].includes(body.activity_delivery)) {
    throw new Error('Invalid incident mutation response; reload before retrying');
  }
  validateIncidentId(body.incident.id);
  if (!Number.isSafeInteger(body.incident.revision) || body.incident.revision < 1 ||
      (revision !== undefined && body.incident.revision !== revision) ||
      (id !== undefined && body.incident.id !== id) ||
      !Number.isSafeInteger(body.incident.finding_count) || body.incident.finding_count < 0 ||
      Object.prototype.hasOwnProperty.call(body.incident, 'pending_activity') ||
      Object.prototype.hasOwnProperty.call(body.incident, 'findings')) {
    throw new Error('Invalid incident mutation projection; reload before retrying');
  }
  return body;
}
