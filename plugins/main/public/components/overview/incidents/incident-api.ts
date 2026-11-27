import { getHttp } from '../../../kibana-services';
import type { IssuedResponsePage, IncidentResponsePage, CollaborationPage, ActivityPage, FindingPage, CreateIncident, IncidentSummary, IndexerIncidentCommand, IndexerIncidentResult, QueuePage, QueueQuery } from '../../../../common/incidents/contracts';

const ROOT = '/indexer/incidents';

export interface IncidentApi {
  issuedResponses(id: string, offset?: number, revision?: number): Promise<IssuedResponsePage>;
  responses(id: string): Promise<IncidentResponsePage>;
  collaboration(id: string, before?: number): Promise<CollaborationPage>;
  activity(id: string, before?: number): Promise<ActivityPage>;
  findings(id: string, offset?: number, revision?: number): Promise<FindingPage>;
  list(query: QueueQuery): Promise<QueuePage>;
  get(id: string): Promise<IncidentSummary>;
  create(input: CreateIncident, requestId: string): Promise<IndexerIncidentResult>;
  command(id: string, revision: number, command: IndexerIncidentCommand): Promise<IndexerIncidentResult>;
}

/** Use the dashboard's authenticated HTTP client, not the manager API or direct index writes. */
export const incidentApi: IncidentApi = {
  async issuedResponses(id, offset = 0, revision = 0) {
    return getHttp().get<IssuedResponsePage>(ROOT + '/' + encodeURIComponent(id) + '/issued-responses', { query: { offset, expected_revision: revision } });
  },
  async responses(id) {
    return getHttp().get<IncidentResponsePage>(ROOT + '/' + encodeURIComponent(id) + '/responses');
  },
  async collaboration(id, before = 0) {
    return getHttp().get<CollaborationPage>(ROOT + '/' + encodeURIComponent(id) + '/collaboration', { query: { before } });
  },
  async activity(id, before = 0) {
    return getHttp().get<ActivityPage>(ROOT + '/' + encodeURIComponent(id) + '/activity', { query: { before } });
  },
  async findings(id, offset = 0, revision = 0) {
    return getHttp().get<FindingPage>(ROOT + '/' + encodeURIComponent(id) + '/findings', { query: { offset, expected_revision: revision } });
  },
  async list({ after, ...query }) {
    return getHttp().get<QueuePage>(ROOT, {
      query: { ...query, ...(after ? { after_time: after.time, after_id: after.id } : {}) },
    });
  },
  async get(id) {
    const result = await getHttp().get<{ incident: IncidentSummary }>(ROOT + '/' + encodeURIComponent(id));
    return result.incident;
  },
  async create(input, requestId) {
    return getHttp().post<IndexerIncidentResult>(ROOT, {
      body: JSON.stringify({ ...input, request_id: requestId }),
    });
  },
  async command(id, revision, command) {
    const { kind, ...body } = command;
    return getHttp().post<IndexerIncidentResult>(ROOT + '/' + encodeURIComponent(id) + '/' + kind, {
      query: { expected_revision: revision },
      body: JSON.stringify(body),
    });
  },
};
