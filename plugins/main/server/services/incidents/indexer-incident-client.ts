import { AnalyticsWindowQuery, AnalyticsStatus, validateWindow, validateAnalyticsStatus } from '../../../common/incidents/analytics-contract';
import { IndicatorInput, IndicatorCatalog, CatalogMutation, validateBatch, validateCatalog, validateMutation, UUID, safeText, timestamp } from '../../../common/incidents/indicator-contract';
import { HuntInput, HuntReport, validateHunt, validateHuntReport } from '../../../common/incidents/hunt-contract';
import { validateInvestigationRegister, validateTags } from '../../../common/incidents/investigation-register-validation';
import type { IssuedResponsePage, IncidentResponsePage, IncidentMetricsQuery, IncidentMetricsReport, CorrelationPolicyDefinition, SavedCorrelationPolicyResult, CorrelationPreview, CorrelationPreviewInput, FindingObservation, CollaborationPage, ActivityPage, FindingPage, CreateIncident, IndexerIncidentCommand, IncidentSummary, QueueCursor, QueueQuery, QueuePage, IndexerIncidentResult } from '../../../common/incidents/contracts';
export type { IndexerIncidentCommand, IncidentSummary, Queue, QueueCursor, QueueQuery, QueuePage, IndexerIncidentResult } from '../../../common/incidents/contracts';
import { validateCorrelationPolicy, validateCorrelationPreview } from '../../../common/incidents/correlation-validation';
import { validateMetricsQuery, validateMetricsReport } from '../../../common/incidents/metrics-validation';
import { validateResponsePage, validateIssuedResponsePage } from '../../../common/incidents/response-validation';
import { validateTuningProposals } from '../../../common/incidents/tuning-proposal-validation';
import { validatePlaybooks } from '../../../common/incidents/playbook-validation';
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

const ROOT = '/_plugins/_setup/incidents';

function commandBody(command: IndexerIncidentCommand): object {
  switch (command.kind) {
    case 'set-tags': return { tags: command.tags };
    case 'add-relation': return { target_id: command.target_id, type: command.type, reason: command.reason };
    case 'remove-relation': return { relation_id: command.relation_id, reason: command.reason };
    case 'register-evidence': return { type: command.type, label: command.label, sha256: command.sha256, custody_reference: command.custody_reference };
    case 'withdraw-evidence': return { evidence_id: command.evidence_id, reason: command.reason };
    case 'offer-handover':
      return { target: command.target, reason: command.reason };
    case 'accept-handover':
    case 'cancel-handover':
      return { reason: command.reason };
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
    case 'add-note':
      return { body: command.body };
    case 'create-task':
      return { title: command.title };
    case 'complete-task':
    case 'reopen-task':
      return { task_id: command.task_id };
    case 'create-tuning-proposal':
      return { rule_uuid: command.rule_uuid, baseline_sha256: command.baseline_sha256, candidate_sha256: command.candidate_sha256,
        type: command.type, reason: command.reason, split: command.split,
        rows: command.rows.map(row => ({ id: row.id, label: row.label, baseline: row.baseline, candidate: row.candidate })) };
    case 'withdraw-tuning-proposal':
      return { proposal_id: command.proposal_id, reason: command.reason };
    case 'review-tuning-proposal':
      return { proposal_id: command.proposal_id, decision: command.decision, fixture_sha256: command.fixture_sha256, reason: command.reason };
    case 'record-ai-feedback':
      return { assessment_id: command.assessment_id, assessed_revision: command.assessed_revision,
        digest_sha256: command.digest_sha256, ...(command.report_sha256 === undefined ? {} : { report_sha256: command.report_sha256 }),
        assessment_mode: command.assessment_mode,
        assessment_rating: command.assessment_rating, hypothesis_review: command.hypothesis_review };
    case 'apply-playbook':
      return { template_id: command.template_id, version: command.version };
    case 'request-response':
      return { type: command.type, scope: command.scope, reason: command.reason };
    case 'approve-response':
    case 'reject-response':
    case 'cancel-response':
      return { response_id: command.response_id, reason: command.reason };
    case 'record-response-outcome':
      return { response_id: command.response_id, outcome: command.outcome, reason: command.reason };
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

  async analyticsStatus(input: AnalyticsWindowQuery): Promise<AnalyticsStatus> {
    let query: AnalyticsWindowQuery;
    try { query = validateWindow(input); } catch (_) { throw { statusCode: 400 }; }
    const { body } = await this.transport.request<AnalyticsStatus>({ method: 'POST', path: '/_plugins/_setup/incident-analytics/status', body: query });
    return validateAnalyticsStatus(body, query);
  }

  async indicators(): Promise<IndicatorCatalog> {
    const { body } = await this.transport.request<IndicatorCatalog>({ method: 'POST', path: '/_plugins/_setup/incident-indicators/read', body: {} });
    return validateCatalog(body);
  }
  async addIndicators(expected: number, items: IndicatorInput[]): Promise<CatalogMutation> {
    let entries: IndicatorInput[];
    try {
      if (!Number.isSafeInteger(expected) || expected < 0 || expected >= 2147483647) throw new Error('Invalid revision');
      entries = validateBatch(items);
    } catch (_) { throw { statusCode: 400 }; }
    const payload = { operation: 'add', expected_revision: expected, indicators: entries };
    if (Buffer.byteLength(JSON.stringify(payload), 'utf8') > 16384) throw { statusCode: 400 };
    const { body } = await this.transport.request<CatalogMutation>({ method: 'POST', path: '/_plugins/_setup/incident-indicators/save', body: payload });
    return validateMutation(body, expected, entries.length);
  }
  async revokeIndicator(expected: number, id: string, reason: string): Promise<CatalogMutation> {
    if (!Number.isSafeInteger(expected) || expected < 1 || expected >= 2147483647 || !UUID.test(id) || !safeText(reason, 1024)) throw { statusCode: 400 };
    const { body } = await this.transport.request<CatalogMutation>({ method: 'POST', path: '/_plugins/_setup/incident-indicators/save',
      body: { operation: 'revoke', expected_revision: expected, id, reason } });
    return validateMutation(body, expected, 1);
  }

  async recordIndicatorSighting(expected: number, id: string, observedAt: string, source: string, count: number): Promise<CatalogMutation> {
    try {
      if (!Number.isSafeInteger(expected) || expected < 1 || expected >= 2147483647 || !UUID.test(id) ||
          !safeText(source, 256) || !Number.isSafeInteger(count) || count < 1 || count > 1000000) throw new Error('Invalid sighting');
      timestamp(observedAt);
    } catch (_) { throw { statusCode: 400 }; }
    const { body } = await this.transport.request<CatalogMutation>({ method: 'POST', path: '/_plugins/_setup/incident-indicators/save',
      body: { operation: 'record-sighting', expected_revision: expected, id, observed_at: observedAt, source, count } });
    return validateMutation(body, expected, 1);
  }
  async withdrawIndicatorSighting(expected: number, id: string, sightingRevision: number, reason: string): Promise<CatalogMutation> {
    if (!Number.isSafeInteger(expected) || expected < 1 || expected >= 2147483647 || !UUID.test(id) ||
        !Number.isSafeInteger(sightingRevision) || sightingRevision < 1 || sightingRevision > expected || !safeText(reason, 1024)) throw { statusCode: 400 };
    const { body } = await this.transport.request<CatalogMutation>({ method: 'POST', path: '/_plugins/_setup/incident-indicators/save',
      body: { operation: 'withdraw-sighting', expected_revision: expected, id, sighting_revision: sightingRevision, reason } });
    return validateMutation(body, expected, 1);
  }

  async hunt(input: HuntInput): Promise<HuntReport> {
    let payload: HuntInput;
    try { payload = validateHunt(input); } catch (_) { throw { statusCode: 400 }; }
    const { body } = await this.transport.request<HuntReport>({
      method: 'POST', path: '/_plugins/_setup/incident-hunt/search', body: payload,
    });
    return validateHuntReport(body, payload);
  }

  async issuedResponses(id: string, offset = 0, expectedRevision = 0, limit = 25): Promise<IssuedResponsePage> {
    validateIncidentId(id);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000 ||
        !Number.isSafeInteger(limit) || limit < 1 || limit > 25 ||
        !Number.isSafeInteger(expectedRevision) || expectedRevision < 0 || expectedRevision > 2147483647 ||
        (offset > 0 && expectedRevision === 0)) throw new Error('Invalid issued response page');
    const { body } = await this.transport.request<IssuedResponsePage>({
      method: 'GET', path: ROOT + '/' + encodeURIComponent(id) + '/issued-responses',
      querystring: { offset, expected_revision: expectedRevision, limit },
    });
    validateIssuedResponsePage(body, offset, limit, expectedRevision);
    return body;
  }

  async responses(id: string): Promise<IncidentResponsePage> {
    validateIncidentId(id);
    const { body } = await this.transport.request<IncidentResponsePage>({
      method: 'GET', path: ROOT + '/' + encodeURIComponent(id) + '/responses',
    });
    validateResponsePage(body, id);
    return body;
  }

  async metrics(input: IncidentMetricsQuery): Promise<IncidentMetricsReport> {
    validateMetricsQuery(input);
    const { body } = await this.transport.request<IncidentMetricsReport>({
      method: 'POST', path: '/_plugins/_setup/incident-metrics/report',
      body: { from: input.from, until: input.until, triage_target_seconds: input.triage_target_seconds,
        resolution_target_seconds: input.resolution_target_seconds },
    });
    validateMetricsReport(body, input);
    return body;
  }

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

  async saveCorrelationPolicy(input: CorrelationPolicyDefinition): Promise<SavedCorrelationPolicyResult> {
    validateCorrelationPolicy(input);
    const { body } = await this.transport.request<SavedCorrelationPolicyResult>({
      method: 'POST', path: '/_plugins/_setup/incident-correlation/policies/save',
      body: { policy_id: input.policy_id, policy_version: input.policy_version, rules: input.rules,
        window_minutes: input.window_minutes, minimum_findings: input.minimum_findings },
    });
    validateSavedPolicy(body, input.policy_id, input.policy_version);
    if (typeof body.replayed !== 'boolean' ||
        JSON.stringify([...body.policy.rules].sort()) !== JSON.stringify([...input.rules].sort()) ||
        body.policy.window_minutes !== input.window_minutes || body.policy.minimum_findings !== input.minimum_findings) {
      throw new Error('Saved correlation policy does not match request');
    }
    return body;
  }

  async readCorrelationPolicy(id: string, version: number): Promise<SavedCorrelationPolicyResult> {
    validateIncidentId(id);
    if (!Number.isSafeInteger(version) || version < 1 || version > 2147483647) throw new Error('Invalid policy version');
    const { body } = await this.transport.request<SavedCorrelationPolicyResult>({
      method: 'POST', path: '/_plugins/_setup/incident-correlation/policies/read',
      body: { policy_id: id, policy_version: version },
    });
    validateSavedPolicy(body, id, version);
    return body;
  }

  async correlationPreview(input: CorrelationPreviewInput): Promise<CorrelationPreview> {
    validateCorrelationPreview(input);
    const { body } = await this.transport.request<CorrelationPreview>({
      method: 'POST', path: '/_plugins/_setup/incident-correlation/preview',
      body: { policy_id: input.policy_id, policy_version: input.policy_version, rules: input.rules,
        window_minutes: input.window_minutes, minimum_findings: input.minimum_findings, from: input.from, until: input.until },
    });
    const countFields = ['distinct_candidates', 'duplicate_inputs', 'insufficient_identity', 'excluded_rule', 'outside_range', 'below_threshold'] as const;
    if (!body || body.mode !== 'preview' || body.scope !== 'caller_visible_search_snapshot' ||
        body.policy_id !== input.policy_id || body.policy_version !== input.policy_version ||
        Date.parse(body.from) !== Date.parse(input.from) || Date.parse(body.until) !== Date.parse(input.until) ||
        !Array.isArray(body.groups) || body.groups.length > 500 ||
        countFields.some(key => !Number.isSafeInteger(body[key]) || body[key] < 0 || body[key] > 1000)) {
      throw new Error('Invalid correlation preview response');
    }
    const refs = new Set<string>(), keys = new Set<string>();
    for (const group of body.groups) {
      const start = Date.parse(group.window_start), end = Date.parse(group.window_end);
      if (!/^[a-f0-9]{64}$/.test(group.key) || keys.has(group.key) ||
          !Number.isFinite(start) || !Number.isFinite(end) || start < Date.parse(input.from) ||
          end > Date.parse(input.until) || end - start !== input.window_minutes * 60000 ||
          start % (input.window_minutes * 60000) !== 0 ||
          !Array.isArray(group.findings) || group.findings.length < input.minimum_findings ||
          group.findings.length > 1000) throw new Error('Invalid correlation group');
      keys.add(group.key);
      for (const ref of group.findings) {
        if (!ref || typeof ref.index !== 'string' || typeof ref.document_id !== 'string' ||
            Object.keys(ref).some(key => key !== 'index' && key !== 'document_id')) throw new Error('Invalid finding reference');
        const key = JSON.stringify([ref.index, ref.document_id]);
        if (refs.has(key)) throw new Error('Duplicate correlation finding');
        refs.add(key);
      }
    }
    if (refs.size + body.insufficient_identity + body.excluded_rule + body.outside_range + body.below_threshold !== body.distinct_candidates ||
        body.distinct_candidates + body.duplicate_inputs > 1000) throw new Error('Correlation counts do not reconcile');
    return body;
  }

  async collaboration(id: string, before = 0, limit = 50): Promise<CollaborationPage> {
    validateIncidentId(id);
    if (!Number.isSafeInteger(before) || before < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 50) {
      throw new Error('Invalid collaboration page');
    }
    const { body } = await this.transport.request<CollaborationPage>({
      method: 'GET', path: ROOT + '/' + encodeURIComponent(id) + '/collaboration', querystring: { before, limit },
    });
    if (!body || !Array.isArray(body.notes) || body.notes.length > limit || !Array.isArray(body.tasks) || body.tasks.length > 100 ||
        !Number.isSafeInteger(body.observed_revision) || body.observed_revision < 1 || typeof body.activity_pending !== 'boolean' ||
        body.notes.some(note => note.incident_id !== id || note.id !== id + ':' + note.revision ||
          !Number.isSafeInteger(note.revision) || note.revision < 1 || note.revision > body.observed_revision ||
          typeof note.body !== 'string' || note.body.length > 8192) ||
        body.tasks.some(task => typeof task.id !== 'string' || !task.id.startsWith(id + ':') ||
          typeof task.title !== 'string' || !['open', 'completed'].includes(task.status))) {
      throw new Error('Invalid collaboration response');
    }
    validatePlaybooks(body, id);
    validateTuningProposals(body, id);
    validateInvestigationRegister(body, id);
    return body;
  }

  async activity(id: string, before = 0, limit = 50): Promise<ActivityPage> {
    validateIncidentId(id);
    if (!Number.isSafeInteger(before) || before < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new Error('Invalid activity page');
    }
    const { body } = await this.transport.request<ActivityPage>({
      method: 'GET', path: ROOT + '/' + encodeURIComponent(id) + '/activity',
      querystring: { before, limit },
    });
    if (!body || !Array.isArray(body.events) || body.events.length > limit ||
        !Number.isSafeInteger(body.observed_revision) || typeof body.activity_pending !== 'boolean' ||
        body.events.some(event => event.incident_id !== id || !Number.isSafeInteger(event.revision) ||
          event.revision < 1 || event.revision > body.observed_revision ||
          event.id !== id + ':' + event.revision)) throw new Error('Invalid incident activity response');
    return body;
  }

  async findings(id: string, offset = 0, expectedRevision = 0, limit = 25): Promise<FindingPage> {
    validateIncidentId(id);
    if (!Number.isSafeInteger(offset) || offset < 0 || offset > 1000 ||
        !Number.isSafeInteger(expectedRevision) || expectedRevision < 0 || (offset > 0 && !expectedRevision) ||
        !Number.isSafeInteger(limit) || limit < 1 || limit > 25) throw new Error('Invalid finding page');
    const { body } = await this.transport.request<FindingPage>({
      method: 'GET', path: ROOT + '/' + encodeURIComponent(id) + '/findings',
      querystring: { offset, expected_revision: expectedRevision, limit },
    });
    if (!body || !Array.isArray(body.findings) || !Number.isSafeInteger(body.revision) ||
        (expectedRevision > 0 && body.revision !== expectedRevision) ||
        !Number.isSafeInteger(body.unavailable_count) || body.unavailable_count < 0 ||
        body.findings.length + body.unavailable_count > limit ||
        (body.next_offset !== undefined && (!Number.isSafeInteger(body.next_offset) || body.next_offset !== offset + limit || body.next_offset > 1000)) ||
        body.findings.some(ref => typeof ref.index !== 'string' || typeof ref.document_id !== 'string' ||
          Object.keys(ref).some(key => key !== 'index' && key !== 'document_id'))) {
      throw new Error('Invalid incident finding response');
    }
    if (body.observations !== undefined) {
      if (!Array.isArray(body.observations) || body.observations.length !== body.findings.length ||
          body.observations.some((observation, index) => !validObservation(observation) ||
            observation.index !== body.findings[index].index || observation.document_id !== body.findings[index].document_id)) {
        throw new Error('Invalid finding intelligence projection');
      }
    }
    return body;
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
  if (incident.tags !== undefined) validateTags(incident.tags);
  const offer = incident.handover;
  if (offer !== undefined && offer !== null &&
      (typeof offer !== 'object' || Object.keys(offer).length !== 3 ||
       typeof offer.target !== 'string' || !offer.target.trim() || offer.target.length > 1024 ||
       typeof offer.offered_by !== 'string' || offer.offered_by !== incident.owner || offer.target === offer.offered_by ||
       typeof offer.offered_at !== 'string' || !Number.isFinite(Date.parse(offer.offered_at)) ||
       incident.status === 'closed')) throw new Error('Invalid incident handover projection');
  validateIncidentId(incident.id);
  if (!Number.isSafeInteger(incident.revision) || incident.revision < 1 ||
      (revision !== undefined && incident.revision !== revision) ||
      (id !== undefined && incident.id !== id) ||
      !Number.isSafeInteger(incident.finding_count) || incident.finding_count < 0 ||
      Object.prototype.hasOwnProperty.call(incident, 'pending_activity') ||
      Object.prototype.hasOwnProperty.call(incident, 'findings') ||
      Object.prototype.hasOwnProperty.call(incident, 'create_request_hash') ||
      Object.prototype.hasOwnProperty.call(incident, 'response_requests') ||
      Object.prototype.hasOwnProperty.call(incident, 'playbook_runs') ||
      Object.prototype.hasOwnProperty.call(incident, 'ai_feedback_ids') ||
      Object.prototype.hasOwnProperty.call(incident, 'tuning_proposals') ||
      Object.prototype.hasOwnProperty.call(incident, 'incident_relations') ||
      Object.prototype.hasOwnProperty.call(incident, 'evidence_register')) {
    throw new Error('Invalid incident projection; reload before retrying');
  }
}

function validObservation(value: FindingObservation): boolean {
  const nullableText = (text: unknown) => text === null || (typeof text === 'string' && text.length <= 1024);
  return !!value && Object.keys(value).every(key => ['index', 'document_id', 'timestamp', 'rule_id', 'rule_title', 'wazuh_rule_id', 'wazuh_rule_uuid', 'entities', 'techniques', 'tactics'].includes(key)) &&
    nullableText(value.timestamp) && nullableText(value.rule_id) && nullableText(value.rule_title) &&
    (value.wazuh_rule_id === undefined || value.wazuh_rule_id === null || (typeof value.wazuh_rule_id === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value.wazuh_rule_id))) &&
    (value.wazuh_rule_uuid === undefined || value.wazuh_rule_uuid === null || (typeof value.wazuh_rule_uuid === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.wazuh_rule_uuid))) &&
    Array.isArray(value.entities) && value.entities.length <= 240 &&
    value.entities.every(entity => !!entity && Object.keys(entity).every(key => ['kind', 'value', 'field'].includes(key)) &&
      typeof entity.kind === 'string' && entity.kind.length <= 64 && typeof entity.field === 'string' && entity.field.length <= 128 &&
      typeof entity.value === 'string' && entity.value.length <= 1024) &&
    Array.isArray(value.techniques) && value.techniques.length <= 96 && value.techniques.every(id => typeof id === 'string' && /^T[0-9]{4}(\.[0-9]{3})?$/.test(id)) &&
    Array.isArray(value.tactics) && value.tactics.length <= 48 && value.tactics.every(id => typeof id === 'string' && /^TA[0-9]{4}$/.test(id));
}

function validateSavedPolicy(body: SavedCorrelationPolicyResult, id: string, version: number): void {
  const policy = body?.policy;
  if (!policy || policy.policy_id !== id || policy.policy_version !== version ||
      policy.mode !== 'preview_only' || typeof policy.created_by !== 'string' ||
      !Number.isFinite(Date.parse(policy.created_at)) ||
      Object.keys(policy).some(key => !['policy_id', 'policy_version', 'rules', 'window_minutes', 'minimum_findings', 'mode', 'created_by', 'created_at'].includes(key))) {
    throw new Error('Invalid saved policy response');
  }
  validateCorrelationPolicy(policy);
}
