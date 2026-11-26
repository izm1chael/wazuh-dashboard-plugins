import { PLAYBOOKS as AUTOMATION_PLAYBOOKS, STATUSES as AUTOMATION_STATUSES } from '../../common/incidents/automation-contract';
import { INDICATOR_TYPES, INDICATOR_TLP } from '../../common/incidents/indicator-contract';
import { HUNT_FIELDS } from '../../common/incidents/hunt-contract';
import { EVIDENCE_TYPES, RELATION_TYPES } from '../../common/incidents/contracts';
import { IRouter, RequestHandlerContext, OpenSearchDashboardsResponseFactory } from 'opensearch_dashboards/server';
import { schema } from '@osd/config-schema';
import { TUNING_TYPES } from '../../common/incidents/tuning-proposal-validation';
import { ruleHistory } from '../services/incidents/rule-history-service';
import { RESPONSE_INTENTS, RESPONSE_OUTCOMES } from '../../common/incidents/response-validation';
import { IndexerIncidentClient, CurrentUserIncidentTransport, IndexerIncidentCommand, QueueQuery } from '../services/incidents/indexer-incident-client';
import { IncidentDomainError, SEVERITIES, PRIORITIES, TLP_VALUES, CLASSIFICATIONS } from '../services/incidents/incident-domain';

const ROOT = '/indexer/incidents';
const idSchema = schema.string({ minLength: 36, maxLength: 36 });
const revisionSchema = schema.number({ min: 1, max: 2147483647 });
const severitySchema = schema.oneOf(SEVERITIES.map(value => schema.literal(value)));
const prioritySchema = schema.oneOf(PRIORITIES.map(value => schema.literal(value)));
const tlpSchema = schema.oneOf(TLP_VALUES.map(value => schema.literal(value)));
const classificationSchema = schema.oneOf(CLASSIFICATIONS.map(value => schema.literal(value)));
const reasonSchema = schema.string({ minLength: 1, maxLength: 8192 });

function client(context: RequestHandlerContext): IndexerIncidentClient {
  const transport = context.core.opensearch.client.asCurrentUser.transport;
  // Explicitly use the original user; no internal/admin fallback.
  const adapter: CurrentUserIncidentTransport = {
    async request<T>(params: Parameters<CurrentUserIncidentTransport['request']>[0]) {
      const result = await transport.request(params);
      return { body: result.body as T };
    },
  };
  return new IndexerIncidentClient(adapter);
}

async function respond<T extends object>(
  response: OpenSearchDashboardsResponseFactory,
  work: () => Promise<T>,
) {
  try {
    return response.ok({ body: await work() });
  } catch (error) {
    const e = error as { meta?: { statusCode?: number }; statusCode?: number };
    const status = error instanceof IncidentDomainError ? (error.code === 'conflict' ? 409 : 400) : e?.meta?.statusCode ?? e?.statusCode;
    // Do not forward arbitrary indexer errors or request bodies to the browser.
    const messages: Record<number, string> = {
      400: 'Invalid incident request.',
      401: 'Authentication required.',
      403: 'Incident operation forbidden or disabled.',
      404: 'Incident or finding unavailable.',
      409: 'Incident changed or request conflicts. Reload before retrying.',
      429: 'Incident service is busy.',
    };
    const code = status && messages[status] ? status : 503;
    return response.customError({
      statusCode: code,
      body: { message: messages[code] ?? 'Incident service unavailable. Reload before retrying.' },
    });
  }
}

// Keep this potentially expensive fan-out separate from ordinary queue requests.
let historyRunning = false;
let huntRunning = false;
export function registerIncidentRoutes(router: IRouter) {
  const tagArray = schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 25 });
  const automationActions = schema.object({
    assign_to: schema.maybe(schema.string({ minLength: 1, maxLength: 1024 })),
    raise_severity: schema.maybe(severitySchema), raise_priority: schema.maybe(prioritySchema),
    add_tags: schema.maybe(tagArray), create_task: schema.maybe(schema.string({ minLength: 1, maxLength: 1024 })),
    apply_playbook: schema.maybe(schema.oneOf(AUTOMATION_PLAYBOOKS.map(value => schema.literal(value)))),
  });
  router.post({ path: '/indexer/incident-automation/save', validate: { body: schema.object({
    policy_id: idSchema, policy_version: revisionSchema,
    rules: schema.arrayOf(schema.object({
      id: schema.string({ minLength: 1, maxLength: 64 }),
      trigger: schema.oneOf([schema.literal('created'), schema.literal('updated')]),
      minimum_severity: severitySchema, status: schema.oneOf(AUTOMATION_STATUSES.map(value => schema.literal(value))),
      minimum_findings: schema.number({ min: 0, max: 1000 }), unassigned_only: schema.boolean(),
      required_tags: tagArray, actions: automationActions,
    }), { minSize: 1, maxSize: 10 }),
  }) } }, async (context, request, response) => respond(response, () => client(context).saveAutomation(
    JSON.parse(JSON.stringify(request.body)))));
  router.post({ path: '/indexer/incident-automation/read', validate: { body: schema.object({
    policy_id: idSchema, policy_version: revisionSchema,
  }) } }, async (context, request, response) => respond(response, () => client(context).readAutomation(request.body)));
  router.post({ path: '/indexer/incident-automation/preview', validate: { body: schema.object({
    policy_id: idSchema, policy_version: revisionSchema, incident_id: idSchema,
  }) } }, async (context, request, response) => respond(response, () => client(context).previewAutomation(
    { policy_id: request.body.policy_id, policy_version: request.body.policy_version }, request.body.incident_id)));
  router.post({ path: '/indexer/incident-automation/history', validate: { body: schema.object({ incident_id: idSchema }) } },
    async (context, request, response) => respond(response, () => client(context).automationHistory(request.body.incident_id)));

  router.post({ path: '/indexer/incident-analytics/status', validate: { body: schema.object({
    policy_id: idSchema, policy_version: revisionSchema,
    from: schema.string({ minLength: 20, maxLength: 20 }),
    until: schema.string({ minLength: 20, maxLength: 20 }),
  }) } }, async (context, request, response) => respond(response, () => client(context).analyticsStatus(request.body)));

  const indicatorInput = schema.object({
    type: schema.oneOf(INDICATOR_TYPES.map(value => schema.literal(value))),
    value: schema.string({ minLength: 1, maxLength: 253 }),
    source: schema.string({ minLength: 1, maxLength: 256 }),
    external_id: schema.maybe(schema.string({ minLength: 47, maxLength: 47 })),
    confidence: schema.number({ min: 0, max: 100 }),
    tlp: schema.oneOf(INDICATOR_TLP.map(value => schema.literal(value))),
    valid_from: schema.string({ minLength: 20, maxLength: 24 }),
    valid_until: schema.string({ minLength: 20, maxLength: 24 }),
  });
  const catalogRevision = schema.number({ min: 0, max: 2147483646 });
  router.post({ path: '/indexer/incident-indicators/read', validate: { body: schema.object({}) } },
    async (context, request, response) => respond(response, () => client(context).indicators()));
  router.post({ path: '/indexer/incident-indicators/add', validate: { body: schema.object({
    expected_revision: catalogRevision, indicators: schema.arrayOf(indicatorInput, { minSize: 1, maxSize: 20 }),
  }) } }, async (context, request, response) => respond(response, () => client(context).addIndicators(
    request.body.expected_revision, request.body.indicators.map(row => ({ ...row, external_id: row.external_id ?? null })))));
  router.post({ path: '/indexer/incident-indicators/revoke', validate: { body: schema.object({
    expected_revision: catalogRevision, id: idSchema, reason: schema.string({ minLength: 1, maxLength: 1024 }),
  }) } }, async (context, request, response) => respond(response, () => client(context).revokeIndicator(
    request.body.expected_revision, request.body.id, request.body.reason)));

  router.post({ path: '/indexer/incident-indicators/record-sighting', validate: { body: schema.object({
    expected_revision: catalogRevision, id: idSchema, observed_at: schema.string({ minLength: 20, maxLength: 24 }),
    source: schema.string({ minLength: 1, maxLength: 256 }), count: schema.number({ min: 1, max: 1000000 }),
  }) } }, async (context, request, response) => respond(response, () => client(context).recordIndicatorSighting(
    request.body.expected_revision, request.body.id, request.body.observed_at, request.body.source, request.body.count)));
  router.post({ path: '/indexer/incident-indicators/withdraw-sighting', validate: { body: schema.object({
    expected_revision: catalogRevision, id: idSchema, sighting_revision: revisionSchema, reason: schema.string({ minLength: 1, maxLength: 1024 }),
  }) } }, async (context, request, response) => respond(response, () => client(context).withdrawIndicatorSighting(
    request.body.expected_revision, request.body.id, request.body.sighting_revision, request.body.reason)));

  router.post({
    path: '/indexer/incident-hunt/search',
    validate: { body: schema.object({
      field: schema.oneOf(HUNT_FIELDS.map(value => schema.literal(value))),
      values: schema.arrayOf(schema.string({ minLength: 1, maxLength: 256 }), { minSize: 1, maxSize: 20 }),
      from: schema.string({ minLength: 20, maxLength: 30 }),
      until: schema.string({ minLength: 20, maxLength: 30 }),
    }) },
  }, async (context, request, response) => respond(response, async () => {
    if (huntRunning) throw { statusCode: 429 };
    huntRunning = true;
    try { return await client(context).hunt(request.body); }
    finally { huntRunning = false; }
  }));

  router.get({
    path: ROOT + '/{id}/rule-history',
    validate: { params: schema.object({ id: idSchema }), query: schema.object({
      expected_revision: revisionSchema, rule_uuid: idSchema,
    }) },
  }, async (context, request, response) => respond(response, async () => {
    if (historyRunning) throw { statusCode: 429 };
    historyRunning = true;
    const deadline = Date.now() + 30000;
    let aborted = false;
    const subscription = request.events.aborted$.subscribe(() => { aborted = true; });
    try {
      return await ruleHistory(client(context), request.params.id, request.query.expected_revision, request.query.rule_uuid, () => {
        if (aborted || Date.now() > deadline) throw { statusCode: 503 };
      });
    } finally { subscription.unsubscribe(); historyRunning = false; }
  }));

  router.post({
    path: '/indexer/incident-metrics/report',
    validate: { body: schema.object({
      from: schema.string({ minLength: 20, maxLength: 30 }),
      until: schema.string({ minLength: 20, maxLength: 30 }),
      triage_target_seconds: schema.number({ min: 1, max: 86400 }),
      resolution_target_seconds: schema.number({ min: 1, max: 604800 }),
    }) },
  }, async (context, request, response) => respond(response, () => client(context).metrics(request.body)));

  router.post({
    path: '/indexer/incident-correlation/policies/save',
    validate: { body: schema.object({
      policy_id: idSchema, policy_version: revisionSchema,
      rules: schema.arrayOf(idSchema, { minSize: 1, maxSize: 100 }),
      window_minutes: schema.number({ min: 5, max: 1440 }),
      minimum_findings: schema.number({ min: 2, max: 100 }),
    }) },
  }, async (context, request, response) => respond(response, () => client(context).saveCorrelationPolicy(request.body)));

  router.post({
    path: '/indexer/incident-correlation/policies/read',
    validate: { body: schema.object({ policy_id: idSchema, policy_version: revisionSchema }) },
  }, async (context, request, response) => respond(response, () =>
    client(context).readCorrelationPolicy(request.body.policy_id, request.body.policy_version)));

  router.post({
    path: '/indexer/incident-correlation/preview',
    validate: { body: schema.object({
      policy_id: idSchema, policy_version: revisionSchema,
      rules: schema.arrayOf(idSchema, { minSize: 1, maxSize: 100 }),
      window_minutes: schema.number({ min: 5, max: 1440 }),
      minimum_findings: schema.number({ min: 2, max: 100 }),
      from: schema.string({ minLength: 20, maxLength: 30 }),
      until: schema.string({ minLength: 20, maxLength: 30 }),
    }) },
  }, async (context, request, response) => respond(response, () =>
    client(context).correlationPreview(request.body)));

  router.get({
    path: ROOT,
    validate: { query: schema.object({
      queue: schema.maybe(schema.oneOf(['open', 'mine', 'handover', 'new', 'triaging', 'active', 'closed', 'unassigned', 'all'].map(value => schema.literal(value)))),
      severity: schema.maybe(severitySchema),
      owner: schema.maybe(schema.string({ maxLength: 1024 })),
      search: schema.maybe(schema.string({ maxLength: 1024 })),
      limit: schema.maybe(schema.number({ min: 1, max: 100 })),
      after_time: schema.maybe(schema.number()),
      after_id: schema.maybe(idSchema),
    }) },
  }, async (context, request, response) => respond(response, async () => {
    const { after_time, after_id, ...query } = request.query;
    if ((after_time === undefined) !== (after_id === undefined)) {
      throw { statusCode: 400 };
    }
    return client(context).list({
      ...query,
      ...(after_time === undefined ? {} : { after: { time: after_time, id: after_id! } }),
    } as QueueQuery);
  }));

  router.get({
    path: ROOT + '/{id}',
    validate: { params: schema.object({ id: idSchema }) },
  }, async (context, request, response) => respond(response, async () => ({
    incident: await client(context).get(request.params.id),
  })));

  router.get({
    path: ROOT + '/{id}/issued-responses',
    validate: { params: schema.object({ id: idSchema }), query: schema.object({
      offset: schema.number({ min: 0, max: 1000, defaultValue: 0 }),
      expected_revision: schema.number({ min: 0, max: 2147483647, defaultValue: 0 }),
      limit: schema.number({ min: 1, max: 25, defaultValue: 25 }),
    }) },
  }, async (context, request, response) => respond(response, () =>
    client(context).issuedResponses(request.params.id, request.query.offset, request.query.expected_revision, request.query.limit)));

  router.get({
    path: ROOT + '/{id}/responses', validate: { params: schema.object({ id: idSchema }) },
  }, async (context, request, response) => respond(response, () => client(context).responses(request.params.id)));

  router.get({
    path: ROOT + '/{id}/collaboration',
    validate: { params: schema.object({ id: idSchema }), query: schema.object({
      before: schema.number({ min: 0, max: 2147483647, defaultValue: 0 }),
      limit: schema.number({ min: 1, max: 50, defaultValue: 50 }),
    }) },
  }, async (context, request, response) => respond(response, () =>
    client(context).collaboration(request.params.id, request.query.before, request.query.limit)));

  router.get({
    path: ROOT + '/{id}/activity',
    validate: { params: schema.object({ id: idSchema }), query: schema.object({
      before: schema.number({ min: 0, max: 2147483647, defaultValue: 0 }),
      limit: schema.number({ min: 1, max: 100, defaultValue: 50 }),
    }) },
  }, async (context, request, response) => respond(response, () =>
    client(context).activity(request.params.id, request.query.before, request.query.limit)));

  router.get({
    path: ROOT + '/{id}/findings',
    validate: { params: schema.object({ id: idSchema }), query: schema.object({
      offset: schema.number({ min: 0, max: 1000, defaultValue: 0 }),
      expected_revision: schema.number({ min: 0, max: 2147483647, defaultValue: 0 }),
      limit: schema.number({ min: 1, max: 25, defaultValue: 25 }),
    }) },
  }, async (context, request, response) => respond(response, () =>
    client(context).findings(request.params.id, request.query.offset, request.query.expected_revision, request.query.limit)));

  router.post({
    path: ROOT,
    validate: { body: schema.object({
      request_id: idSchema,
      title: schema.string({ minLength: 1, maxLength: 1024 }),
      description: schema.maybe(schema.string({ maxLength: 32768 })),
      severity: severitySchema,
      priority: schema.maybe(prioritySchema),
      tlp: schema.maybe(tlpSchema),
    }) },
  }, async (context, request, response) => respond(response, async () => {
    const { request_id, ...input } = request.body;
    return client(context).create(input, request_id);
  }));

  // No generic proxy: each command has a static route and a bounded body schema.
  const params = schema.object({ id: idSchema });
  const query = schema.object({ expected_revision: revisionSchema });

  for (const kind of ['assign-self', 'unassign', 'start-triage', 'activate'] as const) {
    router.post({ path: ROOT + '/{id}/' + kind, validate: { params, query, body: schema.object({}) } },
      async (context, request, response) => respond(response, () =>
        client(context).command(request.params.id, request.query.expected_revision, { kind })));
  }

  router.post({ path: ROOT + '/{id}/offer-handover', validate: { params, query, body: schema.object({
    target: schema.string({ minLength: 1, maxLength: 1024 }), reason: reasonSchema,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'offer-handover', ...request.body })));
  for (const kind of ['accept-handover', 'cancel-handover'] as const) {
    router.post({ path: ROOT + '/{id}/' + kind, validate: { params, query, body: schema.object({ reason: reasonSchema }) } },
      async (context, request, response) => respond(response, () =>
        client(context).command(request.params.id, request.query.expected_revision, { kind, ...request.body })));
  }
  router.post({ path: ROOT + '/{id}/edit', validate: { params, query, body: schema.object({
    title: schema.maybe(schema.string({ minLength: 1, maxLength: 1024 })),
    description: schema.maybe(schema.string({ maxLength: 32768 })),
    severity: schema.maybe(severitySchema), priority: schema.maybe(prioritySchema), tlp: schema.maybe(tlpSchema),
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'edit', ...request.body })));

  router.post({ path: ROOT + '/{id}/close', validate: { params, query, body: schema.object({
    classification: classificationSchema, reason: reasonSchema,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'close', ...request.body })));

  router.post({ path: ROOT + '/{id}/reopen', validate: { params, query, body: schema.object({ reason: reasonSchema }) } },
    async (context, request, response) => respond(response, () =>
      client(context).command(request.params.id, request.query.expected_revision, { kind: 'reopen', ...request.body })));

  const registerReason = schema.string({ minLength: 1, maxLength: 1024 });
  router.post({ path: ROOT + '/{id}/set-tags', validate: { params, query, body: schema.object({
    tags: schema.arrayOf(schema.string({ minLength: 1, maxLength: 64 }), { maxSize: 25 }),
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'set-tags', ...request.body })));
  router.post({ path: ROOT + '/{id}/add-relation', validate: { params, query, body: schema.object({
    target_id: idSchema, type: schema.oneOf(RELATION_TYPES.map(value => schema.literal(value))), reason: registerReason,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'add-relation', ...request.body })));
  router.post({ path: ROOT + '/{id}/remove-relation', validate: { params, query, body: schema.object({
    relation_id: schema.string({ minLength: 1, maxLength: 64 }), reason: registerReason,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'remove-relation', ...request.body })));
  router.post({ path: ROOT + '/{id}/register-evidence', validate: { params, query, body: schema.object({
    type: schema.oneOf(EVIDENCE_TYPES.map(value => schema.literal(value))), label: schema.string({ minLength: 1, maxLength: 256 }),
    sha256: schema.string({ minLength: 64, maxLength: 64 }), custody_reference: schema.string({ minLength: 1, maxLength: 256 }),
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'register-evidence', ...request.body })));
  router.post({ path: ROOT + '/{id}/withdraw-evidence', validate: { params, query, body: schema.object({
    evidence_id: schema.string({ minLength: 1, maxLength: 64 }), reason: registerReason,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'withdraw-evidence', ...request.body })));

  router.post({ path: ROOT + '/{id}/add-note', validate: { params, query, body: schema.object({
    body: schema.string({ minLength: 1, maxLength: 8192 }),
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'add-note', ...request.body })));

  router.post({ path: ROOT + '/{id}/create-task', validate: { params, query, body: schema.object({
    title: schema.string({ minLength: 1, maxLength: 1024 }),
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'create-task', ...request.body })));

  for (const kind of ['complete-task', 'reopen-task'] as const) {
    router.post({ path: ROOT + '/{id}/' + kind, validate: { params, query, body: schema.object({
      task_id: schema.string({ minLength: 1, maxLength: 64 }),
    }) } }, async (context, request, response) => respond(response, () =>
      client(context).command(request.params.id, request.query.expected_revision, { kind, ...request.body })));
  }

  const tuningHash = schema.string({ minLength: 64, maxLength: 64 });
  const tuningReason = schema.string({ minLength: 1, maxLength: 2048 });
  const proposalId = schema.string({ minLength: 1, maxLength: 64 });
  router.post({ path: ROOT + '/{id}/create-tuning-proposal', validate: { params, query, body: schema.object({
    rule_uuid: idSchema, baseline_sha256: tuningHash, candidate_sha256: tuningHash,
    type: schema.oneOf(TUNING_TYPES.map(value => schema.literal(value))), reason: tuningReason, split: schema.literal('holdout'),
    rows: schema.arrayOf(schema.object({ id: schema.string({ minLength: 1, maxLength: 128 }),
      label: schema.oneOf([schema.literal('malicious'), schema.literal('benign'), schema.literal('unknown')]),
      baseline: schema.boolean(), candidate: schema.boolean() }), { minSize: 1, maxSize: 1000 }),
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'create-tuning-proposal', ...request.body })));
  router.post({ path: ROOT + '/{id}/review-tuning-proposal', validate: { params, query, body: schema.object({
    proposal_id: proposalId, decision: schema.oneOf([schema.literal('accepted_for_review'), schema.literal('rejected')]),
    fixture_sha256: tuningHash, reason: tuningReason,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'review-tuning-proposal', ...request.body })));
  router.post({ path: ROOT + '/{id}/withdraw-tuning-proposal', validate: { params, query, body: schema.object({
    proposal_id: proposalId, reason: tuningReason,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'withdraw-tuning-proposal', ...request.body })));

  router.post({ path: ROOT + '/{id}/record-ai-feedback', validate: { params, query, body: schema.object({
    assessment_id: idSchema, assessed_revision: revisionSchema,
    digest_sha256: schema.string({ minLength: 64, maxLength: 64 }),
    report_sha256: schema.maybe(schema.string({ minLength: 64, maxLength: 64 })),
    assessment_mode: schema.oneOf([schema.literal('ai_review'), schema.literal('agentic_soc')]),
    assessment_rating: schema.oneOf([schema.literal('useful'), schema.literal('partly_useful'), schema.literal('not_useful')]),
    hypothesis_review: schema.oneOf([schema.literal('agree'), schema.literal('disagree'), schema.literal('not_reviewed')]),
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'record-ai-feedback', ...request.body })));

  router.post({ path: ROOT + '/{id}/apply-playbook', validate: { params, query, body: schema.object({
    template_id: schema.string({ minLength: 1, maxLength: 64 }), version: revisionSchema,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'apply-playbook', ...request.body })));

  const responseReason = schema.string({ minLength: 1, maxLength: 2048 });
  const responseId = schema.string({ minLength: 1, maxLength: 64 });
  router.post({ path: ROOT + '/{id}/request-response', validate: { params, query, body: schema.object({
    type: schema.oneOf(RESPONSE_INTENTS.map(value => schema.literal(value))),
    scope: schema.string({ minLength: 1, maxLength: 512 }), reason: responseReason,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'request-response', ...request.body })));

  for (const kind of ['approve-response', 'reject-response', 'cancel-response'] as const) {
    router.post({ path: ROOT + '/{id}/' + kind, validate: { params, query, body: schema.object({
      response_id: responseId, reason: responseReason,
    }) } }, async (context, request, response) => respond(response, () =>
      client(context).command(request.params.id, request.query.expected_revision, { kind, ...request.body })));
  }
  router.post({ path: ROOT + '/{id}/record-response-outcome', validate: { params, query, body: schema.object({
    response_id: responseId, outcome: schema.oneOf(RESPONSE_OUTCOMES.map(value => schema.literal(value))), reason: responseReason,
  }) } }, async (context, request, response) => respond(response, () =>
    client(context).command(request.params.id, request.query.expected_revision, { kind: 'record-response-outcome', ...request.body })));

  for (const kind of ['attach-finding', 'detach-finding'] as const) {
    router.post({ path: ROOT + '/{id}/' + kind, validate: { params, query, body: schema.object({
      index: schema.string({ minLength: 1, maxLength: 255 }),
      document_id: schema.string({ minLength: 1, maxLength: 512 }),
    }) } }, async (context, request, response) => respond(response, () =>
      client(context).command(request.params.id, request.query.expected_revision, { kind, ...request.body } as IndexerIncidentCommand)));
  }
}
