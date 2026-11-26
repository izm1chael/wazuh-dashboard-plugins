import { IRouter, RequestHandlerContext, OpenSearchDashboardsResponseFactory } from 'opensearch_dashboards/server';
import { schema } from '@osd/config-schema';
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

export function registerIncidentRoutes(router: IRouter) {
  router.get({
    path: ROOT,
    validate: { query: schema.object({
      queue: schema.maybe(schema.oneOf(['open', 'new', 'triaging', 'active', 'closed', 'unassigned', 'all'].map(value => schema.literal(value)))),
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

  for (const kind of ['attach-finding', 'detach-finding'] as const) {
    router.post({ path: ROOT + '/{id}/' + kind, validate: { params, query, body: schema.object({
      index: schema.string({ minLength: 1, maxLength: 255 }),
      document_id: schema.string({ minLength: 1, maxLength: 512 }),
    }) } }, async (context, request, response) => respond(response, () =>
      client(context).command(request.params.id, request.query.expected_revision, { kind, ...request.body } as IndexerIncidentCommand)));
  }
}
