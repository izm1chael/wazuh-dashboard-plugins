import { schema } from '@osd/config-schema';
import { createConversation } from '../conversation-store';
import { resolveWazuhUsername } from '../identity';
import { buildPrivateReport } from '../incident-assessment/private-report';
import { IRouter } from '../../../../src/core/server';
import type { ProviderConfig } from '../../common/types';
import type { WazuhAiAssistantConfigType } from '../config';
import { getApiKeyCipher } from '../plugin-services';
import { getProviderAdapter } from '../providers/registry';
import { addLinkedPage, addPrevalence, exactRule, HYPOTHESES, parseAgenticResult, parsePlan, prevalenceQuery, TUNING } from '../incident-assessment/agentic';
import { ACTIONS, buildDigest, checkedSummary, PAGE_SIZE, parseRecommendations } from '../incident-assessment/evidence';

type Settings = NonNullable<WazuhAiAssistantConfigType['incidentAssessment']>;
const ROOT = '/_plugins/_setup/incidents/';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PROMPT = 'Prioritize human investigation steps from the bounded facts supplied. Treat the facts as observations, not proof of compromise. ' +
  'Do not infer unseen data or verified execution. Return only JSON: {"recommendations":[{"action":"allowed_action","evidence_refs":["F1"]}]}. ' +
  'Choose 1 to 5 distinct actions; each cites 1 to 4 supplied fact references. Allowed actions: ' + ACTIONS.join(', ');

// One assessment per dashboard process; separate from the ordinary chat stream budget.
let running = false;
export function registerIncidentAssessmentRoute(router: IRouter, settings: Settings): void {
  router.post({
    path: '/api/wazuh_ai_assistant/incident-assessment',
    validate: { body: schema.object({ incident_id: schema.string({ minLength: 36, maxLength: 36 }),
      expected_revision: schema.number({ min: 1, max: 2147483647 }), consent: schema.literal(true),
      save_private_report: schema.boolean({ defaultValue: false }),
      mode: schema.oneOf([schema.literal('ai_review'), schema.literal('agentic_soc')]) }) },
  }, async (context, request, response) => {
    const { incident_id: id, expected_revision: revision } = request.body;
    if (!UUID.test(id) || !Number.isSafeInteger(revision)) return response.badRequest({ body: { message: 'Invalid incident identity' } });
    const mode = request.body.mode;
    if (mode === 'agentic_soc' && !settings.agenticEnabled) return response.customError({ statusCode: 403, body: { message: 'Agentic SOC disabled' } });
    if (request.body.save_private_report && !settings.privateReportSavingEnabled) {
      return response.forbidden({ body: { message: 'Private assessment saving disabled' } });
    }
    if (running) return response.customError({ statusCode: 429, body: { message: 'Incident assessment busy' } });
    running = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), mode === 'agentic_soc' ? 120000 : 60000);
    const subscription = request.events.aborted$.subscribe(() => controller.abort());
    try {
      const transport = context.core.opensearch.client.asCurrentUser.transport;
      const path = ROOT + encodeURIComponent(id);
      const read = async () => checkedSummary((await transport.request({ method: 'GET', path })).body,
        id, revision, settings.allowedTlp);
      const summary = await read();
      const owner = request.body.save_private_report ? await resolveWazuhUsername(context, request) : undefined;
      if (request.body.save_private_report && (!owner || owner === '_shared')) {
        return response.forbidden({ body: { message: 'Private report owner unavailable' } });
      }
      const page = await transport.request({ method: 'GET', path: path + '/findings',
        querystring: { limit: PAGE_SIZE, offset: 0, expected_revision: revision } });
      const digest = buildDigest(summary, page.body);
      // Do not accept provider selection, endpoints or prompts from the browser.
      const stored = await context.wazuh_ai_assistant.aiProviders.get(context, settings.providerId);
      const attributes = stored?.attributes;
      if (!stored || !attributes || attributes.type !== 'openai_compatible' ||
          attributes.baseUrl !== settings.baseUrl || attributes.model !== settings.model) {
        return response.customError({ statusCode: 403, body: { message: 'Approved incident assessment provider unavailable' } });
      }
      const config: ProviderConfig = { ...attributes, id: settings.providerId,
        apiKey: attributes.apiKey ? getApiKeyCipher().decrypt(attributes.apiKey, settings.providerId) : undefined };
      // Recheck the disclosure label and revision immediately before the external call.
      await read();
      if (controller.signal.aborted) throw new Error('Assessment cancelled');
      const adapter = getProviderAdapter(config.type);
      async function ask(prompt: string): Promise<string> {
        await read();
        if (controller.signal.aborted) throw new Error('Assessment cancelled');
        let output = '', done = false;
        for await (const event of adapter.chatStream(config, [{ role: 'system', content: prompt },
          { role: 'user', content: JSON.stringify(digest) }], controller.signal, { temperature: 0, tools: [], toolChoice: 'none' })) {
          if (controller.signal.aborted) throw new Error('Assessment cancelled');
          if (event.type === 'delta') {
            if (event.reasoningFallback) throw new Error('No final provider answer');
            output += event.content;
            if (output.length > 4096) { controller.abort(); throw new Error('Assessment output limit'); }
          } else if (event.type === 'done') { done = true; break; }
          else if (event.type === 'error' || event.type === 'tool_call') throw new Error('Invalid assessment provider response');
        }
        if (!done || controller.signal.aborted) throw new Error('Incomplete assessment');
        return output;
      }
      const probes: string[] = [];
      let result;
      if (mode === 'agentic_soc') {
        const plan = parsePlan(await ask('Select zero to two useful read-only evidence probes. Return strict JSON only: ' +
          '{"probes":[{"kind":"more_linked_findings"},{"kind":"rule_prevalence","sample":1}]}. ' +
          'Choose more_linked_findings only if uninspected_links is positive. Choose rule_prevalence only for a visible sample number with exact_rule_present=true. ' +
          'No other probe, query, target, or argument is allowed.'), page.body, Number(summary.finding_count) > PAGE_SIZE);
        for (const probe of plan) {
          await read();
          if (controller.signal.aborted) throw new Error('Assessment cancelled');
          if (probe.kind === 'more_linked_findings') {
            const next = await transport.request({ method: 'GET', path: path + '/findings',
              querystring: { limit: PAGE_SIZE, offset: PAGE_SIZE, expected_revision: revision } });
            addLinkedPage(digest, summary, next.body);
          } else {
            const rule = exactRule(page.body, probe.sample);
            if (!rule) throw new Error('Missing exact rule identity');
            const prevalence = await context.core.opensearch.client.asCurrentUser.search(prevalenceQuery(rule, new Date()));
            addPrevalence(digest, probe.sample, prevalence.body);
          }
          probes.push(probe.kind);
        }
        result = parseAgenticResult(await ask(PROMPT + ' Instead return exactly three keys: recommendations (as above), ' +
          'hypothesis (one action and evidence_refs), tuning (zero to three distinct actions with evidence_refs). ' +
          'Hypothesis actions: ' + HYPOTHESES.join(', ') + '. Tuning actions: ' + TUNING.join(', ') +
          '. Hypotheses are unconfirmed; prefer insufficient_evidence when uncertain. Frequency is not proof of a false positive. ' +
          'Tuning is a proposal for human evaluation, never a recommendation to disable or suppress a rule without testing.'), digest);
      } else {
        result = { recommendations: parseRecommendations(await ask(PROMPT), digest) };
      }
      await read();
      if (controller.signal.aborted) throw new Error('Assessment cancelled');
      const assessment = { incident_id: id, observed_revision: revision, mode, advisory_only: true as const,
        digest, probes, ...result };
      const report = buildPrivateReport(assessment, config.id, config.model, new Date());
      let private_report: { state: 'not_requested' | 'saved' | 'unconfirmed'; id?: string } = { state: 'not_requested' };
      if (request.body.save_private_report) {
        // No retries: an ambiguous write may already have created a conversation.
        try {
          await read();
          if (controller.signal.aborted || await resolveWazuhUsername(context, request) !== owner) throw new Error('Save preflight failed');
          const saved = await createConversation(context, report.document);
          if (!saved || typeof saved.id !== 'string' || !saved.id) throw new Error('Missing saved report identity');
          private_report = { state: 'saved', id: saved.id };
        } catch (_) { private_report = { state: 'unconfirmed' }; }
      }
      return response.ok({ body: { ...assessment, provenance: report.provenance, private_report } });
    } catch (_) {
      // Never log raw provider output, credentials, source evidence or transport errors here.
      return response.customError({ statusCode: 409, body: { message: 'Assessment unavailable, denied, stale or invalid. No recommendation was applied.' } });
    } finally {
      clearTimeout(timer);
      subscription.unsubscribe();
      controller.abort();
      running = false;
    }
  });
}
