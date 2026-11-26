import { createHash, randomUUID } from 'crypto';
import type { AssessmentDigest, Recommendation } from './evidence';
import type { ConversationDocument } from '../conversation-store';

interface Cited { action: string; evidence_refs: string[] }
interface Assessment {
  incident_id: string; observed_revision: number; mode: 'ai_review' | 'agentic_soc'; advisory_only: true;
  digest: AssessmentDigest; probes: string[]; recommendations: Recommendation[];
  hypothesis?: Cited; tuning?: Cited[];
}

/** Server-created provenance, not a signed or immutable forensic receipt. */
export function buildPrivateReport(assessment: Assessment, providerId: string, model: string, now: Date) {
  const provenance = {
    assessment_id: randomUUID(), schema_version: 1 as const,
    assessed_at: now.toISOString(), provider_id: providerId, model,
    digest_sha256: createHash('sha256').update(JSON.stringify(assessment.digest), 'utf8').digest('hex'),
  };
  // Only server-validated output and the bounded digest enter the report. Never store credentials,
  // endpoint URLs, provider raw output, source references, or arbitrary prompts.
  const document: Pick<ConversationDocument, 'title' | 'messages'> = {
    title: 'Incident assessment ' + assessment.incident_id + ' r' + assessment.observed_revision,
    messages: [{
      role: 'assistant', createdAt: now.getTime(), providerId, providerModel: model,
      // Do NOT mark an incident assessment as safe-to-replay in the privacy-on chat path.
      privacyEnabled: false,
      content: 'Private editable incident assessment copy. Advisory only; not verified forensic evidence. ' +
        'Do not continue this conversation with an unapproved provider. Subject to AI conversation retention.\n\n' +
        JSON.stringify({ provenance, assessment }, null, 2),
    }],
  };
  return { provenance, document };
}
