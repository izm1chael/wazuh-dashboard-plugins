import React, { useEffect, useRef, useState } from 'react';
import { EuiButton, EuiCallOut, EuiCheckbox, EuiFlexGroup, EuiFlexItem, EuiPanel, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { getHttp } from '../../../kibana-services';
import type { IncidentSummary } from '../../../../common/incidents/contracts';

type Mode = 'ai_review' | 'agentic_soc';
interface Cited { action: string; evidence_refs: string[] }
interface Fact { ref: string; kind: string; value: string | number | boolean | string[] }
interface Assessment {
  incident_id: string; observed_revision: number; mode: Mode; advisory_only: true;
  digest: { facts: Fact[]; scope: 'first_finding_page' | 'expanded_linked_findings'; complete_link_coverage: boolean };
  probes: string[]; recommendations: Cited[]; hypothesis?: Cited; tuning?: Cited[];
}
const ACTIONS: Record<string, string> = {
  review_detection: 'Review the detection and its triggering conditions',
  review_entities: 'Review affected entities and corroborate their involvement',
  review_attack_techniques: 'Review reported ATT&CK techniques against actual behaviour',
  review_chronology: 'Reconstruct the event chronology',
  retrieve_missing_evidence: 'Retrieve missing evidence or document its unavailability',
  assess_business_impact: 'Assess business impact and affected scope',
  review_containment_options: 'Review containment options through the approval workflow',
  review_classification: 'Review incident classification',
};
const HYPOTHESES: Record<string, string> = {
  insufficient_evidence: 'Insufficient evidence', possible_true_positive: 'Possible true positive',
  possible_benign_positive: 'Possible benign positive', possible_false_positive: 'Possible false positive',
};
const TUNING: Record<string, string> = {
  compare_benign_baseline: 'Compare against a known benign baseline',
  review_rule_scope: 'Review detection scope and overly broad conditions',
  review_threshold_or_window: 'Evaluate threshold or correlation-window changes',
  review_duplicate_grouping: 'Review duplicate finding grouping',
  replay_positive_and_negative_tests: 'Replay positive and negative detection test cases',
};
const PROBES: Record<string, string> = { more_linked_findings: 'Additional linked findings', rule_prevalence: 'Caller-visible rule prevalence (last 24 hours)' };
const owns = (obj: object, key: string) => Object.prototype.hasOwnProperty.call(obj, key);
function validate(result: Assessment, incident: IncidentSummary, mode: Mode): void {
  if (!result || result.incident_id !== incident.id || result.observed_revision !== incident.revision ||
      result.mode !== mode || result.advisory_only !== true || !result.digest ||
      !['first_finding_page', 'expanded_linked_findings'].includes(result.digest.scope) ||
      typeof result.digest.complete_link_coverage !== 'boolean' || !Array.isArray(result.digest.facts) ||
      result.digest.facts.length < 8 || result.digest.facts.length > 50 || !Array.isArray(result.probes) ||
      result.probes.length > 2 || new Set(result.probes).size !== result.probes.length ||
      result.probes.some(probe => !owns(PROBES, probe))) throw new Error('Invalid assessment response');
  const facts = result.digest.facts;
  if (facts.some((fact, n) => !fact || fact.ref !== 'F' + (n + 1) ||
      typeof fact.kind !== 'string' || !/^[a-z0-9_]{1,96}$/.test(fact.kind) ||
      !(typeof fact.value === 'boolean' || (typeof fact.value === 'number' && Number.isSafeInteger(fact.value) && fact.value >= 0) ||
        (typeof fact.value === 'string' && /^[a-z0-9_]{1,64}$/.test(fact.value)) ||
        (Array.isArray(fact.value) && fact.value.length <= 16 && fact.value.every(v => typeof v === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(v)))))) {
    throw new Error('Invalid assessment facts');
  }
  const ids = new Set(facts.map(fact => fact.ref));
  const cited = (row: Cited, allowed: Record<string, string>) => !!row && owns(allowed, row.action) &&
    Array.isArray(row.evidence_refs) && row.evidence_refs.length >= 1 && row.evidence_refs.length <= 4 &&
    new Set(row.evidence_refs).size === row.evidence_refs.length && row.evidence_refs.every(ref => ids.has(ref));
  if (!Array.isArray(result.recommendations) || result.recommendations.length < 1 || result.recommendations.length > 5 ||
      !result.recommendations.every(row => cited(row, ACTIONS)) ||
      new Set(result.recommendations.map(row => row.action)).size !== result.recommendations.length) throw new Error('Invalid recommendations');
  if (mode === 'agentic_soc') {
    if (!result.hypothesis || !cited(result.hypothesis, HYPOTHESES) || !Array.isArray(result.tuning) ||
        result.tuning.length > 3 || !result.tuning.every(row => cited(row, TUNING)) ||
        new Set(result.tuning.map(row => row.action)).size !== result.tuning.length) throw new Error('Invalid agentic result');
  } else if (result.hypothesis !== undefined || result.tuning !== undefined || result.probes.length !== 0) {
    throw new Error('Invalid review result');
  }
}
const request = (incident: IncidentSummary, mode: Mode) => getHttp().post<Assessment>('/api/wazuh_ai_assistant/incident-assessment',
  { body: JSON.stringify({ incident_id: incident.id, expected_revision: incident.revision, mode, consent: true }) });
const label = (kind: string) => kind.replace(/_/g, ' ');
const valueText = (value: Fact['value']) => Array.isArray(value) ? value.join(', ') || 'None in sampled fields' : String(value);

export function IncidentAiPanel({ incident, disabled, assess = request }: {
  incident: IncidentSummary; disabled: boolean; assess?: (incident: IncidentSummary, mode: Mode) => Promise<Assessment>;
}) {
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState<Mode>();
  const [result, setResult] = useState<Assessment>();
  const [error, setError] = useState('');
  const inFlight = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const blocked = disabled || !!busy || !consent || ['TLP:RED', 'TLP:AMBER+STRICT'].includes(incident.tlp);
  async function run(mode: Mode) {
    if (blocked || inFlight.current) return;
    inFlight.current = true;
    setConsent(false); setBusy(mode); setResult(undefined); setError('');
    try {
      const response = await assess(incident, mode);
      validate(response, incident, mode);
      if (mounted.current) setResult(response);
    } catch (_) {
      if (mounted.current) setError('Assessment unavailable, not enabled, denied, stale or invalid. No incident or rule was changed.');
    } finally {
      inFlight.current = false;
      if (mounted.current) setBusy(undefined);
    }
  }
  function renderCited(row: Cited, labels: Record<string, string>) {
    return <React.Fragment key={row.action}>{labels[row.action]} (facts: {row.evidence_refs.join(', ')})</React.Fragment>;
  }
  return <>
    <EuiTitle size='s'><h2>AI-assisted investigations</h2></EuiTitle>
    <EuiText size='s'><p>Choose a quick AI Review or a deeper Agentic SOC assessment. Both require an operator-approved configured provider and disclosure policy.</p></EuiText>
    <EuiCallOut title='Advisory only'>Only bounded structured facts are sent to the configured provider. Raw finding content, entity values, incident text and credentials are not included in the evidence digest. Agentic SOC may also disclose caller-visible aggregate rule prevalence. No automatic classification, detection tuning, incident closure or response execution.</EuiCallOut>
    <EuiSpacer size='s' />
    <EuiCheckbox id={'incident-ai-consent-' + incident.id} checked={consent} disabled={disabled || !!busy}
      label='I authorize this assessment under the configured provider and disclosure policy' onChange={event => setConsent(event.target.checked)} />
    <EuiFlexGroup wrap>
      <EuiFlexItem>
        <EuiPanel hasBorder hasShadow={false} paddingSize='m'>
          <EuiTitle size='xs'><h3>AI Review</h3></EuiTitle>
          <EuiText size='s'><p>One model pass over the first five linked finding positions. Prioritized human investigation steps with evidence references.</p></EuiText>
          <EuiButton disabled={blocked} isLoading={busy === 'ai_review'} onClick={() => void run('ai_review')}>AI Review</EuiButton>
        </EuiPanel>
      </EuiFlexItem>
      <EuiFlexItem>
        <EuiPanel hasBorder hasShadow={false} paddingSize='m'>
          <EuiTitle size='xs'><h3>Agentic SOC</h3></EuiTitle>
          <EuiText size='s'><p>Two model passes, with up to two constrained follow-up probes. Investigation steps, classification hypotheses and detection-tuning review proposals.</p></EuiText>
          <EuiButton disabled={blocked} isLoading={busy === 'agentic_soc'} onClick={() => void run('agentic_soc')}>Agentic SOC</EuiButton>
        </EuiPanel>
      </EuiFlexItem>
    </EuiFlexGroup>
    {['TLP:RED', 'TLP:AMBER+STRICT'].includes(incident.tlp) && <EuiCallOut color='warning' title='Assessment blocked by disclosure policy' />}
    {error && <EuiCallOut color='warning' title={error} />}
    {result && !disabled && <>
      <EuiSpacer size='m' />
      <EuiTitle size='xs'><h3>{result.mode === 'ai_review' ? 'AI Review' : 'Agentic SOC'} recommendations · Revision {result.observed_revision}</h3></EuiTitle>
      <EuiText size='s'><p>{result.digest.complete_link_coverage ? 'All linked finding positions visible in this assessment.' : 'Partial linked-finding coverage.'} Visibility does not establish source completeness or correctness.</p>
        {result.mode === 'agentic_soc' && <p>Follow-up probes: {result.probes.map(probe => PROBES[probe]).join('; ') || 'None selected'}.</p>}
        <ol>{result.recommendations.map(row => <li key={row.action}>{renderCited(row, ACTIONS)}</li>)}</ol>
        {result.hypothesis && <><h4>Unconfirmed classification hypothesis</h4><p>{renderCited(result.hypothesis, HYPOTHESES)}. Human corroboration required; rule frequency is not proof of a false positive.</p></>}
        {result.tuning && <><h4>Detection tuning proposals — not applied</h4>
          {result.tuning.length ? <ul>{result.tuning.map(row => <li key={row.action}>{renderCited(row, TUNING)}</li>)}</ul> : <p>No tuning proposal returned.</p>}
          <p>Validate against benign and malicious test cases, assess detection coverage and obtain approval before changing a rule.</p></>}
        <h4>Assessment facts</h4><dl>{result.digest.facts.map(fact => <React.Fragment key={fact.ref}>
          <dt>{fact.ref} · {label(fact.kind)}</dt><dd>{valueText(fact.value)}</dd>
        </React.Fragment>)}</dl>
        <p>References identify bounded facts, not verified causal evidence. Results are not automatically saved.</p>
      </EuiText>
    </>}
  </>;
}
