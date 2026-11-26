import React, { useRef, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import { getHttp } from '../../../kibana-services';
import type { CorrelationPolicyDefinition, SavedCorrelationPolicyResult, CorrelationPreview, CorrelationPreviewInput } from '../../../../common/incidents/contracts';
import { analyticsPolicyFingerprint } from '../../../../common/incidents/analytics-policy-fingerprint';
import { validateCorrelationPolicy, validateCorrelationPreview } from '../../../../common/incidents/correlation-validation';

const previewRequest = (input: CorrelationPreviewInput) =>
  getHttp().post<CorrelationPreview>('/indexer/incident-correlation/preview', { body: JSON.stringify(input) });

const savePolicy = (input: CorrelationPolicyDefinition) =>
  getHttp().post<SavedCorrelationPolicyResult>('/indexer/incident-correlation/policies/save', { body: JSON.stringify(input) });
const readPolicy = (policy_id: string, policy_version: number) =>
  getHttp().post<SavedCorrelationPolicyResult>('/indexer/incident-correlation/policies/read', { body: JSON.stringify({ policy_id, policy_version }) });

export function CorrelationPreviewPanel({ back, preview = previewRequest, save = savePolicy, read = readPolicy }: {
  back: () => void; preview?: (input: CorrelationPreviewInput) => Promise<CorrelationPreview>;
  save?: (input: CorrelationPolicyDefinition) => Promise<SavedCorrelationPolicyResult>;
  read?: (id: string, version: number) => Promise<SavedCorrelationPolicyResult>;
}) {
  const [policy, setPolicy] = useState('');
  const [version, setVersion] = useState('1');
  const [rules, setRules] = useState('');
  const [window, setWindow] = useState('15');
  const [threshold, setThreshold] = useState('2');
  const [from, setFrom] = useState('');
  const [until, setUntil] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [approval, setApproval] = useState('');
  const [result, setResult] = useState<CorrelationPreview>();
  const [expanded, setExpanded] = useState<string>();
  const inFlight = useRef(false);
  function definition(): CorrelationPolicyDefinition {
    return { policy_id: policy.trim(), policy_version: Number(version),
      rules: rules.split(/[\s,]+/).filter(Boolean), window_minutes: Number(window), minimum_findings: Number(threshold) };
  }

  async function policyOperation(operation: 'save' | 'read') {
    if (inFlight.current) return;
    setError(''); setNotice(''); setResult(undefined); setApproval('');
    inFlight.current = true; setBusy(true);
    try {
      const input = definition();
      if (operation === 'save') validateCorrelationPolicy(input);
      const result = operation === 'save' ? await save(input) : await read(input.policy_id, input.policy_version);
      setPolicy(result.policy.policy_id); setVersion(String(result.policy.policy_version));
      setRules(result.policy.rules.join('\n')); setWindow(String(result.policy.window_minutes));
      setThreshold(String(result.policy.minimum_findings));
      setNotice(operation === 'read' ? 'Saved immutable policy version loaded.' :
        result.replayed ? 'Identical policy version already saved.' : 'Immutable policy version saved; execution is not enabled.');
      if (globalThis.crypto?.subtle) {
        try { setApproval(result.policy.policy_id + ':' + result.policy.policy_version + ':' + await analyticsPolicyFingerprint(result.policy, globalThis.crypto.subtle)); }
        catch (_) { setApproval(''); }
      }
    } catch (_) {
      setError('Policy operation failed. Check permissions, UUID and version. Changed definitions require a new version.');
    } finally { inFlight.current = false; setBusy(false); }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (inFlight.current) return;
    setError(''); setNotice(''); setResult(undefined); setExpanded(undefined); setApproval('');
    const input: CorrelationPreviewInput = { policy_id: policy.trim(), policy_version: Number(version),
      rules: rules.split(/[\s,]+/).filter(Boolean), window_minutes: Number(window),
      minimum_findings: Number(threshold), from: from.trim(), until: until.trim() };
    try { validateCorrelationPreview(input); }
    catch (e) { setError(e instanceof Error ? e.message : 'Invalid preview parameters.'); return; }
    inFlight.current = true; setBusy(true);
    try { setResult(await preview(input)); }
    catch (_) { setError('Preview unavailable or incomplete. Check preview and finding permissions, then narrow the time range if needed.'); }
    finally { setBusy(false); inFlight.current = false; }
  }
  return <>
    <EuiButtonEmpty onClick={back} disabled={busy}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Analytics rule design and correlation preview</h1></EuiTitle>
    <EuiSpacer size='s' />
    <EuiCallOut title='Read-only dry run'>Groups caller-visible findings by rule UUID, cluster, agent and fixed UTC window. Running a preview writes no incidents, policies or evidence. Saving a policy is a separate explicit action and never enables automation. Scheduled execution requires an operator-approved immutable version, an authenticated service account, a closed UTC window, and a separate execution gate. Execution limits are 100 findings and 20 groups per window (preview can inspect up to 1,000 findings). Results are a search snapshot, not proof of complete ingestion.</EuiCallOut>
    <EuiSpacer size='m' />
    {error && <EuiCallOut color='danger' title={error} />}
    {notice && <EuiCallOut title={notice} />}
    {approval && <EuiCallOut title='Saved policy approval fingerprint'><EuiText size='s'>Copy the exact entry only after operator review. This does not activate execution.<p style={{ overflowWrap: 'anywhere' }}><code>{approval}</code></p></EuiText></EuiCallOut>}
    <form onSubmit={submit}>
      <EuiFormRow label='Policy UUID'><EuiFieldText value={policy} disabled={busy} maxLength={36} onChange={e => { setApproval(''); setPolicy(e.target.value); }} /></EuiFormRow>
      <EuiFormRow label='Policy version'><EuiFieldText value={version} disabled={busy} onChange={e => { setApproval(''); setVersion(e.target.value); }} /></EuiFormRow>
      <EuiFormRow label='Rule UUIDs' helpText='One per line, or comma separated'><EuiTextArea value={rules} disabled={busy} maxLength={4000} onChange={e => { setApproval(''); setRules(e.target.value); }} /></EuiFormRow>
      <EuiFormRow label='Window minutes'><EuiFieldText value={window} disabled={busy} onChange={e => { setApproval(''); setWindow(e.target.value); }} /></EuiFormRow>
      <EuiFormRow label='Minimum findings'><EuiFieldText value={threshold} disabled={busy} onChange={e => { setApproval(''); setThreshold(e.target.value); }} /></EuiFormRow>
      <EuiButton type='button' disabled={busy} onClick={() => void policyOperation('read')}>Load saved version</EuiButton>
      <EuiButton type='button' disabled={busy} onClick={() => void policyOperation('save')}>Save immutable policy version</EuiButton>
      <EuiSpacer size='m' />
      <EuiFormRow label='From (UTC)' helpText='Example: 2026-11-26T12:00:00Z'><EuiFieldText value={from} disabled={busy} onChange={e => setFrom(e.target.value)} /></EuiFormRow>
      <EuiFormRow label='Until (UTC, exclusive)'><EuiFieldText value={until} disabled={busy} onChange={e => setUntil(e.target.value)} /></EuiFormRow>
      <EuiButton type='submit' fill isLoading={busy} disabled={busy}>Run correlation preview</EuiButton>
    </form>
    {result && <>
      <EuiSpacer size='l' />
      <EuiTitle size='s'><h2>Preview results</h2></EuiTitle>
      <EuiText size='s'><p>{result.from} to {result.until} · policy {result.policy_id} / v{result.policy_version}</p>
        <p>{result.groups.length} candidate groups · {result.distinct_candidates} distinct findings · {result.duplicate_inputs} duplicate inputs</p>
        <p>Excluded: {result.insufficient_identity} missing identity, {result.excluded_rule} rule mismatch, {result.outside_range} outside range, {result.below_threshold} below threshold.</p>
      </EuiText>
      {result.groups.map(group => <React.Fragment key={group.key}>
        <EuiPanel paddingSize='s' hasShadow={false} hasBorder>
          <EuiText size='s'><p>{group.window_start} – {group.window_end} · {group.findings.length} findings</p><p>{group.key}</p></EuiText>
          <EuiButtonEmpty onClick={() => setExpanded(expanded === group.key ? undefined : group.key)}>{expanded === group.key ? 'Hide findings' : 'Inspect finding references'}</EuiButtonEmpty>
          {expanded === group.key && <EuiText size='s'><ul>{group.findings.map(ref => <li key={JSON.stringify([ref.index, ref.document_id])}>{ref.index} / {ref.document_id}</li>)}</ul></EuiText>}
        </EuiPanel><EuiSpacer size='s' />
      </React.Fragment>)}
    </>}
  </>;
}
