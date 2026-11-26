import React, { useEffect, useRef, useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiCheckbox, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { getHttp } from '../../../kibana-services';
import { AutomationActions, AutomationRule, AutomationPolicy, AutomationPreview, SavedAutomation,
  SEVERITIES, PRIORITIES, STATUSES, PLAYBOOKS, UUID, validateAutomationKey, validateAutomationPolicy,
  validateAutomationPreview, validateAutomationSave, validateSavedAutomation } from '../../../../common/incidents/automation-contract';

const ROOT = '/indexer/incident-automation/';
const options = (values: readonly string[]) => values.map(value => ({ value, text: value.replace(/_/g, ' ') }));
const optional = (values: readonly string[]) => [{ value: '', text: 'No action' }, ...options(values)];
const list = (value: string) => value.split(/[\s,]+/).filter(Boolean);
const fresh = (): AutomationRule => ({ id: '', trigger: 'created', minimum_severity: 'informational', status: 'any_open',
  minimum_findings: 0, unassigned_only: false, required_tags: [], actions: {} });

export function IncidentAutomationPanel({ back }: { back: () => void }) {
  const [id, setId] = useState('');
  const [version, setVersion] = useState('1');
  const [rules, setRules] = useState<AutomationRule[]>([]);
  const [editing, setEditing] = useState<number>();
  const [rule, setRule] = useState<AutomationRule>(fresh);
  const [minimum, setMinimum] = useState('0');
  const [requiredTags, setRequiredTags] = useState('');
  const [addTags, setAddTags] = useState('');
  const [saved, setSaved] = useState<SavedAutomation>();
  const [incident, setIncident] = useState('');
  const [preview, setPreview] = useState<AutomationPreview>();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const generation = useRef(0);
  const active = useRef(false);
  useEffect(() => () => { generation.current++; }, []);
  const invalidate = () => { setSaved(undefined); setPreview(undefined); setNotice(''); setError(''); };
  const resetEditor = () => { setEditing(undefined); setRule(fresh()); setMinimum('0'); setRequiredTags(''); setAddTags(''); };
  const edit = (index: number) => {
    const row = rules[index]; setEditing(index); setRule(row);
    setMinimum(String(row.minimum_findings)); setRequiredTags(row.required_tags.join(', ')); setAddTags((row.actions.add_tags ?? []).join(', '));
  };
  function action<K extends keyof AutomationActions>(key: K, value: AutomationActions[K] | '') {
    const actions = { ...rule.actions };
    if (value === '') delete actions[key]; else actions[key] = value as AutomationActions[K];
    setRule({ ...rule, actions });
  }
  let candidate: AutomationRule | undefined;
  try {
    if (!/^(0|[1-9][0-9]{0,3})$/.test(minimum)) throw new Error('Invalid count');
    const actions = { ...rule.actions };
    if (list(addTags).length) actions.add_tags = list(addTags); else delete actions.add_tags;
    candidate = validateAutomationPolicy({ policy_id: '00000000-0000-4000-8000-000000000001', policy_version: 1,
      rules: [{ ...rule, minimum_findings: Number(minimum), required_tags: list(requiredTags), actions }] }).rules[0];
    if (rules.some((row, index) => index !== editing && row.id === candidate?.id)) candidate = undefined;
  } catch (_) { /* incomplete rule */ }
  function keepRule() {
    if (!candidate || (editing === undefined && rules.length >= 10)) return;
    invalidate(); const next = [...rules];
    if (editing === undefined) next.push(candidate); else next[editing] = candidate;
    setRules(next); resetEditor();
  }
  let key: { policy_id: string; policy_version: number } | undefined;
  let policy: AutomationPolicy | undefined;
  try {
    if (!/^[1-9][0-9]{0,9}$/.test(version)) throw new Error('Invalid version');
    key = validateAutomationKey({ policy_id: id, policy_version: Number(version) });
    policy = validateAutomationPolicy({ ...key, rules });
  } catch (_) { /* incomplete policy */ }
  async function operate(operation: 'read' | 'save' | 'preview') {
    if (!key || active.current || (operation === 'save' && !policy) ||
        (operation === 'preview' && (!saved || !UUID.test(incident)))) return;
    const run = ++generation.current; const expected = key; const target = incident;
    active.current = true; setBusy(true); setError(''); setNotice(''); setPreview(undefined);
    if (operation !== 'preview') setSaved(undefined);
    try {
      if (operation === 'preview') {
        const result = validateAutomationPreview(await getHttp().post<unknown>(ROOT + 'preview',
          { body: JSON.stringify({ ...expected, incident_id: target }) }), expected, target);
        if (generation.current === run) {
          if (result.rule_id && !saved?.policy.rules.some(item => item.id === result.rule_id)) throw new Error('Unknown preview rule');
          setPreview(result);
        }
      } else {
        const body = await getHttp().post<unknown>(ROOT + operation, { body: JSON.stringify(operation === 'save' ? policy : expected) });
        const result = operation === 'save' ? validateAutomationSave(body, policy!).saved : validateSavedAutomation(body, expected);
        if (generation.current === run) {
          setSaved(result); setRules(result.policy.rules); resetEditor();
          setNotice(operation === 'save' ? 'Immutable rule set saved. Execution is not enabled.' : 'Saved rule set loaded.');
        }
      }
    } catch (_) {
      if (generation.current === run) setError('Automation request unavailable or conflicting. Check permissions and saved version. Reload before retrying.');
    } finally {
      active.current = false; if (generation.current === run) setBusy(false);
    }
  }
  const move = (index: number, delta: number) => {
    const next = [...rules], destination = index + delta;
    if (destination < 0 || destination >= next.length) return;
    [next[index], next[destination]] = [next[destination], next[index]];
    invalidate(); setRules(next); resetEditor();
  };
  const editorDirty = editing !== undefined || !!rule.id || Object.keys(rule.actions).length > 0 ||
    !!requiredTags || !!addTags || minimum !== '0' || rule.trigger !== 'created' || rule.minimum_severity !== 'informational' ||
    rule.status !== 'any_open' || rule.unassigned_only;
  return <>
    <EuiButtonEmpty onClick={back} disabled={busy}>Back to incidents</EuiButtonEmpty>
    <EuiTitle size='l'><h1>Incident automation rules</h1></EuiTitle>
    <EuiCallOut title='Design and preview only'>First matching rule wins, once per incident and saved policy version.
      Rules evaluate the latest delivered creation or supported update event, not every historical event.
      Assignment fills an unowned new incident only; severity and priority can only increase. No closure, response dispatch, or AI calls.
      Execution requires separate operator approval and a service account.</EuiCallOut>
    <EuiSpacer size='m' />
    {error && <EuiCallOut color='warning' title={error} />}
    {notice && <EuiCallOut title={notice} />}
    <EuiFormRow label='Policy UUID'><EuiFieldText value={id} maxLength={36} disabled={busy}
      onChange={e => { invalidate(); setId(e.target.value); }} /></EuiFormRow>
    <EuiButtonEmpty disabled={busy} onClick={() => {
      try {
        const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
        bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
        const hex = Array.from(bytes, n => n.toString(16).padStart(2, '0')).join('');
        invalidate(); setId([hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join('-')); setVersion('1');
      } catch (_) { setError('Secure random UUID unavailable. Enter an operator-generated UUID.'); }
    }}>Generate new policy UUID</EuiButtonEmpty>
    <EuiFormRow label='Policy version'><EuiFieldText value={version} maxLength={10} disabled={busy}
      onChange={e => { invalidate(); setVersion(e.target.value); }} /></EuiFormRow>
    <EuiButton disabled={busy || !key || editorDirty} onClick={() => void operate('read')}>Load immutable version</EuiButton>
    <EuiSpacer size='m' />
    <EuiTitle size='s'><h2>Ordered rule set ({rules.length}/10)</h2></EuiTitle>
    {rules.map((row, index) => <EuiPanel key={row.id} hasBorder hasShadow={false} paddingSize='s'>
      <EuiText size='s'><strong>{index + 1}. {row.id}</strong> · {row.trigger} · {row.status} · severity at least {row.minimum_severity}
        · minimum findings {row.minimum_findings}{row.unassigned_only ? ' · unassigned only' : ''}
        <p>Required tags: {row.required_tags.join(', ') || 'None'}</p>
        <p>Actions: {Object.entries(row.actions).map(([k,v]) => k.replace(/_/g, ' ') + ': ' + String(v)).join(' · ')}</p></EuiText>
      <EuiButtonEmpty disabled={busy || editorDirty} onClick={() => edit(index)}>Edit</EuiButtonEmpty>
      <EuiButtonEmpty disabled={busy || editorDirty || index === 0} onClick={() => move(index,-1)}>Move up</EuiButtonEmpty>
      <EuiButtonEmpty disabled={busy || editorDirty || index === rules.length-1} onClick={() => move(index,1)}>Move down</EuiButtonEmpty>
      <EuiButtonEmpty disabled={busy || editorDirty} onClick={() => { invalidate(); setRules(rules.filter((_,n) => n !== index)); }}>Remove</EuiButtonEmpty>
    </EuiPanel>)}
    <EuiSpacer size='m' />
    <EuiTitle size='s'><h2>{editing === undefined ? 'Add rule' : 'Edit rule'}</h2></EuiTitle>
    <EuiFormRow label='Rule identifier'><EuiFieldText value={rule.id} maxLength={64} disabled={busy} onChange={e => setRule({...rule,id:e.target.value})} /></EuiFormRow>
    <EuiFormRow label='Trigger'><EuiSelect value={rule.trigger} options={options(['created','updated'])} disabled={busy}
      onChange={e => setRule({...rule,trigger:e.target.value as AutomationRule['trigger']})} /></EuiFormRow>
    <EuiFormRow label='Minimum severity'><EuiSelect value={rule.minimum_severity} options={options(SEVERITIES)} disabled={busy}
      onChange={e => setRule({...rule,minimum_severity:e.target.value as AutomationRule['minimum_severity']})} /></EuiFormRow>
    <EuiFormRow label='Incident status'><EuiSelect value={rule.status} options={options(STATUSES)} disabled={busy}
      onChange={e => setRule({...rule,status:e.target.value as AutomationRule['status']})} /></EuiFormRow>
    <EuiFormRow label='Minimum finding count'><EuiFieldText value={minimum} maxLength={4} disabled={busy} onChange={e => setMinimum(e.target.value)} /></EuiFormRow>
    <EuiCheckbox id='automation-unassigned' label='Unassigned incidents only' checked={rule.unassigned_only} disabled={busy}
      onChange={e => setRule({...rule,unassigned_only:e.target.checked})} />
    <EuiFormRow label='Required tags (comma separated)'><EuiFieldText value={requiredTags} maxLength={1625} disabled={busy} onChange={e => setRequiredTags(e.target.value)} /></EuiFormRow>
    <EuiFormRow label='Assign to exact username (optional)'><EuiFieldText value={rule.actions.assign_to ?? ''} maxLength={1024} disabled={busy} onChange={e => action('assign_to',e.target.value)} /></EuiFormRow>
    <EuiFormRow label='Raise severity to'><EuiSelect value={rule.actions.raise_severity ?? ''} options={optional(SEVERITIES)} disabled={busy}
      onChange={e => action('raise_severity',e.target.value as AutomationActions['raise_severity'] | '')} /></EuiFormRow>
    <EuiFormRow label='Raise priority to'><EuiSelect value={rule.actions.raise_priority ?? ''} options={optional(PRIORITIES)} disabled={busy}
      onChange={e => action('raise_priority',e.target.value as AutomationActions['raise_priority'] | '')} /></EuiFormRow>
    <EuiFormRow label='Add tags (comma separated)'><EuiFieldText value={addTags} maxLength={1625} disabled={busy} onChange={e => setAddTags(e.target.value)} /></EuiFormRow>
    <EuiFormRow label='Create task title (optional)'><EuiFieldText value={rule.actions.create_task ?? ''} maxLength={1024} disabled={busy} onChange={e => action('create_task',e.target.value)} /></EuiFormRow>
    <EuiFormRow label='Apply built-in checklist v1'><EuiSelect value={rule.actions.apply_playbook ?? ''} options={optional(PLAYBOOKS)} disabled={busy}
      onChange={e => action('apply_playbook',e.target.value as AutomationActions['apply_playbook'] | '')} /></EuiFormRow>
    <EuiButton disabled={busy || !candidate || (editing === undefined && rules.length >= 10)} onClick={keepRule}>Keep rule in draft</EuiButton>
    <EuiButtonEmpty disabled={busy || !editorDirty} onClick={resetEditor}>Discard rule edit</EuiButtonEmpty>
    <EuiSpacer size='l' />
    <EuiButton fill disabled={busy || !policy || editorDirty} onClick={() => void operate('save')}>Save immutable rule set</EuiButton>
    {saved && !editorDirty && <>
      <EuiSpacer size='m' />
      <EuiCallOut title='Saved approval entry'><EuiText size='s'>Operator must review the saved rules and approve this exact server-derived entry. This is not activation.
        <p style={{overflowWrap:'anywhere'}}><code>{saved.policy.policy_id}:{saved.policy.policy_version}:{saved.fingerprint}</code></p>
        <p>Saved by {saved.created_by} at {saved.created_at}</p></EuiText></EuiCallOut>
      <EuiSpacer size='m' />
      <EuiTitle size='s'><h2>Preview saved rule set against incident</h2></EuiTitle>
      <EuiFormRow label='Incident UUID'><EuiFieldText value={incident} maxLength={36} disabled={busy}
        onChange={e => { setIncident(e.target.value); setPreview(undefined); }} /></EuiFormRow>
      <EuiButton disabled={busy || !UUID.test(incident)} onClick={() => void operate('preview')}>Preview latest delivered event</EuiButton>
      {preview && <EuiText size='s'><p>{preview.state.replace(/_/g,' ')} · revision {preview.revision} · rule {preview.rule_id ?? 'none'} · {preview.changed_fields} proposed changed fields.</p>
        <p>Preview is read-only, not a reservation. A changed incident or ineligible playbook can prevent execution.</p></EuiText>}
    </>}
  </>;
}
