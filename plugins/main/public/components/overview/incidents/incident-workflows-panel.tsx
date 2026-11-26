import React, { useState } from 'react';
import { EuiButton, EuiButtonEmpty, EuiCallOut, EuiFieldText, EuiFormRow, EuiPanel, EuiSelect, EuiSpacer, EuiText, EuiTextArea, EuiTitle } from '@elastic/eui';
import type { IncidentResponsePage, IncidentSummary, IndexerIncidentCommand, WorkflowRun, WorkflowTemplate } from '../../../../common/incidents/contracts';
import { validScanScope } from '../../../../common/incidents/response-validation';
import { workflowStage, workflowTerminal } from '../../../../common/incidents/workflow-validation';

const titles: Record<WorkflowTemplate,string> = {
  vulnerability_investigation: 'Vulnerability investigation', evidence_collection: 'Evidence collection'
};
const phases = { prepare: 'Prepare and validate scope', response: 'Independent response approval and reconciliation',
  review: 'Review evidence and remaining risk', completed: 'Completed (analyst-attested)', failed: 'Stopped after unsuccessful response', cancelled: 'Cancelled' };
const label = (value: string) => value.replace(/_/g,' ');
const safe = (value: string) => !!value.trim() && value === value.trim() && !/[\x00-\x1f\x7f-\x9f]/.test(value);

function Run({ run, disabled, command }: { run: WorkflowRun; disabled: boolean; command: (command: IndexerIncidentCommand) => Promise<void> }) {
  const [reason,setReason] = useState('');
  const stage = workflowStage(run);
  return <EuiPanel hasBorder hasShadow={false} paddingSize='m'>
    <EuiText size='s'>
      <h3>{titles[run.template_id]} v{run.version}</h3>
      <p>Run {run.id} · {phases[stage]}</p>
      <p>Scope: {run.scope} · Reason: {run.reason}</p>
      <ol>{run.steps.map(step => <li key={step.revision}>
        <strong>{phases[step.stage]}</strong> — {step.actor} · {step.at} · revision {step.revision}
        <p>{label(step.observation)}{step.reference && <> · Record {step.reference}</>}</p>
      </li>)}</ol>
      {!workflowTerminal(run) && <p>Current checkpoint: {label(run.observed_state)}.</p>}
      {stage === 'prepare' && <p>Complete the exact preparation task in Investigation tasks, then advance to create a response request.</p>}
      {stage === 'response' && <p>Use the linked response record below. Approval, manager acknowledgement and ambiguous dispatch do not satisfy this checkpoint. Reconcile independently first.</p>}
      {stage === 'review' && <p>Complete the exact evidence review task in Investigation tasks before finishing.</p>}
    </EuiText>
    {!workflowTerminal(run) && <>
      <EuiButton disabled={disabled || !run.can_advance} onClick={() => void command({ kind:'advance-workflow',run_id:run.id })}>
        {stage === 'response' && run.observed_state !== 'reported_completed' && run.can_advance ? 'Record unsuccessful workflow' : 'Advance checkpoint'}
      </EuiButton>
      <EuiSpacer size='s' />
      {run.can_cancel ? <>
        <EuiFormRow label='Workflow cancellation reason'><EuiTextArea disabled={disabled} value={reason} maxLength={2048} onChange={e => setReason(e.target.value)} /></EuiFormRow>
        <EuiButtonEmpty disabled={disabled || !safe(reason)} onClick={() => void command({ kind:'cancel-workflow',run_id:run.id,reason })}>Cancel workflow</EuiButtonEmpty>
      </> : <EuiText size='s'>Resolve or cancel the linked response through its existing governance controls before cancelling this run.</EuiText>}
    </>}
  </EuiPanel>;
}

export function IncidentWorkflowsPanel({ page, incident, disabled, command }: {
  page: IncidentResponsePage; incident: IncidentSummary; disabled: boolean; command: (command: IndexerIncidentCommand) => Promise<void>;
}) {
  const [template,setTemplate] = useState<WorkflowTemplate>('vulnerability_investigation');
  const [scope,setScope] = useState('');
  const [reason,setReason] = useState('');
  if (page.workflow_runs === undefined) return null;
  const runs = page.workflow_runs;
  const active = runs.some(run => !workflowTerminal(run));
  const locked = disabled || !incident.owner || !!incident.handover || !['triaging','active'].includes(incident.status);
  const canStart = !locked && !active && runs.length < 10;
  const valid = safe(scope) && safe(reason) && (template !== 'vulnerability_investigation' || validScanScope(scope));
  return <>
    <EuiTitle size='s'><h2>Executable response playbooks</h2></EuiTitle>
    <EuiCallOut title='Persistent governed workflow'>A run creates real tasks and response requests. Each checkpoint is explicit and revision-controlled; the workflow does not approve requests or invoke the native runner. Completion is an analyst attestation, not independent endpoint verification. Finish or cancel active runs before incident closure. Feature activation and permissions are enforced by the indexer.</EuiCallOut>
    <EuiSpacer size='s' />
    <EuiText size='s'>{runs.length} of 10 lifetime runs · {active ? 'One active run' : 'No active run'}</EuiText>
    {runs.map(run => <React.Fragment key={run.id}><Run run={run} disabled={locked} command={command} /><EuiSpacer size='s' /></React.Fragment>)}
    {canStart && <form onSubmit={event => {
      event.preventDefault();
      if (canStart && valid) void command({ kind:'start-workflow',template_id:template,version:1,scope,reason });
    }}>
      <EuiFormRow label='Versioned playbook'><EuiSelect value={template} options={Object.entries(titles).map(([value,text]) => ({value,text:text+' v1'}))}
        onChange={e => {setTemplate(e.target.value as WorkflowTemplate);setScope('');}} /></EuiFormRow>
      <EuiFormRow label='Scope' helpText={template === 'vulnerability_investigation' ? 'Exact configured manager UUID:agent:001' : 'Human-readable evidence scope, no secret or command'}>
        <EuiFieldText value={scope} maxLength={512} onChange={e => setScope(e.target.value)} /></EuiFormRow>
      <EuiFormRow label='Reason'><EuiTextArea value={reason} maxLength={2048} onChange={e => setReason(e.target.value)} /></EuiFormRow>
      <EuiButton type='submit' disabled={!valid}>Start playbook</EuiButton>
    </form>}
    <EuiSpacer size='m' />
  </>;
}
