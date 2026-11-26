import React from 'react';
import { EuiButton, EuiPanel, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import type { CollaborationPage, IndexerIncidentCommand } from '../../../../common/incidents/contracts';

const STATES = { available: 'Available', already_applied: 'Already applied', not_applicable: 'Conditions not met',
  capacity_exceeded: 'Insufficient task capacity' } as const;
export function IncidentPlaybooksPanel({ page, disabled, command }: {
  page: CollaborationPage; disabled: boolean; command: (value: IndexerIncidentCommand) => Promise<void>;
}) {
  return <>
    <EuiTitle size='xs'><h3>Investigation playbooks</h3></EuiTitle>
    <EuiText size='s'><p>Versioned investigation checklists recommended from current incident metadata. Applying a checklist creates tasks only; it does not perform investigation or response actions.</p></EuiText>
    {page.playbooks === undefined || page.playbook_runs === undefined ? <EuiText size='s'>Playbook recommendations unavailable.</EuiText> : <>
      {page.playbooks.map(template => {
        const receipt = page.playbook_runs?.find(run => run.template_id === template.template_id && run.version === template.version);
        return <React.Fragment key={template.template_id + ':' + template.version}>
          <EuiPanel hasBorder hasShadow={false} paddingSize='m'>
            <EuiText size='s'><p><strong>{template.title}</strong> · v{template.version} · {STATES[template.state]}</p>
              <ol>{template.tasks.map((task, n) => <li key={n}>{task}</li>)}</ol>
              {receipt && <p>Applied by {receipt.applied_by} · {receipt.applied_at} · Revision {receipt.applied_revision} · {receipt.task_ids.length} generated tasks</p>}
            </EuiText>
            <EuiButton disabled={disabled || template.state !== 'available'} onClick={() =>
              void command({ kind: 'apply-playbook', template_id: template.template_id, version: template.version })}>
              Apply {template.title}
            </EuiButton>
          </EuiPanel><EuiSpacer size='s' />
        </React.Fragment>;
      })}
      {page.playbook_runs.length > 0 && <EuiText size='s'><h4>Application history</h4><ul>{page.playbook_runs.map(run =>
        <li key={run.template_id + ':' + run.version}>{run.template_id} v{run.version} · {run.applied_by} · {run.applied_at} · {run.task_ids.length} tasks</li>)}</ul></EuiText>}
    </>}
    <EuiSpacer size='m' />
  </>;
}
