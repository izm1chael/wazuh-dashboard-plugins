import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { IncidentPlaybooksPanel } from './incident-playbooks-panel';
import type { CollaborationPage } from '../../../../common/incidents/contracts';

const page: CollaborationPage = { notes: [], tasks: [], observed_revision: 3, activity_pending: false, playbook_runs: [],
  playbooks: [{ template_id: 'initial_triage', version: 1, title: 'Initial incident triage', tasks: ['Review finding'], state: 'available' }] };
describe('investigation playbooks', () => {
  test('submits only selected template identity', () => {
    const command = jest.fn().mockResolvedValue(undefined);
    render(<IncidentPlaybooksPanel page={page} disabled={false} command={command} />);
    expect(screen.getByText('Review finding')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Apply Initial incident triage' }));
    expect(command).toHaveBeenCalledWith({ kind: 'apply-playbook', template_id: 'initial_triage', version: 1 });
  });
  test('unavailable template cannot be applied', () => {
    render(<IncidentPlaybooksPanel page={{ ...page, playbooks: [{ ...page.playbooks![0], state: 'not_applicable' }] }}
      disabled={false} command={jest.fn()} />);
    expect(screen.getByRole('button', { name: 'Apply Initial incident triage' })).toBeDisabled();
  });
});
