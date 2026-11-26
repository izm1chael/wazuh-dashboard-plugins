import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { IncidentResponsePanel } from './incident-response-panel';
import { IssuedResponsesPanel } from './issued-responses-panel';
import type { IncidentApi } from './incident-api';
import type { IncidentSummary, IncidentResponseRecord } from '../../../../common/incidents/contracts';
const id = '00000000-0000-4000-8000-000000000001';
const now = '2026-11-26T12:00:00Z';
const incident = { id, revision: 3, owner: 'analyst', status: 'active' } as IncidentSummary;
const row: IncidentResponseRecord = { id: id + ':2', type: 'review_containment', scope: 'Host review', reason: 'Evidence',
  state: 'requested', requested_by: 'analyst', requested_at: now, decided_by: null, decided_at: null, decision_reason: null,
  finalized_by: null, finalized_at: null, final_reason: null, execution_verified: false };
describe('response governance', () => {
  test('approval is explicit and does not dispatch', async () => {
    const api = { responses: jest.fn().mockResolvedValue({ responses: [row], observed_revision: 3, activity_pending: false, mode: 'manual_tracking_only' }) } as unknown as IncidentApi;
    const command = jest.fn().mockResolvedValue(undefined);
    render(<IncidentResponsePanel api={api} incident={incident} disabled={false} command={command} />);
    expect(await screen.findByText(/Execution not verified/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Decision or outcome reason for ' + row.id), { target: { value: 'Independent review' } });
    fireEvent.click(screen.getByRole('button', { name: 'Approve request' }));
    expect(command).toHaveBeenCalledWith({ kind: 'approve-response', response_id: row.id, reason: 'Independent review' });
    expect(screen.queryByRole('button', { name: /execute/i })).not.toBeInTheDocument();
  });
  test('issued records are fetched only on demand and labelled unverified', async () => {
    const issuedResponses = jest.fn().mockResolvedValue({ issued_responses: [{ index: '.ds-wazuh-active-responses-000001',
      document_id: 'response', finding: { index: '.ds-wazuh-findings-v5-security-000001', document_id: 'doc' },
      issued_at: now, name: 'Review', type: 'stateless', location: 'local', configured_agent_id: null,
      source_agent_id: '001', state: 'issued_only', execution_verified: false }], revision: 3, visible_finding_count: 1,
      mode: 'exact_visible_finding_page_issued_only' });
    render(<IssuedResponsesPanel api={{ issuedResponses } as unknown as IncidentApi} incident={incident} />);
    expect(issuedResponses).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Inspect related issued actions' }));
    await waitFor(() => expect(issuedResponses).toHaveBeenCalledWith(id, 0, 3));
    expect(await screen.findByText('Issued only — execution unverified')).toBeInTheDocument();
  });
});
