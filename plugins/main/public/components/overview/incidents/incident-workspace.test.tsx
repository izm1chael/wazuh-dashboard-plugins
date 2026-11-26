import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { IncidentQueue } from './incident-queue';
import { IncidentCreate } from './incident-create';
import { IncidentDetail } from './incident-detail';
import type { IncidentApi } from './incident-api';
import type { IncidentSummary } from '../../../../common/incidents/contracts';

const ID = '00000000-0000-4000-8000-000000000001';
const KEY = '00000000-0000-4000-8000-000000000002';
const NOW = '2026-11-26T12:00:00.000Z';
const item: IncidentSummary = {
  id: ID, title: 'Suspicious activity', description: 'Test incident', status: 'new', severity: 'high',
  priority: 'medium', tlp: 'TLP:AMBER', owner: null, created_by: 'analyst', updated_by: 'analyst',
  created_at: NOW, updated_at: NOW, first_assigned_at: null, triage_started_at: null,
  activated_at: null, closed_at: null, first_closed_at: null, reopened_at: null, closure: null, revision: 1, finding_count: 0,
};

function setup() {
  const api = {
    collaboration: jest.fn().mockResolvedValue({ notes: [], tasks: [], observed_revision: 1, activity_pending: false }),
    activity: jest.fn().mockResolvedValue({ events: [], observed_revision: 1, activity_pending: false }),
    findings: jest.fn().mockResolvedValue({ findings: [], revision: 1, unavailable_count: 0 }),
    list: jest.fn().mockResolvedValue({ incidents: [item] }),
    get: jest.fn().mockResolvedValue(item),
    create: jest.fn().mockResolvedValue({ incident: item, activity_delivery: 'delivered', replayed: false }),
    command: jest.fn().mockResolvedValue({ incident: { ...item, revision: 2, owner: 'analyst' }, activity_delivery: 'delivered', replayed: false }),
  };
  return { api, open: jest.fn(), back: jest.fn(), create: jest.fn() };
}

describe('experimental incident workspace', () => {
  test('loads open incidents without a global time filter and opens stable identity', async () => {
    const { api, open, create } = setup();
    render(<IncidentQueue api={api as IncidentApi} open={open} create={create} />);
    fireEvent.click(await screen.findByRole('button', { name: item.title }));
    expect(open).toHaveBeenCalledWith(ID);
    expect(api.list).toHaveBeenCalledWith({ queue: 'open', limit: 50, after: undefined });
  });

  test('applies queue filters and follows a cursor', async () => {
    const { api, open, create } = setup();
    api.list.mockResolvedValue({ incidents: [item], next: { id: ID, time: 123 } });
    render(<IncidentQueue api={api as IncidentApi} open={open} create={create} />);
    await screen.findByRole('button', { name: item.title });
    fireEvent.change(screen.getByLabelText('Queue'), { target: { value: 'unassigned' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    await waitFor(() => expect(api.list).toHaveBeenLastCalledWith({ queue: 'unassigned', limit: 50, after: undefined }));
    await screen.findByRole('button', { name: item.title });
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(api.list).toHaveBeenLastCalledWith({ queue: 'unassigned', limit: 50, after: { id: ID, time: 123 } }));
  });

  test('retains the same create request and content after ambiguous failure', async () => {
    const { api, open, back } = setup();
    api.create.mockRejectedValueOnce(new Error('network lost'));
    const generateId = jest.fn(() => KEY);
    render(<IncidentCreate api={api as IncidentApi} open={open} back={back} generateId={generateId} />);
    fireEvent.change(screen.getByLabelText('Incident title'), { target: { value: 'Example' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create incident' }));
    await screen.findByText('Creation could not be confirmed');
    expect(screen.getByLabelText('Incident title')).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Retry same request' }));
    await waitFor(() => expect(open).toHaveBeenCalledWith(ID));
    expect(generateId).toHaveBeenCalledTimes(1);
    expect(api.create.mock.calls[0]).toEqual(api.create.mock.calls[1]);
  });

  test('displays only returned finding references and delivered audit events', async () => {
    const { api, back } = setup();
    api.findings.mockResolvedValue({ findings: [{ index: '.ds-wazuh-findings-v5-security-000001', document_id: 'visible-doc' }], revision: 1, unavailable_count: 1 });
    api.activity.mockResolvedValue({ events: [{ id: ID + ':1', incident_id: ID, revision: 1,
      kind: 'created', actor: 'analyst', at: NOW, changes: {} }], observed_revision: 1, activity_pending: true });
    render(<IncidentDetail api={api as IncidentApi} id={ID} back={back} />);
    expect(await screen.findByText('visible-doc')).toBeInTheDocument();
    expect(await screen.findByText('1 unavailable finding(s) on this page')).toBeInTheDocument();
    expect(await screen.findByText('Incident created')).toBeInTheDocument();
    expect(await screen.findByText('Audit delivery pending')).toBeInTheDocument();
    expect(api.findings).toHaveBeenCalledWith(ID, 0, 1);
  });

  test('renders notes and tasks and adds an attributed note through the revision-checked command', async () => {
    const { api, back } = setup();
    api.collaboration.mockResolvedValue({ notes: [{ id: ID + ':1', incident_id: ID, revision: 1, actor: 'reviewer', at: NOW, body: 'Analyst observation' }],
      tasks: [{ id: ID + ':2', title: 'Check logs', status: 'open', created_by: 'reviewer', created_at: NOW, completed_by: null, completed_at: null }],
      observed_revision: 1, activity_pending: false });
    render(<IncidentDetail api={api as IncidentApi} id={ID} back={back} />);
    expect(await screen.findByText('Analyst observation')).toBeInTheDocument();
    expect(await screen.findByText('Check logs')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Investigation note'), { target: { value: 'New observation' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add note' }));
    await waitFor(() => expect(api.command).toHaveBeenCalledWith(ID, 1, { kind: 'add-note', body: 'New observation' }));
  });

  test('sends expected revision and blocks another mutation until reload after failure', async () => {
    const { api, back } = setup();
    api.command.mockRejectedValueOnce(new Error('conflict'));
    render(<IncidentDetail api={api as IncidentApi} id={ID} back={back} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Claim incident' }));
    await screen.findByText('The change could not be confirmed. Reload the incident before another operation.');
    expect(api.command).toHaveBeenCalledWith(ID, 1, { kind: 'assign-self' });
    expect(screen.getByRole('button', { name: 'Claim incident' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Reload incident' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Claim incident' })).toBeEnabled());
  });
});
