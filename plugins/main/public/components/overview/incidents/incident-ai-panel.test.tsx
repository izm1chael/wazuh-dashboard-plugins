import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { IncidentAiPanel } from './incident-ai-panel';
import type { IncidentSummary } from '../../../../common/incidents/contracts';
const incident = { id: '00000000-0000-4000-8000-000000000001', revision: 3, tlp: 'TLP:CLEAR' } as IncidentSummary;
describe('incident AI modes', () => {
  test('requires consent and sends only selected mode and incident identity through adapter', async () => {
    const assess = jest.fn().mockRejectedValue(new Error('disabled'));
    render(<IncidentAiPanel incident={incident} disabled={false} assess={assess} />);
    expect(screen.getByRole('button', { name: 'AI Review' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Agentic SOC' })).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Agentic SOC' }));
    expect(assess).toHaveBeenCalledWith(incident, 'agentic_soc');
    await screen.findByText(/Assessment unavailable/);
    expect(screen.getByRole('button', { name: 'AI Review' })).toBeDisabled();
  });
  test('blocks restricted disclosure labels', () => {
    render(<IncidentAiPanel incident={{ ...incident, tlp: 'TLP:RED' }} disabled={false} assess={jest.fn()} />);
    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByRole('button', { name: 'Agentic SOC' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'AI Review' })).toBeDisabled();
  });
});
