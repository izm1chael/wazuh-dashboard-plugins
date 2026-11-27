import React from 'react';
import { EuiCallOut, EuiDescriptionList, EuiPanel, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { SourceIdentity, assessHealth } from './wucf-health-model';

const messages = {
  unknown: 'No matching observation',
  stale: 'Observation is stale',
  collection_error: 'Collection error',
  delivery_blocked: 'Delivery blocked',
  local_events_observed: 'Events observed at a non-native delivery boundary',
  no_events_observed: 'No events observed',
};

/**
 * Unmounted read-only candidate. Receives sanitized observations from the
 * eventual authenticated server. No direct transport or secret access.
 */
export function WucfHealthPanel({ source, observation, nowMs }: {
  source: SourceIdentity;
  observation: unknown;
  nowMs: number;
}) {
  const result = assessHealth(observation, source, nowMs);
  const row = result.observation;
  return (
    <EuiPanel>
      <EuiTitle size='s'><h2>Connector health</h2></EuiTitle>
      <EuiSpacer size='s' />
      <EuiCallOut title={messages[result.state]} color='warning'>
        <p>Native delivery and detection coverage are not qualified.</p>
      </EuiCallOut>
      <EuiSpacer size='s' />
      {row ? (
        <EuiDescriptionList listItems={[
          { title: 'Observation time (UTC)', description: row.observed_at },
          { title: 'Execution status', description: row.execution_status },
          { title: 'Delivery boundary', description: row.delivery_boundary },
          { title: 'Acknowledged pages (local)', description: String(row.acknowledged_pages) },
          { title: 'Acknowledged events (local)', description: String(row.acknowledged_events) },
          { title: 'Pending delivery', description: row.pending ? 'Yes' : 'No' },
          { title: 'Coverage', description: 'Unknown' },
        ]} />
      ) : <EuiText size='s'>No validated data for this source revision.</EuiText>}
    </EuiPanel>
  );
}
