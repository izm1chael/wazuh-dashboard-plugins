import React from 'react';
import { EuiCallOut, EuiPanel, EuiSpacer, EuiText, EuiTitle } from '@elastic/eui';
import { parseManagementHealth, statusLabel } from './wucf-management-health';

type Props = { snapshot: unknown; environment: string };

/** Not registered; caller must fetch an authorized environment-local snapshot. */
export const WucfManagementHealthView = ({ snapshot, environment }: Props) => {
  const health = parseManagementHealth(snapshot, environment);
  if (!health) return (
    <EuiCallOut title='Connector health unavailable' color='warning'>
      <p>No valid environment-scoped observation is available.</p>
    </EuiCallOut>
  );
  return (
    <>
      <EuiTitle size='m'><h2>Connector health</h2></EuiTitle>
      <EuiSpacer size='s' />
      <EuiCallOut title='Local collection observations only' color='warning'>
        <p>Native Wazuh delivery and telemetry coverage have not been established. A successful local run is not proof that events were indexed or detected.</p>
      </EuiCallOut>
      <EuiSpacer size='m' />
      {health.sources.length === 0 && <EuiText>No registered sources.</EuiText>}
      {health.sources.map(source => (
        <React.Fragment key={JSON.stringify([source.instance, source.dataset])}>
          <EuiPanel>
            <EuiTitle size='s'><h3>{source.instance} · {source.dataset}</h3></EuiTitle>
            <EuiText size='s'>
              <p>{statusLabel(source.status)} · Poll interval {source.interval} seconds</p>
              {source.last_run ? (
                <p>Last recorded run: {source.last_run.outcome}; {source.last_run.acknowledged_events} events in {source.last_run.acknowledged_pages} locally acknowledged pages.
                  {source.last_run.completed_version !== source.version && ' Historical observation; not the current lifecycle version.'}
                  {source.last_run.pending && ' Delivery remains unconfirmed for a pending page.'}
                </p>
              ) : <p>No completed run counters available.</p>}
            </EuiText>
          </EuiPanel>
          <EuiSpacer size='s' />
        </React.Fragment>
      ))}
    </>
  );
};
