import React from 'react';
import { EuiCallOut, EuiBasicTable, EuiPanel, EuiSpacer, EuiTitle } from '@elastic/eui';
import { ScheduledSource, parseSchedulerSnapshot } from './wucf-scheduler-model';

const labels: Record<string, string> = {
  draft: 'Draft', ready: 'Ready', paused: 'Paused', review: 'Review required',
  revoked: 'Revoked', expired_claim: 'Expired claim', collecting: 'Collecting',
  not_observed: 'Not observed', overdue: 'Overdue', local_observation: 'Local observation',
};

/** Unmounted, read-only lab scheduler view. No lifecycle mutations. */
export function WucfSchedulerPanel({ environment, snapshot }: {
  environment: string; snapshot: unknown;
}) {
  const parsed = parseSchedulerSnapshot(snapshot, environment);
  return (
    <EuiPanel>
      <EuiTitle size='s'><h2>Connector execution status</h2></EuiTitle>
      <EuiSpacer size='s' />
      <EuiCallOut color='warning' title='Local reference state only'>
        <p>Native ingestion, detection coverage and production activation are not qualified.</p>
      </EuiCallOut>
      <EuiSpacer />
      {parsed ? (
        <EuiBasicTable<ScheduledSource>
          items={parsed.sources}
          itemId={item => JSON.stringify([item.instance, item.dataset])}
          noItemsMessage='No registered sources'
          columns={[
            { field: 'instance', name: 'Source' },
            { field: 'dataset', name: 'Dataset' },
            { field: 'status', name: 'Status', render: (status: string) => labels[status] || 'Unknown' },
            { field: 'last_run', name: 'Local events (last run)', render: (run: ScheduledSource['last_run']) => run ? String(run.acknowledged_events) : 'Not observed' },
            { field: 'last_run', name: 'Pending', render: (run: ScheduledSource['last_run']) => run ? (run.pending ? 'Yes' : 'No') : 'Unknown' },
          ]}
        />
      ) : <EuiCallOut title='No valid scoped snapshot' color='warning' />}
    </EuiPanel>
  );
}
