import React, { useEffect, useRef, useState } from 'react';
import { EuiBasicTable, EuiBasicTableColumn, EuiButton, EuiCallOut, EuiText, EuiTitle, EuiSpacer } from '@elastic/eui';
import { getHttp } from '../../../kibana-services';
import { AutomationHistory, AutomationReceipt, validateAutomationHistory } from '../../../../common/incidents/automation-contract';

export function IncidentAutomationHistoryPanel({ id, revision, disabled }: { id: string; revision: number; disabled: boolean }) {
  const [history, setHistory] = useState<AutomationHistory>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const generation = useRef(0), active = useRef(false);
  useEffect(() => () => { generation.current++; }, []);
  async function load() {
    if (active.current || disabled) return;
    const run = ++generation.current; active.current = true; setBusy(true); setHistory(undefined); setError('');
    try {
      const result = validateAutomationHistory(await getHttp().post<unknown>('/indexer/incident-automation/history',
        { body: JSON.stringify({ incident_id: id }) }), id);
      if (result.revision !== revision) throw new Error('Incident changed');
      if (generation.current === run) setHistory(result);
    } catch (_) {
      if (generation.current === run) setError('Automation history unavailable or incident changed. Check permission and reload incident.');
    } finally {
      active.current = false; if (generation.current === run) setBusy(false);
    }
  }
  const columns: Array<EuiBasicTableColumn<AutomationReceipt>> = [
    { name: 'Policy version', render: row => row.policy_id + ' / ' + row.policy_version },
    { field: 'rule_id', name: 'Rule' }, { field: 'trigger_revision', name: 'Trigger revision' },
    { field: 'applied_revision', name: 'Recorded revision' }, { field: 'changed_fields', name: 'Changed fields' },
    { field: 'actor', name: 'Service account' }, { field: 'at', name: 'Recorded (UTC)' },
  ];
  return <>
    <EuiTitle size='s'><h2>Automation history</h2></EuiTitle>
    <EuiText size='s'>Recorded automation outcomes for this incident. Zero changed fields means the rule matched but had no eligible state changes. Pending audit is not a confirmed delivered event.</EuiText>
    <EuiSpacer size='s' />
    <EuiButton disabled={busy || disabled} isLoading={busy} onClick={() => void load()}>Load automation history</EuiButton>
    {error && <EuiCallOut color='warning' title={error} />}
    {history && <>
      {history.activity_pending && <EuiCallOut color='warning' title='Incident activity delivery pending' />}
      <EuiBasicTable<AutomationReceipt> items={history.runs} columns={columns} noItemsMessage='No recorded automation runs' />
      <EuiText size='s'>Revision {history.revision} · {history.runs.length} of 50 lifetime rule-set receipts.</EuiText>
    </>}
  </>;
}
