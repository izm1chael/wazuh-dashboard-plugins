import React, { useState } from 'react';
import {
  EuiCallOut,
  EuiFieldSearch,
  EuiFieldText,
  EuiFormRow,
  EuiPanel,
  EuiSpacer,
  EuiText,
  EuiTitle,
  EuiButton,
  EuiButtonEmpty,
} from '@elastic/eui';
import { Dataset, findDatasets, preview } from './wucf-model';

/**
 * Native EUI component candidate. Deliberately not mounted or registered.
 * No requests, secret collection, persistence or activation are possible.
 */
export const WucfCatalogue = () => {
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Dataset | null>(null);
  const [interval, setInterval] = useState('300');
  const config = selected ? preview(selected, interval) : null;

  return (
    <>
      <EuiTitle size='l'><h1>Data connectors</h1></EuiTitle>
      <EuiSpacer size='m' />
      <EuiCallOut title='Development preview' color='warning'>
        <p>Connector activation is unavailable. Provider permissions are preliminary and native delivery is not qualified.</p>
      </EuiCallOut>
      <EuiSpacer />
      <EuiFormRow label='Search connector catalogue' fullWidth>
        <EuiFieldSearch fullWidth value={search} onChange={e => setSearch(e.target.value)} />
      </EuiFormRow>
      <EuiSpacer size='m' />
      {findDatasets(search).length === 0 && <EuiText>No matching connectors.</EuiText>}
      {findDatasets(search).map(item => (
        <React.Fragment key={item.provider + ':' + item.dataset}>
          <EuiPanel>
            <EuiTitle size='s'><h2>{item.label}</h2></EuiTitle>
            <EuiText size='s'><p>{item.credentialKind} · Not qualified</p></EuiText>
            <EuiButtonEmpty onClick={() => { setSelected(item); setInterval('300'); }}>
              Review setup for {item.label}
            </EuiButtonEmpty>
          </EuiPanel>
          <EuiSpacer size='s' />
        </React.Fragment>
      ))}
      {selected && (
        <EuiPanel>
          <EuiTitle size='m'><h2>Setup: {selected.label}</h2></EuiTitle>
          <EuiSpacer size='s' />
          <EuiText>
            <p>Credential type: {selected.credentialKind}</p>
            <p>Candidate permission prerequisites:</p>
            <ul>{selected.permissions.map(permission => <li key={permission}>{permission}</li>)}</ul>
            <p>Credentials will be entered only after the authorized secret endpoint is qualified.</p>
          </EuiText>
          <EuiSpacer />
          <EuiFormRow label='Polling interval (seconds)' isInvalid={!config} error={!config ? 'Enter a whole number between 60 and 86400.' : undefined}>
            <EuiFieldText value={interval} onChange={e => setInterval(e.target.value)} isInvalid={!config} />
          </EuiFormRow>
          <EuiSpacer size='s' />
          {config && <EuiText size='s'><p>Configuration preview: every {config.interval_seconds} seconds. Nothing is saved.</p></EuiText>}
          <EuiButton isDisabled>Activate connector</EuiButton>
          <EuiButtonEmpty onClick={() => setSelected(null)}>Cancel setup</EuiButtonEmpty>
        </EuiPanel>
      )}
    </>
  );
};
