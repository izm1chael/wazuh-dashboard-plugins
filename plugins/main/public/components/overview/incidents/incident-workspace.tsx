import React from 'react';
import { useHistory, useParams } from 'react-router-dom';
import { EuiButtonEmpty, EuiPage, EuiPageBody, EuiPanel, EuiSpacer } from '@elastic/eui';
import { incidentApi } from './incident-api';
import { IncidentQueue } from './incident-queue';
import { IncidentCreate } from './incident-create';
import { IncidentDetail } from './incident-detail';
import { CorrelationPreviewPanel } from './correlation-preview-panel';

export function IncidentWorkspace() {
  const { incidentId } = useParams<{ incidentId?: string }>();
  const history = useHistory();
  const back = () => history.push('/incidents');
  const open = (id: string) => history.push('/incidents/' + encodeURIComponent(id));
  return <EuiPage><EuiPageBody><EuiPanel paddingSize='l'>
    {incidentId === 'correlation' ? <CorrelationPreviewPanel back={back} /> : incidentId === 'new' ? <IncidentCreate api={incidentApi} back={back} open={open} /> :
      incidentId ? <IncidentDetail key={incidentId} id={incidentId} api={incidentApi} back={back} /> :
        <><EuiButtonEmpty onClick={() => history.push('/incidents/correlation')}>Correlation preview</EuiButtonEmpty><EuiSpacer size='s' /><IncidentQueue api={incidentApi} open={open} create={() => history.push('/incidents/new')} /></>}
  </EuiPanel></EuiPageBody></EuiPage>;
}
