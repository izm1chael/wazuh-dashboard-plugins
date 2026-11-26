import React from 'react';
import { useHistory, useParams } from 'react-router-dom';
import { EuiButtonEmpty, EuiPage, EuiPageBody, EuiPanel, EuiSpacer } from '@elastic/eui';
import { incidentApi } from './incident-api';
import { IncidentQueue } from './incident-queue';
import { IncidentCreate } from './incident-create';
import { IncidentDetail } from './incident-detail';
import { IncidentTuningPanel } from './incident-tuning-panel';
import { IncidentHuntPanel } from './incident-hunt-panel';
import { IncidentMetricsPanel } from './incident-metrics-panel';
import { CorrelationPreviewPanel } from './correlation-preview-panel';

export function IncidentWorkspace() {
  const { incidentId } = useParams<{ incidentId?: string }>();
  const history = useHistory();
  const back = () => history.push('/incidents');
  const open = (id: string) => history.push('/incidents/' + encodeURIComponent(id));
  return <EuiPage><EuiPageBody><EuiPanel paddingSize='l'>
    {incidentId === 'hunt' ? <IncidentHuntPanel back={back} /> : incidentId === 'tuning' ? <IncidentTuningPanel back={back} /> : incidentId === 'metrics' ? <IncidentMetricsPanel back={back} /> : incidentId === 'correlation' ? <CorrelationPreviewPanel back={back} /> : incidentId === 'new' ? <IncidentCreate api={incidentApi} back={back} open={open} /> :
      incidentId ? <IncidentDetail key={incidentId} id={incidentId} api={incidentApi} back={back} openRelated={open} /> :
        <><EuiButtonEmpty onClick={() => history.push('/incidents/hunt')}>Threat hunting</EuiButtonEmpty><EuiButtonEmpty onClick={() => history.push('/incidents/tuning')}>Detection tuning evaluation</EuiButtonEmpty><EuiButtonEmpty onClick={() => history.push('/incidents/metrics')}>SOC reporting</EuiButtonEmpty><EuiButtonEmpty onClick={() => history.push('/incidents/correlation')}>Correlation preview</EuiButtonEmpty><EuiSpacer size='s' /><IncidentQueue api={incidentApi} open={open} create={() => history.push('/incidents/new')} /></>}
  </EuiPanel></EuiPageBody></EuiPage>;
}
