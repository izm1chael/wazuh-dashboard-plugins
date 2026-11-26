import React from 'react';
import { EuiButton, EuiSpacer } from '@elastic/eui';
import { useHistory } from 'react-router-dom';
import { getCapabilities } from '../../../../kibana-services';
import { InventoryDashboardTable } from '../../../common/dashboards';
import {
  CasesDataSource,
  FindingsDataSourceRepository,
} from '../../../common/data-source';
import { caseManagementDocumentDetailsTabs } from '../../../common/document-details/case-management';
import { CASE_MANAGEMENT_CASES_DASHBOARD_ID } from '../../../../../common/constants';
import tableColumns from './table-columns';
import managedFilters from './managed-filters';

const CASES_DASHBOARD_PANELS = [
  { dashboardId: CASE_MANAGEMENT_CASES_DASHBOARD_ID },
];

export const CaseManagementCases = () => {
  const history = useHistory();
  return (
    <>
      {getCapabilities().wazuh?.experimentalIncidents && (
        <>
          <EuiButton onClick={() => history.push('/incidents')}>Open experimental incidents</EuiButton>
          <EuiSpacer size='m' />
        </>
      )}
    <InventoryDashboardTable
      DataSource={CasesDataSource}
      DataSourceRepositoryCreator={FindingsDataSourceRepository}
      tableDefaultColumns={tableColumns}
      managedFilters={managedFilters}
      getDashboardPanels={CASES_DASHBOARD_PANELS}
      tableId='case-management-cases'
      additionalDocumentDetailsTabs={caseManagementDocumentDetailsTabs}
    />
    </>
  );
};
