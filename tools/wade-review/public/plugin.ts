// SPDX-License-Identifier: AGPL-3.0-or-later
import { AppMountParameters, CoreSetup, Plugin } from 'opensearch-dashboards/public';
export class WadeReviewPlugin implements Plugin {
  public setup(core: CoreSetup) {
    core.application.register({
      id: 'wadeReview',
      title: 'WADE Detection Engineering (offline)',
      euiIconType: 'securityApp',
      mount: async (params: AppMountParameters) => {
        const { renderWorkspace } = await import('./application');
        return renderWorkspace(params.element);
      },
    });
    return {};
  }
  public start() { return {}; }
  public stop() {}
}
