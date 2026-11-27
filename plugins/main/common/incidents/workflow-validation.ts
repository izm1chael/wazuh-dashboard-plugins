import type { IncidentResponsePage, WorkflowRun } from './contracts';

const TERMINAL = ['completed', 'failed', 'cancelled'];
const RESPONSE_TERMINAL = ['rejected', 'cancelled', 'reported_completed', 'reported_failed', 'reported_not_performed'];
const RESPONSE_FAILURE = ['rejected', 'cancelled', 'reported_failed', 'reported_not_performed'];
const SCAN_SCOPE = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:agent:[0-9]{3,8}$/;
const fail = (): never => { throw new Error('Invalid workflow projection'); };
const exact = (row: object, keys: string[]) => Object.keys(row).length === keys.length && keys.every(k => Object.prototype.hasOwnProperty.call(row, k));
const text = (value: unknown, max: number): value is string => typeof value === 'string' && value.length <= max &&
  !!value.trim() && value.trim() === value && !/[\x00-\x1f\x7f-\x9f]/.test(value);
const time = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value));
const int = (value: number, max: number) => Number.isSafeInteger(value) && value > 0 && value <= max;

export function validateWorkflowRuns(page: IncidentResponsePage, incident: string): void {
  // Earlier governed-response versions may omit workflow history. Never imply an empty run history.
  if (page.workflow_runs === undefined) return;
  if (page.mode !== 'governed_response_tracking' || !Array.isArray(page.workflow_runs) || page.workflow_runs.length > 10) fail();
  const responses = new Map(page.responses.map(row => [row.id, row]));
  const revisions = new Set<number>();
  let priorEnd = 0, active = false;
  for (const run of page.workflow_runs) {
    if (!run || !exact(run, ['id','template_id','version','scope','reason','steps','observed_state','can_advance','can_cancel']) ||
        !['vulnerability_investigation','evidence_collection'].includes(run.template_id) || run.version !== 1 ||
        !text(run.scope,512) || !text(run.reason,2048) || !Array.isArray(run.steps) || run.steps.length < 1 || run.steps.length > 4 ||
        (run.template_id === 'vulnerability_investigation' && (!SCAN_SCOPE.test(run.scope) || /^0+$/.test(run.scope.split(':').pop()!))) ||
        typeof run.can_advance !== 'boolean' || typeof run.can_cancel !== 'boolean' || active) fail();
    let previous = '', prior = 0, before = -Infinity, responseState: string | undefined;
    for (const step of run.steps) {
      if (!step || !exact(step,['stage','revision','actor','at','reference','observation']) ||
          !int(step.revision,page.observed_revision) || step.revision <= prior || revisions.has(step.revision) ||
          !text(step.actor,1024) || !time(step.at) || Date.parse(step.at) < before ||
          typeof step.reference !== 'string' || typeof step.observation !== 'string' || step.observation.length > 2048) fail();
      const expected = incident + ':' + step.revision;
      switch (step.stage) {
        case 'prepare':
          if (previous !== '' || step.revision <= priorEnd || run.id !== expected || step.reference !== expected || step.observation !== 'started') fail();
          break;
        case 'response': {
          if (previous !== 'prepare' || step.reference !== expected || step.observation !== 'task_completed') fail();
          const response = responses.get(step.reference);
          if (!response || response.type !== (run.template_id === 'vulnerability_investigation' ? 'scan_vulnerability' : 'collect_evidence') ||
              response.scope !== run.scope || response.reason !== run.reason || response.requested_by !== step.actor || response.requested_at !== step.at) return fail();
          responseState = response.state; break;
        }
        case 'review':
          if (previous !== 'response' || step.observation !== 'reported_completed' || responseState !== step.observation || step.reference !== expected) fail();
          break;
        case 'completed':
          if (previous !== 'review' || step.reference !== '' || step.observation !== 'task_completed') fail();
          break;
        case 'failed':
          if (previous !== 'response' || step.reference !== '' || !RESPONSE_FAILURE.includes(step.observation) || responseState !== step.observation) fail();
          break;
        case 'cancelled':
          if (!['prepare','response','review'].includes(previous) || step.reference !== '' || !text(step.observation,2048) ||
              (previous === 'response' && !RESPONSE_TERMINAL.includes(responseState ?? ''))) fail();
          break;
        default: fail();
      }
      revisions.add(step.revision); previous = step.stage; prior = step.revision; before = Date.parse(step.at);
    }
    priorEnd = prior;
    active = !TERMINAL.includes(previous);
    const task = previous === 'prepare' || previous === 'review';
    if (task ? !['open','completed'].includes(run.observed_state) :
        previous === 'response' ? run.observed_state !== responseState : run.observed_state !== 'terminal') fail();
    if (run.can_advance !== (task && run.observed_state === 'completed' || previous === 'response' && RESPONSE_TERMINAL.includes(run.observed_state)) ||
        run.can_cancel !== (task || previous === 'response' && RESPONSE_TERMINAL.includes(run.observed_state))) fail();
  }
}

export function workflowStage(run: WorkflowRun) { return run.steps[run.steps.length - 1].stage; }
export function workflowTerminal(run: WorkflowRun) { return TERMINAL.includes(workflowStage(run)); }
