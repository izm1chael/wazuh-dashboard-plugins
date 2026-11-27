import type { IncidentResponsePage, IncidentResponseRecord, WorkflowRun, WorkflowStep } from './contracts';
import { validateWorkflowRuns, workflowStage, workflowTerminal } from './workflow-validation';

const id = '00000000-0000-4000-8000-000000000001';
const at = '2026-11-26T12:00:00.000Z';
const scope = 'Host review';
const prepare: WorkflowStep = { stage:'prepare',revision:4,actor:'analyst',at,reference:id+':4',observation:'started' };
const response: WorkflowStep = { stage:'response',revision:6,actor:'analyst',at,reference:id+':6',observation:'task_completed' };
const review: WorkflowStep = { stage:'review',revision:9,actor:'analyst',at,reference:id+':9',observation:'reported_completed' };
const finish: WorkflowStep = { stage:'completed',revision:11,actor:'analyst',at,reference:'',observation:'task_completed' };
const base: WorkflowRun = { id:id+':4',template_id:'evidence_collection',version:1,scope,reason:'Investigate',
  steps:[prepare],observed_state:'open',can_advance:false,can_cancel:true };
const record: IncidentResponseRecord = { id:id+':6',type:'collect_evidence',scope,reason:'Investigate',state:'reported_completed',
  requested_by:'analyst',requested_at:at,decided_by:'reviewer',decided_at:at,decision_reason:'Reviewed',
  finalized_by:'reviewer',finalized_at:at,final_reason:'Reviewed artifact',execution_verified:false };
const page = (run: WorkflowRun, responses: IncidentResponseRecord[] = []): IncidentResponsePage => ({
  mode:'governed_response_tracking',observed_revision:20,activity_pending:false,responses,workflow_runs:[run]
});
describe('persistent workflow projection', () => {
  it('accepts preparation, response, review and completion checkpoints', () => {
    validateWorkflowRuns(page(base),id);
    validateWorkflowRuns(page({...base,observed_state:'completed',can_advance:true}),id);
    validateWorkflowRuns(page({...base,steps:[prepare,response],observed_state:'approved',can_cancel:false},
      [{...record,state:'approved',finalized_by:null,finalized_at:null,final_reason:null}]),id);
    validateWorkflowRuns(page({...base,steps:[prepare,response,review],observed_state:'open'},[record]),id);
    const run = {...base,steps:[prepare,response,review,finish],observed_state:'terminal',can_cancel:false};
    validateWorkflowRuns(page(run,[record]),id);
    expect(workflowStage(run)).toBe('completed'); expect(workflowTerminal(run)).toBe(true);
  });
  it('rejects out of sequence or mismatched links, forged readiness, revisions and terminal outcomes', () => {
    const run = {...base,steps:[prepare,response],observed_state:'reported_completed',can_advance:true};
    validateWorkflowRuns(page(run,[record]),id);
    for (const bad of [{...base,can_advance:true},{...base,id:id+':5'},
      {...run,steps:[response]},{...run,steps:[prepare,{...response,reference:id+':7'}]},
      {...run,steps:[prepare,{...response,revision:4}]},{...run,steps:[prepare,response,finish]},
      {...run,observed_state:'approved'},{...run,can_cancel:false},
      {...run,steps:[prepare,response,review],observed_state:'open',can_advance:true},
      {...base,template_id:'vulnerability_investigation' as const,scope:id+':agent:000'}]) {
      expect(() => validateWorkflowRuns(page(bad,[record]),id)).toThrow();
    }
    expect(() => validateWorkflowRuns(page(run,[{...record,scope:'Other'}]),id)).toThrow();
    expect(() => validateWorkflowRuns({...page(base),workflow_runs:[base,base]},id)).toThrow();
  });
  it('accepts failed and cancelled terminal runs without equating acknowledgement to completion', () => {
    const failed: WorkflowStep = {...finish,stage:'failed',observation:'reported_failed'};
    validateWorkflowRuns(page({...base,steps:[prepare,response,failed],observed_state:'terminal',can_cancel:false},
      [{...record,state:'reported_failed'}]),id);
    validateWorkflowRuns(page({...base,steps:[prepare,{...finish,stage:'cancelled',observation:'Stop'}],observed_state:'terminal',can_cancel:false}),id);
    const scan = {...base,template_id:'vulnerability_investigation' as const,scope:id+':agent:001',steps:[prepare,response],
      observed_state:'manager_accepted',can_cancel:false};
    const scanRecord = {...record,type:'scan_vulnerability' as const,scope:scan.scope,state:'manager_accepted' as const};
    validateWorkflowRuns(page(scan,[scanRecord]),id);
    expect(() => validateWorkflowRuns(page({...scan,can_advance:true},[scanRecord]),id)).toThrow();
  });
});
