import { validateAutomationPolicy, validateAutomationSave, validateAutomationPreview, validateAutomationHistory } from './automation-contract';

const id='00000000-0000-4000-8000-000000000001', target='00000000-0000-4000-8000-000000000002', incident='00000000-0000-4000-8000-000000000003';
const key={policy_id:id,policy_version:1};
const rule={id:'route',trigger:'created',minimum_severity:'informational',status:'any_open',minimum_findings:2,unassigned_only:true,required_tags:['z','a'],correlation_policy_id:target,actions:{assign_to:'analyst',raise_priority:'urgent',add_tags:['z','a'],create_task:'Investigate'}};
const policy={...key,rules:[rule]};
const canonical=validateAutomationPolicy(policy);

describe('automation contracts', () => {
  it('canonicalizes tags and retains exact originating policy condition', () => {
    expect(canonical.rules[0].required_tags).toEqual(['a','z']);
    expect(canonical.rules[0].actions.add_tags).toEqual(['a','z']);
    expect(canonical.rules[0].correlation_policy_id).toBe(target);
    expect(validateAutomationPolicy({...policy,rules:[{...rule,correlation_policy_id:null}]}).rules[0].correlation_policy_id).toBeNull();
  });
  it('rejects invalid conditions, actions and unexpected fields', () => {
    for(const patch of [{id:'Bad'},{trigger:'closed'},{status:'closed'},{minimum_findings:1001},{minimum_findings:1.5},{unassigned_only:1},
      {minimum_severity:'unknown'},{required_tags:['a','a']},{required_tags:['UPPER']},{correlation_policy_id:'bad'},{correlation_policy_id:undefined},
      {actions:{}},{actions:{close:true}},{actions:{assign_to:'_shared'}},{actions:{assign_to:' a'}},{actions:{create_task:'x\ny'}},
      {actions:{raise_priority:'critical'}},{actions:{raise_severity:'urgent'}},{actions:{apply_playbook:'arbitrary'}},
      {actions:{add_tags:[]}},{actions:{add_tags:['a','a']}},{actor:'forged'}])
      expect(() => validateAutomationPolicy({...policy,rules:[{...rule,...patch}]})).toThrow();
    for(const patch of [{policy_id:'bad'},{policy_version:0},{policy_version:2147483648},{rules:[]},{rules:[rule,rule]},{rules:Array(11).fill(rule)},{enabled:true}])
      expect(() => validateAutomationPolicy({...policy,...patch})).toThrow();
  });
  it('checks saved version and exact returned definition', () => {
    const saved={policy:canonical,fingerprint:'a'.repeat(64),created_by:'author',created_at:'2026-11-26T12:00:00Z'};
    expect(validateAutomationSave({saved,replayed:false},canonical)).toEqual({saved,replayed:false});
    for(const patch of [{fingerprint:'bad'},{created_by:' '},{created_at:'2026-02-30T00:00:00Z'},
      {policy:{...canonical,rules:[{...canonical.rules[0],minimum_findings:3}]}}])
      expect(() => validateAutomationSave({saved:{...saved,...patch},replayed:false},canonical)).toThrow();
  });
  it('checks read-only preview identity and state conservation', () => {
    const preview={...key,incident_id:incident,revision:1,state:'matched',rule_id:'route',changed_fields:4};
    expect(validateAutomationPreview(preview,key,incident)).toEqual(preview);
    expect(validateAutomationPreview({...preview,state:'not_matched',rule_id:null,changed_fields:0},key,incident).state).toBe('not_matched');
    for(const patch of [{incident_id:id},{policy_version:2},{revision:0},{rule_id:null},{changed_fields:8},{state:'blocked'},{state:'ineligible'},{raw:'secret'}])
      expect(() => validateAutomationPreview({...preview,...patch},key,incident)).toThrow();
  });
  it('checks receipt provenance, no-op outcome and unique ordered revisions', () => {
    const run={...key,policy_hash:'a'.repeat(64),rule_id:'route',trigger_revision:1,applied_revision:2,actor:'runner',at:'2026-11-26T12:00:00.123Z',changed_fields:4};
    const history={incident_id:incident,revision:2,activity_pending:false,runs:[run]};
    expect(validateAutomationHistory(history,incident)).toEqual(history);
    expect(validateAutomationHistory({...history,activity_pending:true,runs:[{...run,changed_fields:0}]},incident).runs[0].changed_fields).toBe(0);
    for(const patch of [{trigger_revision:2},{applied_revision:3},{policy_hash:'bad'},{actor:' '},{at:'bad'},{changed_fields:8},{raw:'secret'}])
      expect(() => validateAutomationHistory({...history,runs:[{...run,...patch}]},incident)).toThrow();
    expect(() => validateAutomationHistory({...history,revision:4,runs:[run,{...run,trigger_revision:3,applied_revision:4}]},incident)).toThrow();
    expect(() => validateAutomationHistory({...history,revision:4,runs:[{...run,policy_version:2,trigger_revision:3,applied_revision:4},run]},incident)).toThrow();
  });
});
