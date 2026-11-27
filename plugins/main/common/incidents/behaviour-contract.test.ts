import { assessVolume, baselineInput, validateBehaviourInput, validateBehaviourReport, BehaviourReport } from './behaviour-contract';
import type { HuntReport } from './hunt-contract';
const q=validateBehaviourInput({field:'user.name',values:['bob','alice'],from:'2026-11-25T00:00:00Z',until:'2026-11-26T00:00:00Z'},Date.parse('2026-11-26T00:02:00Z'));
const baseline=baselineInput(q);
const index='.ds-wazuh-findings-v5-security-000001';
const row=(id:string,timestamp:string,matched_values:string[])=>({index,document_id:id,timestamp,matched_values});
const history:HuntReport={...baseline,scope:'caller_visible_findings_exact_terms',rows:[row('a',baseline.from,q.values),
  row('b','2026-11-19T00:00:00Z',['alice']),row('c','2026-11-24T23:59:59.999999999Z',['alice'])],match_count:3};
const current:HuntReport={...q,scope:'caller_visible_findings_exact_terms',rows:[row('d',q.from,q.values)],match_count:1};
const report:BehaviourReport={scope:'caller_visible_finding_volume',model:'daily_volume_v1',baseline:history,current,
  assessments:[assessVolume('alice',[1,1,0,0,0,0,1],1),assessVolume('bob',[1,0,0,0,0,0,0],1)]};
describe('bounded behaviour model',()=>{
  it('separates observed novelty and sparse history from volume elevation',()=>{
    const zero=[0,0,0,0,0,0,0],regular=[2,2,2,2,2,2,2];
    expect(assessVolume('a',zero,0).classification).toBe('no_observed_activity');
    expect(assessVolume('a',zero,1).classification).toBe('newly_observed');
    expect(assessVolume('a',[1,0,0,0,0,0,0],100).classification).toBe('sparse_baseline');
    expect(assessVolume('a',regular,4).classification).toBe('within_volume_threshold');
    expect(assessVolume('a',regular,5).classification).toBe('elevated_volume');
    expect(assessVolume('a',[10,10,10,10,10,10,10],20).threshold).toBe(20);
    expect(()=>assessVolume('a',[100,1,0,0,0,0,0],0)).toThrow();
    expect(()=>assessVolume('a',regular,101)).toThrow();
    expect(()=>assessVolume('a',[1,2],1)).toThrow();
  });
  it('requires completed aligned UTC day, bounded fields and values',()=>{
    expect(q.values).toEqual(['alice','bob']);
    expect(baseline.from).toBe('2026-11-18T00:00:00.000Z');
    for(const bad of [{...q,from:'2026-11-25T00:00:01Z'},{...q,until:'2026-11-26T00:00:01Z'},
      {...q,values:['a','b','c','d','e','f']},{...q,field:'dns.question.name' as const}])
      expect(()=>validateBehaviourInput(bad,Date.parse('2026-11-26T00:10:00Z'))).toThrow();
    expect(()=>validateBehaviourInput(q,Date.parse('2026-11-26T00:01:59Z'))).toThrow();
  });
  it('recomputes exact counts and rejects changed populations, classifications and duplicate identity',()=>{
    expect(()=>validateBehaviourReport(report,q)).not.toThrow();
    expect(()=>validateBehaviourReport({...report,assessments:[{...report.assessments[0],classification:'elevated_volume'},report.assessments[1]]},q)).toThrow();
    expect(()=>validateBehaviourReport({...report,assessments:[{...report.assessments[0],daily_counts:[1,1,0,0,0,1,0]},report.assessments[1]]},q)).toThrow();
    expect(()=>validateBehaviourReport({...report,current:{...current,rows:[row('a',q.from,q.values)]}},q)).toThrow();
    expect(()=>validateBehaviourReport({...report,current:{...current,match_count:2}},q)).toThrow();
    expect(()=>validateBehaviourReport({...report,current:{...current,rows:[row('d',q.until,q.values)]}},q)).toThrow();
    expect(()=>validateBehaviourReport({...report,assessments:[...report.assessments].reverse()},q)).toThrow();
    expect(()=>validateBehaviourReport({...report,baseline:{...history,rows:[...history.rows,row('z',baseline.from,['other'])],match_count:4}},q)).toThrow();
    expect(()=>validateBehaviourReport({...report,current:{...current,rows:[{...current.rows[0],index:'.ds-wazuh-findings-v5-security-000002',document_id:'a'}]}},q)).not.toThrow();
  });
});
