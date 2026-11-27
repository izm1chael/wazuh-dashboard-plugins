import { assessRuleVolume, validateRuleBehaviour, validateRuleBehaviourReport, RuleBehaviourInput, RuleBehaviourReport } from './rule-behaviour-contract';
const q:RuleBehaviourInput={field:'user.name',value:'alice',rule_uuid:'00000000-0000-4000-8000-000000000001',day:'2026-11-25T00:00:00Z'};
const now=Date.parse('2026-11-26T00:02:00Z'),index='.ds-wazuh-findings-v5-security-000001';
const daily=Array<number>(28).fill(2);
const report:RuleBehaviourReport={scope:'caller_visible_rule_finding_scan',model:'rule_volume_v2',query:q,
  baseline_from:'2026-10-28T00:00:00Z',until:'2026-11-26T00:00:00Z',finding_count:61,assessment:assessRuleVolume(daily,5),
  current_sample:Array.from({length:5},(_,i)=>({index,document_id:String(i),timestamp:q.day})),
  coverage:'search_complete_telemetry_unverified',actor:'analyst',observed_at:'2026-11-26T00:02:00Z'};
describe('rule behaviour',()=>{
  it('computes robust and weekday thresholds and separates sparse history',()=>{
    const zero=Array<number>(28).fill(0),sparse=[1,...zero.slice(1)];
    expect(assessRuleVolume(zero,0).classification).toBe('no_observed_activity');
    expect(assessRuleVolume(zero,1).classification).toBe('newly_observed');
    expect(assessRuleVolume(sparse,100).classification).toBe('sparse_baseline');
    expect(assessRuleVolume(daily,4).classification).toBe('within_volume_threshold');
    expect(assessRuleVolume(daily,5).classification).toBe('elevated_rule_volume');
    const mixed=assessRuleVolume([...Array<number>(14).fill(0),...Array<number>(14).fill(10)],20);
    expect(mixed.median_times_two).toBe(10);expect(mixed.mad_times_four).toBe(20);expect(mixed.threshold).toBe(20);
    const half=assessRuleVolume([...Array<number>(14).fill(1),...Array<number>(14).fill(2)],5);
    expect(half.median_times_two).toBe(3);expect(half.mad_times_four).toBe(2);
    expect(assessRuleVolume([40,...Array<number>(27).fill(1)],42).threshold).toBe(43);
    expect(()=>assessRuleVolume(Array<number>(28).fill(72),0)).toThrow();
    expect(()=>assessRuleVolume(daily,-1)).toThrow();
  });
  it('requires exact completed UTC input and rule identity',()=>{
    expect(validateRuleBehaviour(q,now)).toEqual(q);
    expect(()=>validateRuleBehaviour(q,now-1)).toThrow();
    for(const patch of [{day:'2026-11-25T00:00:01Z'},{day:'2026-11-25T00:00:00.000Z'},{rule_uuid:'anything'},
      {field:'dns.question.name'},{value:' '},{field:'source.ip',value:'001.2.3.4'}])
      expect(()=>validateRuleBehaviour({...q,...patch} as RuleBehaviourInput,now)).toThrow();
  });
  it('rejects changed counts, scope, query, coverage and sampled identities',()=>{
    expect(()=>validateRuleBehaviourReport(report,q)).not.toThrow();
    for(const patch of [{finding_count:62},{assessment:{...report.assessment,threshold:4}},
      {assessment:{...report.assessment,classification:'within_volume_threshold'}},{coverage:'complete'},
      {query:{...q,value:'other'}},{observed_at:'2026-11-26T00:01:59Z'},{current_sample:report.current_sample.slice(1)},
      {current_sample:[...report.current_sample.slice(0,4),report.current_sample[0]]},
      {current_sample:[...report.current_sample.slice(0,4),{...report.current_sample[4],timestamp:report.until}]}])
      expect(()=>validateRuleBehaviourReport({...report,...patch} as RuleBehaviourReport,q)).toThrow();
  });
});
