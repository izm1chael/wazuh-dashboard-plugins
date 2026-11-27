import { assessRuleVolume } from './rule-behaviour-contract';
import { EventProfile, EventProfileInput, validateEventProfile, validateEventProfileInput } from './event-behaviour-contract';
const q:EventProfileInput={mode:'authentication',cluster:'lab',space:'standard',dataset:'sshd',subject:'user-1',day:'2026-11-25T00:00:00Z'};
const now=Date.parse('2026-11-26T00:02:00Z');
const days=[1,...Array<number>(26).fill(0),1],zero=Array<number>(28).fill(0);
const profile:EventProfile={scope:'caller_visible_native_event_profile',model:'event_profile_v1',query:q,actor:'reader',observed_at:'2026-11-26T00:02:00Z',event_count:5,
  volume:assessRuleVolume(days,3),authentication:{success:assessRuleVolume([1,...zero.slice(1)],0),failure:assessRuleVolume([...zero.slice(0,27),1],1),unknown:assessRuleVolume(zero,2)},
  relationship:{baseline_distinct:1,comparison_distinct:1,baseline_missing:0,comparison_missing:1,newly_observed:[{value:'host-b',count:2}]},
  source_relationship:{baseline_distinct:1,comparison_distinct:1,baseline_missing:0,comparison_missing:1,newly_observed:[{value:'192.0.2.2',count:2}]},
  coverage:{status:'search_complete_telemetry_unverified',active_baseline_days:2,ingest_lag_known:2,ingest_lag_missing:1,ingest_before_event:1,ingest_after_observation:1,lag_over_120s:1,max_lag_seconds:122}};
describe('native event profile',()=>{
  it('validates input, counts and unknown outcomes',()=>{
    expect(validateEventProfileInput(q,now)).toEqual(q);
    expect(()=>validateEventProfileInput(q,now-1)).toThrow();
    expect(()=>validateEventProfileInput({...q,subject:' '},now)).toThrow();
    expect(validateEventProfile(profile,q)).toEqual(profile);
    expect(()=>validateEventProfile({...profile,event_count:6},q)).toThrow();
    expect(()=>validateEventProfile({...profile,authentication:{...profile.authentication!,unknown:assessRuleVolume(zero,1)}},q)).toThrow();
    expect(()=>validateEventProfile({...profile,authentication:null},q)).toThrow();
    expect(()=>validateEventProfile({...profile,query:{...q,dataset:'other'}},q)).toThrow();
  });
  it('rejects inconsistent novelty and ingestion coverage',()=>{
    expect(()=>validateEventProfile({...profile,relationship:{...profile.relationship,newly_observed:[{value:'host-b',count:1}]}},q)).toThrow();
    expect(()=>validateEventProfile({...profile,relationship:{...profile.relationship,comparison_missing:4}},q)).toThrow();
    expect(()=>validateEventProfile({...profile,source_relationship:{...profile.source_relationship!,newly_observed:[{value:'2001:db8::1',count:2}]}},q)).toThrow();
    expect(()=>validateEventProfile({...profile,coverage:{...profile.coverage,ingest_lag_missing:2}},q)).toThrow();
    expect(()=>validateEventProfile({...profile,coverage:{...profile.coverage,lag_over_120s:0}},q)).toThrow();
    expect(()=>validateEventProfile({...profile,coverage:{...profile.coverage,max_lag_seconds:100}},q)).toThrow();
  });
});
