import { assessRuleVolume } from './rule-behaviour-contract';
import { BehaviourObservation, ObservationPage, validateObservation, validateObservationDay, validateObservationPage, validateObservationReview, validateReviewResult, validatePromotionResult } from './behaviour-observation-contract';
const day='2026-11-25T00:00:00Z',at='2026-11-26T00:02:00Z',id='197591c7-8a01-840e-9b4c-02f888e34dd7';
const row:BehaviourObservation={id,model:'rule_volume_v2',query:{field:'user.name',value:'alice',rule_uuid:'00000000-0000-4000-8000-000000000001',day},
  actor:'publisher',observed_at:at,coverage:'search_complete_telemetry_unverified',finding_count:61,assessment:assessRuleVolume(Array<number>(28).fill(2),5),
  state:'unreviewed',revision:1,review:null,incident_id:null,promoted_at:null};
const review={id,expected_revision:1,decision:'escalation_requested' as const,reason:'Investigate'};
const reviewed:BehaviourObservation={...row,state:'escalation_requested',revision:2,review:{actor:'reviewer',at,decision:review.decision,reason:review.reason}};
const promoted:BehaviourObservation={...reviewed,state:'promoted',revision:3,incident_id:'aff3d786-fca1-8bf0-83ea-09be8a066c9f',promoted_at:at};
const page:ObservationPage={scope:'shared_soc_observation_metadata',day,rows:[row],count:1};
describe('behaviour observation contract',()=>{
  it('validates statistics and exact lifecycle states',()=>{
    expect(validateObservation(row)).toEqual(row);
    expect(validateObservation(reviewed)).toEqual(reviewed);
    expect(validateObservation(promoted)).toEqual(promoted);
    for(const patch of [{finding_count:99},{coverage:'complete'},{assessment:{...row.assessment,threshold:4}},
      {state:'not_flagged'},{revision:2},{current_sample:[]},{incident_id:promoted.incident_id},{observed_at:'2026-11-26T00:01:59Z'}])
      expect(()=>validateObservation({...row,...patch} as BehaviourObservation)).toThrow();
    expect(()=>validateObservation({...reviewed,review:{...reviewed.review!,actor:'publisher'}})).toThrow();
    expect(()=>validateObservation({...reviewed,review:{...reviewed.review!,at:'2026-11-26T00:01:59Z'}})).toThrow();
    expect(()=>validateObservation({...promoted,promoted_at:null})).toThrow();
    expect(()=>validateObservation({...promoted,review:{...reviewed.review!,decision:'monitor'}})).toThrow();
  });
  it('binds exact queue day and rejects duplicate or unordered rows',()=>{
    expect(validateObservationDay(day,Date.parse(at))).toBe(day);
    expect(()=>validateObservationDay(day,Date.parse(at)-1)).toThrow();
    expect(validateObservationPage(page,day)).toEqual(page);
    expect(()=>validateObservationPage({...page,count:2},day)).toThrow();
    expect(()=>validateObservationPage({...page,rows:[row,row],count:2},day)).toThrow();
    expect(()=>validateObservationPage({...page,rows:[{...row,query:{...row.query,day:'2026-11-24T00:00:00Z'}}]},day)).toThrow();
    expect(()=>validateObservationPage({...page,rows:[{...reviewed,id:'00000000-0000-4000-8000-000000000001'},row],count:2},day)).toThrow();
  });
  it('binds review and promotion command responses',()=>{
    expect(validateObservationReview(review)).toEqual(review);
    expect(()=>validateObservationReview({...review,reason:' '})).toThrow();
    expect(validateReviewResult(reviewed,review)).toEqual(reviewed);
    expect(()=>validateReviewResult(reviewed,{...review,reason:'Other'})).toThrow();
    expect(validatePromotionResult(promoted,{id,expected_revision:2})).toEqual(promoted);
    expect(()=>validatePromotionResult(reviewed,{id,expected_revision:2})).toThrow();
    expect(()=>validatePromotionResult(promoted,{id:'00000000-0000-4000-8000-000000000001',expected_revision:2})).toThrow();
  });
});
