import { CampaignPack, validateCampaignPack } from './native-campaign-contract';
const rule='00000000-0000-4000-8000-000000000001',hash='a'.repeat(64),plan='b'.repeat(64);
const m={positive:10,negative:10,unknown:0,lost_positive:0,gained_positive:0,new_false_positive:0,removed_false_positive:10,
  baseline_tp:10,baseline_fp:10,baseline_tn:0,baseline_fn:0,candidate_tp:10,candidate_fp:0,candidate_tn:10,candidate_fn:0};
const pack:CampaignPack={format:'wazuh-native-rule-review-pack-v1',status:'ready_for_independent_release_review',blockers:[],
  scope:{integration:rule,cluster:'lab',space:'standard',dataset:'sshd'},changed_rules:[rule],
  test_sha256:hash,custom_sha256:hash,preview_sha256:hash,review_plan_sha256:plan,labels_sha256:hash,
  historical_receipt_sha256:[hash],prospective_receipt_sha256:Array.from({length:24},(_,i)=>(i+1).toString(16).padStart(64,'0')),
  review_attestation:{author:'author',reviewer:'reviewer',review_plan_sha256:plan,reason:'reviewed'},
  registered_epoch:1795550000,prospective_windows:24,prospective_seconds:86400,historical_events:20,prospective_events:20,
  historical_metrics:{[rule]:m},prospective_metrics:{[rule]:m},coverage:'exact_search_telemetry_unverified',promotion_authorized:false};
describe('native campaign review',()=>{
  it('validates complete evidence and never grants permission',()=>{
    expect(validateCampaignPack(pack)).toEqual(pack);
    for(const patch of [{promotion_authorized:true},{historical_events:21},{status:'blocked'},{blockers:['fake']},
      {review_attestation:{...pack.review_attestation,reviewer:'author'}},{changed_rules:[rule,rule]},
      {historical_metrics:{[rule]:{...m,removed_false_positive:11}}},{prospective_seconds:86399},
      {prospective_receipt_sha256:Array(24).fill(hash)}]){
      expect(()=>validateCampaignPack({...pack,...patch} as CampaignPack)).toThrow();
    }
  });
  it('recomputes duration and regression blockers',()=>{
    const short:CampaignPack={...pack,prospective_windows:23,prospective_seconds:82800,
      prospective_receipt_sha256:pack.prospective_receipt_sha256.slice(1),status:'blocked',blockers:['prospective_duration_under_24h']};
    expect(validateCampaignPack(short)).toEqual(short);
    const loss={...m,lost_positive:1,candidate_tp:9,candidate_fn:1};
    expect(()=>validateCampaignPack({...pack,prospective_metrics:{[rule]:loss}})).toThrow();
    expect(validateCampaignPack({...pack,status:'blocked',blockers:[rule+':prospective:regression'],prospective_metrics:{[rule]:loss}}).status).toBe('blocked');
  });
});
