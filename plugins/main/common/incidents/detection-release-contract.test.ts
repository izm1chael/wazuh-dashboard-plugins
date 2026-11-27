import { DetectionRelease, ReleaseEvidence, validateRelease, validateReleaseEvidence, validateReleasePage, validateReviewInput, sameReleaseEvidence } from './detection-release-contract';
import { PostReleaseReview, validatePostReleaseReview } from './post-release-contract';
const rule='00000000-0000-4000-8000-000000000001',plan='a'.repeat(64),pack='b'.repeat(64);
const at='2026-11-27T09:00:00Z',reviewed='2026-11-27T09:05:00Z',reserved='2026-11-27T09:10:00Z',reported='2026-11-27T09:15:00Z',expires='2026-11-27T10:00:00Z';
const m={positive:10,negative:10,unknown:0,lost_positive:0,gained_positive:0,new_false_positive:0,removed_false_positive:10,
  baseline_tp:10,baseline_fp:10,baseline_tn:0,baseline_fn:0,candidate_tp:10,candidate_fp:0,candidate_tn:10,candidate_fn:0};
const evidence:ReleaseEvidence={pack_sha256:pack,test_sha256:plan,custom_sha256:pack,preview_sha256:pack,labels_sha256:pack,
  integration:rule,cluster:'lab',space:'standard',dataset:'sshd',changed_rules:[rule],historical_events:20,prospective_events:20,prospective_seconds:86400,
  historical_metrics:{[rule]:m},prospective_metrics:{[rule]:m}};
const submitted:DetectionRelease={format:'wazuh-detection-release-v1',id:plan,evidence,author:'author',submitted_at:at,state:'submitted',revision:1,
  review:null,reservation:null,outcome:null};
const approved:DetectionRelease={...submitted,state:'approved',revision:2,review:{actor:'reviewer',at:reviewed,decision:'approved',reason:'review',
  pack_sha256:pack,deployer:'deployer',expires}};
const consumed:DetectionRelease={...approved,state:'reserved',revision:3,reservation:{actor:'deployer',at:reserved}};
const complete:DetectionRelease={...consumed,state:'native_reported',revision:4,outcome:{at:reported,native_status:200}};
describe('detection release lifecycle',()=>{
  it('validates eligible evidence and strict independent actor state',()=>{
    for(const r of [submitted,approved,consumed,complete])expect(validateRelease(r)).toEqual(r);
    expect(sameReleaseEvidence(evidence,{...evidence,changed_rules:[rule]})).toBe(true);
    expect(sameReleaseEvidence(evidence,{...evidence,cluster:'other'})).toBe(false);
    for(const patch of [{prospective_seconds:86399},{historical_events:21},{changed_rules:[rule,rule]},
      {historical_metrics:{[rule]:{...m,removed_false_positive:11}}}])
      expect(()=>validateReleaseEvidence({...evidence,...patch})).toThrow();
    expect(()=>validateRelease({...approved,review:{...approved.review!,actor:'author'}})).toThrow();
    expect(()=>validateRelease({...approved,review:{...approved.review!,deployer:'reviewer'}})).toThrow();
    expect(()=>validateRelease({...consumed,reservation:{actor:'deployer',at:expires}})).toThrow();
    expect(()=>validateRelease({...complete,outcome:{at:reviewed,native_status:200}})).toThrow();
  });
  it('validates scoped queue and review input',()=>{
    const day='2026-11-27T00:00:00Z';
    const page={scope:'shared_detection_release_metadata' as const,day,rows:[submitted],count:1};
    expect(validateReleasePage(page,day)).toEqual(page);
    expect(()=>validateReleasePage({...page,rows:[submitted,submitted],count:2},day)).toThrow();
    const input={id:plan,pack_json:'{}',decision:'approved' as const,reason:'review',deployer:'deployer',expires};
    expect(validateReviewInput(input,Date.parse(reviewed))).toEqual(input);
    expect(()=>validateReviewInput(input,Date.parse(expires))).toThrow();
  });
});
const report:PostReleaseReview={format:'wazuh-native-post-release-review-v1',plan_sha256:plan,pack_sha256:pack,
  scope:{integration:rule,cluster:'lab',space:'standard',dataset:'sshd'},observed_at:'2026-11-27T11:02:00+00:00',native_status:200,
  reserved_at:reserved,native_reported_at:reported,windows:{baseline_from:'2026-11-27T08:00:00Z',baseline_until:'2026-11-27T09:00:00Z',
    post_from:'2026-11-27T10:00:00Z',post_until:'2026-11-27T11:00:00Z'},
  content:{test_snapshot_sha256:plan,custom_snapshot_sha256:pack,integration_document_equal:true,all_integration_rule_documents_equal:true,
    reviewed_rules:[{rule_uuid:rule,expected_document_sha256:pack,actual_document_sha256:pack,equal:true}]},
  baseline:{events:{count:10,population_sha256:pack},findings:{count:4,population_sha256:pack,by_rule:{[rule]:4}}},
  post:{events:{count:20,population_sha256:plan},findings:{count:2,population_sha256:pack,by_rule:{[rule]:2}}},
  rules:[{rule_uuid:rule,baseline_findings:4,post_findings:2,delta:-2,classification:'lower_observed_volume'}],
  coverage:'exact_search_telemetry_unverified',deployment_verified:false,automatic_rollback_authorized:false};
describe('post release evidence',()=>{
  it('binds actual record and checks count/content conservation',()=>{
    expect(validatePostReleaseReview(report,complete)).toEqual(report);
    expect(()=>validatePostReleaseReview(report,consumed)).toThrow();
    for(const patch of [{deployment_verified:true},{plan_sha256:pack},{reserved_at:at},{rules:[{...report.rules[0],delta:-1}]},
      {post:{...report.post,findings:{...report.post.findings,count:3}}},
      {content:{...report.content,reviewed_rules:[{...report.content.reviewed_rules[0],actual_document_sha256:plan}]}},
      {windows:{...report.windows,post_until:'2026-11-27T11:01:00Z'}}])
      expect(()=>validatePostReleaseReview({...report,...patch} as PostReleaseReview,complete)).toThrow();
  });
});
