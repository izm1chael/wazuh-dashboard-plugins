/** Contract shared by the dashboard client and experimental workspace. */
export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type Priority = 'low' | 'medium' | 'high' | 'urgent';
export type Tlp = 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:AMBER+STRICT' | 'TLP:RED';
export type Classification = 'true_positive' | 'benign_positive' | 'false_positive' | 'undetermined' | 'duplicate';
export type Status = 'new' | 'triaging' | 'active' | 'closed';
export type Queue = 'open' | 'new' | 'triaging' | 'active' | 'closed' | 'unassigned' | 'all';

export interface CreateIncident {
  title: string;
  description?: string;
  severity: Severity;
  priority?: Priority;
  tlp?: Tlp;
}

export interface IncidentSummary {
  id: string;
  title: string;
  description: string;
  status: Status;
  severity: Severity;
  priority: Priority;
  tlp: Tlp;
  owner: string | null;
  created_by: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
  first_assigned_at: string | null;
  triage_started_at: string | null;
  activated_at: string | null;
  closed_at: string | null;
  first_closed_at: string | null;
  reopened_at: string | null;
  closure: { classification: Classification; reason: string; closed_by: string } | null;
  revision: number;
  finding_count: number;
}

export type IndexerIncidentCommand =
  | { kind: 'assign-self' | 'unassign' | 'start-triage' | 'activate' }
  | { kind: 'edit'; title?: string; description?: string; severity?: Severity; priority?: Priority; tlp?: Tlp }
  | { kind: 'close'; classification: Classification; reason: string }
  | { kind: 'reopen'; reason: string }
  | { kind: 'attach-finding' | 'detach-finding'; index: string; document_id: string }
  | { kind: 'add-note'; body: string }
  | { kind: 'create-task'; title: string }
  | { kind: 'complete-task' | 'reopen-task'; task_id: string }
  | ({ kind: 'record-ai-feedback' } & AiFeedback)
  | { kind: 'apply-playbook'; template_id: string; version: number }
  | { kind: 'request-response'; type: ResponseIntent; scope: string; reason: string }
  | { kind: 'approve-response' | 'reject-response' | 'cancel-response'; response_id: string; reason: string }
  | { kind: 'record-response-outcome'; response_id: string; outcome: ManualResponseOutcome; reason: string };

export interface QueueCursor { time: number; id: string }
export interface QueueQuery {
  queue?: Queue;
  severity?: Severity;
  owner?: string;
  search?: string;
  limit?: number;
  after?: QueueCursor;
}
export interface QueuePage { incidents: IncidentSummary[]; next?: QueueCursor }
export interface IndexerIncidentResult {
  incident: IncidentSummary;
  activity_delivery: 'delivered' | 'pending';
  replayed: boolean;
}

export interface FindingReference { index: string; document_id: string }
export interface FindingEntity { kind: string; value: string; field: string }
export interface FindingObservation extends FindingReference {
  timestamp: string | null; rule_id: string | null; rule_title: string | null; wazuh_rule_id?: string | null;
  entities: FindingEntity[]; techniques: string[]; tactics: string[];
}
export interface FindingPage {
  observations?: FindingObservation[];
  findings: FindingReference[];
  revision: number;
  unavailable_count: number;
  next_offset?: number;
}
export interface IncidentActivity {
  id: string;
  incident_id: string;
  revision: number;
  kind: string;
  actor: string;
  at: string;
  changes: Record<string, { before: string | number | boolean | null; after: string | number | boolean | null }>;
}
export interface ActivityPage {
  events: IncidentActivity[];
  observed_revision: number;
  activity_pending: boolean;
  next_before?: number;
}

export interface IncidentNote {
  id: string; incident_id: string; revision: number; actor: string; at: string; body: string;
}
export interface IncidentTask {
  id: string; title: string; status: 'open' | 'completed'; created_by: string; created_at: string;
  completed_by: string | null; completed_at: string | null;
}
export interface CollaborationPage {
  playbooks?: PlaybookPreview[]; playbook_runs?: PlaybookRun[];
  notes: IncidentNote[]; tasks: IncidentTask[]; observed_revision: number; activity_pending: boolean; next_before?: number;
}

export interface CorrelationPreviewInput {
  policy_id: string; policy_version: number; rules: string[];
  window_minutes: number; minimum_findings: number; from: string; until: string;
}
export interface CorrelationGroup {
  key: string; window_start: string; window_end: string; findings: FindingReference[];
}
export interface CorrelationPreview {
  mode: 'preview'; scope: 'caller_visible_search_snapshot';
  policy_id: string; policy_version: number; from: string; until: string;
  groups: CorrelationGroup[]; distinct_candidates: number; duplicate_inputs: number;
  insufficient_identity: number; excluded_rule: number; outside_range: number; below_threshold: number;
}

export type CorrelationPolicyDefinition = Omit<CorrelationPreviewInput, 'from' | 'until'>;
export interface SavedCorrelationPolicy extends CorrelationPolicyDefinition {
  mode: 'preview_only'; created_by: string; created_at: string;
}
export interface SavedCorrelationPolicyResult { policy: SavedCorrelationPolicy; replayed?: boolean }

export interface IncidentMetricsQuery { from: string; until: string; triage_target_seconds: number; resolution_target_seconds: number }
export interface DurationMetric {
  samples: number; missing: number; invalid: number;
  mean_seconds: number | null; p50_seconds: number | null; p95_seconds: number | null;
  target_seconds?: number; met?: number; breached?: number;
}
export interface IncidentMetricsReport {
  scope: 'current_state_creation_cohort_and_open_backlog';
  from: string; until: string; observed_at: string; scanned: number;
  cohort_count: number; cohort_statuses: Record<Status, number>; reopened_incidents: number;
  cohort_pending_audit: number; invalid_created_records: number;
  classifications: Record<Classification, number>; unknown_classification: number;
  open_backlog: number; unassigned: number; backlog_severities: Record<Severity, number>; unknown_severity: number;
  backlog_age_buckets: Record<'lt_1h' | '1h_to_24h' | '1d_to_7d' | 'gte_7d' | 'unknown', number>;
  owner_workload: Array<{ owner: string; open: number }>;
  open_resolution_breached: number; open_resolution_unknown: number;
  open_triage_breached: number; open_triage_unknown: number;
  creation_to_first_assignment: DurationMetric; mttt: DurationMetric; mttr: DurationMetric;
  creation_to_first_close: DurationMetric; mtti_available: false;
}

export type ResponseIntent = 'investigate_endpoint' | 'review_containment' | 'review_indicator_block' | 'collect_evidence';
export type ManualResponseOutcome = 'completed' | 'failed' | 'not_performed';
export type ResponseState = 'requested' | 'approved' | 'rejected' | 'cancelled' | 'reported_completed' | 'reported_failed' | 'reported_not_performed';
export interface IncidentResponseRecord {
  id: string; type: ResponseIntent; scope: string; reason: string; state: ResponseState;
  requested_by: string; requested_at: string;
  decided_by: string | null; decided_at: string | null; decision_reason: string | null;
  finalized_by: string | null; finalized_at: string | null; final_reason: string | null;
  execution_verified: false;
}
export interface IncidentResponsePage {
  responses: IncidentResponseRecord[]; observed_revision: number; activity_pending: boolean; mode: 'manual_tracking_only';
}

export interface IssuedResponseRecord extends FindingReference {
  finding: FindingReference; issued_at: string | null; name: string | null; type: string | null; location: string | null;
  configured_agent_id: string | null; source_agent_id: string | null; state: 'issued_only'; execution_verified: false;
}
export interface IssuedResponsePage {
  issued_responses: IssuedResponseRecord[]; revision: number; visible_finding_count: number;
  next_offset?: number; mode: 'exact_visible_finding_page_issued_only';
}

export interface PlaybookPreview {
  template_id: string; version: number; title: string; tasks: string[];
  state: 'available' | 'already_applied' | 'not_applicable' | 'capacity_exceeded';
}
export interface PlaybookRun {
  template_id: string; version: number; applied_revision: number; applied_by: string; applied_at: string; task_ids: string[];
}

export type AiFeedbackRating = 'useful' | 'partly_useful' | 'not_useful';
export type AiHypothesisReview = 'agree' | 'disagree' | 'not_reviewed';
export interface AiFeedback {
  assessment_id: string; assessed_revision: number; digest_sha256: string;
  assessment_mode: 'ai_review' | 'agentic_soc'; assessment_rating: AiFeedbackRating; hypothesis_review: AiHypothesisReview;
}
