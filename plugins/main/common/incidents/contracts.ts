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
  | { kind: 'attach-finding' | 'detach-finding'; index: string; document_id: string };

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
export interface FindingPage {
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
