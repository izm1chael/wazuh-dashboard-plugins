/**
 * First-class incident domain. No route or permissions are implied by this module.
 * The caller supplies a trusted authenticated actor, generated ID and server clock.
 */

export const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'] as const;
export const PRIORITIES = ['low', 'medium', 'high', 'urgent'] as const;
export const TLP_VALUES = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'] as const;
export const CLASSIFICATIONS = ['true_positive', 'benign_positive', 'false_positive', 'undetermined', 'duplicate'] as const;

export type Severity = typeof SEVERITIES[number];
export type Priority = typeof PRIORITIES[number];
export type Tlp = typeof TLP_VALUES[number];
export type Classification = typeof CLASSIFICATIONS[number];
export type Status = 'new' | 'triaging' | 'active' | 'closed';

export interface Activity {
  id: string;
  incident_id: string;
  revision: number;
  kind: 'created' | IncidentCommand['kind'];
  actor: string;
  at: string;
  changes: Record<string, { before: unknown; after: unknown }>;
}

export interface Incident {
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
  pending_activity: Activity | null;
}

export interface CreateIncident {
  title: string;
  description?: string;
  severity: Severity;
  priority?: Priority;
  tlp?: Tlp;
}

export type IncidentCommand =
  | { kind: 'assign'; owner: string | null }
  | { kind: 'start_triage' }
  | { kind: 'activate' }
  | { kind: 'close'; classification: Classification; reason: string }
  | { kind: 'reopen'; reason: string };

export class IncidentDomainError extends Error {
  constructor(public readonly code: 'invalid' | 'conflict', message: string) {
    super(message);
    this.name = 'IncidentDomainError';
  }
}

function invalid(message: string): never {
  throw new IncidentDomainError('invalid', message);
}

function conflict(message: string): never {
  throw new IncidentDomainError('conflict', message);
}

function requiredText(value: unknown, maximum: number, field: string): string {
  if (typeof value !== 'string' || !value.trim() || value.length > maximum) {
    return invalid(field + ' must be non-empty and at most ' + maximum + ' characters');
  }
  return value.trim();
}

function choice<T extends string>(value: T, values: readonly T[], field: string): T {
  if (!values.includes(value)) return invalid('Invalid ' + field);
  return value;
}

function timestamp(at: string): string {
  if (typeof at !== 'string' || !Number.isFinite(Date.parse(at)) || new Date(at).toISOString() !== at) {
    return invalid('Expected a canonical UTC timestamp');
  }
  return at;
}

function event(record: Incident, kind: Activity['kind'], changes: Activity['changes']): Activity {
  return {
    id: record.id + ':' + record.revision,
    incident_id: record.id,
    revision: record.revision,
    kind,
    actor: record.updated_by,
    at: record.updated_at,
    changes,
  };
}

export function createIncident(input: CreateIncident, id: string, actor: string, at: string): Incident {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    return invalid('Expected a server-generated incident UUID');
  }
  const principal = requiredText(actor, 1024, 'actor');
  const now = timestamp(at);
  const description = input.description === undefined ? '' : input.description;
  if (typeof description !== 'string' || description.length > 32768) return invalid('Invalid description');
  const record: Incident = {
    id, title: requiredText(input.title, 1024, 'title'), description,
    status: 'new',
    severity: choice(input.severity, SEVERITIES, 'severity'),
    priority: choice(input.priority === undefined ? 'medium' : input.priority, PRIORITIES, 'priority'),
    tlp: choice(input.tlp === undefined ? 'TLP:AMBER' : input.tlp, TLP_VALUES, 'TLP'),
    owner: null, created_by: principal, updated_by: principal, created_at: now, updated_at: now,
    first_assigned_at: null, triage_started_at: null, activated_at: null, closed_at: null,
    first_closed_at: null, reopened_at: null, closure: null, revision: 1, pending_activity: null,
  };
  const changes: Activity['changes'] = {};
  for (const [key, value] of Object.entries(record)) {
    if (key !== 'pending_activity') changes[key] = { before: null, after: value };
  }
  return { ...record, pending_activity: event(record, 'created', changes) };
}

export function applyIncidentCommand(current: Incident, command: IncidentCommand, actor: string, at: string): Incident {
  if (current.pending_activity !== null) return conflict('Pending activity must be delivered before another mutation');
  const principal = requiredText(actor, 1024, 'actor');
  const now = timestamp(at);
  if (Date.parse(now) < Date.parse(current.updated_at)) return invalid('Incident clock moved backwards');
  if (!Number.isSafeInteger(current.revision) || current.revision < 1 || current.revision >= 2147483647) {
    return conflict('Incident revision is invalid or exhausted');
  }
  const next: Incident = { ...current, updated_by: principal, updated_at: now, revision: current.revision + 1 };
  const changes: Activity['changes'] = {};
  const set = <K extends keyof Incident>(key: K, value: Incident[K]) => {
    if (current[key] !== value) {
      changes[key] = { before: current[key], after: value };
      next[key] = value;
    }
  };
  if (current.status === 'closed' && command.kind !== 'reopen') {
    return conflict('Reopen a closed incident before modifying it');
  }
  switch (command.kind) {
    case 'assign': {
      const owner = command.owner === null ? null : requiredText(command.owner, 1024, 'owner');
      if (current.owner === owner) return conflict('Incident assignment did not change');
      if (owner === null && current.status !== 'new') return conflict('In-progress incidents must retain an owner');
      set('owner', owner);
      if (owner !== null && current.first_assigned_at === null) set('first_assigned_at', now);
      break;
    }
    case 'start_triage':
      if (current.status !== 'new') return conflict('Only a new incident can enter triage');
      if (current.owner === null) return conflict('Assign the incident before triage');
      set('status', 'triaging');
      set('triage_started_at', now);
      break;
    case 'activate':
      if (current.status !== 'triaging') return conflict('Start triage before activating an incident');
      if (current.owner === null) return conflict('An active incident must be assigned');
      set('status', 'active');
      set('activated_at', now);
      break;
    case 'close':
      if (current.status !== 'triaging' && current.status !== 'active') return conflict('Triage the incident before closing');
      set('status', 'closed');
      set('closed_at', now);
      if (current.first_closed_at === null) set('first_closed_at', now);
      set('closure', {
        classification: choice(command.classification, CLASSIFICATIONS, 'classification'),
        reason: requiredText(command.reason, 8192, 'closure reason'),
        closed_by: principal,
      });
      break;
    case 'reopen':
      if (current.status !== 'closed') return conflict('Only a closed incident can be reopened');
      if (current.owner === null) return conflict('An incident must have an owner to reopen');
      changes.reopen_reason = { before: null, after: requiredText(command.reason, 8192, 'reopen reason') };
      set('status', 'active');
      set('closed_at', null);
      set('closure', null);
      set('reopened_at', now);
      break;
    default:
      return invalid('Unknown incident command');
  }
  return { ...next, pending_activity: event(next, command.kind, changes) };
}
