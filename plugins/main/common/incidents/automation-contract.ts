export const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'] as const;
export const PRIORITIES = ['low', 'medium', 'high', 'urgent'] as const;
export const PLAYBOOKS = ['initial_triage', 'high_severity_review', 'linked_finding_review'] as const;
export const STATUSES = ['any_open', 'new', 'triaging', 'active'] as const;
export const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const RULE = /^[a-z][a-z0-9_-]{0,63}$/;
const TAG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
export interface AutomationActions {
  assign_to?: string; raise_severity?: typeof SEVERITIES[number]; raise_priority?: typeof PRIORITIES[number];
  add_tags?: string[]; create_task?: string; apply_playbook?: typeof PLAYBOOKS[number];
}
export interface AutomationRule {
  id: string; trigger: 'created' | 'updated'; minimum_severity: typeof SEVERITIES[number];
  status: typeof STATUSES[number]; minimum_findings: number; unassigned_only: boolean; required_tags: string[]; correlation_policy_id: string | null;
  actions: AutomationActions;
}
export interface AutomationPolicy { policy_id: string; policy_version: number; rules: AutomationRule[] }
export interface AutomationKey { policy_id: string; policy_version: number }
export interface SavedAutomation { policy: AutomationPolicy; fingerprint: string; created_by: string; created_at: string }
export interface AutomationSave { saved: SavedAutomation; replayed: boolean }
export interface AutomationPreview extends AutomationKey {
  incident_id: string; revision: number; state: 'ineligible' | 'not_matched' | 'blocked' | 'matched';
  rule_id: string | null; changed_fields: number;
}
export interface AutomationReceipt extends AutomationKey {
  policy_hash: string; rule_id: string; trigger_revision: number; applied_revision: number; actor: string; at: string; changed_fields: number;
}
export interface AutomationHistory { incident_id: string; revision: number; activity_pending: boolean; runs: AutomationReceipt[] }

type Obj = Record<string, unknown>;
const fail = (): never => { throw new Error('Invalid automation contract'); };
function obj(value: unknown): Obj {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
  return value as Obj;
}
function exact(value: Obj, keys: string[]) {
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.prototype.hasOwnProperty.call(value, key))) fail();
}
function text(value: unknown, max: number): string {
  if (typeof value !== 'string' || !value.trim() || value.trim() !== value || value.length > max || /[\x00-\x1f\x7f-\x9f]/.test(value)) return fail();
  return value;
}
function pattern(value: unknown, re: RegExp): string {
  if (typeof value !== 'string' || !re.test(value)) return fail();
  return value;
}
function integer(value: unknown, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) return fail();
  return value;
}
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) return fail();
  return value as T;
}
function bool(value: unknown): boolean { if (typeof value !== 'boolean') return fail(); return value; }
function tags(value: unknown, min = 0): string[] {
  if (!Array.isArray(value) || value.length < min || value.length > 25) return fail();
  const result = value.map(v => pattern(v, TAG)).sort();
  if (new Set(result).size !== result.length) return fail();
  return result;
}
function time(value: unknown): string {
  const at = pattern(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/);
  if (!Number.isFinite(Date.parse(at)) || new Date(at).toISOString().slice(0, 19) !== at.slice(0, 19)) return fail();
  return at;
}
export function validateAutomationKey(value: unknown): AutomationKey {
  const row = obj(value);
  exact(row, ['policy_id', 'policy_version']);
  return { policy_id: pattern(row.policy_id, UUID), policy_version: integer(row.policy_version, 1, 2147483647) };
}
export function validateAutomationPolicy(value: unknown): AutomationPolicy {
  const row = obj(value); exact(row, ['policy_id', 'policy_version', 'rules']);
  const key = validateAutomationKey({ policy_id: row.policy_id, policy_version: row.policy_version });
  if (!Array.isArray(row.rules) || row.rules.length < 1 || row.rules.length > 10) return fail();
  const rules: AutomationRule[] = row.rules.map(raw => {
    const rule = obj(raw);
    exact(rule, ['id', 'trigger', 'minimum_severity', 'status', 'minimum_findings', 'unassigned_only', 'required_tags', 'correlation_policy_id', 'actions']);
    const input = obj(rule.actions), actions: AutomationActions = {};
    const keys = Object.keys(input);
    if (!keys.length || keys.some(k => !['assign_to', 'raise_severity', 'raise_priority', 'add_tags', 'create_task', 'apply_playbook'].includes(k))) return fail();
    if ('assign_to' in input) {
      actions.assign_to = text(input.assign_to, 1024);
      if (actions.assign_to === '_shared') return fail();
    }
    if ('raise_severity' in input) actions.raise_severity = choice(input.raise_severity, SEVERITIES);
    if ('raise_priority' in input) actions.raise_priority = choice(input.raise_priority, PRIORITIES);
    if ('add_tags' in input) actions.add_tags = tags(input.add_tags, 1);
    if ('create_task' in input) actions.create_task = text(input.create_task, 1024);
    if ('apply_playbook' in input) actions.apply_playbook = choice(input.apply_playbook, PLAYBOOKS);
    return { id: pattern(rule.id, RULE), trigger: choice(rule.trigger, ['created', 'updated'] as const),
      minimum_severity: choice(rule.minimum_severity, SEVERITIES), status: choice(rule.status, STATUSES),
      minimum_findings: integer(rule.minimum_findings, 0, 1000), unassigned_only: bool(rule.unassigned_only),
      required_tags: tags(rule.required_tags), correlation_policy_id: rule.correlation_policy_id === null ? null : pattern(rule.correlation_policy_id, UUID), actions };
  });
  if (new Set(rules.map(rule => rule.id)).size !== rules.length) return fail();
  return { ...key, rules };
}
export function validateSavedAutomation(value: unknown, key: AutomationKey, expected?: AutomationPolicy): SavedAutomation {
  const row = obj(value); exact(row, ['policy', 'fingerprint', 'created_by', 'created_at']);
  const policy = validateAutomationPolicy(row.policy);
  if (policy.policy_id !== key.policy_id || policy.policy_version !== key.policy_version ||
      (expected && JSON.stringify(policy) !== JSON.stringify(validateAutomationPolicy(expected)))) return fail();
  return { policy, fingerprint: pattern(row.fingerprint, HASH), created_by: text(row.created_by, 1024), created_at: time(row.created_at) };
}
export function validateAutomationSave(value: unknown, expected: AutomationPolicy): AutomationSave {
  const row = obj(value); exact(row, ['saved', 'replayed']);
  return { saved: validateSavedAutomation(row.saved, expected, expected), replayed: bool(row.replayed) };
}
export function validateAutomationPreview(value: unknown, key: AutomationKey, incident: string): AutomationPreview {
  const row = obj(value); exact(row, ['policy_id', 'policy_version', 'incident_id', 'revision', 'state', 'rule_id', 'changed_fields']);
  if (row.policy_id !== key.policy_id || row.policy_version !== key.policy_version || row.incident_id !== incident) return fail();
  const state = choice(row.state, ['ineligible', 'not_matched', 'blocked', 'matched'] as const);
  const rule = row.rule_id === null ? null : pattern(row.rule_id, RULE);
  const changed = integer(row.changed_fields, 0, 7);
  if ((state === 'matched' || state === 'blocked') !== (rule !== null) || (state !== 'matched' && changed !== 0)) return fail();
  return { policy_id: key.policy_id, policy_version: key.policy_version, incident_id: incident,
    revision: integer(row.revision, 1, 2147483647), state, rule_id: rule, changed_fields: changed };
}
export function validateAutomationHistory(value: unknown, incident: string): AutomationHistory {
  const row = obj(value); exact(row, ['incident_id', 'revision', 'activity_pending', 'runs']);
  if (row.incident_id !== incident || !UUID.test(incident) || !Array.isArray(row.runs) || row.runs.length > 50) return fail();
  const revision = integer(row.revision, 1, 2147483647);
  const seen = new Set<string>(); let previous = 0;
  const runs = row.runs.map(raw => {
    const item = obj(raw);
    exact(item, ['policy_id', 'policy_version', 'policy_hash', 'rule_id', 'trigger_revision', 'applied_revision', 'actor', 'at', 'changed_fields']);
    const key = validateAutomationKey({ policy_id: item.policy_id, policy_version: item.policy_version });
    const identity = key.policy_id + ':' + key.policy_version;
    const trigger = integer(item.trigger_revision, 1, revision);
    const applied = integer(item.applied_revision, 2, revision);
    if (seen.has(identity) || applied !== trigger + 1 || applied <= previous) return fail();
    seen.add(identity); previous = applied;
    return { ...key, policy_hash: pattern(item.policy_hash, HASH), rule_id: pattern(item.rule_id, RULE), trigger_revision: trigger,
      applied_revision: applied, actor: text(item.actor, 1024), at: time(item.at), changed_fields: integer(item.changed_fields, 0, 7) };
  });
  return { incident_id: incident, revision, activity_pending: bool(row.activity_pending), runs };
}
