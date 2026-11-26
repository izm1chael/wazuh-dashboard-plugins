# Enterprise incident management — fork development plan

Target: a native SIEM analyst workflow comparable to Sentinel incident management, without adding a mandatory paid service or database. Baseline Wazuh v5.0.0-rc2 (dashboard 22901fa354f20616d4bc707003b4b8a115cfb3d9; indexer e2871f7d68ee46fef2b01e21d3261dc6ab411489; manager 0a951d08bafdd194af395ca67d923ed706d3df07).

This is an independent fork plan, not an upstream roadmap. Do not open upstream issues/PRs until reviewed and qualified. Keep original finding triage working.

| Phase | Deliverables / exit criteria |
| --- | --- |
| 1 Foundation | Separate incident IDs/index; strict schema; server-controlled attribution; explicit lifecycle and classification; durable audit activity; compare-and-set updates; recovery after failed event delivery. |
| 2 Security and API | Dedicated authorisation, deny direct write bypass, principal and assignment validation, bounded paginated queries, idempotent requests, explicit API errors, no inherited finding time picker. Cross-role and direct API tests mandatory. |
| 3 Incident relationships | Multiple findings and entities, manual attach/detach, evidence snapshot/provenance, missing/expired finding handling, merge/split with auditable references. |
| 4 SOC workspace | New/active/unassigned/closed queues, ownership, bulk actions, search and filters, incident detail route, activity timeline and closure workflows. |
| 5 Detection correlation | Configurable grouping by rule/entity/time window, deduplication, automatic incident creation, safe reopen policy, backlog/replay handling and audit. |
| 6 Investigation and collaboration | Entity pivots, MITRE aggregation, timeline, comments with revision history, tasks and templates, query evidence, shift handover. |
| 7 Response and SOAR | Incident automation rules, external webhooks, approval gates, retry/idempotency, execution receipts and endpoint confirmation. No claim of containment based on dispatch alone. |
| 8 SOC analytics | Incident creation/assignment/triage/activation/closure milestones, reopen cycles, SLA policies, backlog ageing, throughput and analyst workload. Define MTTI/MTTT/MTTR denominators before publication. |
| 9 AI/CTI | Evidence-backed case-scoped summaries, query assistance, similar incidents, prompt-injection resistance, permission-aware context and no unsupervised response. Optional local providers. |
| 10 Production qualification | Migration of legacy annotations without invented attribution, independent retention and backup/restore, security review, concurrency/fault tests, RC2 Docker packaging, integration/end-to-end tests and performance evidence. |

## Foundation contract

The domain module is not a public endpoint. It returns an incident with a pending activity event, atomically persisted with the incident mutation. The persistence adapter must use OpenSearch compare-and-set and create-only activity writes; a pending event must not be discarded. Retrying a failed request requires distinguishing committed state from activity-delivery failure. The internal persistence adapter now implements CAS, create-only delivery, identical-event replay and CAS acknowledgement. It does not yet schedule recovery or implement request idempotency. Until access control, recovery orchestration and integration tests are complete, do not provision or expose the new API.

Existing Wazuh finding case API is intentionally unchanged. The core manager is not modified until verified response execution requires it.

## Release gate

No production deployment or upstream submission until local AGY validation has established indexer/dashboard version compatibility, successful builds, role restrictions, migration integrity, durable activity recovery, realistic SOC workflows and regression results. Rebase/forward-port to the supported upstream release after RC2 qualification.

## Security architecture decision

The authoritative mutation engine is now implemented in the indexer fork, following Wazuh's permission-gated transport action pattern. The earlier TypeScript domain/store/service are isolated reference scaffolding; they must not be registered as a production privileged writer. Production dashboard routes will bind the dedicated indexer client to the current user. See [indexer security boundary](https://github.com/izm1chael/wazuh-indexer-plugins/blob/siem/incident-foundation/docs/ref/modules/case-management/incident-security-boundary.md).

Initial staged indexer operations: create, self-assign, unassign new incident, start triage, activate, edit, close, reopen, attach and detach findings. These are not active routes until the indexer plugin registers them and role integration is qualified. The reference queue is also not a production privileged read path; a staged permission-bearing indexer read action now implements summary queries and detail lookup. The current-user dashboard adapter supports both read and write contracts. Supervisor reassignment, idempotency, recovery scheduling, per-reader finding projection and API registration remain outstanding. The dashboard adapter must never fall back to direct index writes or retry ambiguous mutations automatically.

## Experimental activation and retry safety

Both components now register routes only after explicit opt-in. Dashboard setting: `wazuh.experimentalIncidentsEnabled: true` (default false); indexer setting: `plugins.setup.incidents.enabled: true` (default false). The dashboard routes bind only to `asCurrentUser` and never forward arbitrary index paths. Do not enable outside disposable qualification until actual OpenSearch roles and direct index bypass are tested. Verify the final dashboard plugin config prefix locally.

Creation requires an explicit stable request UUID from the caller. The server derives the incident ID from the authenticated actor and key and stores a normalized creation fingerprint. A replay returns the current record and `replayed: true`; a different payload with the same key conflicts. Ordinary commands remain revision-checked, with no automatic retries. A bounded indexer cluster-manager recovery worker is now staged to deliver pending audit events every 30 seconds. Build and failover qualification remain mandatory.

## Experimental workspace

The existing Case Management cases page links to a standalone hash-route workspace only when the dashboard experimental capability is enabled. The original finding-based table remains available. Initial screens include a queue (status, owner, severity, text, cursor pagination), standalone creation with an in-memory stable request key, and incident detail with claim/triage/activate/close/reopen actions. The route is gated by the capability, but authorization is always enforced by the indexer. The UI does not yet have per-action capability hints, supervisor assignment, finding/activities tabs, metrics, editing, or Security Operations navigation. Creation retries preserve the key only while the form remains mounted; leaving the form or reloading loses the key, so reconcile the queue before attempting a new create. Dashboard manifest confirms the `wazuh` config prefix. All code remains unqualified and must be tested in an isolated environment.

## Investigation read and privacy update

The workspace now displays paginated delivered audit activity and a separately permission-filtered linked-finding list, with manual attach/detach and metadata editing. The indexer restores the original authenticated context for each finding lookup, returns references only, and redacts raw audit changes. Missing and inaccessible references are combined; the analyst cannot detach one without current visibility. Evidence retention, entity extraction, supervisor handover, per-action UI hints, durable create retry state and production RBAC remain outstanding. Private backing index names are now `.wazuh-cases-v1` and `.wazuh-case-activity-v1` (hidden, exact names). Reference TypeScript constants are aligned; never expose the reference writer. These names reduce overlap with the common `wazuh-*` grant but are not a substitute for permission checks.

## Collaboration implementation

Dedicated read projection and collaborate action now support append-only attributed analyst notes and owner-managed task checklists. Notes are delivered through the existing audit outbox, without a 20-note lifetime cap; tasks have a 100-item aggregate limit and full transition history. The UI shows task completion counts, notes, pagination, and pending-delivery/stale revision states. All commands remain revision-checked; closed incidents must reopen before collaboration writes. Task assignee management, reusable templates, note redaction/amendment governance and qualification remain outstanding. Notes and tasks are single-SOC content, not automatically copied finding evidence.

## Live finding intelligence

The existing revision-bound, caller-filtered finding page now carries optional allowlisted observations (source time, rule ID/title, host/agent/user/network/domain/hash fields and MITRE ATT&CK IDs). The workspace groups entity values, deduplicates technique/tactic IDs and sorts the visible page chronologically. This is a live per-page projection, not a complete incident-wide timeline, persistent entity graph or retained evidence. Unknown data stays unknown; source security and retention still apply. No raw event or hidden finding is copied to case storage.

## Correlation dry-run workflow

The workspace now links to a read-only preview form, with a dedicated current-user indexer API and permission. The rule UUID list, version, threshold and full UTC time windows are validated; no arbitrary query DSL or index names accepted. Search rejects incomplete results or over 1,000 matching findings rather than silently truncating. The preview shows candidate group identities, references and exclusion counters; no configuration is persisted and no cases are written. Search visibility and ingestion completeness remain separate concepts. Verify actual DLS/FLS, source mapping, result caps and repeatability before enabling automatic execution.

## Saved correlation policies

The correlation screen can explicitly save or load an immutable policy UUID/version under separate policy read/save permissions. Identical saves replay; changed definitions require a new version. Time ranges are supplied only for preview, not stored in the policy. All saved policies remain preview-only; no active version pointer or automatic execution is implemented. The preview itself remains read-only. No finding source or preview result is stored with a policy.

## SOC operational reporting

The incident queue links to a dedicated metrics report. The report is read-only, permission-gated and explicitly separates current-state creation cohorts from the entire current open backlog. MTTT is triage to active; MTTR is creation to current closure for currently closed cohort members; first assignment and first closure are separate metrics. Missing/invalid samples are counted, not converted to zero. Configurable strict SLA limits default to 600 and 1200 seconds; mean, nearest-rank P50/P95 and completed-sample compliance are displayed. Workloads, severity, age buckets and closure classifications are counted. MTTI and detection compression are not claimed without trusted detection and identification evidence. The current bounded search fails at more than 5,000 union records; scalable aggregation and true historical as-of reporting remain outstanding. No automatic refresh or raw index grant.
