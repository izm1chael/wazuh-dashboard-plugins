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

The domain module is not a public endpoint. It returns an incident with a pending activity event, atomically persisted with the incident mutation. The persistence adapter must use OpenSearch compare-and-set and create-only activity writes; a pending event must not be discarded. Retrying a failed request requires distinguishing committed state from activity-delivery failure. Until access control and delivery are implemented and integration-tested, do not provision or expose the new API.

Existing Wazuh finding case API is intentionally unchanged. The core manager is not modified until verified response execution requires it.

## Release gate

No production deployment or upstream submission until local AGY validation has established indexer/dashboard version compatibility, successful builds, role restrictions, migration integrity, durable activity recovery, realistic SOC workflows and regression results. Rebase/forward-port to the supported upstream release after RC2 qualification.
