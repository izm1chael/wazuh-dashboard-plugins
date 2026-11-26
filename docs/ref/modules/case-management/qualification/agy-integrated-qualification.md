# Integrated RC2 incident qualification — AGY handoff

Status: development candidate, not production qualified. Use both forks' siem/incident-foundation draft PRs together; record exact checkout SHAs and clean trees. Initial feature boundary: dashboard 47e97505fe721de92e6cbd8837569b607a2a10fe; indexer 3251a7bdbc1282549f01d3d327d71d202254947a. Include subsequent qualification-only commits. Core RC2 remains unchanged. Do not deploy to production or promote rules.

## Build and test gates

1. Follow each repository's docs/dev/build-sources.md and docs/dev/run-tests.md. In indexer run ./gradlew test and ./gradlew check; capture seed, counts and failures. Run Python unittest discovery for test_incident*.py. Run the standalone paired parity qualification from the indexer checkout with the dashboard checkout path. In dashboard's disposable Docker dev environment, run yarn test:jest from plugins/main and plugins/wazuh-ai-assistant. Build both actual plugin distributions using the RC2-pinned instructions; record dependency versions, artifact hashes and logs. Run node tools/verify_incident_assessment_report.test.cjs.
2. Deploy matching artifacts into a disposable RC2 stack. Verify flags off by default, then enable explicitly. Verify setup/template initialization on a fresh index and upgrade from the earlier incident foundation. Verify strict mappings and hidden-index permissions; no wildcard backing index grants.
3. Execute the indexer incident-security-qualification.md and disposable role fixtures with separate users. Cover ownership, denied finding visibility, stale revisions, idempotency, audit pending/recovery, conflicting mutations, restart and ordinary incident read redaction. Verify that reloading after a pending mutation does not indefinitely disable workspace controls; actual pending status remains authoritative on the server.
4. Create synthetic incidents with exact UUIDs, duplicate/ambiguous rule identities, mixed TLP and partial/unavailable finding pages. Verify manual rule history counts each incident once, never labels individual findings, and rejects absent UUIDs. Verify numeric JSON rule IDs rejected by adapter; historical AI probe is default off, bounded and only disclosed aggregates are sent. Recheck revision/TLP denial before final model request, return and save. Explicitly test permission revocation between reads; this design is not an atomic authorization snapshot.
5. Use local small-model provider (existing approved configuration). Inspect outbound payloads in disposable environment; assert no source identity, raw content or disallowed TLP. Exercise malformed model output, timeout, cancellation, concurrency, consent, private save failure and report export. Verify optional report hash against independent delivered activity hash. No shared raw report storage.
6. Use separate baseline/candidate disposable test integrations per indexer disposable-detection-replay.md; run controls, holdout fixtures, verify actual loaded rule asset identity out-of-band, reject empty/failed/mismatched evaluations. Repeat with a regression candidate. Compare receipt to dashboard evaluator and indexer recomputation. Test independent reviewer, exact fixture fingerprint, rejected gate, withdrawal, duplicate proposals and closed-case lifecycle preservation. No deployment or promotion path.
7. Browser-test entire incident workflow, response governance, playbooks, metrics, correlation preview and AI panels. Check permissions, empty states, pagination, pending state, stale/reload paths. Measure resource use with local provider. Capture screenshots and logs. Do not mark scheduled correlation execution, autonomous SOC, fleet-wide historical FP rates, actual rule replay, or permanent shared reports qualified without evidence specific to each claim.

## Evidence already obtained in cloud

Pure Java TuningReplay and TypeScript tuning evaluator: 305 deterministic paired fixtures, all exact counts/gates/canonical hashes agreed; Java roundtrip, permutation, tamper and three invalid input checks passed. Python replay runner: four mocked test methods passed (no network). Portable verifier: five assertions passed. AI evidence/agentic/history modules strict TypeScript compilation plus 13 standalone assertions on mock readers passed. No full Gradle/Jest/build/live test, production change or upstream submission. All live gates remain required.

## Completion criteria

Return a single consolidated receipt with exact SHAs, build commands/results, unit/integration counts, failures and fixes, live access matrix, replay provenance, provider disclosure checks, and any remaining blockers. Keep both PRs draft until independently reviewed and local qualification passes. Do not substitute mock checks for actual stack verification.

## Handover and investigation follow-on gate

Include the later handover and investigation commits in both checkout SHAs. Execute the five additional disposable checks in ../incident-handover-investigation.md. Verify additive mapping upgrade, exact authenticated recipient acceptance and personal queue scope, bounded live timeline coverage and rejection of partial/stale responses. Record full build and role evidence; no qualification by mock results alone.

## Investigation register follow-on gate

Include both forks' latest investigation-register commits. Execute all five qualification groups in ../incident-investigation-register.md, including additive mapping upgrades, actual collaboration role matrix, local file digest network inspection, and malformed projection tests. Treat relationship assertions and external artifact attestations as analyst metadata, not verified evidence. Record exact SHAs and results in the consolidated qualification receipt.

## Historical entity and IOC hunt follow-on gate

Include both forks' latest hunt commits. Execute the four qualification groups in ../incident-historical-hunt.md. Verify real field mappings, actual hunt/search permission intersection, DLS/FLS, partial results, local concurrency and timeline attachment. Record exact SHAs and results in the consolidated qualification receipt. Manual exact hunting is not a persistent IOC watchlist, external enrichment or autonomous Agentic SOC search.

## Threat intelligence catalog phase gate

Include both forks' final CTI phase commits. Execute all six qualification groups in ../incident-threat-intelligence.md. Verify isolated state index, explicit grants, CAS and revision conservation, external sighting attestation boundaries, restricted STIX subset, local export, and historical hunt DLS/FLS. No production qualification based on standalone validators alone. Record exact SHAs and full build, browser, OpenSearch and independent STIX evidence in the integrated receipt.

## Native-finding analytics execution phase gate

Use both forks' final analytics heads. Follow indexer docs/ref/modules/case-management/incident-analytics-execution.md and the six integrated qualification groups. Keep both analytics and incident gates off in production pending approval. Exercise exact policy content approval, real service-account search/GET context and DLS/FLS, deterministic group/window receipts, crash/replay and late arrivals, local cursor and TLS, read-only dashboard health. Python scheduler 11 mocked-service tests and strict TypeScript 47 standalone assertions passed; 33 source checks passed. Full builds and live authorization/execution remain unqualified. Record exact SHAs, live results and blocked recovery procedures. Native detection engine and CTI catalog are unchanged; do not claim full Sentinel analytics parity.
