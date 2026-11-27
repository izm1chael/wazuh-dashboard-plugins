# WADE offline detection engineering review

Independent, unregistered candidate workspace for Dashboard issue #15, based on RC2 branch commit 22901fa354f20616d4bc707003b4b8a115cfb3d9. This directory is deliberately outside the existing plugin packaging. The public Plugin/application.register entrypoint follows the RC2 public plugin registration convention, but has not been compiled against OpenSearch Dashboards dependencies or browser-mounted. No server routes, no live Indexer requests, no promotion controls, no stored evidence, no AI provider or changes to the incident application.

The actual TypeScript review model and DOM application compiled locally with TypeScript strict mode; seven Node test cases passed. To rerun without modifying the checkout:

    cd tools/wade-review
    out=$(mktemp -d)
    cp -R public test "$out/"
    cd "$out"
    tsc --strict --target ES2020 --module commonjs --lib ES2020,DOM --rootDir public --outDir build public/review.ts public/application.ts
    node --test test/review.test.cjs

Import a local JSON cohort with format wade-tuning-cohort-v1, distinct 64-character lowercase SHA-256 champion_digest and challenger_digest, positive integer min_benign and min_malicious, and cases (max 100000, total 8 MiB). Every case has id (opaque pseudonymous ID), label (BENIGN, MALICIOUS, UNLABELLED), champion/challenger (MATCH, NO_MATCH, UNKNOWN), and protected (boolean). Unknown fields are rejected. Use supplied paired outcomes only. The local review rules mirror the Indexer offline tuning review, but backend provenance, authoritative policy minima, receipt verification, independent review, verified label authority, and real parity testing remain mandatory. Browser calculations are advisory. Never treat REVIEW_CANDIDATE as approval or deployment. Imported evidence is untrusted and never transmitted. Use no raw event data or sensitive identifiers.

Production workspace still needs native packaging, navigation integration, authenticated replay and shadow APIs, verified immutable cohort receipts, rule editor, analyst dispositions, lifecycle approvals, coverage and entity views, EUI styling/accessibility and browser tests. Live promotion remains disabled. See Indexer draft PR #14. The offline app is a real starting point, not a completed WADE-11 deliverable.
