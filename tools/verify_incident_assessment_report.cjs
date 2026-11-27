#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
const fs = require('node:fs');
const crypto = require('node:crypto');
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  if (value === null || typeof value === 'string' || typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isSafeInteger(value))) return JSON.stringify(value);
  throw new Error('Invalid report value');
}
function verify(envelope, expected) {
  if (!envelope || Object.keys(envelope).length !== 2 || !envelope.provenance || !envelope.assessment) throw new Error('Invalid report envelope');
  const { report_sha256, report_hash_serialization, ...core } = envelope.provenance;
  if (report_hash_serialization !== 'sorted-json-v1' || typeof report_sha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(report_sha256) || (expected !== undefined && !/^[a-f0-9]{64}$/.test(expected))) throw new Error('Invalid report fingerprint');
  const actual = crypto.createHash('sha256').update(canonical({ provenance: core, assessment: envelope.assessment }), 'utf8').digest('hex');
  if (actual !== report_sha256 || (expected !== undefined && actual !== expected)) throw new Error('Report fingerprint mismatch');
  return { actual, externally_compared: expected !== undefined };
}
if (require.main === module) {
  try {
    if (process.argv.length < 3 || process.argv.length > 4 || fs.statSync(process.argv[2]).size > 65536) throw new Error('Invalid arguments');
    const result = verify(JSON.parse(fs.readFileSync(process.argv[2], 'utf8')), process.argv[3]);
    console.log('Fingerprint matches: ' + result.actual);
    console.log(result.externally_compared ? 'Matches separately supplied fingerprint; not a provider signature.' :
      'Self-consistent only; compare with separately recorded audit fingerprint.');
  } catch (_) { console.error('Report verification failed.'); process.exitCode = 1; }
}
module.exports = { canonical, verify };
