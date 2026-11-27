// SPDX-License-Identifier: AGPL-3.0-or-later
const test=require('node:test');const assert=require('node:assert/strict');
const {parseCohort,reviewCohort}=require('../build/review.js');
const sample={format:'wade-tuning-cohort-v1',champion_digest:'a'.repeat(64),challenger_digest:'b'.repeat(64),min_benign:1,min_malicious:1,cases:[{id:'b',label:'BENIGN',champion:'MATCH',challenger:'NO_MATCH',protected:false},{id:'m',label:'MALICIOUS',champion:'MATCH',challenger:'MATCH',protected:true}]};
const parse=x=>parseCohort(JSON.stringify(x));
test('eligible for review, never automatic approval',()=>{const r=reviewCohort(parse(sample));assert.equal(r.status,'REVIEW_CANDIDATE');assert.equal(r.false_positives_before,1);assert.equal(r.false_positives_after,0);assert.equal(r.requires_human_approval,true);});
test('malicious regression and unknown are withheld',()=>{const x=structuredClone(sample);x.cases[1].challenger='UNKNOWN';const r=reviewCohort(parse(x));assert.equal(r.status,'WITHHELD');assert.deepEqual(r.reasons,['INCOMPLETE_PAIRED_EVALUATION','MALICIOUS_REGRESSION','PROTECTED_CASE_FAILURE']);});
test('unlabelled is not benign',()=>{const x=structuredClone(sample);x.cases[0].label='UNLABELLED';const r=reviewCohort(parse(x));assert.equal(r.benign,0);assert.ok(r.reasons.includes('INSUFFICIENT_LABELLED_COHORT'));});
test('duplicate, invalid fields and equal rule digests rejected',()=>{for(const x of [{...sample,cases:[...sample.cases,sample.cases[0]]},{...sample,activate:true},{...sample,challenger_digest:sample.champion_digest},{...sample,min_benign:0},{...sample,cases:[{...sample.cases[0],protected:'false'}]}])assert.throws(()=>parse(x));});
test('no reduction withheld and ordering stable',()=>{const x=structuredClone(sample);x.cases[0].challenger='MATCH';assert.ok(reviewCohort(parse(x)).reasons.includes('NO_FALSE_POSITIVE_REDUCTION'));assert.deepEqual(reviewCohort(parse(sample)),reviewCohort(parse({...sample,cases:[...sample.cases].reverse()})));});
test('protected benign label is withheld',()=>{const x=structuredClone(sample);x.cases[0].protected=true;assert.ok(reviewCohort(parse(x)).reasons.includes('PROTECTED_CASE_FAILURE'));});
test('oversized import rejected',()=>assert.throws(()=>parseCohort(' '.repeat(8*1024*1024+1))));
