import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { evaluate, boundKeys } from './backed-action.js';
import { STATEMENT_V1 } from './backed.js';

const sha256 = b => createHash('sha256').update(b).digest();
const b64u = b => Buffer.from(b).toString('base64url');
const rpId = 'alice.github.io';
const head = 'a'.repeat(40);
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const key = { github: 'alice', github_id: 42, credentialId: 'cred1', publicKey: b64u(publicKey.export({ type: 'spki', format: 'der' })) };
const ctx = { repo: 'alice/proj', number: 7, headSha: head, authorId: 42, keys: [key], rpId, origin: `https://${rpId}` };

// Signs like a browser on https://<signRpId> would.
function bundle(fields = {}, { signRpId = rpId, editStatement } = {}) {
  const statement = JSON.stringify({ v: 1, repo: 'alice/proj', pr: 7, head_sha: head, statement: STATEMENT_V1, ai_use: 'none', signed_at: 'now', ...fields });
  const cd = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64u(sha256(statement)), origin: `https://${signRpId}` }));
  const ad = Buffer.concat([sha256(signRpId), Buffer.from([0x05, 0, 0, 0, 1])]);
  const sig = sign('sha256', Buffer.concat([ad, sha256(cd)]), privateKey);
  const b = { statement: editStatement ? editStatement(statement) : statement, credentialId: 'cred1', authenticatorData: b64u(ad), clientDataJSON: b64u(cd), signature: b64u(sig) };
  return '```backed\n' + JSON.stringify(b, null, 2) + '\n```';
}

test('valid bundle for the current head backs the PR', async () => {
  const r = await evaluate({ ...ctx, comments: ['lgtm', `Signed:\n${bundle()}`] });
  assert.equal(r.backed, true);
  assert.equal(r.key.github, 'alice');
});

test('bundle for an older commit is ignored without a failure reason', async () => {
  assert.deepEqual(await evaluate({ ...ctx, comments: [bundle({ head_sha: 'b'.repeat(40) })] }), { backed: false, reason: undefined });
});

test('bundle copied to another PR or repo gets a reason, even for a different commit', async () => {
  assert.match((await evaluate({ ...ctx, comments: [bundle({ pr: 8 })] })).reason, /different repo or PR/);
  assert.match((await evaluate({ ...ctx, comments: [bundle({ repo: 'mallory/proj', head_sha: 'c'.repeat(40) })] })).reason, /different repo or PR/);
});

test('key bound to someone else, or not enrolled, fails', async () => {
  assert.match((await evaluate({ ...ctx, authorId: 99, comments: [bundle()] })).reason, /not bound to the PR author/);
  assert.match((await evaluate({ ...ctx, keys: [], comments: [bundle()] })).reason, /not enrolled/);
});

test('edited statement, wrong domain, wrong text and bad ai_use fail', async () => {
  const edited = bundle({}, { editStatement: s => s.replace('"none"', '"assisted"') });
  assert.match((await evaluate({ ...ctx, comments: [edited] })).reason, /challengeIsStatementHash/);
  assert.match((await evaluate({ ...ctx, comments: [bundle({}, { signRpId: 'evil.example' })] })).reason, /origin, rpIdHash/);
  assert.match((await evaluate({ ...ctx, comments: [bundle({ statement: 'I glanced at it.' })] })).reason, /statement version or text/);
  assert.match((await evaluate({ ...ctx, comments: [bundle({ ai_use: 'maybe' })] })).reason, /ai_use/);
});

test('garbage blocks are skipped and a later valid bundle still counts', async () => {
  const r = await evaluate({ ...ctx, comments: ['```backed\nnot json\n```', bundle()] });
  assert.equal(r.backed, true);
});

test('a key counts only if a merged PR by its own account added it', () => {
  const added = '@@ -1 +1,5 @@\n-[]\n+[\n+  {\n+    "github_id": 42,\n+    "credentialId": "cred1",\n+  }\n+]';
  assert.deepEqual(boundKeys([key], [{ authorId: 42, patch: added }]), [key]);
  assert.deepEqual(boundKeys([key], [{ authorId: 99, patch: added }]), [], 'added by someone else');
  assert.deepEqual(boundKeys([key], [{ authorId: 42, patch: ' "credentialId": "cred1",\n+    "github_id": 42,' }]), [], 'only an unchanged context line');
  assert.deepEqual(boundKeys([key], [{ authorId: 42, patch: '+    "note": "cred1",' }]), [], 'id in another field');
  assert.deepEqual(boundKeys([key], [{ authorId: 42, patch: '+    "credentialId": "cred1x",' }]), [], 'prefix of another id');
  assert.deepEqual(boundKeys([key], []), [], 'pushed directly, no PR');
});
