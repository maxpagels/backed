// GitHub Action: marks a PR as backed when a comment holds a valid signature bundle for its current head.
// Phase 1 policy is label-only: a `backed` label plus a `backed` commit status; nothing is closed or blocked.
// Runs from the default branch (see .github/workflows/backed.yml) and treats every comment as untrusted input.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { STATEMENT_V1, AI_USE, verifyAssertion } from './backed.js';
import { verifyAttestation, pems } from './verify-attestation.js';

const BLOCK = /```backed[^\n]*\n([\s\S]*?)```/g;

async function checkBundle(text, { repo, number, headSha, author, keys, rpId }) {
  let b, s;
  try { b = JSON.parse(text); s = JSON.parse(b.statement); } catch { return { reason: 'bundle is not valid JSON' }; }
  const forHead = s.head_sha === headSha;
  const fail = reason => ({ forHead, reason });
  if (s.v !== 1 || s.statement !== STATEMENT_V1) return fail('unknown statement version or text');
  if (String(s.repo).toLowerCase() !== repo.toLowerCase() || s.pr !== number || !forHead) return fail('statement is for a different repo, PR or commit');
  if (!AI_USE.includes(s.ai_use)) return fail(`ai_use must be one of ${AI_USE.join(', ')}`);
  const key = keys.find(k => k.credentialId === b.credentialId);
  if (!key) return fail('key is not enrolled in .github/backed-keys.json');
  // shortcut: binds keys to GitHub logins, which can be renamed and reused; switch to numeric account IDs before Phase 2.
  if (key.github.toLowerCase() !== author.toLowerCase()) return fail('key is not bound to the PR author');
  const checks = await verifyAssertion(b, key, { rpId, origin: `https://${rpId}` });
  const failed = Object.keys(checks).filter(k => !checks[k]);
  return failed.length ? fail(`failed checks: ${failed.join(', ')}`) : { ok: true, key };
}

// comments: comment bodies, oldest first. Returns { backed, key } or { backed: false, reason } (reason only when a bundle targeted this head).
export async function evaluate({ comments, ...ctx }) {
  let reason;
  for (const body of comments) {
    for (const [, text] of body.matchAll(BLOCK)) {
      const r = await checkBundle(text, ctx);
      if (r.ok) return { backed: true, key: r.key };
      if (r.forHead) reason = r.reason;
    }
  }
  return { backed: false, reason };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const repo = process.env.GITHUB_REPOSITORY;
  const rpId = process.env.BACKED_RP_ID.toLowerCase();
  const number = (event.pull_request ?? event.issue).number;
  const api = async (method, path, body) => {
    const res = await fetch(`${process.env.GITHUB_API_URL ?? 'https://api.github.com'}/repos/${repo}${path}`, {
      method,
      headers: { authorization: `Bearer ${process.env.GITHUB_TOKEN}`, accept: 'application/vnd.github+json' },
      body: body && JSON.stringify(body),
    });
    if (method === 'DELETE' && res.status === 404) return null; // label wasn't there
    if (!res.ok) throw Error(`${method} ${path}: ${res.status} ${await res.text()}`);
    return method === 'DELETE' ? null : res.json();
  };

  // Only keys whose attestation verifies count, so the keys file is auditable by anyone.
  const roots = pems(new URL('./certs/yubico-ca-certs.txt', import.meta.url));
  const intermediates = pems(new URL('./certs/yubico-intermediate.pem', import.meta.url));
  const keys = JSON.parse(readFileSync(new URL('./.github/backed-keys.json', import.meta.url), 'utf8')).filter(k => {
    const ok = verifyAttestation(k, { rpId, roots, intermediates }).ok;
    if (!ok) console.log(`ignoring key for ${k.github}: attestation does not verify for ${rpId}`);
    return ok;
  });

  const pr = await api('GET', `/pulls/${number}`);
  // shortcut: reads the first 100 comments only; paginate if PR threads get that long.
  const comments = (await api('GET', `/issues/${number}/comments?per_page=100`)).map(c => c.body ?? '');
  const result = await evaluate({ comments, repo, number, headSha: pr.head.sha, author: pr.user.login, keys, rpId });
  console.log(JSON.stringify({ number, head: pr.head.sha, ...result, key: result.key?.github }));

  const status = (state, description) => api('POST', `/statuses/${pr.head.sha}`, { state, context: 'backed', description: description.slice(0, 140) });
  if (result.backed) {
    await status('success', `Backed by a hardware key enrolled to @${result.key.github}`);
    await api('POST', `/issues/${number}/labels`, { labels: ['backed'] });
  } else {
    await api('DELETE', `/issues/${number}/labels/backed`);
    if (result.reason) await status('failure', `Not backed: ${result.reason}`);
  }
}
