// GitHub Action: marks a PR as backed when a comment holds a valid signature bundle for its current head.
// Phase 1 policy is label-only: a `backed` label, a `backed` commit status and one status comment; nothing is closed or blocked.
// Runs from the default branch (see .github/workflows/backed.yml) and treats every comment as untrusted input.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { STATEMENT_V1, AI_USE, verifyAssertion } from './backed.js';
import { verifyAttestation, pems } from './verify-attestation.js';

const BLOCK = /```backed[^\n]*\n([\s\S]*?)```/g;
const KEYS_PATH = '.github/backed-keys.json';
const MARKER = '<!-- backed-action -->';
const BOT = 'github-actions[bot]';

// Reasons are fixed strings: nothing from the bundle is echoed into the bot's comment.
async function checkBundle(text, { repo, number, headSha, authorId, keys, rpId, origin }) {
  let b, s;
  try { b = JSON.parse(text); s = JSON.parse(b.statement); } catch { return { reason: 'bundle is not valid JSON' }; }
  const thisPr = String(s.repo).toLowerCase() === repo.toLowerCase() && s.pr === number;
  if (!thisPr) return { reason: 'bundle is for a different repo or PR' };
  if (s.head_sha !== headSha) return {}; // stale: signed an earlier commit of this PR
  if (s.v !== 1 || s.statement !== STATEMENT_V1) return { reason: 'unknown statement version or text' };
  if (!AI_USE.includes(s.ai_use)) return { reason: `ai_use must be one of ${AI_USE.join(', ')}` };
  const key = keys.find(k => k.credentialId === b.credentialId);
  if (!key) return { reason: 'key is not enrolled, or was not added by a PR from its own account' };
  if (key.github_id !== authorId) return { reason: 'key is not bound to the PR author' };
  const checks = await verifyAssertion(b, key, { rpId, origin });
  const failed = Object.keys(checks).filter(k => !checks[k]);
  return failed.length ? { reason: `failed checks: ${failed.join(', ')}` } : { ok: true, key };
}

// comments: comment bodies, oldest first. Returns { backed, key } or { backed: false, reason } (reason from the latest failing, non-stale bundle).
export async function evaluate({ comments, ...ctx }) {
  let reason;
  for (const body of comments) {
    for (const [, text] of body.matchAll(BLOCK)) {
      const r = await checkBundle(text, ctx);
      if (r.ok) return { backed: true, key: r.key };
      if (r.reason) reason = r.reason;
    }
  }
  return { backed: false, reason };
}

// history: [{ authorId, patch }] for each default-branch commit that touched the keys file and came from a merged PR.
// A key counts only if a merged PR authored by its github_id added its credentialId line, so nobody can bind a key to someone else's account.
export function boundKeys(keys, history) {
  return keys.filter(k => history.some(h => h.authorId === k.github_id &&
    h.patch.split('\n').some(l => /^\+\s*"credentialId":\s*"([^"]+)"/.exec(l)?.[1] === k.credentialId)));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const repo = process.env.GITHUB_REPOSITORY;
  const page = new URL(process.env.BACKED_PAGE_URL); // the signing page; its host is the WebAuthn RP ID
  const rpId = page.hostname, origin = page.origin;
  const defaultBranch = event.repository.default_branch;
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

  // Keys must attest as genuine hardware for this RP ID and be bound by their own account's merged PR.
  const roots = pems(new URL('./certs/yubico-ca-certs.txt', import.meta.url));
  const intermediates = pems(new URL('./certs/yubico-intermediate.pem', import.meta.url));
  const attested = JSON.parse(readFileSync(new URL(`./${KEYS_PATH}`, import.meta.url), 'utf8'))
    .filter(k => {
      const ok = verifyAttestation(k, { rpId, roots, intermediates }).ok;
      if (!ok) console.log(`ignoring key for ${k.github}: attestation does not verify for ${rpId}`);
      return ok;
    });
  const history = [];
  // shortcut: reads the last 100 commits touching the keys file, with 2 API calls each; paginate or cache once enrollment grows.
  for (const c of await api('GET', `/commits?path=${KEYS_PATH}&sha=${defaultBranch}&per_page=100`)) {
    const pr = (await api('GET', `/commits/${c.sha}/pulls`)).find(p => p.merged_at && p.base.ref === defaultBranch);
    // shortcut: GitHub omits patches for very large diffs; fine while the keys file is small.
    const patch = (await api('GET', `/commits/${c.sha}`)).files?.find(f => f.filename === KEYS_PATH)?.patch;
    if (pr && patch) history.push({ authorId: pr.user.id, patch });
  }
  const keys = boundKeys(attested, history);
  for (const k of attested) if (!keys.includes(k)) console.log(`ignoring key for ${k.github}: not added by a merged PR from account ${k.github_id}`);

  const pr = await api('GET', `/pulls/${number}`);
  // shortcut: reads the first 100 comments only; paginate if PR threads get that long.
  const all = await api('GET', `/issues/${number}/comments?per_page=100`);
  const comments = all.filter(c => c.user.login !== BOT).map(c => c.body ?? '');
  const result = await evaluate({ comments, repo, number, headSha: pr.head.sha, authorId: pr.user.id, keys, rpId, origin });
  console.log(JSON.stringify({ number, head: pr.head.sha, ...result, key: result.key?.github }));

  const status = (state, description) => api('POST', `/statuses/${pr.head.sha}`, { state, context: 'backed', description: description.slice(0, 140) });
  const short = pr.head.sha.slice(0, 7);
  const link = new URL(page);
  link.search = new URLSearchParams({ repo, pr: number, sha: pr.head.sha });
  let body;
  if (result.backed) {
    await status('success', `Backed by a hardware key enrolled to @${result.key.github}`);
    await api('POST', `/issues/${number}/labels`, { labels: ['backed'] });
    body = `**Backed**: commit \`${short}\` is signed by a hardware key enrolled to **${result.key.github}**.`;
  } else {
    await api('DELETE', `/issues/${number}/labels/backed`);
    if (result.reason) await status('failure', `Not backed: ${result.reason}`);
    body = `**Not backed**: commit \`${short}\` has no valid signature. [Sign it here](${link}) with an enrolled key, ` +
      'then paste the bundle into a new comment inside a `backed` code block.' +
      (result.reason ? `\n\nThe latest bundle on this PR was rejected: ${result.reason}.` : '');
  }

  // One status comment per PR, edited in place. Comments made with GITHUB_TOKEN don't retrigger the workflow.
  body = `${MARKER}\n${body}`;
  const mine = all.find(c => c.user.login === BOT && c.body?.includes(MARKER));
  if (!mine) await api('POST', `/issues/${number}/comments`, { body });
  else if (mine.body !== body) await api('PATCH', `/issues/comments/${mine.id}`, { body });
}
