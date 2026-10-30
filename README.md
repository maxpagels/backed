# Backed

Hardware-key signatures on pull requests: a person touches a FIDO2 key to say they read a change and stand behind it. The full proposal is in [design.md](design.md).

## Spike: sign a PR statement with WebAuthn

`index.html` is a single page, with no backend, that tests the core loop with a real security key:

1. **Enroll**: creates an ES256 credential on the key with `attestation: "direct"` and shows the attestation format, cert count, AAGUID (the authenticator model), and the raw attestation data for the verifier below.
2. **Sign**: signs the PR statement JSON. The WebAuthn challenge is `SHA-256(statement)`, and touch plus PIN are required.
3. **Verify**: checks the bundle with the same code the GitHub Action uses (`backed.js`): credential ID, `webauthn.get` type, challenge equals the statement hash, origin, RP ID hash, user-present and user-verified flags, and the ECDSA signature. It also confirms that a tampered statement is rejected.

### Run it

```sh
python3 -m http.server 8000
```

Open http://localhost:8000 in Chrome. WebAuthn requires HTTPS or `localhost`, so don't use `127.0.0.1` or a LAN IP. Plug in the YubiKey, click **Enroll key**, then **Sign**, then **Verify**. Edit the bundle and verify again to watch the checks fail.

### Verify the attestation (genuine hardware)

The page doesn't check attestation itself, because a contributor can edit the page. `verify-attestation.js` does it on the verifier's side, with Node 20+ and no dependencies:

1. Copy the JSON from the page's **Enroll** output into `enrollment.json`.
2. Run `node verify-attestation.js enrollment.json` (the second argument is the RP ID, `localhost` by default).

It checks the packed attestation signature, the attestation certificate (not a CA, `OU=Authenticator Attestation`, AAGUID extension matching), the chain to a Yubico root through the bundled intermediates in `certs/`, the RP ID and origin, the flags, and that the public key the page signs with is the attested one. It exits 0 only if every check passes.

`npm test` runs all tests: the attestation verifier against a throwaway CA chain built with `openssl`, and the Action's decision logic against software-key bundles.

`certs/` holds Yubico's published [CA certs](https://developers.yubico.com/PKI/yubico-ca-certs.txt) and [intermediates](https://developers.yubico.com/PKI/yubico-intermediate.pem), downloaded October 30, 2026. The OpenPGP signature on the CA file was not checked.

## Pilot: the GitHub Action

`.github/workflows/backed.yml` runs `backed-action.js` whenever a PR is opened or pushed to, or a PR comment is posted or edited. It looks for a `backed` code block in the PR's comments and, if one is valid for the PR's current head commit, sets a `backed` commit status and adds a `backed` label. That's the Phase 1 label-only policy: nothing is closed or blocked. The workflow's own check, `backed-action / evaluate`, only shows that the Action ran; the `backed` status and label are the result.

The Action also keeps one status comment on each PR, edited in place rather than reposted. When the head isn't backed, the comment links to the signing page with the repo, PR number and head SHA already filled in. A new push removes the label and updates the link. A bundle that's rejected gets a `failure` status, and the comment gives the reason, including when the bundle names a different repo or PR. A bundle for an earlier commit of the same PR is treated as stale and gets no reason.

A bundle counts only if:

- the statement is v1 with the exact v1 text and a valid `ai_use`
- `repo`, `pr` and `head_sha` match this PR, so a bundle can't be copied to another PR or commit
- the key is in `.github/backed-keys.json`, its `github_id` is the PR author's numeric account ID, and its attestation verifies against the bundled Yubico CAs
- a merged PR **opened by that same account** added the key's `credentialId` line to the keys file. Keys pushed directly, or added in someone else's PR, are ignored, so nobody can bind a key to another person's account.
- the WebAuthn assertion verifies for the signing page's domain (`BACKED_PAGE_URL` in the workflow, by default `https://<owner>.github.io/<repo>/`)

The workflow uses `pull_request_target`, so PRs from forks get a token that can write labels, statuses and comments. That's safe only because the job checks out the default branch and never runs the PR's code; keep it that way.

### Set it up

1. Push this repo to GitHub, then turn on Pages under Settings → Pages (deploy from the default branch, root folder). The page is then at `https://<owner>.github.io/<repo>/`.
2. Each contributor opens that page, enters their GitHub login and clicks **Enroll key**. The output is a complete keys-file entry, including the numeric `github_id`. An enrollment made on `localhost` won't work, because WebAuthn ties every credential to the domain it was made on.
3. Optional check: save the output as `enrollment.json` and run `node verify-attestation.js enrollment.json <owner>.github.io`.
4. The contributor opens a PR **from their own account** that adds the entry to the `.github/backed-keys.json` array, and a maintainer merges it.

To back a PR, the contributor follows the link in the Action's comment, checks the statement and clicks **Sign**. Then they paste the bundle into a new PR comment:

````
```backed
{ ...bundle... }
```
````

To use the Action in another repo, copy `.github/`, `certs/`, `backed.js`, `backed-action.js`, `verify-attestation.js`, `cbor.js` and `package.json`, which sets `"type": "module"`. Point `BACKED_PAGE_URL` at wherever the signing page is hosted.

## Known limits

- Attestation is checked against Yubico's roots only, not the FIDO Metadata Service, so other vendors' keys fail.
- There's no server, so the enrollment challenge isn't checked for freshness.
- The exact statement text is signed; there's no JSON canonicalization.
- Only ES256 (P-256) keys are supported. YubiKeys use it by default.
- The page stores the key in `localStorage`, so the key is tied to the domain the page is served from. A real deployment fixes the RP ID to one domain (e.g. `backed.dev`) so the browser and the CLI (via libfido2) produce the same format.
- `.github/backed-keys.json` stands in for the ledger. The binding proves that the account opened the PR adding the key, but the key doesn't sign the binding itself. A maintainer who pushes to a contributor's PR branch could swap the key in it, so review key-file PRs.
- The Action reads the last 100 commits touching the keys file, with two API calls each, on every run.
- The Action reads only the first 100 comments on a PR.
- The policy is hardcoded as label-only; there's no `.github/backed.yml` yet.
- Safari and the Apple and Google passkey managers often return attestation `none`. That's expected for the lighter passkey tier.
test
