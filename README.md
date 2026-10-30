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

`.github/workflows/backed.yml` runs `backed-action.js` whenever a PR is opened or pushed to, or a PR comment is posted or edited. It looks for a `backed` code block in the PR's comments and, if one is valid for the PR's current head commit, sets a `backed` commit status and adds a `backed` label. That's the Phase 1 label-only policy: nothing is closed or blocked. A new push removes the label until the contributor signs again. A bundle that targets the current head but fails gets a `failure` status with the reason, so the contributor can see what's wrong.

A bundle counts only if:

- the statement is v1 with the exact v1 text and a valid `ai_use`
- `repo`, `pr` and `head_sha` match this PR, so a bundle can't be copied to another PR or commit
- the key is listed in `.github/backed-keys.json`, bound to the PR author's login, and its attestation still verifies against the bundled Yubico CAs
- the WebAuthn assertion verifies for the Pages domain (`https://<owner>.github.io`)

The workflow uses `pull_request_target`, so PRs from forks get a token that can write labels and statuses. That's safe only because the job checks out the default branch and never runs the PR's code; keep it that way.

### Set it up

1. Push this repo to GitHub, then turn on Pages under Settings → Pages (deploy from the default branch, root folder). The page is then at `https://<owner>.github.io/<repo>/`.
2. Open that page and click **Enroll key**. An enrollment made on `localhost` won't work, because WebAuthn ties every credential to the domain it was made on.
3. Optional check: save the output as `enrollment.json` and run `node verify-attestation.js enrollment.json <owner>.github.io`.
4. Add the enrollment to `.github/backed-keys.json` on the default branch, with the contributor's GitHub login: `[{ "github": "<login>", ...the Enroll output }]`.

To back a PR: get the full head SHA (`git rev-parse HEAD`), put it with the repo and PR number into the statement on the page, click **Sign**, and paste the bundle into a PR comment:

````
```backed
{ ...bundle... }
```
````

To use the Action in another repo, copy `.github/`, `certs/`, `backed.js`, `backed-action.js`, `verify-attestation.js`, `cbor.js` and `package.json`, which sets `"type": "module"`.

## Known limits

- Attestation is checked against Yubico's roots only, not the FIDO Metadata Service, so other vendors' keys fail.
- There's no server, so the enrollment challenge isn't checked for freshness.
- The exact statement text is signed; there's no JSON canonicalization.
- Only ES256 (P-256) keys are supported. YubiKeys use it by default.
- The page stores the key in `localStorage`, so the key is tied to the domain the page is served from. A real deployment fixes the RP ID to one domain (e.g. `backed.dev`) so the browser and the CLI (via libfido2) produce the same format.
- The Action binds keys to GitHub logins, which can be renamed and reused. Numeric account IDs would be safer.
- Maintainers edit `.github/backed-keys.json` by hand. It stands in for the ledger, and there's no signed account-binding statement yet.
- The Action reads only the first 100 comments on a PR.
- The policy is hardcoded as label-only; there's no `.github/backed.yml` yet.
- Safari and the Apple and Google passkey managers often return attestation `none`. That's expected for the lighter passkey tier.
test
