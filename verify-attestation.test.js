// Builds a throwaway root -> intermediate -> leaf chain with openssl and a packed attestation signed by the leaf.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { X509Certificate, createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyAttestation, pems } from './verify-attestation.js';

const sha256 = b => createHash('sha256').update(b).digest();
const b64u = b => Buffer.from(b).toString('base64url');

// Tiny CBOR encoder for test fixtures.
const head = (mt, n) => Buffer.from(n < 24 ? [mt << 5 | n] : n < 256 ? [mt << 5 | 24, n] : [mt << 5 | 25, n >> 8, n & 255]);
const enc = x =>
  typeof x === 'number' ? (x >= 0 ? head(0, x) : head(1, -1 - x))
  : typeof x === 'string' ? Buffer.concat([head(3, Buffer.byteLength(x)), Buffer.from(x)])
  : Buffer.isBuffer(x) ? Buffer.concat([head(2, x.length), x])
  : Array.isArray(x) ? Buffer.concat([head(4, x.length), ...x.map(enc)])
  : Buffer.concat([head(5, x.size), ...[...x].flatMap(([k, v]) => [enc(k), enc(v)])]);

const dir = mkdtempSync(join(tmpdir(), 'backed-'));
const f = name => join(dir, name);
const aaguid = randomBytes(16);
const ssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
const keyFile = name => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  writeFileSync(f(name), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  return privateKey;
};
writeFileSync(f('ext.cnf'), `[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\n` +
  `[leaf]\nbasicConstraints=critical,CA:FALSE\n1.3.6.1.4.1.45724.1.1.4=DER:0410${aaguid.toString('hex')}\n`);
keyFile('root.key'); keyFile('int.key');
const leafKey = keyFile('leaf.key');
ssl('req', '-x509', '-new', '-key', 'root.key', '-subj', '/CN=Test Root', '-days', '30', '-config', 'ext.cnf', '-extensions', 'ca', '-out', 'root.pem');
ssl('req', '-new', '-key', 'int.key', '-subj', '/CN=Test Int', '-config', 'ext.cnf', '-out', 'int.csr');
ssl('x509', '-req', '-in', 'int.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-days', '30', '-extfile', 'ext.cnf', '-extensions', 'ca', '-out', 'int.pem');
ssl('req', '-new', '-key', 'leaf.key', '-subj', '/C=SE/O=Test/OU=Authenticator Attestation/CN=Test Leaf', '-config', 'ext.cnf', '-out', 'leaf.csr');
ssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'int.pem', '-CAkey', 'int.key', '-CAcreateserial', '-days', '30', '-extfile', 'ext.cnf', '-extensions', 'leaf', '-out', 'leaf.pem');
const [root, int, leaf] = ['root.pem', 'int.pem', 'leaf.pem'].map(n => new X509Certificate(readFileSync(f(n))));

function enrollment({ clientData = { type: 'webauthn.create', challenge: 'x', origin: 'http://localhost:8000' } } = {}) {
  const cred = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey;
  const jwk = cred.export({ format: 'jwk' });
  const credId = randomBytes(16);
  const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]);
  const authData = Buffer.concat([sha256('localhost'), Buffer.from([0x45, 0, 0, 0, 0]), aaguid, Buffer.from([0, credId.length]), credId, enc(cose)]);
  const cd = Buffer.from(JSON.stringify(clientData));
  const sig = sign('sha256', Buffer.concat([authData, sha256(cd)]), leafKey);
  const attStmt = new Map([['alg', -7], ['sig', sig], ['x5c', [leaf.raw]]]);
  return {
    credentialId: b64u(credId),
    publicKey: b64u(cred.export({ type: 'spki', format: 'der' })),
    attestationObject: b64u(enc(new Map([['fmt', 'packed'], ['attStmt', attStmt], ['authData', authData]]))),
    clientDataJSON: b64u(cd),
  };
}
const opts = { rpId: 'localhost', roots: [root], intermediates: [int] };

test('valid attestation chaining through an intermediate passes', () => {
  const r = verifyAttestation(enrollment(), opts);
  assert.ok(r.ok, JSON.stringify(r.checks));
});

test('missing intermediate or untrusted root fails the chain', () => {
  const e = enrollment();
  assert.equal(verifyAttestation(e, { ...opts, intermediates: [] }).checks.chainsToYubicoRoot, false);
  assert.equal(verifyAttestation(e, { ...opts, roots: pems(new URL('./certs/yubico-ca-certs.txt', import.meta.url)) }).checks.chainsToYubicoRoot, false);
});

test('tampered client data fails the signature', () => {
  const e = enrollment();
  const forged = { ...e, clientDataJSON: b64u(JSON.stringify({ type: 'webauthn.create', challenge: 'y', origin: 'http://localhost:8000' })) };
  assert.equal(verifyAttestation(forged, opts).checks.signature, false);
});

test('wrong rpId, swapped public key and wrong type fail', () => {
  const e = enrollment();
  const r = verifyAttestation(e, { ...opts, rpId: 'evil.example' });
  assert.equal(r.checks.origin, false);
  assert.equal(r.checks.rpIdHash, false);
  assert.equal(verifyAttestation({ ...e, publicKey: enrollment().publicKey }, opts).checks.publicKeyMatches, false);
  assert.equal(verifyAttestation(enrollment({ clientData: { type: 'webauthn.get', origin: 'http://localhost:8000' } }), opts).checks.type, false);
});

test('bundled Yubico CA files load', () => {
  assert.ok(pems(new URL('./certs/yubico-ca-certs.txt', import.meta.url)).some(c => /Yubico Attestation Root 1/.test(c.subject)));
  assert.ok(pems(new URL('./certs/yubico-intermediate.pem', import.meta.url)).some(c => /Yubico FIDO Attestation A 1/.test(c.subject)));
});
