// Verifies a WebAuthn "packed" attestation exported from index.html against Yubico's CA certs.
// This runs on the verifier's side (later: the GitHub App/Action), never in the contributor's browser,
// because a check the contributor can edit proves nothing.
import { X509Certificate, createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { cbor } from './cbor.js';

const sha256 = b => createHash('sha256').update(b).digest();
const b64u = b => Buffer.from(b).toString('base64url');
export const pems = path => readFileSync(path, 'utf8')
  .match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)
  .map(p => new X509Certificate(p));
// OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid), then OCTET STRING { OCTET STRING (16 bytes) }
const AAGUID_EXT = Buffer.from('060b2b0601040182e51c01010404120410', 'hex');

const current = (c, now) => new Date(c.validFrom) <= now && now <= new Date(c.validTo);

// True if cert chains to a trusted root through any certs in pool (which are untrusted).
function chainsToRoot(cert, roots, pool, now, depth = 0) {
  const signedBy = p => p.ca && current(p, now) && cert.checkIssued(p) && cert.verify(p.publicKey);
  return roots.some(signedBy) || (depth < 4 && pool.some(p => signedBy(p) && chainsToRoot(p, roots, pool, now, depth + 1)));
}

export function verifyAttestation(enrollment, { rpId, roots, intermediates, now = new Date() }) {
  const att = cbor(Buffer.from(enrollment.attestationObject, 'base64url'));
  const clientDataBytes = Buffer.from(enrollment.clientDataJSON, 'base64url');
  const clientData = JSON.parse(clientDataBytes);
  const ad = Buffer.from(att.authData);
  const aaguid = ad.subarray(37, 53);
  const idLen = ad.readUInt16BE(53);
  const credentialId = ad.subarray(55, 55 + idLen);
  const cose = cbor(ad.subarray(55 + idLen));
  const { alg, sig, x5c = [] } = att.attStmt;
  const [leaf, ...sentChain] = x5c.map(c => new X509Certificate(Buffer.from(c)));
  const es256 = alg === -7 && cose[3] === -7 && cose[-1] === 1;
  const spki = es256 && b64u(createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: b64u(cose[-2]), y: b64u(cose[-3]) } })
    .export({ type: 'spki', format: 'der' }));
  const ext = leaf ? leaf.raw.indexOf(AAGUID_EXT) : -1;

  const checks = {
    format: att.fmt === 'packed',
    type: clientData.type === 'webauthn.create',
    origin: new URL(clientData.origin).hostname === rpId,
    rpIdHash: ad.subarray(0, 32).equals(sha256(rpId)),
    flags: (ad[32] & 0x45) === 0x45, // user present, user verified, credential data included
    credentialMatches: b64u(credentialId) === enrollment.credentialId,
    publicKeyMatches: spki === enrollment.publicKey, // the key the page signs with is the attested one
    es256,
    signature: !!leaf && verify('sha256', Buffer.concat([ad, sha256(clientDataBytes)]), leaf.publicKey, Buffer.from(sig)),
    leafNotCA: !!leaf && !leaf.ca && current(leaf, now),
    leafSubject: !!leaf && /^OU=Authenticator Attestation$/m.test(leaf.subject),
    aaguidExtension: !!leaf && (ext === -1 || leaf.raw.subarray(ext + AAGUID_EXT.length, ext + AAGUID_EXT.length + 16).equals(aaguid)),
    chainsToYubicoRoot: !!leaf && chainsToRoot(leaf, roots, [...sentChain, ...intermediates], now),
  };
  const h = aaguid.toString('hex');
  return {
    ok: Object.values(checks).every(Boolean),
    checks,
    aaguid: `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`,
    leafSubject: leaf?.subject.replace(/\n/g, ', '),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [file, rpId = 'localhost'] = process.argv.slice(2);
  if (!file) {
    console.error('usage: node verify-attestation.js enrollment.json [rpId]');
    process.exit(2);
  }
  const result = verifyAttestation(JSON.parse(readFileSync(file, 'utf8')), {
    rpId,
    roots: pems(new URL('./certs/yubico-ca-certs.txt', import.meta.url)),
    intermediates: pems(new URL('./certs/yubico-intermediate.pem', import.meta.url)),
  });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.ok ? 0 : 1);
}
