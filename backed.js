// Backed v1 statement and WebAuthn assertion verification.
// Shared by index.html (browser) and backed-action.js (Node): WebCrypto only, no dependencies.
export const STATEMENT_V1 = 'I have read and understand this change and take responsibility for it.';
export const AI_USE = ['none', 'assisted', 'mostly-generated'];

const enc = new TextEncoder();
export const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
export const sha256 = async data => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? enc.encode(data) : data));
export const hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');

// WebAuthn returns DER-encoded ECDSA signatures; WebCrypto wants raw r||s.
function derToRaw(der) {
  const out = new Uint8Array(64);
  let i = 2; // skip SEQUENCE tag + length (short form for P-256)
  for (const off of [0, 32]) {
    const n = der[i + 1];
    let int = der.slice(i + 2, i + 2 + n);
    while (int.length > 32 && int[0] === 0) int = int.slice(1);
    out.set(int, off + 32 - int.length);
    i += 2 + n;
  }
  return out;
}

// Checks a signature bundle against an enrolled key ({ credentialId, publicKey }). Returns one boolean per check.
export async function verifyAssertion(b, key, { rpId, origin }) {
  const clientDataBytes = unb64u(b.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  const authData = unb64u(b.authenticatorData);
  const pub = await crypto.subtle.importKey('spki', unb64u(key.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const signed = new Uint8Array([...authData, ...await sha256(clientDataBytes)]);
  return {
    credentialMatches: b.credentialId === key.credentialId,
    type: clientData.type === 'webauthn.get',
    challengeIsStatementHash: clientData.challenge === b64u(await sha256(b.statement)),
    origin: clientData.origin === origin,
    rpIdHash: hex(authData.slice(0, 32)) === hex(await sha256(rpId)),
    userPresent: (authData[32] & 0x01) !== 0,
    userVerified: (authData[32] & 0x04) !== 0,
    signature: await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, derToRaw(unb64u(b.signature)), signed),
  };
}
