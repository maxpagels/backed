// Minimal CBOR decoder: just enough for WebAuthn attestation objects and COSE keys.
// Shared by index.html (browser) and verify-attestation.js (Node).
export function cbor(bytes) {
  let i = 0;
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const len = ai => {
    if (ai < 24) return ai;
    if (ai === 24) return bytes[i++];
    if (ai === 25) return (i += 2, v.getUint16(i - 2));
    if (ai === 26) return (i += 4, v.getUint32(i - 4));
    throw Error('unsupported CBOR length');
  };
  const item = () => {
    const b = bytes[i++], n = len(b & 31);
    switch (b >> 5) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: return bytes.slice(i, i += n);
      case 3: return new TextDecoder().decode(bytes.slice(i, i += n));
      case 4: return Array.from({ length: n }, () => item());
      case 5: { const m = {}; for (let k = 0; k < n; k++) { const key = item(); m[key] = item(); } return m; }
      default: throw Error('unsupported CBOR type ' + (b >> 5));
    }
  };
  return item();
}
