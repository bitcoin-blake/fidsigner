// Fid test suite. Runs the 166 Knots unified sighash vectors, then Fid's own
// vectors (vectors.json): keys, a PSBT signed on each chain, a nostr event.
// `node test.mjs --write` regenerates vectors.json from the current code.
// Any other build of Fid, firmware included, must reproduce vectors.json
// byte for byte.
import { readFileSync, writeFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha256';
import { unifiedSighash, parseTransaction, SCRIPT_TYPE_TAPROOT, SIGHASH_ALL, SIGHASH_UNIFIED } from './unified.js';
import {
  CHAINS, parsePrivateKey, keyInfo, xOnlyPubKey, p2trScript, hexToBytes, bytesToHex,
  bytesToBase64, base64ToBytes, parsePsbt, serializePsbt, signPsbt, describePsbt,
  taprootSighashDefault, verify, signEvent, verifyEvent, serializeTransaction, concat, txid,
} from './fid.js';
import { compactSize, u32le, i64le } from './unified.js';

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) pass++; else { fail++; console.error('FAIL', msg); } };
const write = process.argv.includes('--write');

// ---- 1. Knots unified sighash vectors --------------------------------------
{
  const [header, ...rows] = JSON.parse(readFileSync(new URL('./unified_sighash.json', import.meta.url)));
  ok(header.join() === 'scriptCode,rawTx,inIdx,hashType,scriptType,spentOutputs,sighash', 'vector header');
  for (const [scriptCodeHex, rawTx, inIdx, hashType, scriptType, spent, expected] of rows) {
    const tx = parseTransaction(hexToBytes(rawTx));
    const spentOutputs = spent.map(([value, script]) => ({ value: BigInt(value), script: hexToBytes(script) }));
    const scriptCode = hexToBytes(scriptCodeHex);
    const opts = scriptType === 3 ? { leafScript: scriptCode } : { scriptCode };
    let got;
    try { got = bytesToHex(unifiedSighash(tx, inIdx, hashType, scriptType, spentOutputs, opts)); } catch (e) { got = 'error: ' + e.message; }
    ok(got === expected, `knots vector type=${scriptType} hashType=0x${hashType.toString(16)} in=${inIdx}`);
  }
  console.log(`knots unified sighash vectors: ${rows.length}`);
}

// ---- 2. Fid vectors --------------------------------------------------------
const priv = sha256(new TextEncoder().encode('fid test key'));
const privHex = bytesToHex(priv);
const xonly = xOnlyPubKey(priv);
const info = keyInfo(priv);

// key import round trips
ok(bytesToHex(parsePrivateKey(privHex)) === privHex, 'hex import');
ok(bytesToHex(parsePrivateKey(nsecOf(priv))) === privHex, 'nsec import');
ok(bytesToHex(parsePrivateKey(wifOf(priv))) === privHex, 'wif import');
let threw = false; try { parsePrivateKey('00'.repeat(32)); } catch { threw = true; } ok(threw, 'zero key rejected');

// a PSBT: two inputs to our key, one output to another key, one change
const other = xOnlyPubKey(sha256(new TextEncoder().encode('fid other key')));
const unsignedTx = {
  version: 2, locktime: 0, segwit: false,
  inputs: [
    { txid: hexToBytes('aa'.repeat(32)), vout: 1, scriptSig: new Uint8Array(), sequence: 0xfffffffd, witness: [] },
    { txid: hexToBytes('bb'.repeat(32)), vout: 0, scriptSig: new Uint8Array(), sequence: 0xfffffffd, witness: [] },
  ],
  outputs: [
    { value: 60_000n, script: p2trScript(other) },
    { value: 19_500n, script: p2trScript(xonly) },
  ],
};
const spent = [{ value: 50_000n, script: p2trScript(xonly) }, { value: 30_000n, script: p2trScript(xonly) }];
const psbtBytes = buildPsbt(unsignedTx, spent);
const psbtB64 = bytesToBase64(psbtBytes);
ok(bytesToHex(serializePsbt(parsePsbt(psbtBytes))) === bytesToHex(psbtBytes), 'psbt parse/serialize round trip');

const desc = describePsbt(parsePsbt(psbtBytes), xonly, 'txbt');
ok(desc.inputs.every(i => i.mine) && desc.fee === 500n && desc.outputs[1].mine && !desc.outputs[0].mine, 'psbt description');

const psbtResults = {};
for (const chain of Object.keys(CHAINS)) {
  const r = signPsbt(parsePsbt(psbtBytes), priv, chain);
  ok(r.signed.length === 2 && r.final, `${chain}: both inputs signed and finalized`);
  const final = parseTransaction(hexToBytes(r.final));
  for (let i = 0; i < 2; i++) {
    const w = final.inputs[i].witness[0];
    if (CHAINS[chain].unified) {
      ok(w.length === 65 && w[64] === (SIGHASH_ALL | SIGHASH_UNIFIED), `${chain} input ${i} carries 0x21`);
      ok(verify(w.subarray(0, 64), unifiedSighash(final, i, 0x21, SCRIPT_TYPE_TAPROOT, spent), xonly), `${chain} input ${i} verifies`);
    } else {
      ok(w.length === 64, `${chain} input ${i} is a 64-byte default sig`);
      ok(verify(w, taprootSighashDefault(final, i, spent), xonly), `${chain} input ${i} verifies`);
    }
  }
  psbtResults[chain] = { signedPsbt: bytesToBase64(serializePsbt(r.psbt)), finalTx: r.final };
}
// same bytes on both unified chains and on both sha256d chains: the chain only picks the sighash
ok(psbtResults.xbt.finalTx === psbtResults.txbt.finalTx && psbtResults.btc.finalTx === psbtResults.tbtc.finalTx, 'chain pairs agree');
ok(psbtResults.xbt.finalTx !== psbtResults.btc.finalTx, 'unified and default differ');
// signing twice gives the same bytes
ok(signPsbt(parsePsbt(psbtBytes), priv, 'txbt').final === psbtResults.txbt.finalTx, 'deterministic psbt signature');

// nostr event
const unsignedEvent = { created_at: 1700000000, kind: 1, tags: [['t', 'fid']], content: 'signed by fid' };
const ev = signEvent(unsignedEvent, priv);
ok(verifyEvent(ev), 'event verifies');
ok(ev.pubkey === info.xonly, 'event pubkey is the key');
ok(signEvent(unsignedEvent, priv).sig === ev.sig, 'deterministic event signature');
threw = false; try { signEvent({ ...unsignedEvent, pubkey: bytesToHex(other) }, priv); } catch { threw = true; } ok(threw, 'foreign pubkey rejected');

const vectors = {
  note: 'Fid reference vectors. Deterministic BIP340 signatures with aux_rand = 32 zero bytes. Every build must reproduce these bytes.',
  key: { priv: privHex, nsec: nsecOf(priv), wif: wifOf(priv), ...info },
  psbt: { unsigned: psbtB64, txid: txid(unsignedTx), spent: spent.map(s => ({ value: Number(s.value), script: bytesToHex(s.script) })), chains: psbtResults },
  nostr: { unsigned: unsignedEvent, signed: ev },
};

const path = new URL('./vectors.json', import.meta.url);
if (write) {
  writeFileSync(path, JSON.stringify(vectors, null, 2) + '\n');
  console.log('wrote vectors.json');
} else {
  const want = JSON.parse(readFileSync(path));
  ok(JSON.stringify(want) === JSON.stringify(vectors), 'vectors.json matches this build');
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

// ---- helpers ---------------------------------------------------------------

function nsecOf(priv) {
  // bech32 of the key, built by hand here so the test does not trust fid.js for it
  return bech32('nsec', convert(priv), 1);
}
function wifOf(priv) {
  const payload = concat(Uint8Array.of(0xef), priv, Uint8Array.of(0x01));
  const check = sha256(sha256(payload)).subarray(0, 4);
  return base58(concat(payload, check));
}
function convert(bytes) {
  let acc = 0, bits = 0; const out = [];
  for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out.push((acc >> bits) & 31); } }
  if (bits) out.push((acc << (5 - bits)) & 31);
  return out;
}
function bech32(hrp, data, spec) {
  const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  const exp = [...[...hrp].map(c => c.charCodeAt(0) >> 5), 0, ...[...hrp].map(c => c.charCodeAt(0) & 31)];
  const vals = exp.concat(data, [0, 0, 0, 0, 0, 0]);
  let chk = 1;
  for (const v of vals) { const b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]; }
  chk ^= spec;
  const cs = []; for (let i = 0; i < 6; i++) cs.push((chk >> (5 * (5 - i))) & 31);
  return hrp + '1' + data.concat(cs).map(d => CH[d]).join('');
}
function base58(bytes) {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt('0x' + bytesToHex(bytes)), s = '';
  while (n > 0n) { s = A[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b === 0) s = '1' + s; else break; }
  return s;
}
function buildPsbt(tx, spent) {
  const map = (entries) => concat(...entries.flatMap(([k, v]) => [compactSize(k.length), k, compactSize(v.length), v]), Uint8Array.of(0));
  const global = map([[Uint8Array.of(0x00), serializeTransaction(tx, false)]]);
  const inputs = spent.map(s => map([[Uint8Array.of(0x01), concat(i64le(s.value), compactSize(s.script.length), s.script)]]));
  const outputs = tx.outputs.map(() => map([]));
  return concat(Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff), global, ...inputs, ...outputs);
}
