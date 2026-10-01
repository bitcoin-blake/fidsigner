// Fid core: keys, PSBT signing, nostr event signing.
// Browser reference build. Shared between index.html (import map -> esm.sh)
// and test.mjs (node_modules). secp256k1 is the one trusted dependency.
//
// Key model (same as blaketest and the npub): the x-only public key is used
// directly as the v1 witness program, no BIP341 tweak. So the taproot address
// and the nostr npub are the same key, and key-path spends sign with the
// plain private key.
//
// Signatures are deterministic: BIP340 with aux_rand fixed to 32 zero bytes.
// The same key and message always give the same signature, so a build can be
// checked against vectors.json bit for bit.

import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import {
  unifiedSighash, parseTransaction, compactSize, u32le, i64le, concat, taggedHash,
  SIGHASH_ALL, SIGHASH_UNIFIED, SCRIPT_TYPE_TAPROOT,
} from './unified.js';

export { parseTransaction, concat };

// ---- chains ----------------------------------------------------------------

export const CHAINS = {
  btc:  { name: 'Bitcoin',          hrp: 'bc', unified: false, wif: 0x80 },
  tbtc: { name: 'Bitcoin testnet4', hrp: 'tb', unified: false, wif: 0xef },
  xbt:  { name: 'BLAKE2b',          hrp: 'bc', unified: true,  wif: 0x80 },
  txbt: { name: 'BLAKE2b testnet4', hrp: 'tb', unified: true,  wif: 0xef },
};

// ---- bytes -----------------------------------------------------------------

export function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 || /[^0-9a-fA-F]/.test(hex)) throw new Error('bad hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function base64ToBytes(s) {
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ---- bech32 ----------------------------------------------------------------

const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

export function convertBits(data, from, to, pad = true) {
  let acc = 0, bits = 0;
  const out = [], maxv = (1 << to) - 1;
  for (const v of data) {
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits > 0) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error('bad padding');
  return out;
}

export function bech32Encode(hrp, data, spec) {
  const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const pm = polymod(values) ^ spec;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((pm >> (5 * (5 - i))) & 31);
  return hrp + '1' + data.concat(checksum).map(d => CHARSET[d]).join('');
}

export function bech32Decode(str) {
  const s = str.toLowerCase();
  const pos = s.lastIndexOf('1');
  if (pos < 1) return null;
  const hrp = s.slice(0, pos);
  const data = [];
  for (const c of s.slice(pos + 1)) {
    const i = CHARSET.indexOf(c);
    if (i === -1) return null;
    data.push(i);
  }
  const spec = polymod(hrpExpand(hrp).concat(data));
  return { hrp, data: data.slice(0, -6), spec };
}

// ---- base58 (WIF import only) ---------------------------------------------

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(str) {
  let num = 0n;
  for (const c of str) {
    const i = B58.indexOf(c);
    if (i === -1) throw new Error('bad base58');
    num = num * 58n + BigInt(i);
  }
  let hex = num.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const body = hex === '0' ? new Uint8Array() : hexToBytes(hex);
  let zeros = 0;
  for (const c of str) { if (c === '1') zeros++; else break; }
  return concat(new Uint8Array(zeros), body);
}

function wifToPrivateKey(wif) {
  const bytes = base58Decode(wif);
  const payload = bytes.subarray(0, -4);
  const check = sha256(sha256(payload)).subarray(0, 4);
  if (!bytesEqual(check, bytes.subarray(-4))) throw new Error('bad WIF checksum');
  if (payload[0] !== 0x80 && payload[0] !== 0xef) throw new Error('bad WIF prefix');
  if (payload.length === 34 && payload[33] === 0x01) return payload.slice(1, 33);
  if (payload.length === 33) return payload.slice(1);
  throw new Error('bad WIF length');
}

// ---- keys ------------------------------------------------------------------

// Import only. Accepts 64 hex chars, an nsec, or a WIF. Never generates.
export function parsePrivateKey(input) {
  const s = input.trim();
  let key;
  if (/^[0-9a-fA-F]{64}$/.test(s)) key = hexToBytes(s.toLowerCase());
  else if (/^nsec1[a-z0-9]+$/i.test(s)) {
    const d = bech32Decode(s);
    if (!d || d.hrp !== 'nsec' || d.spec !== BECH32_CONST) throw new Error('bad nsec');
    key = new Uint8Array(convertBits(d.data, 5, 8, false));
    if (key.length !== 32) throw new Error('bad nsec length');
  } else key = wifToPrivateKey(s);
  if (!secp256k1.utils.isValidPrivateKey(key)) throw new Error('key out of range');
  return key;
}

export function xOnlyPubKey(priv) {
  return schnorr.getPublicKey(priv);
}

export function npub(xonly) {
  return bech32Encode('npub', convertBits(Array.from(xonly), 8, 5), BECH32_CONST);
}

export function taprootAddress(xonly, chain) {
  return bech32Encode(CHAINS[chain].hrp, [1].concat(convertBits(Array.from(xonly), 8, 5)), BECH32M_CONST);
}

export function p2trScript(xonly) {
  return concat(Uint8Array.of(0x51, 0x20), xonly);
}

export function keyInfo(priv) {
  const xonly = xOnlyPubKey(priv);
  const addresses = {};
  for (const c of Object.keys(CHAINS)) addresses[c] = taprootAddress(xonly, c);
  return { xonly: bytesToHex(xonly), npub: npub(xonly), addresses };
}

// ---- deterministic schnorr ---------------------------------------------------

const AUX_ZERO = new Uint8Array(32);

export function sign(msg32, priv) {
  return schnorr.sign(msg32, priv, AUX_ZERO);
}

export function verify(sig, msg32, xonly) {
  return schnorr.verify(sig, msg32, xonly);
}

// ---- BIP341 key-path sighash, SIGHASH_DEFAULT (btc, tbtc) --------------------

function serializeOutput(o) { return concat(i64le(o.value), compactSize(o.script.length), o.script); }

export function taprootSighashDefault(tx, inIdx, spentOutputs) {
  const hashPrevouts = sha256(concat(...tx.inputs.map(i => concat(i.txid, u32le(i.vout)))));
  const hashAmounts = sha256(concat(...spentOutputs.map(s => i64le(s.value))));
  const hashScripts = sha256(concat(...spentOutputs.map(s => concat(compactSize(s.script.length), s.script))));
  const hashSequences = sha256(concat(...tx.inputs.map(i => u32le(i.sequence))));
  const hashOutputs = sha256(concat(...tx.outputs.map(serializeOutput)));
  const msg = concat(
    Uint8Array.of(0x00, 0x00), u32le(tx.version), u32le(tx.locktime),
    hashPrevouts, hashAmounts, hashScripts, hashSequences, hashOutputs,
    Uint8Array.of(0x00), u32le(inIdx),
  );
  return taggedHash('TapSighash', msg);
}

// ---- transaction serialization ---------------------------------------------

export function serializeTransaction(tx, withWitness = true) {
  const parts = [u32le(tx.version)];
  const segwit = withWitness && tx.inputs.some(i => i.witness && i.witness.length);
  if (segwit) parts.push(Uint8Array.of(0x00, 0x01));
  parts.push(compactSize(tx.inputs.length));
  for (const i of tx.inputs) parts.push(i.txid, u32le(i.vout), compactSize(i.scriptSig.length), i.scriptSig, u32le(i.sequence));
  parts.push(compactSize(tx.outputs.length));
  for (const o of tx.outputs) parts.push(serializeOutput(o));
  if (segwit) for (const i of tx.inputs) {
    parts.push(compactSize(i.witness.length));
    for (const w of i.witness) parts.push(compactSize(w.length), w);
  }
  parts.push(u32le(tx.locktime));
  return concat(...parts);
}

export function txid(tx) {
  return bytesToHex(sha256(sha256(serializeTransaction(tx, false))).reverse());
}

// ---- PSBT (BIP174 v0, BIP371 taproot fields) -------------------------------

const PSBT_MAGIC = Uint8Array.of(0x70, 0x73, 0x62, 0x74, 0xff);
const G_UNSIGNED_TX = 0x00;
const IN_WITNESS_UTXO = 0x01;
const IN_SIGHASH_TYPE = 0x03;
const IN_FINAL_WITNESS = 0x08;
const IN_TAP_KEY_SIG = 0x13;

function readMap(bytes, o) {
  const entries = [];
  for (;;) {
    const [klen, o1] = readCS(bytes, o);
    o = o1;
    if (klen === 0) break;
    const key = bytes.subarray(o, o + klen); o += klen;
    const [vlen, o2] = readCS(bytes, o);
    o = o2;
    const value = bytes.subarray(o, o + vlen); o += vlen;
    if (o > bytes.length) throw new Error('truncated psbt');
    entries.push({ key, value });
  }
  return [entries, o];
}

function readCS(bytes, o) {
  const first = bytes[o++];
  if (first === undefined) throw new Error('truncated psbt');
  if (first < 0xfd) return [first, o];
  const size = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
  let v = 0n;
  for (let i = 0; i < size; i++) v |= BigInt(bytes[o + i]) << BigInt(8 * i);
  return [Number(v), o + size];
}

function writeMap(entries) {
  const parts = [];
  for (const { key, value } of entries) parts.push(compactSize(key.length), key, compactSize(value.length), value);
  parts.push(Uint8Array.of(0));
  return concat(...parts);
}

function keyType(entry) { return readCS(entry.key, 0)[0]; }
function find(entries, type) { return entries.find(e => keyType(e) === type); }

export function parsePsbt(bytes) {
  if (!bytesEqual(bytes.subarray(0, 5), PSBT_MAGIC)) throw new Error('not a psbt');
  let o = 5;
  const [global, o1] = readMap(bytes, o); o = o1;
  const txEntry = find(global, G_UNSIGNED_TX);
  if (!txEntry) throw new Error('psbt v2 or missing unsigned tx');
  const tx = parseTransaction(txEntry.value);
  const inputs = [], outputs = [];
  for (let i = 0; i < tx.inputs.length; i++) { const [m, o2] = readMap(bytes, o); inputs.push(m); o = o2; }
  for (let i = 0; i < tx.outputs.length; i++) { const [m, o2] = readMap(bytes, o); outputs.push(m); o = o2; }
  if (o !== bytes.length) throw new Error('trailing bytes after psbt');
  return { global, tx, inputs, outputs };
}

export function serializePsbt(psbt) {
  return concat(PSBT_MAGIC, writeMap(psbt.global), ...psbt.inputs.map(writeMap), ...psbt.outputs.map(writeMap));
}

function witnessUtxo(entries) {
  const e = find(entries, IN_WITNESS_UTXO);
  if (!e) return null;
  const v = e.value;
  let amount = 0n;
  for (let i = 7; i >= 0; i--) amount = (amount << 8n) | BigInt(v[i]);
  const [slen, so] = readCS(v, 8);
  return { value: BigInt.asIntN(64, amount), script: v.subarray(so, so + slen) };
}

// Describe a PSBT for the confirmation screen. Which inputs are ours, where
// the coins go, and the fee if every input carries a witness utxo.
export function describePsbt(psbt, xonly, chain) {
  const ours = p2trScript(xonly);
  const inputs = psbt.tx.inputs.map((inp, i) => {
    const utxo = witnessUtxo(psbt.inputs[i]);
    return {
      index: i,
      outpoint: bytesToHex(Uint8Array.from(inp.txid).reverse()) + ':' + inp.vout,
      value: utxo ? utxo.value : null,
      mine: !!utxo && bytesEqual(utxo.script, ours),
      signed: !!find(psbt.inputs[i], IN_TAP_KEY_SIG) || !!find(psbt.inputs[i], IN_FINAL_WITNESS),
    };
  });
  const outputs = psbt.tx.outputs.map((o, i) => ({
    index: i,
    value: o.value,
    address: scriptToAddress(o.script, chain),
    mine: bytesEqual(o.script, ours),
  }));
  const allValued = inputs.every(i => i.value !== null);
  const inSum = allValued ? inputs.reduce((a, i) => a + i.value, 0n) : null;
  const outSum = outputs.reduce((a, o) => a + o.value, 0n);
  return { inputs, outputs, fee: allValued ? inSum - outSum : null, txid: txid(psbt.tx) };
}

export function scriptToAddress(script, chain) {
  const hrp = CHAINS[chain].hrp;
  if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) return bech32Encode(hrp, [1].concat(convertBits(Array.from(script.subarray(2)), 8, 5)), BECH32M_CONST);
  if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) return bech32Encode(hrp, [0].concat(convertBits(Array.from(script.subarray(2)), 8, 5)), BECH32_CONST);
  if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) return bech32Encode(hrp, [0].concat(convertBits(Array.from(script.subarray(2)), 8, 5)), BECH32_CONST);
  if (script[0] === 0x6a) return 'OP_RETURN ' + bytesToHex(script.subarray(1));
  return 'script ' + bytesToHex(script);
}

// Sign every input whose witness utxo pays to our untweaked key. On the
// BLAKE2b chains the signature opts in to the unified sighash (0x21); on the
// SHA256d chains it is a plain BIP341 SIGHASH_DEFAULT key-path signature.
// Returns { psbt, signed: [indices], final: hex or null }.
export function signPsbt(psbt, priv, chain) {
  const xonly = xOnlyPubKey(priv);
  const ours = p2trScript(xonly);
  const unified = CHAINS[chain].unified;
  const spent = psbt.inputs.map(witnessUtxo);
  const signed = [];
  const out = { global: psbt.global, tx: psbt.tx, inputs: psbt.inputs.map(m => m.slice()), outputs: psbt.outputs };

  for (let i = 0; i < psbt.tx.inputs.length; i++) {
    const utxo = spent[i];
    if (!utxo || !bytesEqual(utxo.script, ours)) continue;
    if (find(out.inputs[i], IN_FINAL_WITNESS)) continue;
    const sighashEntry = find(psbt.inputs[i], IN_SIGHASH_TYPE);
    if (sighashEntry) {
      const want = sighashEntry.value[0] | (sighashEntry.value[1] << 8) | (sighashEntry.value[2] << 16) | (sighashEntry.value[3] << 24);
      const have = unified ? (SIGHASH_ALL | SIGHASH_UNIFIED) : 0;
      if (want !== have && !(want === SIGHASH_ALL && !unified)) throw new Error(`input ${i} asks for sighash 0x${want.toString(16)}, this chain signs 0x${have.toString(16)}`);
    }
    if (spent.some(s => !s)) throw new Error('every input needs a witness utxo to sign');
    let sig;
    if (unified) {
      const ht = SIGHASH_ALL | SIGHASH_UNIFIED;
      const msg = unifiedSighash(psbt.tx, i, ht, SCRIPT_TYPE_TAPROOT, spent);
      sig = concat(sign(msg, priv), Uint8Array.of(ht));
    } else {
      const msg = taprootSighashDefault(psbt.tx, i, spent);
      sig = sign(msg, priv);
    }
    out.inputs[i] = out.inputs[i].filter(e => keyType(e) !== IN_TAP_KEY_SIG);
    out.inputs[i].push({ key: Uint8Array.of(IN_TAP_KEY_SIG), value: sig });
    signed.push(i);
  }

  // Finalize when every input is now ours and signed: the witness is just the
  // signature, and the final transaction can be extracted.
  let final = null;
  const allOurs = out.inputs.every(m => find(m, IN_FINAL_WITNESS) || find(m, IN_TAP_KEY_SIG));
  if (signed.length && allOurs) {
    const tx = { ...psbt.tx, inputs: psbt.tx.inputs.map((inp, i) => {
      const fin = find(out.inputs[i], IN_FINAL_WITNESS);
      if (fin) return { ...inp, witness: parseWitness(fin.value) };
      const sig = find(out.inputs[i], IN_TAP_KEY_SIG).value;
      return { ...inp, witness: [sig] };
    }) };
    for (let i = 0; i < out.inputs.length; i++) {
      if (find(out.inputs[i], IN_FINAL_WITNESS)) continue;
      const utxo = find(out.inputs[i], IN_WITNESS_UTXO);
      out.inputs[i] = [utxo, { key: Uint8Array.of(IN_FINAL_WITNESS), value: serializeWitness(tx.inputs[i].witness) }];
    }
    final = bytesToHex(serializeTransaction(tx));
  }
  return { psbt: out, signed, final };
}

function serializeWitness(items) {
  return concat(compactSize(items.length), ...items.map(w => concat(compactSize(w.length), w)));
}

function parseWitness(bytes) {
  let [n, o] = readCS(bytes, 0);
  const items = [];
  for (let i = 0; i < n; i++) { const [len, o2] = readCS(bytes, o); items.push(bytes.subarray(o2, o2 + len)); o = o2 + len; }
  return items;
}

// ---- nostr events (NIP-01) -------------------------------------------------

export function eventId(ev) {
  const s = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
  return sha256(new TextEncoder().encode(s));
}

// Takes an unsigned event (pubkey optional, filled from the key). Returns the
// signed event. Refuses an event whose pubkey is someone else's.
export function signEvent(ev, priv) {
  const xonly = bytesToHex(xOnlyPubKey(priv));
  if (ev.pubkey && ev.pubkey !== xonly) throw new Error('event pubkey is not this key');
  if (!Number.isInteger(ev.kind) || !Number.isInteger(ev.created_at)) throw new Error('kind and created_at must be integers');
  if (!Array.isArray(ev.tags) || typeof ev.content !== 'string') throw new Error('tags must be an array and content a string');
  const unsigned = { pubkey: xonly, created_at: ev.created_at, kind: ev.kind, tags: ev.tags, content: ev.content };
  const id = eventId(unsigned);
  const sig = sign(id, priv);
  return { id: bytesToHex(id), ...unsigned, sig: bytesToHex(sig) };
}

export function verifyEvent(ev) {
  const id = bytesToHex(eventId(ev));
  return id === ev.id && verify(hexToBytes(ev.sig), hexToBytes(id), hexToBytes(ev.pubkey));
}
