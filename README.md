# Fid

**An airgapped signer for the BLAKE2b chain and nostr.** A fid is the pointed tool sailors use to work knots. This one signs: show an xpub and an npub, sign a PSBT, sign a nostr event. QR in, QR out, nothing else.

Live: https://bitcoin-blake.github.io/fidsigner/

## Shape

- **Import only, never generate.** The seed comes in as a SeedQR or words. No entropy code on the device.
- **Stateless.** Nothing is stored. Power off and the key is gone.
- **Three operations.** Keys, PSBT, nostr event. Blocktrail updates are PSBTs signed with the nostr key path.
- **Chains.** btc, tbtc, xbt (BLAKE2b mainnet), txbt (BLAKE2b testnet4). Unified sighash on the BLAKE2b chains.
- **Deterministic signatures with published vectors.** Every build, firmware or browser, must match the vectors bit for bit. That is how a nonce backdoor gets caught.
- **One trusted dependency.** secp256k1. Everything else is small enough to read.

## Two builds, one contract

The browser build is the reference and the development loop. It runs in a tab, or on an old phone in airplane mode. The firmware build targets a commodity board with a camera and a screen, flashed over USB. The test vectors are the contract between them.

Target boards, all off the shelf: Maix Amigo, M5StickV, M5Stack CoreS3.

## Trust model

No secure element, no vendor. Reproducible builds and a thin, readable codebase instead. Run it on txbt4 for months before pointing mainnet funds at it.

## What works today

The browser build. Import a key (hex, nsec or WIF), see the npub and the taproot address on each chain, review and sign a PSBT, review and sign a nostr event. QR out for everything, QR in where the browser has BarcodeDetector. The page checks itself against `vectors.json` on load and says so at the top.

```
npm install
npm test          # 166 Knots unified sighash vectors, then Fid's own
npm run vectors   # regenerate vectors.json from this code
```

Files: `fid.js` is the signer (keys, PSBT, BIP341 and unified sighash, nostr), `unified.js` is the unified sighash from blaketest, `index.html` is the page. Nothing else.

## Not yet

- Mnemonic import and NIP-06 derivation. Today the key is the raw 32 bytes, and the taproot output is the untweaked npub key, same as blaketest.
- Animated QR for PSBTs too big for one code.
- Multisig and script-path inputs. Only key-path spends to this key are signed.
- BIP341 sighash checked against the BIP's own vectors. The unified sighash is checked against the Knots vectors; the plain taproot one is only round-tripped.
- The firmware.
