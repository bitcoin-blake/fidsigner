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

## Status

Nothing yet. This page is the plan.
