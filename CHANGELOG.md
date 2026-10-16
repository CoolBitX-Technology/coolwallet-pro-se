## [347] - 2026-10-16

- `ErrorMessage` **BREAKING:** renumber custom status words into module-based ranges (SW1 = module, SW2 high nibble = file/feature). Most custom codes changed; SDK/App error mapping must be updated.
  - `69xx` command auth / device / backup, `6Axx` ScriptInterpreter, `6Bxx` NumberUtil, `6Dxx` key derivation / crypto, `6Exx` parsers, `6Fxx` internal state.
  - Codes reused for different errors were split (`6A00`, `6A76`, `6205`, `6D63`); codes in `60xx` / `61xx` / `62xx` were moved out of ISO-reserved ranges.
  - Some old values now carry a different meaning (e.g. `6A01` was "unknown command", now "script signature invalid"; `6A05` was "bit array length invalid", now "script abort"; also `6A03`, `6A04`, `6A10`-`6A12`, `6B04`). The SDK must pick the error table by card version (`getVersion` <= 346: old table, >= 347: new table) and cannot decode by status word alone.
- `ScriptInterpreter` reset segment digests at the start of every script execution, so an aborted segmented transaction cannot corrupt the next transaction's hash.

## [341] - 2024-08-30

- `Blake2b` fix blake2b with key bug.

## [340] - 2024-08-23

- `Main` update utxo transaction to support blake2b with key hash.
- `ScriptInterpreter` add blake2b with key hash.
- `ShaUtil` add blake2b with key hash.

## [339] - 2024-08-09

- `Main` remove workspace to increase ram space.
- `CardInfo` constructor updated to differentiate between Go Card and Pro Card.
- `Device` constructor updated to differentiate between Go Card and Pro Card.
- `KeyStore` add trans key derivation
- `ErrorMessage` - add ErrorMessage to collect error codes.
- `UniqueImplement` - added UniqueImplement to differentiate method between Go Card and Pro Card.

## [337] - 2024-06-03

- `ScriptInterpreter` add bit to byte array method.

## [336] - 2024-02-20

- `Main` add 80E0 Shamir separate and 80E2 Shamir derive.
- `ScriptInterpreter` fix setBufferInt and getDerivedPublicKey bug.
- `Shamir` support Shamir separate and derive.

## [334] - 2023-12-15

- `Bip86` add tweak key.
- `ScriptInterpreter` add tagged hash.
- `ShaUtil` add bech32m checksum.
- `Schnorr` support Schnorr signature.

## [333] - 2023-08-11

- `ScriptInterpreter` add place holder parameter for utxo.
- `Main` add 80AA for new utxo sign flow.

## [332] - 2023-08-10

- `Blake3` support Blake3.

## [331] - 2023-08-01

- `ScriptInterpreter` fix btc replace-by-fee bug.

## [330] - 2023-06-28

- `ScriptInterpreter` support btc replace-by-fee.

## [329] - 2023-04-27

- `Secp256k1` support deterministic ECDSA.

## [325] - 2022-05-11

- `NumberUtil` support message pack encode.
- `ScriptInterpreter` add message pack command and update arrayEnd to support array and map for message pack.

## [324] - 2022-04-28

- `ScriptInterpreter` support protocol buffer data placeholder.
- `ScriptInterpreter` support showing amount with larger decimal.

## [323] - 2022-03-30

- `ScriptInterpreter` support signing solana spl token.
- `BackupController` support backup without cardano seed.

## [322] - 2022-03-23

- `ScriptInterpreter` support prototype int with 0.
- `Main` support 80A2 consecutive signing.

## [321] - 2022-03-02

### Added

- `ScriptInterpreter` support signing transaction without hash.
- `CardInfo` now contains some information about cardano seed.
- `Main` 8052 with `P1=0x12, P2=0x34` will get device mode(develop/factory or production).

## [320] - 2022-01-13

### Added

- `ScriptInterpreter` support signing data segmentally.
- `Main` new command 80A8 can signing data segmentally.