## [348] - Unreleased

- `ScriptInterpreter` add script version 13 command `0xC9` (UTXO section): the script stops there, and `80AA` then runs the rest of the script once per UTXO with the UTXO data as its argument. The section appends what is to be signed to the transaction buffer, which is hashed with the header's hash type (0: signed as is, must be 32 bytes). This lets a script express sighashes that nest the UTXO data in several hashes, such as ZEC v5 (ZIP-244), without coin-specific code in the SE.
  - Every UTXO starts from the state the main part of the script left (caches cleared, transaction buffer cut back), so UTXOs cannot affect each other.
  - A UTXO section cannot change what the user confirms, and `80AA` cannot supply a hash key for it: what is hashed is decided by the signed script alone.
- `ErrorMessage` add `6A96`-`6A9A` for UTXO section errors: nested section, hash key supplied, UTXO data split across APDUs, confirmed content modified, and a result that is not 32 bytes with hash type 0.

## [347] - 2026-10-16

- `ErrorMessage` **BREAKING:** renumber custom status words into module-based ranges (SW1 = module, SW2 high nibble = file/feature). Most custom codes changed; SDK/App error mapping must be updated.
  - `69xx` command auth / device / backup, `6Axx` ScriptInterpreter, `6Bxx` NumberUtil, `6Dxx` key derivation / crypto, `6Exx` parsers, `6Fxx` internal state.
  - Codes reused for different errors were split (`6A00`, `6A76`, `6205`, `6D63`); codes in `60xx` / `61xx` / `62xx` were moved out of ISO-reserved ranges.
  - Some old values now carry a different meaning (e.g. `6A01` was "unknown command", now "script signature invalid"; `6A05` was "bit array length invalid", now "script abort"; also `6A02`-`6A04`, `6A10`-`6A12`, `6B04`; 9 values in total). The SDK must pick the error table by card version (`getVersion` <= 346: old table, >= 347: new table) and cannot decode by status word alone.
- `Check` remove the unused helpers `takeString`, `checkArray`, `checkZero` and the two-argument `checkValue` overloads. Their status words (old `6201`-`6204`) could never be returned.
- `Check.checkRange` throws the status word its caller passes in. Its only caller, the script wrap page command (`0xD2`), now returns `6A16` `SCRIPT_WRAP_PAGE_OUT_OF_RANGE` (old `6205`). `6F20`-`6F24` stay reserved.
- `ErrorMessage` split the `6F1x` runtime state group by file, so the high nibble of SW2 identifies the file: `6F10` FlowCounter (unchanged), `6F30` CardInfo (old `6F11`), `6F40`-`6F42` WorkCenter (old `6F12`, `6F13`, `6EA5`), `6F50` Main (old `6091`). `6F11`-`6F15` stay reserved.
- `ScriptInterpreter` reset segment digests at the start of every script execution, so an aborted segmented transaction cannot corrupt the next transaction's hash.
- `Main` reset the shared SHA-256 digest at the start of every command. A command that left it before `doFinal` (an unsupported UTXO script type in `80A4`, or the developMode wildcard signature) made the next command's hash wrong, e.g. a valid signature returned `6904`.

## [346] - 2026-09-07

- `ScriptInterpreter` `ifSigned` (`0x11`) handle RLP and CONCATENATED argType separately. RLP uses `RlpDataParser.decodeChildByIndex` to take `[tokenInfo, sign]` and verifies the signature against `CBPubKey`. An unknown argType returns `6A77` (renumbered to `6A15` in 347). (CW-28307)
- `ScriptInterpreter` advanced hash (`0x5C`) use `RlpDataParser.decodeChildByIndex` to take `[data, context]`.
- `ScriptInterpreter` bump scriptVersion `11` -> `12`.
- `RlpDataParser` add `decodeChildByIndex`, which indexes into list content whose header was already stripped.
- `DeviceManager` cast device array indices to `short`.
- `crypto` submodule `41baaa0` -> `e655b48`; `Installation.java` uses real symlinks. No behavior change.

## [345] - 2026-03-19

- `ScriptInterpreter` bump scriptVersion `9` -> `11`.
- `ScriptInterpreter` the 5th script header byte (formerly argType) is now reserved and ignored. RLP argument mode is selected per command with data source nibble `0xB`: the argument is parsed as RLP, and `[pathLength][path]` follows in the script. Data sources `0xA`, `0xE`, `0xF` and `0x7` use concatenated mode.
- `ScriptInterpreter` add command `0x5C` advanced hash: the data is an RLP list `[data, context]`, where context is a key or a personalization; the hash type comes from the arg nibbles.
- `ScriptInterpreter` add command `0x5D`: set the advanced hash context (key or personalization) for the streaming hash. It must be followed by `0x5A`.
- `ScriptInterpreter` add hash types `0x15` Blake2b-256 and `0x16` Blake2b-512 with personalization (advanced hash), alongside `0x13`/`0x14` (keyed).
- `ScriptInterpreter` plain hash (`0x5A`) and segment update hashing accept `0x13`-`0x16` again, as unkeyed Blake2b-256/512.
- `ScriptInterpreter` give the hash errors separate status words: update hash `6A10`, advanced update hash `6A11`, hash `6A12` (all were `6A0A`). An unknown advanced hash type still returns `6A0A`.
- `ScriptInterpreter` placeholder command `0xC4` accept data length `0` as well as `4`. An invalid length now returns `6701` (was `6700`).
- `RlpDataParser` add `RlpDataParser`, which moves the RLP path traversal out of `ScriptInterpreter`, plus `decodeByIndex`.
- `RlpDataParser` a short list (`0xC0`-`0xF7`) resolves to its payload without the header byte, as long lists already did.
- `RlpDataParser` a string or list longer than 32767 bytes returns `6EB6`. An invalid final prefix now returns the new `6EB7` (was `6EB6`).
- `ShaUtil` add `Blake2b512WithPersonal`.
- `Blake2b` a personalization longer than 16 bytes returns `6D02` (was `6D01`).
- `Ed25519` build the EC private key with size 256 instead of 255.

## [344] - 2026-01-17

- `ScriptInterpreter` fix RLP argument parsing: the arg byte is now consumed before `getInt`, so inline lengths (`0xC`/`0xD` nibbles) and the RLP path are read from the right position.
- `ScriptInterpreter` separate hash and advanced hash. Keyed Blake2b (`0x13`/`0x14`) now goes only through advanced hash (`0x5B`) and the keyed first update of segment signing (key length > 0). Plain hash `0x5A`, transaction hashing and segment data updates return `6A0A` for `0x13`/`0x14`.
- `ShaUtil` use one shared `Blake2b` instance configured with `setDigestLength`/`setKey`, replacing the separate 256/512 instances. Rename the keyed helpers to `Blake2b256WithKey`/`Blake2b512WithKey` and add `Blake2b256WithPersonal`.
- `Blake2b` add `setDigestLength`, `setKey` and `setPersonal` (personalization up to 16 bytes, `6D01` if longer).
- `KeyStore` `setKey` add the missing `break`s in its switch. No behavior change (no callers).

## [343] - 2025-09-30

- `Main` add `0x88` backup to backup card: verify the command signature, derive the backup card public key from `SEBackupPubKey`/`SEBackupChainCode` at index `sha256(cardId) & 0x7FFFFFFF`, then return the backup data ECIES-encrypted to that key.
- `Main` add `0x8A` recover from main card: decrypt with the SE backup private key and restore the data. It returns `6985` if the card is already paired.
- `UniqueImplement` add `deriveBackupCardKey`.
- `ScriptInterpreter` replace RLP argument handling. The argument is no longer pre-decoded into a separate buffer: data source `0xB` and the `0xA` length nibble meaning "RLP item" are removed. When argType is `0x01` and the data source is the argument, each command carries `[pathLength][path]` and data offset/length resolve to the RLP element at that path.
- `ErrorMessage` add RLP parse errors `6EB0`-`6EB6`.

## [342] - 2024-09-30

The keyed Blake2b work listed under 340 and 341 was developed on another line and first reached this line here, so some of it repeats below.

- `ScriptInterpreter` bump scriptVersion `8` -> `9`.
- `ScriptInterpreter` add command `0x5B` hash with key: data is `hashType(1) + hashLen(2) + hashData + keyLen(2) + key`.
- `ScriptInterpreter` add hash types `0x13` Blake2b-256 and `0x14` Blake2b-512 with key.
- `Main` `txPrepSegmentData` (`0xA8`) and `txPrepUTXOSegmentData` (`0xAA`) take the key length in P2 and the key appended after the sign data. The key is applied when the transaction hash is first updated (P1 = `0`).
- `Blake2b` support keyed hashing (key up to 64 bytes, `6D01` if longer), and fix `doFinal` with key missing the update.
- `Blake2b` store the hash state in a persistent array instead of transient RAM, and compress in workspace.
- `KeyStore` stop deriving the SE backup private key; the derivation key constant was removed from `KeyGenerate`. Deriving `KEY_SE_BACKUP` now returns `6EA1`.
- `KeyStore` move SE enc key derivation into `KeyGenerate` with the same algorithm, and add `setKey`. No behavior change.
- `ErrorMessage` add `6EA1` (invalid keyType for key derivation).

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