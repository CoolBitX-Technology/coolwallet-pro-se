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