---
'openzeppelin-solidity': minor
---

`ERC7535`: Add an implementation of the ERC-7535 Native Asset Tokenized Vault standard, an ERC-4626-style vault whose underlying asset is the chain's native asset (e.g. Ether). Deposits and mints are `payable` and use `msg.value`, the same configurable virtual shares/assets are used to mitigate the inflation attack, and plain native-asset transfers via `receive()` are rejected with the named `ERC7535UnsolicitedDeposit` error.
