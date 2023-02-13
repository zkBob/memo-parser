# memo-parser

A small tool to parse zkBob Pool transaction's calldata. The following transactions are ccurrently supported:

| Contract method                                                    | Selector | Description                                                                                                |
|--------------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------|
| transact()                                                         | af989083 | A regular transaction within the pool (deposit/transfer/withdrawal)                                        |
| directDeposit(address,uint256,bytes)                               | 02592d37 | Sending direct deposit to the pool (it's just a request from the external actor to include it in the pool) |
| appendDirectDeposit (uint256,uint256[],uint256,uint256[],uint256[]) | 1dc4cb33 | Include early created direct deposits in the pool (transaction made by relayer node)                       |
| refundDirectDeposit(uint256)                                       | d7f59caa | Refund direct deposit for a single index (in case of it wasn't included during the DD timeout)             |
| refundDirectDeposit(uint256[])                                     | 68dc1c55 | Refund several direct deposits by indices                                                                  |


## Using

```
git clone https://github.com/zkBob/memo-parser
cd memo-parser/
cargo run <calldata_or_tx_hash>
```

To change network you should select appropriate file (`.env.sepolia`, `.env.goerli` or `.env.polygon`) and copy in into `.env` file with owerwrite. E.g. to swith tool to Sepolia testnet:

```bash
cp .env.sepolia .env
```

or to switch to the mainnet Polygon network:

```bash
cp .env.polygon .env
```

You also can directly modify `RPC_URL` variable in the `.env` file to change RPC node manually


## Example

All input is just a hex strings without any spaces (prefix 0x is optional)

You can provide a transaction hash ...

```bash
cargo run 0x29ce7981c15bde7d0ae922f495a9fd1e00f3a329dc123f225ddff0c05e275845
```
 ... or the calldata directly
```bash
cargo run 0xaf98908313d8c81b7a356cf396dba6258a24e8c682a4c2cbaf80b63b14fe710ca653035f1278cac65e4dac2c934b0ed65335558672d93cbc04931d06ed669407102e9102000000052c800000000000000000000000000000fffffffffa0a1f00079d632a547d1fad1f2097ee68fe9bfd1d4792af52e6b5eb71a2c57ea3fdfe31144b8299ba9b089cfae556e2a3278b3562faa026dadaccd044f1ea9a3e683d732731e28831db7e486bf7f3226bf9a6115379872d19e7d2da10ba87d58b07078623594c220a439e8c5528c9196d6c83f2c979a5aa6670d2262215506a27b451122f89f492a3e1a1d5cf9bdb7856a917a1f2ad515086234ec2653a94595627c00720b68089e7c2baf8a6ff155dfecfac9f659b855c682daeadf86db3fc574831aa0400d0a1d6d4b25e7c4a5dd2095ffc14a67f0b78b2b3ec8d1c5173b3280c6a35286faac4c84d04695d97681944f8b8f8a7fab95bb001c8225235d20dda3abe7d15524aea9e1ec76e073d011ff561ad1dcf89680afadc8d6fbfd126ffdd4944f21b8d46e0cec65a8ce787dafaf1d818ef2baad96274b693e6829493000872a36a0bffde1539e339c24c8c54533f57e390809eafca103762a93c93dac718bff3281401bdd0b0eb92992b9b54cbdb7e1be2df8c9bc869325bac8c0147f516b981540ff38eaabe8de7d9a6ff1dc9dcd6926054fff502e453e023a8c522097aa938de0b5cbfb65f0f7edf3d50ecf38d9de51fe944ee7e8d2a732151d093660a7e4d97153c1bce718b9c093ae3cf0db08efdc6fc372abcf9ba0e110939dc6b31fd7bcd20986fd8cd6088b6ea66479a10c74580bbb4e1832746bc5e6f7dbb582d0b8758089f85004040f680f3d85931220379eef15dfa1470e653f98401ae5d0cb6c9690001017e0000000005f5e10002000000456d3309d1c39ffef8e0778cf4e2dbb07a9c743d015fccc982ac0a3c02ba74195d6e5e5e9e4ff55905e43dabc2e879d70f702087a21c37b822e77453b8256203da7364c1f438f94a6dfc70431b9b7b5074380ece886bb893529f392e56802c0d596858b43c245a6b32b817e90317cd7b223b18311a214a2343951bd023f7db4d0dea83fb9cc2c0a2b01d7907a413344361e469cdb8b9888319f7b289ff071282623247a9eb749c8f29d1f37393481398c1a8c1f1464ce2c618733a2cb7b7f207e39b49ea49b06c1a468ce10ed0d7e34098681efed31c934fd952be90b30d770b9058cd6820b56c9016f385bcb1c67dc82f1d912f42f850ea3b40ca4c7782f226ae543c4db2ebf81ebbe38a75a0565aa78c233f7ad633da45fb1c5c3f85a82509962ae984bf1e0e775006d01c5ef37c40bcde9ffffac3543f4d0bc9eb7cb352ff8fab554f249ed9e9542662f7c12a7e3abd4a03fbab115a4bb2b3a2c04d05107c91d4bb1aeeb1ad5c8a835ec775fabf7ea419
```

## Output

```bash
$ cargo run 0x0e629c6489eb549711db9f676335ebe77e1c1ac1094ec0e25f2e44c4cee08a44
    Finished dev [unoptimized + debuginfo] target(s) in 0.65s
     Running `target/debug/memo-parser 0x0e629c6489eb549711db9f676335ebe77e1c1ac1094ec0e25f2e44c4cee08a44`

Working on Sepolia network...
Fetched calldata: 918 bytes
Tx selector     : transact (0xaf989083)
Nullifier       : 0x12084075017e986c799dca67d2e4af6c0fc4b6b592ff00ad1e8cfdb5d19b5c22
Commitnment     : 0x1b39aa83020180880cc07b78a3bd253806f793312e5b6083d17c2229244969c1
Index           : 341248 (0x53500)
Energy delta    : 0 Gwei (0x0)
Token delta     : 100,000,000,000 Gwei (0x174876e800)
Tx proof        : 09a6ecd02095a3ef3c5eb4b9c1ec081d0cc79fe81595a875911edd8b6c4e4559
                  0f5c19c98b5efd0ecf82792b4d8fc4aa06053bd7ebf29e492f6265fbd85d9237
                  0fe8b5e24cbb5117393c855ae0f9ec80f8ae2d2b38ccbaceefc093eeac515721
                  0e8664c06943f324372cd729ae7c91766d0dc17487bd800af3e7a2afd92fd753
                  01f896ec2d2811f834d364ea81a6c9621d4249c966b3a731917b69569310f0f7
                  2a57dca9ded47913528e2fd753333d75e2a595fa9d593fe497142aad3424b033
                  271bf89506ae46695915729f4845b0fd99c712ad26a4220901e15498a359764a
                  18459c3d15a7c0351598590f83a25f3b28eba30960233b0338bad59f9433c6cc

Tree proof      : 084158e5bad5c3bc52b9c94e9f4e38bafd66b9f1deafafdd5c286e8632117f77
                  14e2ea590bc0ba2732540ecfb1f191c1ed82ecc4f73b691193e33fd6fd4b401c
                  0e12f33208f067682aef83211970cd3397b80ef68a4b9a829e324ee086fd6274
                  2c5f57fc6b9382456b04462d00c133ae310a48425fc7ec7ef2daf7f93147be24
                  14cc231e8371b5757e94da283ded3143bf1e78ed8be23f6c120cb94c0462b2df
                  24d1b43ff2d64efc84368488e91982f93cf42e8bb9684ae8f3214eecca57fcc4
                  07a05e98387d3cf54465cdb5497d9e72f21b72ac4df05ec96e20ead8e9cc00b0
                  1107f3f516c771b1fe9d709bad99056290f557493ff6eb3237d3a1be066e7ba0

New Merkle Root : 02c76a6392d0ba1efbcfbba9239d419b0500ce61a8f1855774e09e8567bb62f2
Tx type         : Deposit (0)
Memo size       : 210 bytes
----------------------------------- MEMO BLOCK -----------------------------------
Tx fee          : 100,000,000 (0x5f5e100)
Items number    : 1
Account hash    : fd937d0dc6a8e846d8a8c596f5a7ff700d0103129233a93acda24ef90afd8e15
A_p             : 9e7be74c58c8ebb34e06c9dcf2facf4f5990031a1ab5cec20dd589963370a61e
Encrypted keys  : 54ff6697be9b2f4e3f6d182d38a6d90c0f3b6a5f5473c7c7fcad4d532d8c7db9
                  872fdca5768d7dea4a3450f888a7f0a1
Encrypted acc   : 424120c26e90d64bb12e1caa5d459fc661b6d32cae2cbcb9c6f5532ac912ad96
                  68ef31b8ae3261f3372293789a55761017fea4786d3e4d7cc8103e58a150632e
                  a29b7a1aeb9f0ea45cb2f04a288bc7c7e11bcbcc0066
----------------------------------------------------------------------------------
ECDSA signature: e5c8b067b9fe152d818cd9143ac104b1624ae6bb23c577ca70c5d702bc6f2fdc
                 f00e43ef6641cb58512608b4c7cef16512ac829f3bbe2292dd9001d5320f6f9c
Deposit spender: 0xde261c040afad48890ec7eaec36e7721699b043c (recovered from ECDSA)

```
