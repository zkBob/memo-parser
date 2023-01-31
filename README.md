# memo-parser

A small tool to parse zkBob Pool transaction's calldata. The calldata should be started with 'af989083' which is a `transact` method selector

## Using

```
git clone https://github.com/zkBob/memo-parser
cd memo-parser/
cargo run <calldata_or_tx_hash>
```

To change network you should select appropriate file (`.env.sepolia` or `.env.polygon`) and copy in into `.env` file with owerwrite. E.g. to swith tool for Sepolia testnet type:

```bash
cp .env.sepolia .env
```

or to switch to the mainnet Polygon network:

```bash
cp .env.sepolia .env
```

You also can directly modify RPC_URL in the `.env` file to change RPC node manually


## Example

All input is just a hex strings without any spaces (prefix 0x is optional)

You can provide a transaction hash ...

```bash
cargo run 0xee3f83154d2837e348be3789c550eaffc6dfbc272720c579db523233097473f2
```
 ... or the calldata directly
```bash
cargo run 0xaf9890832711712d54721af2e6acb4ebe63681baa29da74a6bf1b79419e949ed88cc5105229a17b5c68611cbfb9a85e0b7bb2d24673df1e3f6c35b199e324d12502d076f000000007400000000000000000000000000000000000000000000002e659ce1958431d5c01e857727180cdd052a7c267231aba68af1d3470493e62c15b71d52972a03d77ebc3d93c0a476d1ccb7d6202cc923963ca10d92f6cf46911def6467f39edba34ba768ded8d65ff0b225e4993f75ee7d147572f6f809b1c300ddc550e31053eac49534035c4f7749bce4a125045f79380ba8c8ab7f40df9b2e1038f7d1114b9834ecc20be88ce0fea65637b8faa805c104eb8e98ba152c381d5fd83ad744e4ebcd88323ed829902797d79dbe808934364015fa9d7fa5b9551d042927e37e9cfc850a6cb6d9b16eaed8cdffecd662eff10731242a5a9dfafe16d8900ed5d1d1fd5e1eb22bc3bb60666ee0302667f5836b1282868527ef3efd22b822acd5c7cc53cfcdd57b57f65656d36b36f568723c881dd981e30558d6fe2da4a4c7ca8047fbc1177233e6a3c17c164aaf12a1fc51cf94634d57ca8c57632ba7f1d3ce29368abc7b8167a5bbde47c4c5837fe8725b15bb9e24bc7a14030b30152c50b7b32ed03711ac6599d3ead91c291a52ecb3088dd5767ba61e54f7ad2957900ddb6b3c0dcdef84ffb18a78c38d5f8176a797adc2b2834223eb3f275b12b86adfadf3e4c0a2f2c97ad6044e67e89262375184ece0a83dcf5e578a82220e544caccc1210473085e7ac1b20b66a45e31205d172dc031892fad8500f6b181e0f8b26405849dfccf599b65923d2aadeff51649d7d15fe9c02a6396fa000b518f1c076f7e42940a3f4a0ee4687aebfe9af4cf78367d0232bce9c728cd448040001017e000000000000000002000000dbd4e206613eeb2af78861d23aca9dbd520cf85af0edbb6743c48a71587f390454ae9059d8c6b53c94ca75d82238309d519bf553736000e5b47673c01d9fc72c10e949a1f8c1869612221b3574f0001a11cca764e632684593b4a943f6916f1b9ff08faec58970738caeee8cd840c544cf4ca350bc0cf505f25f4d8be63787ae30b485da1dfaf6e6df2012a6b8c866b6951f1b97e321be70ba8e301327767c878ab8cd799b56a9f109b4d4d9c2b5b0c5e5c288a41f5af6c55ab33756e6210fdd9385c0b27a3cd85d73c7f1d3ccef8ef77229e5a09595dbab6ecdb4c7298f608c80ebceb5d3da781917d2e549fffa7d1b2cf21db14d1338ddebe44201c698f8e2652c386bc2306eb9d923df8bf2e29bfc7a7f014078acdcf2884e76280ab777aa8987f6e9352e662cd7db9849fc8453c34df2d1b4974c0bf3c3bd8b85097e702c6c4edd00111963cbe18ba6f89a255f591371374d1cc920268bd8021fa65e567d21d246acb3b3837be8f59bd6de6d4e67d3eb
```

## Output

```bash
$ $ cargo run 0xe18505b332c5942176e9288c1b0043afd64c58cbf8e64edf31365e5dc35327a8
    Finished dev [unoptimized + debuginfo] target(s) in 0.48s
     Running `target/debug/memo-parser 0xe18505b332c5942176e9288c1b0043afd64c58cbf8e64edf31365e5dc35327a8`

Fetched calldata: 918 bytes
Selector       : 0xaf989083
Nullifier      : 0x0b1e48e793b78b8a0e42dc588e678114a5a35b20ad0f54804c911b65f728a2b3
Commitnment    : 0x125cea68695d94789930911523b70217d6da29d5f8c138b0e0a3e1659de13640
Index          : 31104 (0x7980)
Energy delta   : 0 Gwei (0x0)
Token delta    : 2,000,000,000 Gwei (0x77359400)
Tx proof       : 2d050b6d7184f2aebea328972a8a29289c39f2f5048546e2d1592aa0e56ed168
                 2eef33b76dea51ed51d2fafa42600e82894f03edf41d15964ac40758ebd7b25a
                 20605cad3f227027f0348bd41efe63ad6c3e2da0b7d295c8bbcd2ca3b7bd94fd
                 1b85ffbbb725a405852b9d19331d085e7c81c0f2d33141fa780f35d6fc1a7fe4
                 259bdada3b6623b1eca123af93e5bf98569b41a3d0c5f1485ee811332b40d01b
                 287b99ba6c31f98cd6b5a75443b2a76c7f05f84a702f437dfd7bbe6afd4c74fe
                 1a7b3083af489e69ca0407a911eec0993d312b800809ff3cd0183bcdd97fa554
                 2e11ef304c0677bd14bfd10b0151da63d0b61a1ddcec31913163969d8460f18b

Tree proof     : 0eead7cef2dd6ee9af74dbf2b84b451261526bfdd7267aeaf72940b5fc94d692
                 092405e7a32c7b92960efce485269026b1099d478656ff4f38ca4c00d2bff5ee
                 26a808815f0eeb6839bd0d79d872cdaa8d7b74debdebe86ce2be8abe0cde27e4
                 202116d7b36ee173fff9d54048650ea8d15e24a0adda0cd7cdde2b065d27eae4
                 133777c0c37585ac71ce25c9ea4d56f66150f04acb92823ba84e0e697d9abd0f
                 050770a07e06899c7938c92c0ce5431968f582aec10fbba034ba030e38dddb5c
                 1db3035c6e6997527e728268889dabaf51e320110a3d340d4cbb7fc6663ee659
                 14336d040dfc668489ef72bb5296045fd0b0bd9d6c511356c910841a9777f24c

New Merkle Root: 29d0eb4674bad45b3cab15556750cdb7263ee4ef772c78ba378b32584f25bf02
Tx type        : Deposit (0)
Memo size      : 210 bytes
----------------------------------- MEMO BLOCK -----------------------------------
Tx fee         : 0 (0x0)
Items number   : 1
Account hash   : 798580acf077a9fa84cc72e8df4f8fd3b74a363d80435a04ac4ee229b45fc00c
A_p            : aaefd96e2ffdd2922086e3f5487a10f86992677c988058544ca67051d2876015
Encrypted keys : 24534fc93382b5d32e288b3d780f67139cce6d1fcac7d75f1357057f3f491cae
                 4204d01efad840b1d336fa80b5ddf06f

Encrypted acc  : 5ddc81a0812cdd3233290339a082081adc68b19296841813a8f8d3b7d8a5cf7d
                 f3a9791385040165d48e22d6102377b0c7f391b8b45fa705c1b1474e32c3f8cd
                 9759fd858836635d1a3901640fdec357189a1552d529
----------------------------------------------------------------------------------
ECDSA signature: fee3d380f303ed3d7fb17edd6a1682fbe2881e086c7cf524926adf0648f52254
                 e92c237927fc3052d2ebc9f7d2a7797db1cbbe09d35b22af322723cf25d5e222
Deposit spender: 0x6d16337b9a1651556749230eeaa4dc602a22dcaf (recovered from ECDSA)

Transaction has been processed successfully!
```
