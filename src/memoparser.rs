use std::fmt::Display;

use crate::ethutils::ecrecover;
use crate::memo::Memo;
use crate::memo::TxType;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use thousands::Separable;
extern crate hex;

//use memo::{TxType, Memo};

fn print_long_hex(title: String, str: String, width: usize) -> String {
    use std::str;
    let mut result = String::new();
    let subs = str
        .as_bytes()
        .chunks(width)
        .map(str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap();
    result += &format!("{}", title);
    for (idx, substr) in subs.iter().enumerate() {
        if idx > 0 {
            result += &format!("{: <1$}", "", title.len());
        }
        result += &format!("{}\n", substr);
    }

    if subs.len() == 0 {
        result += &format!("\n");
    }
    result
}

pub struct Calldata {
    pub selector: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub out_commit: Vec<u8>,
    pub tx_index: u64,
    pub energy_amount: i128,
    pub token_amount: i128,
    pub tx_proof: Vec<u8>,
    pub root_after: Vec<u8>,
    pub tree_proof: Vec<u8>,
    pub tx_type: u32,
    pub memo_size: u32,
    pub memo: Memo,
    pub ecdsa_sign: Vec<u8>,
    pub addr: Option<String>,
}

impl Display for Calldata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = String::new();
        result += &format!("Selector       : 0x{}\n", hex::encode(&self.selector));
        result += &format!("Nullifier      : 0x{}\n", hex::encode(&self.nullifier));
        result += &format!("Commitnment    : 0x{}\n", hex::encode(&self.out_commit));
        result += &format!("Index          : {} (0x{:x})\n", &self.tx_index, &self.tx_index);
        result += &format!("Energy delta   : {} Gwei (0x{:x})\n", &self.energy_amount.separate_with_commas(), &self.energy_amount & 0xffffffffffffffffffffffffffff);
        result += &format!("Token delta    : {} Gwei (0x{:x})\n", &self.token_amount.separate_with_commas(), &self.token_amount);
        result += &print_long_hex("Tx proof       : ".to_string(), hex::encode(&self.tx_proof), 64);
        result += &format!("\n");
        result += &print_long_hex("Tree proof     : ".to_string(), hex::encode(&self.tree_proof), 64);
        result += &format!("\n");
        result += &format!("New Merkle Root: {}\n", hex::encode(&self.root_after));
        result += &format!("Tx type        : {} ({})\n", &self.tx_type.to_string(), &self.tx_type);
        result += &format!("Memo size      : {} bytes\n", &self.memo_size);
        result += &format!("----------------------------------- MEMO BLOCK -----------------------------------\n");
        result += &format!("Tx fee         : {} (0x{:x})\n", &self.memo.fee.separate_with_commas(), &self.memo.fee);
        result += &format!("Items number   : {}\n", &self.memo.items_num);
        if TxType::from_u32(self.tx_type) == TxType::Withdrawal {
            result += &format!("Native amount  : {} Gwei (0x{:x})\n", &self.memo.amount.separate_with_commas(), &self.memo.amount);
            result += &format!("Withdraw addr  : 0x{}\n", &self.memo.receiver);
        }
        if TxType::from_u32(self.tx_type) == TxType::DepositPermittable {
            let dt_utc = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(self.memo.deadline as i64, 0), Utc);
            let dt_local: DateTime<Local> = DateTime::from(dt_utc);
            result += &format!("Deadline       : {} (0x{:x})\n", dt_local.format("%Y-%m-%d %H:%M:%S"), &self.memo.deadline);
        }
        result += &format!("Account hash   : {}\n", hex::encode(&self.memo.acc_hash));
        for (note_idx, note_hash) in self.memo.notes_hashes.iter().enumerate() {
            result += &format!("Note #{} hash   : {}\n", note_idx, hex::encode(note_hash));
        }
        result += &format!("A_p            : {}\n", hex::encode(&self.memo.a_p));
        result += &print_long_hex("Encrypted keys : ".to_string(), hex::encode(&self.memo.keys_enc), 64);
        result += &print_long_hex("Encrypted acc  : ".to_string(), hex::encode(&self.memo.acc_enc), 64);

        for (note_idx, enc_note) in self.memo.notes_enc.iter().enumerate() {
            //println!("Encrypt note #{}: {}", note_idx, hex::encode(enc_note));
            result += &print_long_hex(format!("Encrypt note #{}: ", note_idx), hex::encode(enc_note), 64);
        };

        if self.memo.extra.is_some() {
            let extra = self.memo.extra.as_ref().unwrap();

            result += &print_long_hex("Additional data: ".to_string(), hex::encode(extra), 64);

            if let Ok(str_repr) = String::from_utf8(extra.to_vec()) {
                result += &format!("        [UTF-8]: {}\n", str_repr);
            }
        }

        result += &format!("----------------------------------------------------------------------------------\n");
        if !self.ecdsa_sign.is_empty() {
            result += &print_long_hex("ECDSA signature: ".to_string(), hex::encode(&self.ecdsa_sign.to_vec()), 64);
        }
        if self.addr.is_some() {
            let addr = self.addr.as_ref().unwrap();
            result += &format!("Deposit spender: 0x{} (recovered from ECDSA)", addr);
        }

        write!(f, "{}", result)
    }
}

#[derive(Debug)]
pub enum ParsedCalldataError {
    InternalError(String),
}

// data is a hex-string, without any 0x prefixes
pub fn parse_calldata(
    bytes: Vec<u8>,
    rpc: Option<String>,
) -> Result<Calldata, ParsedCalldataError> {
    let selector = &bytes[0..4];
    if hex::encode(selector) != "af989083" {
        return Err(ParsedCalldataError::InternalError(format!(
            "Incorrect method selector (0x{}). Probably it isn't a zkBob transaction!",
            hex::encode(selector)
        )));
    }

    if bytes.len() < 644 {
        return Err(ParsedCalldataError::InternalError(format!(
            "Incorrect calldata length! It must be at least 644 bytes"
        )));
    }

    let nullifier = &bytes[4..36];
    let commit = &bytes[36..68];
    let index_raw = &bytes[68..74];
    let index = u64::from_str_radix(&hex::encode(index_raw), 16).unwrap();

    let delta_energy_raw = &bytes[74..88];
    let mut delta_energy = i128::from_str_radix(&hex::encode(delta_energy_raw), 16).unwrap();
    if delta_energy > ((1 as i128) << 111) {
        // process delta negative values
        delta_energy -= (1 as i128) << 112;
    }

    let delta_token_raw = &bytes[88..96];
    let mut delta_token = i128::from_str_radix(&hex::encode(delta_token_raw), 16).unwrap();
    if delta_token > ((1 as i128) << 63) {
        // process delta negative values
        delta_token -= (1 as i128) << 64;
    }

    let tx_proof = &bytes[96..352];
    let root_after = &bytes[352..384];
    let tree_proof = &bytes[384..640];
    let tx_type_raw = &bytes[640..642];
    let tx_type = TxType::from_u32(u32::from_str_radix(&hex::encode(tx_type_raw), 16).unwrap());
    let memo_size_raw = &bytes[642..644];
    let memo_size = u32::from_str_radix(&hex::encode(memo_size_raw), 16).unwrap();

    if bytes.len() < 644 + memo_size as usize {
        return Err(ParsedCalldataError::InternalError(format!(
            "Incorrect calldata length! Memo block corrupted"
        )));
    }

    let is_extra_fields: bool =
        tx_type == TxType::Withdrawal || tx_type == TxType::DepositPermittable;
    if (!is_extra_fields && memo_size < 210) || (is_extra_fields && memo_size < 238) {
        return Err(ParsedCalldataError::InternalError(format!(
            "Incorrect memo block length"
        )));
    }

    let memo = Memo::parse_memoblock(Vec::from(&bytes[644..(644 + memo_size) as usize]), tx_type);
    let memo_clone = memo.clone();

    let mut ecdsa_sign: Vec<u8> = Vec::new();
    let cur_offset = 644 + memo_size as usize;
    let mut addr = None;
    if tx_type == TxType::Deposit {
        let rem_len = bytes.len() - cur_offset;
        if rem_len < 64 {
            return Err(ParsedCalldataError::InternalError(format!("Cannot find correct ECDSA signature for deposit transaction. It should be 64 bytes length (got {})\n", bytes.len() - cur_offset)));
        };

        ecdsa_sign = bytes[cur_offset..cur_offset + 64].to_vec();

        if rpc.is_some() {
            addr = Some(ecrecover(nullifier.to_vec(), ecdsa_sign.to_vec(), rpc.unwrap()));
        }
    } else if tx_type == TxType::DepositPermittable {
        let rem_len = bytes.len() - cur_offset;
        if rem_len < 64 {
            return Err(ParsedCalldataError::InternalError(format!("Cannot find correct ECDSA signature for deposit transaction. It should be 64 bytes length (got {})\n", bytes.len() - cur_offset)));
        };

        ecdsa_sign = bytes[cur_offset..cur_offset + 64].to_vec();
    }

    Ok(Calldata {
        selector: selector.to_vec(),
        nullifier: nullifier.to_vec(),
        out_commit: commit.to_vec(),
        tx_index: index,
        energy_amount: delta_energy,
        token_amount: delta_token,
        tx_proof: tx_proof.to_vec(),
        root_after: root_after.to_vec(),
        tree_proof: tree_proof.to_vec(),
        tx_type: tx_type.to_u32(),
        memo_size: memo_size,
        memo: memo_clone,
        ecdsa_sign: ecdsa_sign,
        addr: addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_calldata_1() {
        let res = parse_calldata(hex::decode("af9890831a0fe6f449922ed4173f73c77c7fff97cea27dbeb81188ec72ebec3c6ddc0f370a3f732edcf1584a9b83d2baf55ed5a7613b7f4d2101bdcf5ce2c34d57008d65000000007600000000000000000000000000000000000000b2d05e001fd8a58c1b5c949ac17cd3d316e4d6267aac0d3889bca318344e85c1065aad3f1ab34677b1228385b241859d102163a0ab3fd17c959481905d46608e192e46cb1192a04a311add9ab1dc456a0d82a27a99fee79158bb2e266c327596e99488c92cc1f53854916eec56cf8f8d89977aaf0bc0a8e1f19ba1017c65c56ca02432dc1bbd0ed8edc9563688b1ed6bacd4a3005e2a2cfee5316c78d7161395dba7daeb11188ce1e5dc056086a74d895e108af85206618eb23b88596bdf295ef05bb674164f2d7e92d0cd1cc2393257424d914c65472fa83b7230f98028575c897b615d16cfc8da751c5d8aa92352e7a2e13dfbe7b79c9391ba4d36db2bbf6d9d702afa015c913d6f602f0c161a239642bdd34d759adf71551abc76e335ae0706c6586303a7bce20c08104125349866aa894b7ae11acdf5a8c8913d66663b4cafffdf602782b62554da604e5715069abfa6b023fb5409dbfdbc9613d388b3aba6899e6f254f1539a1d815bb6c79b59bfcc7155fc47c3c6b955990bc82a835373d2ed77d116e7f4b6c1564a3e2d73eac8ccb767efa349a48167a26915ba957c4ced0dabc2cc1ca6c03b926a9a197c5debd43415d9fd0b6ea041657e6721d2cd472b7244d19c70096444151809bc3432cfd0ca1131525f5c6bd8bc2af6564eda22abc01da0d4a7b824ef32d03e981cb5365c3f90675d273aef751d13cb70a67ce251d4d2c11467533892f0c951ad48013281560a2e764139d84fb370b88a2d60427bcac98000000d20000000000000000010000004c39bb90fdc7fdc3f6355a828f7a8e684c0ffb1d0e92d3363a8b3a610eb5a32e86e46e5dbf49b0cfd960042f77493a73628f998cdcbe7b9d1eecefb8e6090c06cb20ca3d203666652938a7533155fd52ee7882e255e6b12cee25355af14bdd92956cfc93cbca314e81582c45512b6199c5182b40eb7c1c256aa7ce40be3432328476f08143428aaf03662b97728825573231e75b72f47cefd983a7f5c320e68c845e482c4b61ace16069b0dfa386611ab6a6d39b4a22ec9e7a59e4f40d67b2e959aba28a10285dab9ccb5c7aa6c4359f36f6d5f3447783b2591a1f4910730dc3166032445ded7949702f9627195283348387f6b01efe586941b6160fd9cb85bd45acd400c3321b").unwrap(), None);
        let parsed_calldata = res.unwrap();
        assert_eq!(hex::encode(parsed_calldata.selector), "af989083");
        assert_eq!(
            hex::encode(parsed_calldata.nullifier),
            "1a0fe6f449922ed4173f73c77c7fff97cea27dbeb81188ec72ebec3c6ddc0f37"
        );
        assert_eq!(
            hex::encode(parsed_calldata.out_commit),
            "0a3f732edcf1584a9b83d2baf55ed5a7613b7f4d2101bdcf5ce2c34d57008d65"
        );
        assert_eq!(parsed_calldata.tx_index, 30208);
        assert_eq!(parsed_calldata.energy_amount, 0);
        assert_eq!(parsed_calldata.token_amount, 3_000_000_000);
        assert_eq!(hex::encode(parsed_calldata.tx_proof), "1fd8a58c1b5c949ac17cd3d316e4d6267aac0d3889bca318344e85c1065aad3f1ab34677b1228385b241859d102163a0ab3fd17c959481905d46608e192e46cb1192a04a311add9ab1dc456a0d82a27a99fee79158bb2e266c327596e99488c92cc1f53854916eec56cf8f8d89977aaf0bc0a8e1f19ba1017c65c56ca02432dc1bbd0ed8edc9563688b1ed6bacd4a3005e2a2cfee5316c78d7161395dba7daeb11188ce1e5dc056086a74d895e108af85206618eb23b88596bdf295ef05bb674164f2d7e92d0cd1cc2393257424d914c65472fa83b7230f98028575c897b615d16cfc8da751c5d8aa92352e7a2e13dfbe7b79c9391ba4d36db2bbf6d9d702afa");
        assert_eq!(hex::encode(parsed_calldata.tree_proof), "03a7bce20c08104125349866aa894b7ae11acdf5a8c8913d66663b4cafffdf602782b62554da604e5715069abfa6b023fb5409dbfdbc9613d388b3aba6899e6f254f1539a1d815bb6c79b59bfcc7155fc47c3c6b955990bc82a835373d2ed77d116e7f4b6c1564a3e2d73eac8ccb767efa349a48167a26915ba957c4ced0dabc2cc1ca6c03b926a9a197c5debd43415d9fd0b6ea041657e6721d2cd472b7244d19c70096444151809bc3432cfd0ca1131525f5c6bd8bc2af6564eda22abc01da0d4a7b824ef32d03e981cb5365c3f90675d273aef751d13cb70a67ce251d4d2c11467533892f0c951ad48013281560a2e764139d84fb370b88a2d60427bcac98");
        assert_eq!(
            hex::encode(parsed_calldata.root_after),
            "015c913d6f602f0c161a239642bdd34d759adf71551abc76e335ae0706c65863"
        );
        assert_eq!(parsed_calldata.tx_type, 0);
        assert_eq!(parsed_calldata.memo_size, 210);
        assert_eq!(hex::encode(parsed_calldata.ecdsa_sign), "5dab9ccb5c7aa6c4359f36f6d5f3447783b2591a1f4910730dc3166032445ded7949702f9627195283348387f6b01efe586941b6160fd9cb85bd45acd400c332");
    }

    #[test]
    fn test_parse_calldata_2() {
        let res = parse_calldata(hex::decode("af9890832711712d54721af2e6acb4ebe63681baa29da74a6bf1b79419e949ed88cc5105229a17b5c68611cbfb9a85e0b7bb2d24673df1e3f6c35b199e324d12502d076f000000007400000000000000000000000000000000000000000000002e659ce1958431d5c01e857727180cdd052a7c267231aba68af1d3470493e62c15b71d52972a03d77ebc3d93c0a476d1ccb7d6202cc923963ca10d92f6cf46911def6467f39edba34ba768ded8d65ff0b225e4993f75ee7d147572f6f809b1c300ddc550e31053eac49534035c4f7749bce4a125045f79380ba8c8ab7f40df9b2e1038f7d1114b9834ecc20be88ce0fea65637b8faa805c104eb8e98ba152c381d5fd83ad744e4ebcd88323ed829902797d79dbe808934364015fa9d7fa5b9551d042927e37e9cfc850a6cb6d9b16eaed8cdffecd662eff10731242a5a9dfafe16d8900ed5d1d1fd5e1eb22bc3bb60666ee0302667f5836b1282868527ef3efd22b822acd5c7cc53cfcdd57b57f65656d36b36f568723c881dd981e30558d6fe2da4a4c7ca8047fbc1177233e6a3c17c164aaf12a1fc51cf94634d57ca8c57632ba7f1d3ce29368abc7b8167a5bbde47c4c5837fe8725b15bb9e24bc7a14030b30152c50b7b32ed03711ac6599d3ead91c291a52ecb3088dd5767ba61e54f7ad2957900ddb6b3c0dcdef84ffb18a78c38d5f8176a797adc2b2834223eb3f275b12b86adfadf3e4c0a2f2c97ad6044e67e89262375184ece0a83dcf5e578a82220e544caccc1210473085e7ac1b20b66a45e31205d172dc031892fad8500f6b181e0f8b26405849dfccf599b65923d2aadeff51649d7d15fe9c02a6396fa000b518f1c076f7e42940a3f4a0ee4687aebfe9af4cf78367d0232bce9c728cd448040001017e000000000000000002000000dbd4e206613eeb2af78861d23aca9dbd520cf85af0edbb6743c48a71587f390454ae9059d8c6b53c94ca75d82238309d519bf553736000e5b47673c01d9fc72c10e949a1f8c1869612221b3574f0001a11cca764e632684593b4a943f6916f1b9ff08faec58970738caeee8cd840c544cf4ca350bc0cf505f25f4d8be63787ae30b485da1dfaf6e6df2012a6b8c866b6951f1b97e321be70ba8e301327767c878ab8cd799b56a9f109b4d4d9c2b5b0c5e5c288a41f5af6c55ab33756e6210fdd9385c0b27a3cd85d73c7f1d3ccef8ef77229e5a09595dbab6ecdb4c7298f608c80ebceb5d3da781917d2e549fffa7d1b2cf21db14d1338ddebe44201c698f8e2652c386bc2306eb9d923df8bf2e29bfc7a7f014078acdcf2884e76280ab777aa8987f6e9352e662cd7db9849fc8453c34df2d1b4974c0bf3c3bd8b85097e702c6c4edd00111963cbe18ba6f89a255f591371374d1cc920268bd8021fa65e567d21d246acb3b3837be8f59bd6de6d4e67d3eb").unwrap(), None);
        let parsed_calldata = res.unwrap();
        assert_eq!(hex::encode(parsed_calldata.selector), "af989083");
        assert_eq!(
            hex::encode(parsed_calldata.nullifier),
            "2711712d54721af2e6acb4ebe63681baa29da74a6bf1b79419e949ed88cc5105"
        );
        assert_eq!(
            hex::encode(parsed_calldata.out_commit),
            "229a17b5c68611cbfb9a85e0b7bb2d24673df1e3f6c35b199e324d12502d076f"
        );
        assert_eq!(parsed_calldata.tx_index, 29696);
        assert_eq!(parsed_calldata.energy_amount, 0);
        assert_eq!(parsed_calldata.token_amount, 0);
        assert_eq!(hex::encode(parsed_calldata.tx_proof), "2e659ce1958431d5c01e857727180cdd052a7c267231aba68af1d3470493e62c15b71d52972a03d77ebc3d93c0a476d1ccb7d6202cc923963ca10d92f6cf46911def6467f39edba34ba768ded8d65ff0b225e4993f75ee7d147572f6f809b1c300ddc550e31053eac49534035c4f7749bce4a125045f79380ba8c8ab7f40df9b2e1038f7d1114b9834ecc20be88ce0fea65637b8faa805c104eb8e98ba152c381d5fd83ad744e4ebcd88323ed829902797d79dbe808934364015fa9d7fa5b9551d042927e37e9cfc850a6cb6d9b16eaed8cdffecd662eff10731242a5a9dfafe16d8900ed5d1d1fd5e1eb22bc3bb60666ee0302667f5836b1282868527ef3efd");
        assert_eq!(hex::encode(parsed_calldata.tree_proof), "2da4a4c7ca8047fbc1177233e6a3c17c164aaf12a1fc51cf94634d57ca8c57632ba7f1d3ce29368abc7b8167a5bbde47c4c5837fe8725b15bb9e24bc7a14030b30152c50b7b32ed03711ac6599d3ead91c291a52ecb3088dd5767ba61e54f7ad2957900ddb6b3c0dcdef84ffb18a78c38d5f8176a797adc2b2834223eb3f275b12b86adfadf3e4c0a2f2c97ad6044e67e89262375184ece0a83dcf5e578a82220e544caccc1210473085e7ac1b20b66a45e31205d172dc031892fad8500f6b181e0f8b26405849dfccf599b65923d2aadeff51649d7d15fe9c02a6396fa000b518f1c076f7e42940a3f4a0ee4687aebfe9af4cf78367d0232bce9c728cd44804");
        assert_eq!(
            hex::encode(parsed_calldata.root_after),
            "22b822acd5c7cc53cfcdd57b57f65656d36b36f568723c881dd981e30558d6fe"
        );
        assert_eq!(parsed_calldata.tx_type, 1);
        assert_eq!(parsed_calldata.memo_size, 382);
        assert_eq!(hex::encode(parsed_calldata.ecdsa_sign), "");
    }
}
