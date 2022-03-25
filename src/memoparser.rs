use crate::memo::Memo;
use crate::memo::TxType;
use crate::ethutils::ecrecover;
use thousands::Separable;
extern crate hex;

//use memo::{TxType, Memo};

fn print_long_hex(title: String, str: String, width: usize) {
    use std::str;
    let subs = str.as_bytes()
                                .chunks(width)
                                .map(str::from_utf8)
                                .collect::<Result<Vec<&str>, _>>()
                                .unwrap();
    print!("{}", title);
    for (idx, substr) in subs.iter().enumerate() {
        if idx > 0 {
            print!("{: <1$}", "", title.len());
        }
        println!("{}", substr);
    }

    if subs.len() == 0 {
        println!();
    }
}

// data is a hex-string, without any 0x prefixes
pub fn parse_calldata(data: String, rpc: String) {
    let res = hex::decode(data);
    let bytes = match res {
        Ok(vec) => vec,
        Err(err) => panic!("Cannot parse the input hex string: {:?}", err),
    };

    let selector = &bytes[0..4];
    if hex::encode(selector) != "af989083" {
        println!("Incorrect method selector (0x{}). Probably it isn't a zkBob transaction!", hex::encode(selector));
        return;
    }

    if bytes.len() < 644 {
        println!("Incorrect calldata length! It must be at least 644 bytes");
        return;
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

    println!("Selector       : 0x{}", hex::encode(selector));
    //assert_eq!(hex::encode(selector), "af989083");

    println!("Nullifier      : 0x{}", hex::encode(nullifier));
    println!("Commitnment    : 0x{}", hex::encode(commit));
    println!("Index          : {} (0x{:x})", index, index);
    println!("Energy delta   : {} Gwei (0x{:x})", delta_energy.separate_with_commas(), delta_energy & 0xffffffffffffffffffffffffffff);
    println!("Token delta    : {} Gwei (0x{:x})", delta_token.separate_with_commas(), delta_token as i64);
    print_long_hex("Tx proof       : ".to_string(), hex::encode(tx_proof), 64);
    println!();
    print_long_hex("Tree proof     : ".to_string(), hex::encode(tree_proof), 64);
    println!();
    println!("New Merkle Root: {}", hex::encode(root_after));
    println!("Tx type        : {} ({})", tx_type.to_string(), tx_type.to_u32());
    println!("Memo size      : {} bytes", memo_size);

    if bytes.len() < 644 + memo_size as usize {
        println!("Incorrect calldata length! Memo block corrupted");
        return;
    }

    if (tx_type != TxType::Withdrawal && memo_size < 210) || (tx_type == TxType::Withdrawal && memo_size < 238) {
        println!("Incorrect memo block length");
        return;
    }

    let memo = Memo::parse_memoblock(Vec::from(&bytes[644..(644+memo_size) as usize]), tx_type);
    println!("----------------------------------- MEMO BLOCK -----------------------------------");
    println!("Tx fee         : {} (0x{:x})", memo.fee.separate_with_commas(), memo.fee);
    println!("Items number   : {}", memo.items_num);
    if tx_type == TxType::Withdrawal {
        println!("Native amount  : {} Gwei (0x{:x})", memo.amount.separate_with_commas(), memo.amount);
        println!("Withdraw addr  : 0x{}", memo.receiver);
    }
    println!("Account hash   : {}", hex::encode(memo.acc_hash));
    for (note_idx, note_hash) in memo.notes_hashes.iter().enumerate() {
        println!("Note #{} hash   : {}", note_idx, hex::encode(note_hash));
    }
    println!("A_p            : {}", hex::encode(memo.a_p));
    print_long_hex("Encrypted keys : ".to_string(), hex::encode(memo.keys_enc), 64);
    println!();

    print_long_hex("Encrypted acc  : ".to_string(), hex::encode(memo.acc_enc), 64);

    for (note_idx, enc_note) in memo.notes_enc.iter().enumerate() {
        //println!("Encrypt note #{}: {}", note_idx, hex::encode(enc_note));
        print_long_hex(format!("Encrypt note #{}: ", note_idx), hex::encode(enc_note), 64);
    };

    println!("----------------------------------------------------------------------------------");

    let mut cur_offset = 644 + memo_size as usize;
    if tx_type == TxType::Deposit {
        let rem_len = bytes.len() - cur_offset;
        if rem_len < 64 {
            println!("Cannot find correct ECDSA signature for deposit transaction. It should be 64 bytes length (got {})\n", bytes.len() - cur_offset);
            return;
        };

        let ecdsa_sign = bytes[cur_offset..cur_offset+64].to_vec();
        cur_offset += 64;

        /*if rem_len > 64 {
            ecdsa_sign.push(bytes[cur_offset]);
            cur_offset = cur_offset + 1;
        }*/

        print_long_hex("ECDSA signature: ".to_string(), hex::encode(ecdsa_sign.to_vec()), 64);
        let addr = ecrecover(nullifier.to_vec(), ecdsa_sign.to_vec(), rpc);
        println!("Deposit spender: 0x{} (recovered from ECDSA)", addr);
    }

    if cur_offset == bytes.len() {
        println!("\nTransaction has been processed successfully!\n");
    } else {
        println!("\n!!! There are extra byte(s) ({}) at the end of the calldata!\n", bytes.len() - cur_offset);
    }
}