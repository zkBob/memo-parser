//use core::slice::SlicePattern;
use std::fmt::Display;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use thousands::Separable;
use crate::utils::print_long_hex;
use crate::errors::MemoParserError;

pub mod memo;
pub mod helper;

use memo::{ TxType, Memo };
use helper::ecrecover;

use super::TxSelector;

pub struct CalldataTransact {
    pub version: u8,
    pub nullifier: Vec<u8>,
    pub out_commit: Vec<u8>,
    pub tx_index: u64,
    pub energy_amount: i128,
    pub token_amount: i128,
    pub tx_proof: Vec<u8>,
    pub root_after: Vec<u8>,
    pub tree_proof: Vec<u8>,
    pub tx_type: TxType,
    pub memo_size: u32,
    pub memo: Memo,
    pub ecdsa_sign: Vec<u8>,
    pub addr: Option<String>,
}

impl CalldataTransact {
    /// bytes should be started with selector
    pub fn new(bytes: &[u8], rpc: Option<String>) -> Result<Self, MemoParserError> {
        let selector = match TxSelector::from_bytes(&bytes[0..4]) {
            Some(sel) => sel,
            None => return Err(MemoParserError::ParseError(
                format!("The selector {} doesn't supported currently", &hex::encode(&bytes[0..4]))
            ))
        };

        let mut off = 4;

        let (min_calldata_len, version) = match selector {
            TxSelector::Transact => {
                (644, 1)
            },
            TxSelector::TransactV2 => {
                off += 1;
                (357, bytes[off - 1])
            },
            _ => {
                return Err(MemoParserError::ParseError(
                    format!("The provided calldata ({}) doesn't belong to the regular transaction",
                        selector)
                ))
            }
        };

        if bytes.len() < min_calldata_len {
            return Err(MemoParserError::ParseError(
                format!("Incorrect calldata length! It must be at least {} bytes for {}",
                min_calldata_len,
                selector)
            ));
        }
    
        let nullifier = &bytes[off..off+32];
        let commit = &bytes[off+32..off+64];
        let index_raw = &bytes[off+64..off+70];
        let index = u64::from_str_radix(&hex::encode(index_raw), 16).unwrap();
    
        let delta_energy_raw = &bytes[off+70..off+84];
        let mut delta_energy = i128::from_str_radix(&hex::encode(delta_energy_raw), 16).unwrap();
        if delta_energy > ((1 as i128) << 111) {
            // process delta negative values
            delta_energy -= (1 as i128) << 112;
        }
    
        let delta_token_raw = &bytes[off+84..off+92];
        let mut delta_token = i128::from_str_radix(&hex::encode(delta_token_raw), 16).unwrap();
        if delta_token > ((1 as i128) << 63) {
            // process delta negative values
            delta_token -= (1 as i128) << 64;
        }
    
        let tx_proof = &bytes[off+92..off+348];

        off += 348;


        let mut root_after = [].as_slice();
        let mut tree_proof = [].as_slice();
        if selector == TxSelector::Transact {
            root_after = &bytes[off..off+32];
            tree_proof = &bytes[off+32..off+288];
            off += 288;
        }

        let tx_type_raw = &bytes[off..off+2];
        let tx_type = TxType::from_u32(u32::from_str_radix(&hex::encode(tx_type_raw), 16).unwrap());

        let memo_size_raw = &bytes[off+2..off+4];
        let memo_size = u32::from_str_radix(&hex::encode(memo_size_raw), 16).unwrap();

        off += 4;
    
        if bytes.len() < off + memo_size as usize {
            return Err(MemoParserError::ParseError(format!(
                "Incorrect calldata length! Memo block corrupted"
            )));
        }
    
        let memo = Memo::parse_memoblock(Vec::from(&bytes[off..(off + memo_size as usize)]), tx_type, version)?;
        let memo_clone = memo.clone();

        off += memo_size as usize;
    
        let mut ecdsa_sign: Vec<u8> = Vec::new();
        //let cur_offset = 644 + memo_size as usize;
        let mut addr = None;
        if tx_type == TxType::Deposit || tx_type == TxType::DepositPermittable {
            let rem_len = bytes.len() - off;
            if rem_len < 64 {
                return Err(MemoParserError::ParseError(format!("Cannot find correct ECDSA signature for deposit transaction. It should be 64 bytes length (got {})\n", bytes.len() - off)));
            };
    
            ecdsa_sign = bytes[off..off + 64].to_vec();

            if tx_type == TxType::Deposit && rpc.is_some() {
                addr = Some(ecrecover(nullifier.to_vec(), ecdsa_sign.to_vec(), rpc.unwrap()));
            }
        }
    
        Ok(CalldataTransact {
            version,
            nullifier: nullifier.to_vec(),
            out_commit: commit.to_vec(),
            tx_index: index,
            energy_amount: delta_energy,
            token_amount: delta_token,
            tx_proof: tx_proof.to_vec(),
            root_after: root_after.to_vec(),
            tree_proof: tree_proof.to_vec(),
            tx_type: tx_type,
            memo_size,
            memo: memo_clone,
            ecdsa_sign: ecdsa_sign,
            addr: addr,
        })
    }
}

impl Display for CalldataTransact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = String::new();
        result += &format!("Calldata version : {}\n", self.version);
        result += &format!("Nullifier        : 0x{}\n", hex::encode(&self.nullifier));
        result += &format!("Commitnment      : 0x{}\n", hex::encode(&self.out_commit));
        result += &format!("Index            : {} (0x{:x})\n", &self.tx_index, &self.tx_index);
        result += &format!("Energy delta     : {} Gwei (0x{:x})\n", &self.energy_amount.separate_with_commas(), &self.energy_amount & 0xffffffffffffffffffffffffffff);
        result += &format!("Token delta      : {} Gwei (0x{:x})\n", &self.token_amount.separate_with_commas(), &self.token_amount);
        result += &print_long_hex("Tx proof         : ".to_string(), hex::encode(&self.tx_proof), 64);
        result += &format!("\n");
        if self.tree_proof.len() > 0 {
            result += &print_long_hex("Tree proof       : ".to_string(), hex::encode(&self.tree_proof), 64);
            result += &format!("\n");
        }
        if self.root_after.len() > 0 {
            result += &format!("New Merkle Root  : {}\n", hex::encode(&self.root_after));
        }
        result += &format!("Tx type          : {} ({})\n", &self.tx_type.to_string(), &self.tx_type.to_u32());
        result += &format!("Memo size        : {} bytes\n", &self.memo_size);
        result += &format!("----------------------------------- MEMO BLOCK -----------------------------------\n");
        if self.version == 1 {
            result += &format!("Tx fee           : {} (0x{:x})\n", &self.memo.proxy_fee.separate_with_commas(), &self.memo.proxy_fee);
        } else if self.version >= 2 {
            result += &format!("Proxy address    : {}\n", &self.memo.proxy_address);
            result += &format!("Proxy fee        : {} (0x{:x})\n", &self.memo.proxy_fee.separate_with_commas(), &self.memo.proxy_fee);
            result += &format!("Prover fee       : {} (0x{:x})\n", &self.memo.prover_fee.unwrap().separate_with_commas(), &self.memo.prover_fee.unwrap());
        }
        result += &format!("Items number     : {}\n", &self.memo.items_num);
        
        match self.tx_type {
            TxType::Withdrawal => {
                result += &format!("Native amount    : {} Gwei (0x{:x})\n", &self.memo.amount.separate_with_commas(), &self.memo.amount);
                result += &format!("Withdraw addr    : {}\n", &self.memo.receiver);
            },
            TxType::DepositPermittable => {
                let dt_utc = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp_opt(self.memo.deadline as i64, 0).unwrap(), Utc);
                let dt_local: DateTime<Local> = DateTime::from(dt_utc);
                result += &format!("Deadline         : {} (0x{:x})\n", dt_local.format("%Y-%m-%d %H:%M:%S"), &self.memo.deadline);
                result += &format!("Deposit holder   : {}\n", &self.memo.holder);
            },
            _ => {},
        };

        if self.version == 2 && self.memo.message_size.is_some() {
            result += &format!("Message length   : {}\n", &self.memo.message_size.unwrap());
        }

        result += &format!("Account hash     : {}\n", hex::encode(&self.memo.acc_hash));
        for (note_idx, note_hash) in self.memo.notes_hashes.iter().enumerate() {
            result += &format!("Note #{} hash     : {}\n", note_idx, hex::encode(note_hash));
        }
        if self.memo.a_p.len() > 0 {
            result += &format!("A_p              : {}\n", hex::encode(&self.memo.a_p));
        }
        if self.memo.nonce.len() > 0 {
            result += &format!("Nonce            : {}\n", hex::encode(&self.memo.nonce));
        }
        result += &print_long_hex("Encrypted keys   : ".to_string(), hex::encode(&self.memo.keys_enc), 64);
        result += &print_long_hex("Encrypted acc    : ".to_string(), hex::encode(&self.memo.acc_enc), 64);

        for (note_idx, enc_note) in self.memo.notes_enc.iter().enumerate() {
            //println!("Encrypt note #{}: {}", note_idx, hex::encode(enc_note));
            result += &print_long_hex(format!("Encrypt note #{} : ", note_idx), hex::encode(enc_note), 64);
        };

        if self.memo.extra.is_some() {
            let extra = self.memo.extra.as_ref().unwrap();

            result += &print_long_hex("Additional data: ".to_string(), hex::encode(extra), 64);

            if let Ok(str_repr) = String::from_utf8(extra.to_vec()) {
                result += &format!("         [UTF-8]: {}\n", str_repr);
            }
        }

        result += &format!("----------------------------------------------------------------------------------\n");
        if !self.ecdsa_sign.is_empty() {
            result += &print_long_hex("ECDSA signature:  ".to_string(), hex::encode(&self.ecdsa_sign.to_vec()), 64);
        }
        if self.addr.is_some() {
            let addr = self.addr.as_ref().unwrap();
            result += &format!("Deposit spender  : {} (recovered from ECDSA)", addr);
        }

        write!(f, "{}", result)
    }
}