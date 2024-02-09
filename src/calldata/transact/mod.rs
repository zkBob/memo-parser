use std::fmt::Display;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use thousands::Separable;
use crate::utils::print_long_hex;
use crate::errors::MemoParserError;

pub mod memo;
pub mod helper;

use memo::{ TxType, Memo };
use helper::ecrecover;

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
        if bytes.len() < 644 {
            return Err(MemoParserError::ParseError(format!(
                "Incorrect calldata length! It must be at least 644 bytes for transact() method"
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
            return Err(MemoParserError::ParseError(format!(
                "Incorrect calldata length! Memo block corrupted"
            )));
        }
    
        let is_extra_fields: bool =
            tx_type == TxType::Withdrawal || tx_type == TxType::DepositPermittable;
        if (!is_extra_fields && memo_size < 210) || (is_extra_fields && memo_size < 238) {
            return Err(MemoParserError::ParseError(format!(
                "Incorrect memo block length"
            )));
        }
    
        let memo = Memo::parse_memoblock(Vec::from(&bytes[644..(644 + memo_size) as usize]), tx_type);
        let memo_clone = memo.clone();
    
        let mut ecdsa_sign: Vec<u8> = Vec::new();
        let cur_offset = 644 + memo_size as usize;
        let mut addr = None;
        if tx_type == TxType::Deposit || tx_type == TxType::DepositPermittable {
            let rem_len = bytes.len() - cur_offset;
            if rem_len < 64 {
                return Err(MemoParserError::ParseError(format!("Cannot find correct ECDSA signature for deposit transaction. It should be 64 bytes length (got {})\n", bytes.len() - cur_offset)));
            };
    
            ecdsa_sign = bytes[cur_offset..cur_offset + 64].to_vec();

            if tx_type == TxType::Deposit && rpc.is_some() {
                addr = Some(ecrecover(nullifier.to_vec(), ecdsa_sign.to_vec(), rpc.unwrap()));
            }
        }
    
        Ok(CalldataTransact {
            version: 1,
            nullifier: nullifier.to_vec(),
            out_commit: commit.to_vec(),
            tx_index: index,
            energy_amount: delta_energy,
            token_amount: delta_token,
            tx_proof: tx_proof.to_vec(),
            root_after: root_after.to_vec(),
            tree_proof: tree_proof.to_vec(),
            tx_type: tx_type,
            memo_size: memo_size,
            memo: memo_clone,
            ecdsa_sign: ecdsa_sign,
            addr: addr,
        })
    }

    pub fn new_v2(bytes: &[u8], rpc: Option<String>) -> Result<Self, MemoParserError> {
        if bytes.len() < 357 {
            return Err(MemoParserError::ParseError(format!(
                "Incorrect calldata length! It must be at least 357 bytes for transact() method"
            )));
        }
    
        let version = bytes[4];
        if version != 2 {
            return Err(MemoParserError::ParseError(format!("Unsupported calldata version ({})", version)));
        }
        let nullifier = &bytes[5..37];
        let commit = &bytes[37..69];
        let index_raw = &bytes[69..75];
        let index = u64::from_str_radix(&hex::encode(index_raw), 16).unwrap();
    
        let delta_energy_raw = &bytes[75..89];
        let mut delta_energy = i128::from_str_radix(&hex::encode(delta_energy_raw), 16).unwrap();
        if delta_energy > ((1 as i128) << 111) {
            // process delta negative values
            delta_energy -= (1 as i128) << 112;
        }
    
        let delta_token_raw = &bytes[89..97];
        let mut delta_token = i128::from_str_radix(&hex::encode(delta_token_raw), 16).unwrap();
        if delta_token > ((1 as i128) << 63) {
            // process delta negative values
            delta_token -= (1 as i128) << 64;
        }
    
        let tx_proof = &bytes[97..353];
        let tx_type_raw = &bytes[353..355];
        let tx_type = TxType::from_u32(u32::from_str_radix(&hex::encode(tx_type_raw), 16).unwrap());
        let memo_size_raw = &bytes[355..357];
        let memo_size = u32::from_str_radix(&hex::encode(memo_size_raw), 16).unwrap();
    
        if bytes.len() < 357 + memo_size as usize {
            return Err(MemoParserError::ParseError(format!("Incorrect calldata length! Memo block corrupted")));
        }
    
        let is_extra_fields: bool =
            tx_type == TxType::Withdrawal || tx_type == TxType::DepositPermittable;
        if (!is_extra_fields && memo_size < 264) || (is_extra_fields && memo_size < 292) {
            return Err(MemoParserError::ParseError(format!("Incorrect memo block length")));
        }
    
        let memo = Memo::parse_memoblock(Vec::from(&bytes[357..(357 + memo_size) as usize]), tx_type);
        let memo_clone = memo.clone();
    
        let mut ecdsa_sign: Vec<u8> = Vec::new();
        let cur_offset = 644 + memo_size as usize;
        let mut addr = None;
        if tx_type == TxType::Deposit || tx_type == TxType::DepositPermittable {
            let rem_len = bytes.len() - cur_offset;
            if rem_len < 64 {
                return Err(MemoParserError::ParseError(format!("Cannot find correct ECDSA signature for deposit transaction. It should be 64 bytes length (got {})\n", bytes.len() - cur_offset)));
            };
    
            ecdsa_sign = bytes[cur_offset..cur_offset + 64].to_vec();

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
            root_after: [].to_vec(),
            tree_proof: [].to_vec(),
            tx_type,
            memo_size,
            memo: memo_clone,
            ecdsa_sign,
            addr,
        })
    }
}

impl Display for CalldataTransact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = String::new();
        result += &format!("Nullifier       : 0x{}\n", hex::encode(&self.nullifier));
        result += &format!("Commitnment     : 0x{}\n", hex::encode(&self.out_commit));
        result += &format!("Index           : {} (0x{:x})\n", &self.tx_index, &self.tx_index);
        result += &format!("Energy delta    : {} Gwei (0x{:x})\n", &self.energy_amount.separate_with_commas(), &self.energy_amount & 0xffffffffffffffffffffffffffff);
        result += &format!("Token delta     : {} Gwei (0x{:x})\n", &self.token_amount.separate_with_commas(), &self.token_amount);
        result += &print_long_hex("Tx proof        : ".to_string(), hex::encode(&self.tx_proof), 64);
        result += &format!("\n");
        if self.tree_proof.len() > 0 {
            result += &print_long_hex("Tree proof      : ".to_string(), hex::encode(&self.tree_proof), 64);
            result += &format!("\n");
        }
        if self.root_after.len() > 0 {
            result += &format!("New Merkle Root : {}\n", hex::encode(&self.root_after));
        }
        result += &format!("Tx type         : {} ({})\n", &self.tx_type.to_string(), &self.tx_type.to_u32());
        result += &format!("Memo size       : {} bytes\n", &self.memo_size);
        result += &format!("----------------------------------- MEMO BLOCK -----------------------------------\n");
        result += &format!("Tx fee          : {} (0x{:x})\n", &self.memo.proxy_fee.separate_with_commas(), &self.memo.proxy_fee);
        result += &format!("Items number    : {}\n", &self.memo.items_num);
        
        match self.tx_type {
            TxType::Withdrawal => {
                result += &format!("Native amount   : {} Gwei (0x{:x})\n", &self.memo.amount.separate_with_commas(), &self.memo.amount);
                result += &format!("Withdraw addr   : 0x{}\n", &self.memo.receiver);
            },
            TxType::DepositPermittable => {
                let dt_utc = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp_opt(self.memo.deadline as i64, 0).unwrap(), Utc);
                let dt_local: DateTime<Local> = DateTime::from(dt_utc);
                result += &format!("Deadline        : {} (0x{:x})\n", dt_local.format("%Y-%m-%d %H:%M:%S"), &self.memo.deadline);
            },
            _ => {},
        };

        result += &format!("Account hash    : {}\n", hex::encode(&self.memo.acc_hash));
        for (note_idx, note_hash) in self.memo.notes_hashes.iter().enumerate() {
            result += &format!("Note #{} hash    : {}\n", note_idx, hex::encode(note_hash));
        }
        result += &format!("A_p             : {}\n", hex::encode(&self.memo.a_p));
        result += &print_long_hex("Encrypted keys  : ".to_string(), hex::encode(&self.memo.keys_enc), 64);
        result += &print_long_hex("Encrypted acc   : ".to_string(), hex::encode(&self.memo.acc_enc), 64);

        for (note_idx, enc_note) in self.memo.notes_enc.iter().enumerate() {
            //println!("Encrypt note #{}: {}", note_idx, hex::encode(enc_note));
            result += &print_long_hex(format!("Encrypt note #{} : ", note_idx), hex::encode(enc_note), 64);
        };

        if self.memo.extra.is_some() {
            let extra = self.memo.extra.as_ref().unwrap();

            result += &print_long_hex("Additional data:".to_string(), hex::encode(extra), 64);

            if let Ok(str_repr) = String::from_utf8(extra.to_vec()) {
                result += &format!("         [UTF-8]: {}\n", str_repr);
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