
pub(crate) use std::fmt;

#[derive(Copy, Clone, PartialEq)]
pub enum TxType {
    Deposit = 0,
    Transfer = 1,
    Withdrawal = 2,
}

impl TxType {
    pub fn from_u32(value: u32) -> TxType {
        match value {
            0 => TxType::Deposit,
            1 => TxType::Transfer,
            2 => TxType::Withdrawal,
            _ => panic!("Unknown tx type ({})", value),
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            TxType::Deposit => 0,
            TxType::Transfer => 1,
            TxType::Withdrawal => 2,
        }
    }
}

impl fmt::Display for TxType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TxType::Deposit => write!(f, "Deposit"),
            TxType::Transfer => write!(f, "Transfer"),
            TxType::Withdrawal => write!(f, "Withdrawal"),
        }
    }
}

pub struct Memo {
    pub fee: u64,
    pub amount: u64,
    pub receiver: String,
    pub items_num: u32,
    pub acc_hash: Vec<u8>,
    pub notes_hashes: Vec<Vec<u8>>, // 32 x (items_num - 1) bytes
    pub a_p: Vec<u8>,               // 32 bytes
    pub keys_enc: Vec<u8>,          // 32 * items_num + 16
    pub acc_enc: Vec<u8>,           // 86 bytes
    pub notes_enc: Vec<Vec<u8>>,    // 108 x (items_num - 1) bytes
}

impl Memo {
    pub fn parse_memoblock(block: Vec<u8>, txtype: TxType) -> Memo {
        let fee_raw = &block[0..8];
        let mut offset: usize = 8;

        let mut amount_raw: Vec<u8> = Vec::new();
        let mut receiver_raw: Vec<u8> = Vec::new();
        if txtype == TxType::Withdrawal {
            amount_raw = block[offset..offset+8].to_vec();
            receiver_raw = block[offset+8..offset+8+20].to_vec();
            offset += 28;
        }

        let items_num_raw = &block[offset..offset+1];
        let items_num = u32::from_str_radix(&hex::encode(items_num_raw), 16).unwrap();
        offset += 4;

        let acc_hash_raw = block[offset..offset+32].to_vec();
        offset += 32;

        let mut notes_hashes_raw: Vec<Vec<u8>> = Vec::new();
        for _note_idx in 0..(items_num - 1) as usize {
            notes_hashes_raw.push(block[offset..offset+32].to_vec());
            offset += 32;
        }

        let a_p = block[offset..offset+32].to_vec();
        offset += 32;

        let keys_enc_raw = block[offset..offset+(items_num as usize)*32+16].to_vec();
        offset += (items_num as usize)*32+16;

        let acc_enc_raw = block[offset..offset+86].to_vec();
        offset += 86;

        let mut notes_enc_raw: Vec<Vec<u8>> = Vec::new();
        for _note_idx in 0..(items_num - 1) as usize {
            notes_enc_raw.push(block[offset..offset+108].to_vec());
            offset += 108;
        }


        Memo {
            fee: u64::from_str_radix(&hex::encode(fee_raw), 16).unwrap(),
            amount: u64::from_str_radix(&hex::encode(amount_raw), 16).unwrap_or(0),
            receiver: hex::encode(receiver_raw),
            items_num: items_num,
            acc_hash: acc_hash_raw,
            notes_hashes: notes_hashes_raw,
            a_p: a_p,
            keys_enc: keys_enc_raw,
            acc_enc: acc_enc_raw,
            notes_enc: notes_enc_raw,
        }
    }
}