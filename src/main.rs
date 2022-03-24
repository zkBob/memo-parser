use thousands::Separable;
pub(crate) use std::i128;
pub(crate) use std::fmt;
use clap::Parser;
extern crate hex;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct Cli {
    /// The pattern to look for
    calldata: String,
}

#[derive(Copy, Clone, PartialEq)]
enum TxType {
    Deposit = 0,
    Transfer = 1,
    Withdrawal = 2,
}

impl TxType {
    fn from_u32(value: u32) -> TxType {
        match value {
            0 => TxType::Deposit,
            1 => TxType::Transfer,
            2 => TxType::Withdrawal,
            _ => panic!("Unknown tx type ({})", value),
        }
    }

    fn to_u32(&self) -> u32 {
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

struct Memo {
    fee: u64,
    amount: u64,
    receiver: String,
    items_num: u32,
    acc_hash: Vec<u8>,
    notes_hashes: Vec<Vec<u8>>, // 32 x (items_num - 1) bytes
    A_p: Vec<u8>,               // 32 bytes
    keys_enc: Vec<u8>,          // 32 * items_num + 16
    acc_enc: Vec<u8>,           // 86 bytes
    notes_enc: Vec<Vec<u8>>,    // 108 x (items_num - 1) bytes
}

impl Memo {
    fn parse_memoblock(block: Vec<u8>, txtype: TxType) -> Memo {
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

        Memo {
            fee: u64::from_str_radix(&hex::encode(fee_raw), 16).unwrap(),
            amount: u64::from_str_radix(&hex::encode(amount_raw), 16).unwrap_or(0),
            receiver: hex::encode(receiver_raw),
            items_num: items_num,
            acc_hash: acc_hash_raw,
            notes_hashes: notes_hashes_raw,
            A_p: Vec::new(),
            keys_enc: Vec::new(),
            acc_enc: Vec::new(),
            notes_enc: Vec::new(),
        }
    }
}


fn main() {
    let args = Cli::parse();
    let calldata = &args.calldata;

    let mut unprefixed_calldata = calldata.clone();
    if unprefixed_calldata.chars().nth(1) == Some('x') || unprefixed_calldata.chars().nth(1) == Some('X') {
        unprefixed_calldata.remove(0);
        unprefixed_calldata.remove(0);
    }

    let res = hex::decode(unprefixed_calldata);
    let bytes = match res {
        Ok(vec) => vec,
        Err(err) => panic!("Cannot parse the input hex string: {:?}", err),
    };
    
    println!("Calldata length: {}", bytes.len());

    let selector = &bytes[0..4];
    let nullifier = &bytes[4..36];
    let commit = &bytes[36..68];
    let index_raw = &bytes[68..74];
    let index = u64::from_str_radix(&hex::encode(index_raw), 16).unwrap();
    let delta_energy_raw = &bytes[74..88];
    let delta_energy = i128::from_str_radix(&hex::encode(delta_energy_raw), 16).unwrap();
    let delta_token_raw = &bytes[88..96];
    let delta_token = i64::from_str_radix(&hex::encode(delta_token_raw), 16).unwrap();
    let tx_proof = &bytes[96..352];
    let root_after = &bytes[352..384];
    let tree_proof = &bytes[384..640];
    let tx_type_raw = &bytes[640..642];
    let tx_type = TxType::from_u32(u32::from_str_radix(&hex::encode(tx_type_raw), 16).unwrap());
    let memo_size_raw = &bytes[642..644];
    let memo_size = u32::from_str_radix(&hex::encode(memo_size_raw), 16).unwrap();

    println!("Selector       : 0x{}", hex::encode(selector));
    assert_eq!(hex::encode(selector), "af989083");

    println!("Nullifier      : 0x{}", hex::encode(nullifier));
    println!("Commitnment    : 0x{}", hex::encode(commit));
    println!("Index          : {} (0x{:x})", index, index);
    println!("Energy delta   : {} (0x{:x})", delta_energy.separate_with_commas(), delta_energy);
    println!("Token delta    : {} (0x{:x})", delta_token.separate_with_commas(), delta_token);
    println!("Tx proof       : {}", hex::encode(tx_proof));
    println!("New Merkle Root: {}", hex::encode(root_after));
    println!("Tree proof     : {}", hex::encode(tree_proof));
    println!("Tx type        : {} ({})", tx_type.to_string(), tx_type.to_u32());
    println!("Memo size      : {} bytes", memo_size);

    let memo = Memo::parse_memoblock(Vec::from(&bytes[644..(644+memo_size) as usize]), tx_type);
    println!("--------------- MEMO BLOCK ---------------");
    println!("Tx fee         : {} (0x{:x})", memo.fee.separate_with_commas(), memo.fee);
    println!("Items number   : {}", memo.items_num);
    if tx_type == TxType::Withdrawal {
        println!("Withdraw amount: {} (0x{:x})", memo.amount.separate_with_commas(), memo.amount);
        println!("Withdraw addr  : {}", memo.receiver);
    }
    println!("Account hash   : {}", hex::encode(memo.acc_hash));
    for (note_idx, note_hash) in memo.notes_hashes.iter().enumerate() {
        println!("Note #{} hash   : {}", note_idx, hex::encode(note_hash));
    }
    println!("A_p            : {}", hex::encode(memo.A_p));
    println!("Encrypted keys : {}", hex::encode(memo.keys_enc));
    for (note_idx, enc_note) in memo.notes_enc.iter().enumerate() {
        println!("Encrypt note #{}: {}", note_idx, hex::encode(enc_note));
    };

}