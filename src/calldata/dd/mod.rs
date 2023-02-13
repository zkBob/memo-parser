use std::fmt::Display;
use thousands::Separable;
use crate::utils::print_long_hex;
use crate::errors::MemoParserError;
use bs58;



pub struct CalldataDirectDeposit {
    pub fallback_user: String,
    pub amount: u128,
    pub raw_zk_address: Vec<u8>,
}

impl CalldataDirectDeposit {
    pub fn new(bytes: &[u8]) -> Result<Self, MemoParserError> {
        if bytes.len() != 196 {
            return Err(MemoParserError::ParseError(format!(
                "Incorrect calldata length! It must contain 196 bytes for directDeposit() method"
            )));
        }

        let fallback = format!("0x{}", hex::encode(&bytes[16..36]));
        let amount = u128::from_str_radix(&hex::encode(&bytes[36..68]), 16).unwrap();
        let zk_address_length = usize::from_str_radix(&hex::encode(&bytes[100..132]), 16).unwrap();
        if bytes.len() - 132 < zk_address_length {
            return Err(MemoParserError::ParseError(format!(
                "Incorrect calldata length! No enough bytes for zkAddress field ({} bytes needed)", zk_address_length
            )));
        }

        Ok(CalldataDirectDeposit {
            fallback_user: fallback,
            amount,
            raw_zk_address: bytes[132..132 + zk_address_length].to_vec(),
        })
    }
}

impl Display for CalldataDirectDeposit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = String::new();
        result += &format!("Fallback address: {}\n", &self.fallback_user);
        result += &format!("Tokens amount   : {} Gwei (0x{:x})\n", (&self.amount / 1000000000).separate_with_commas(), &self.amount);
        result += &format!("Raw zk address  : {}\n", hex::encode(&self.raw_zk_address));
        result += &format!("    ...encoded  : {}\n", bs58::encode(&self.raw_zk_address).into_string());

        write!(f, "{}", result)
    }
}

pub struct CalldataAppendDirectDeposit {
    pub root_after: Vec<u8>,
    pub indices: Vec<u32>,
    pub commitment: Vec<u8>,
    pub dd_proof: Vec<u8>,
    pub tree_proof: Vec<u8>,
}

impl CalldataAppendDirectDeposit {
    pub fn new(bytes: &[u8]) -> Result<Self, MemoParserError> {
        if bytes.len() < 644 {
            return Err(MemoParserError::ParseError(format!(
                "Incorrect calldata length! It must contain 644 bytes for appendDirectDeposit() method"
            )));
        }

        let root_after = &bytes[4..36];
        let out_commit = &bytes[68..100];
        let dd_proof = &bytes[100..356];
        let tree_proof = &bytes[356..612];

        let idx_cnt = usize::from_str_radix(&hex::encode(&bytes[612..644]), 16).unwrap();
        if bytes.len() - 644 < idx_cnt * 32 {
            return Err(MemoParserError::ParseError(format!(
                "Incorrect calldata length! No enough bytes for indices field ({} bytes needed)", idx_cnt * 32
            )));
        }

        let indices: Vec<u32> = (0..idx_cnt)
            .into_iter()
            .map(|idx| 
                u32::from_str_radix(&hex::encode(&bytes[644 + idx * 32..676 + idx * 32]), 16).unwrap()
            )
            .collect();
        

        Ok(CalldataAppendDirectDeposit {
            root_after: root_after.to_vec(),
            indices: indices,
            commitment: out_commit.to_vec(),
            dd_proof: dd_proof.to_vec(),
            tree_proof: tree_proof.to_vec(),
        })
    }
}

impl Display for CalldataAppendDirectDeposit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result = String::new();
        result += &format!("New Merkle Root : {}\n", hex::encode(&self.root_after));
        result += &format!("Appended indices: {:?}\n", &self.indices);
        result += &format!("Commitment      : {}\n", hex::encode(&self.commitment));
        result += &print_long_hex("DD batch proof  : ".to_string(), hex::encode(&self.dd_proof), 64);
        result += &format!("\n");
        result += &print_long_hex("Tree proof      : ".to_string(), hex::encode(&self.tree_proof), 64);
        result += &format!("\n");

        write!(f, "{}", result)
    }
}

pub struct CalldataRefundDirectDeposit {
    pub indices: Vec<u32>,
}

impl CalldataRefundDirectDeposit {
    pub fn new(bytes: &[u8]) -> Result<Self, MemoParserError> {
        if bytes.len() == 36 {
            // selector d7f59caa: refundDirectDeposit(uint256)
            let index = u32::from_str_radix(&hex::encode(&bytes[4..36]), 16).unwrap();

            Ok(CalldataRefundDirectDeposit {indices: [index].to_vec()} )
        } else if bytes.len() >= 68 {
            // selector d7f59caa: refundDirectDeposit(uint256[])
            let idx_cnt = usize::from_str_radix(&hex::encode(&bytes[36..68]), 16).unwrap();
            if bytes.len() - 68 < idx_cnt * 32 {
                return Err(MemoParserError::ParseError(format!(
                    "Incorrect calldata length! No enough bytes for indices field ({} bytes needed)", idx_cnt * 32
                )));
            }

            let indices: Vec<u32> = (0..idx_cnt)
                .into_iter()
                .map(|idx| 
                    u32::from_str_radix(&hex::encode(&bytes[68 + idx * 32..100 + idx * 32]), 16).unwrap()
                )
                .collect();

            Ok(CalldataRefundDirectDeposit { indices })
        } else {
            return Err(MemoParserError::ParseError(format!(
                "Incorrect calldata length! It must contain 196 bytes for directDeposit() method"
            )));
        }
    }
}

impl Display for CalldataRefundDirectDeposit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Refund indices  : {:?}\n", &self.indices)
    }
}