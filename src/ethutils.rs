use web3;
use web3::types::{TransactionId, H256};

use crate::errors::MemoParserError;
extern crate hex;

pub async fn get_calldata(tx_hash: String, rpc: String) -> Result<String, MemoParserError> {
    let transport = web3::transports::Http::new(&rpc).unwrap();
    let web3 = web3::Web3::new(transport);

    if tx_hash.len() != 64 {
        return Err(MemoParserError::ParseError("Incorrect tx hash".to_string()))
    }

    let fixed_hash_bytes: [u8; 32] = hex::decode(tx_hash)
        .unwrap()
        .try_into()
        .unwrap();

    let tx_id = TransactionId::from(H256(fixed_hash_bytes));
    let req_result = web3.eth().transaction(tx_id).await.unwrap();

    match req_result {
        Some(tx) => Ok(hex::encode(tx.input.0)),
        None => Err(MemoParserError::FetchError("hash not found or network error".to_string())),
    }
}