use std::io::Result;
use web3;
use web3::types::{Recovery, TransactionId, H256};
extern crate hex;

pub async fn get_calldata(tx_hash: String, rpc: String) -> Result<String> {
    let transport = web3::transports::Http::new(&rpc).unwrap();
    let web3 = web3::Web3::new(transport);

    if tx_hash.len() < 64 {
        panic!("Incorrect tx hash");
    }

    let fixed_hash_bytes: [u8; 32] = hex::decode(tx_hash)
        .unwrap()
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length 32 but it was {}", v.len()));

    let tx_id = TransactionId::from(H256(fixed_hash_bytes));
    let req_result = web3.eth().transaction(tx_id).await.unwrap();

    let data = match req_result {
        Some(tx) => tx,
        None => panic!("Cannot fetch transaction"),
    };

    Ok(hex::encode(data.input.0))
}

pub fn ecrecover(data: Vec<u8>, signature: Vec<u8>, rpc: String) -> String {
    let transport = web3::transports::Http::new(&rpc).unwrap();
    let web3 = web3::Web3::new(transport);

    let recovery;
    if signature.len() == 64 {
        let r = H256::from_slice(&signature[0..32]);
        let v = signature[32] >> 7;
        let mut s_data: [u8; 32] = signature[32..64].try_into().unwrap();
        s_data[0] &= 0x7f;
        let s = H256::from_slice(&s_data);
        recovery = Recovery::new(data, 27 + v as u64, r, s);
    } else if signature.len() == 65 {
        recovery = match Recovery::from_raw_signature(data, signature) {
            Ok(rec) => rec,
            Err(_error) => return "signature_error".to_string(),
        }
    } else {
        return "<incorrect_signature>".to_string();
    }

    let addr_res = web3.accounts().recover(recovery);

    if addr_res.is_ok() {
        return hex::encode(addr_res.unwrap().0);
    } else {
        return "unavailable".to_string();
    }
}
