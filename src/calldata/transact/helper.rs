use web3::types::{Recovery, H256};
use crate::ethutils::bytes_to_address;

pub fn ecrecover(data: Vec<u8>, signature: Vec<u8>, rpc: String) -> String {
    // TODO: support Tron recovery
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
        return bytes_to_address(&addr_res.unwrap().0.to_vec(), crate::ethutils::L1AddressType::Ethereum).unwrap();
    } else {
        return "unavailable".to_string();
    }
}