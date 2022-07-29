
pub(crate) use std::fmt;

#[derive(Copy, Clone, PartialEq)]
pub enum TxType {
    Deposit = 0,
    Transfer = 1,
    Withdrawal = 2,
    DepositPermittable = 3,
}

impl TxType {
    pub fn from_u32(value: u32) -> TxType {
        match value {
            0 => TxType::Deposit,
            1 => TxType::Transfer,
            2 => TxType::Withdrawal,
            3 => TxType::DepositPermittable,
            _ => panic!("Unknown tx type ({})", value),
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            TxType::Deposit => 0,
            TxType::Transfer => 1,
            TxType::Withdrawal => 2,
            TxType::DepositPermittable => 3,
        }
    }
}

impl fmt::Display for TxType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TxType::Deposit => write!(f, "Deposit"),
            TxType::Transfer => write!(f, "Transfer"),
            TxType::Withdrawal => write!(f, "Withdrawal"),
            TxType::DepositPermittable => write!(f, "DepositPermittable"),
        }
    }
}

#[derive(Clone)]
pub struct Memo {
    pub fee: u64,
    pub amount: u64,        // withdrawal only field
    pub receiver: String,   // withdrawal only field
    pub deadline: u64,      // permittable deposit only field
    pub holder: String,     // permittable deposit only field
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
        let mut deadline_raw: Vec<u8> = Vec::new();
        let mut holder_raw: Vec<u8> = Vec::new();
        if txtype == TxType::Withdrawal {
            amount_raw = block[offset..offset+8].to_vec();
            receiver_raw = block[offset+8..offset+8+20].to_vec();
            offset += 28;
        } else if txtype == TxType::DepositPermittable {
            deadline_raw = block[offset..offset+8].to_vec();
            holder_raw = block[offset+8..offset+8+20].to_vec();
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
            deadline: u64::from_str_radix(&hex::encode(deadline_raw), 16).unwrap_or(0),
            holder: hex::encode(holder_raw),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_deposit_permittable() {
        let data = "00000000009896800000000062e15368ffcf8fdee72ac11b5c542428b35eef5769c409f00100000087fb41aaa56d16e7d9ec4c59c402c83267456fa38977a727de21b91fd8bf7b1c1f96bc9c905604325ce22215362500952a9dacc358aa744a7723cddc55e03830c7386d956d3f810dcca3370fcd913c318009e4a8373821146a781be3b0a4360a65411d2b21821dfdd09f64da7ac3c7b16a55d62b777eacedf4d8838fde72d0fe0e298e4fc9c9ae9db8e7c40d9ccbfd7182819501776d2c2101a29bb8379b8e325ceff28aea04e421230f9331250f335b0a2c1bcac00ade1702c0d193ec8af996bf8010289969";
        let res = hex::decode(data);
        let parsed = Memo::parse_memoblock(res.unwrap(), TxType::DepositPermittable);
        assert_eq!(parsed.fee, 10000000);
        assert_eq!(parsed.amount, 0);
        assert_eq!(parsed.receiver, "");
        assert_eq!(parsed.deadline, 1658934120);
        assert_eq!(parsed.holder, "ffcf8fdee72ac11b5c542428b35eef5769c409f0");
        assert_eq!(parsed.items_num, 1);
        assert_eq!(parsed.acc_hash, [135, 251, 65, 170, 165, 109, 22, 231, 217, 236, 76, 89, 196, 2, 200, 50, 103, 69, 111, 163, 137, 119, 167, 39, 222, 33, 185, 31, 216, 191, 123, 28]);
        assert!(parsed.notes_hashes.is_empty());
        assert_eq!(parsed.a_p, [31, 150, 188, 156, 144, 86, 4, 50, 92, 226, 34, 21, 54, 37, 0, 149, 42, 157, 172, 195, 88, 170, 116, 74, 119, 35, 205, 220, 85, 224, 56, 48]);
        assert_eq!(parsed.keys_enc, [199, 56, 109, 149, 109, 63, 129, 13, 204, 163, 55, 15, 205, 145, 60, 49, 128, 9, 228, 168, 55, 56, 33, 20, 106, 120, 27, 227, 176, 164, 54, 10, 101, 65, 29, 43, 33, 130, 29, 253, 208, 159, 100, 218, 122, 195, 199, 177]);
        assert_eq!(parsed.acc_enc, [106, 85, 214, 43, 119, 126, 172, 237, 244, 216, 131, 143, 222, 114, 208, 254, 14, 41, 142, 79, 201, 201, 174, 157, 184, 231, 196, 13, 156, 203, 253, 113, 130, 129, 149, 1, 119, 109, 44, 33, 1, 162, 155, 184, 55, 155, 142, 50, 92, 239, 242, 138, 234, 4, 228, 33, 35, 15, 147, 49, 37, 15, 51, 91, 10, 44, 27, 202, 192, 10, 222, 23, 2, 192, 209, 147, 236, 138, 249, 150, 191, 128, 16, 40, 153, 105]);
        assert!(parsed.notes_enc.is_empty());
    }

    #[test]
    fn parse_transfer() {
        let data = "000000000098968002000000b5b9df94791305ea7563234b563b01db73d70ff02a41b306b9eea01197fd942c850f816d1835fa3bdadbb223367e1344533e1d4e0cbd90f36c067589266b8802cc6bdf18540b74d7aed60bd2f176e01cb71c40c74065fe94ca6e42c511b3341b39f54533eeb239ea3957dd62200dba111b4dd38bc5d51b52582d5ad7d41f87be64306ce0615d3cffba77e6dc1b8e7d59f4553cbee37744a6888a1f88dfbd33c98428877a066d3fd734ceda45071fe3f8a3a7a98a18d83405d180d7b1460cf7e73f871a55e26d4397e33cc3fc9c81422a448b189a660767ffc58ec13f70bf79b1ba099562c813a294673649576f910db169db800c741e079fff24f993cb35e732243911b30bc9b0b5e0d4654ff6dbb9f42614fe8943a38c7ca30e48bc048107b1ef9e7e24d51f99ab65faf146222dc1de58069be027a8a5e2b978aaf2a5397fff3a563e96558a66018e59612b740983bdc81d5612416cf202aad6f0ad572a93200915ecac2cb77bbca594ce41a255935bfa4d";
        let res = hex::decode(data);
        let parsed = Memo::parse_memoblock(res.unwrap(), TxType::Transfer);
        assert_eq!(parsed.fee, 10000000);
        assert_eq!(parsed.amount, 0);
        assert_eq!(parsed.receiver, "");
        assert_eq!(parsed.deadline, 0);
        assert_eq!(parsed.holder, "");
        assert_eq!(parsed.items_num, 2);
        assert_eq!(parsed.acc_hash, [181, 185, 223, 148, 121, 19, 5, 234, 117, 99, 35, 75, 86, 59, 1, 219, 115, 215, 15, 240, 42, 65, 179, 6, 185, 238, 160, 17, 151, 253, 148, 44]);
        assert_eq!(parsed.notes_hashes, [[133, 15, 129, 109, 24, 53, 250, 59, 218, 219, 178, 35, 54, 126, 19, 68, 83, 62, 29, 78, 12, 189, 144, 243, 108, 6, 117, 137, 38, 107, 136, 2]]);
        assert_eq!(parsed.a_p, [204, 107, 223, 24, 84, 11, 116, 215, 174, 214, 11, 210, 241, 118, 224, 28, 183, 28, 64, 199, 64, 101, 254, 148, 202, 110, 66, 197, 17, 179, 52, 27]);
        assert_eq!(parsed.keys_enc, [57, 245, 69, 51, 238, 178, 57, 234, 57, 87, 221, 98, 32, 13, 186, 17, 27, 77, 211, 139, 197, 213, 27, 82, 88, 45, 90, 215, 212, 31, 135, 190, 100, 48, 108, 224, 97, 93, 60, 255, 186, 119, 230, 220, 27, 142, 125, 89, 244, 85, 60, 190, 227, 119, 68, 166, 136, 138, 31, 136, 223, 189, 51, 201, 132, 40, 135, 122, 6, 109, 63, 215, 52, 206, 218, 69, 7, 31, 227, 248]);
        assert_eq!(parsed.acc_enc, [163, 167, 169, 138, 24, 216, 52, 5, 209, 128, 215, 177, 70, 12, 247, 231, 63, 135, 26, 85, 226, 109, 67, 151, 227, 60, 195, 252, 156, 129, 66, 42, 68, 139, 24, 154, 102, 7, 103, 255, 197, 142, 193, 63, 112, 191, 121, 177, 186, 9, 149, 98, 200, 19, 162, 148, 103, 54, 73, 87, 111, 145, 13, 177, 105, 219, 128, 12, 116, 30, 7, 159, 255, 36, 249, 147, 203, 53, 231, 50, 36, 57, 17, 179, 11, 201]);
        assert_eq!(parsed.notes_enc, [[176, 181, 224, 212, 101, 79, 246, 219, 185, 244, 38, 20, 254, 137, 67, 163, 140, 124, 163, 14, 72, 188, 4, 129, 7, 177, 239, 158, 126, 36, 213, 31, 153, 171, 101, 250, 241, 70, 34, 45, 193, 222, 88, 6, 155, 224, 39, 168, 165, 226, 185, 120, 170, 242, 165, 57, 127, 255, 58, 86, 62, 150, 85, 138, 102, 1, 142, 89, 97, 43, 116, 9, 131, 189, 200, 29, 86, 18, 65, 108, 242, 2, 170, 214, 240, 173, 87, 42, 147, 32, 9, 21, 236, 172, 44, 183, 123, 188, 165, 148, 206, 65, 162, 85, 147, 91, 250, 77]]);
    }

    #[test]
    fn parse_withdrawal() {
        let data = "00000000009896800000000000000000ffcf8fdee72ac11b5c542428b35eef5769c409f001000000b1ae14b2bd52c7616b76e5919447232ec27204fbb5090c76ecb618fe8a2b6d015062794aa7b5bfc8033c001a3fde4d3d6575c1a2953681252ff3a49af14353093fc49a480122265c9fc66b26819f1d97577f3ac2a53a884046906bb976a949db223105a0b0bf15c41dfa00e6832a9d848c869582f3432284afe008777b9f1ddfb113308f6c490ae6386201080d0dc7102ac1b3521877518442da126d47ef4072686b8a4e43e20057026959cd4952f20535ac43ecbc45846225e902b3022c89d393d8dae2241b";
        let res = hex::decode(data);
        let parsed = Memo::parse_memoblock(res.unwrap(), TxType::Withdrawal);

        assert_eq!(parsed.fee, 10000000);
        assert_eq!(parsed.amount, 0);
        assert_eq!(parsed.receiver, "ffcf8fdee72ac11b5c542428b35eef5769c409f0");
        assert_eq!(parsed.deadline, 0);
        assert_eq!(parsed.holder, "");
        assert_eq!(parsed.items_num, 1);
        assert_eq!(parsed.acc_hash, [177, 174, 20, 178, 189, 82, 199, 97, 107, 118, 229, 145, 148, 71, 35, 46, 194, 114, 4, 251, 181, 9, 12, 118, 236, 182, 24, 254, 138, 43, 109, 1]);
        assert!(parsed.notes_hashes.is_empty());
        assert_eq!(parsed.a_p, [80, 98, 121, 74, 167, 181, 191, 200, 3, 60, 0, 26, 63, 222, 77, 61, 101, 117, 193, 162, 149, 54, 129, 37, 47, 243, 164, 154, 241, 67, 83, 9]);
        assert_eq!(parsed.keys_enc, [63, 196, 154, 72, 1, 34, 38, 92, 159, 198, 107, 38, 129, 159, 29, 151, 87, 127, 58, 194, 165, 58, 136, 64, 70, 144, 107, 185, 118, 169, 73, 219, 34, 49, 5, 160, 176, 191, 21, 196, 29, 250, 0, 230, 131, 42, 157, 132]);
        assert_eq!(parsed.acc_enc, [140, 134, 149, 130, 243, 67, 34, 132, 175, 224, 8, 119, 123, 159, 29, 223, 177, 19, 48, 143, 108, 73, 10, 230, 56, 98, 1, 8, 13, 13, 199, 16, 42, 193, 179, 82, 24, 119, 81, 132, 66, 218, 18, 109, 71, 239, 64, 114, 104, 107, 138, 78, 67, 226, 0, 87, 2, 105, 89, 205, 73, 82, 242, 5, 53, 172, 67, 236, 188, 69, 132, 98, 37, 233, 2, 179, 2, 44, 137, 211, 147, 216, 218, 226, 36, 27]);
        assert!(parsed.notes_enc.is_empty());
    }
}