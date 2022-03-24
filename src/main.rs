mod memoparser;
mod memo;
mod ethutils;

use std::io::Result;
use tokio;
use clap::Parser;
pub use memo::TxType;
pub use memo::Memo;

pub const ETHEREUM_RPC: &str = "https://kovan.infura.io/v3/84842078b09946638c03157f83405213";

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct Cli {
    /// The pattern to look for
    calldata_or_tx_hash: String,
}

#[tokio::main]
async fn main() -> web3::Result<()> {
    let args = Cli::parse();
    let calldata = &args.calldata_or_tx_hash;

    let mut unprefixed = calldata.clone();
    if unprefixed.chars().nth(1) == Some('x') || unprefixed.chars().nth(1) == Some('X') {
        unprefixed.remove(0);
        unprefixed.remove(0);
    }
    
    if unprefixed.len() == 64 {
        // It's probably a transaction hash => fetch calldata
        let calldata = ethutils::get_calldata(unprefixed, ETHEREUM_RPC.to_string()).await.unwrap();
        println!("Fetched calldata: {} bytes", calldata.len() / 2);
        memoparser::parse_calldata(calldata, ETHEREUM_RPC.to_string());
    } else {
        memoparser::parse_calldata(unprefixed, ETHEREUM_RPC.to_string());
    }

    Ok(())
}