mod memoparser;
mod memo;
mod ethutils;
mod errors;

use dotenv::dotenv;
use tokio;
use colored::Colorize;
use clap::Parser;

pub use memo::TxType;
pub use memo::Memo;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct Cli {
    /// The pattern to look for
    calldata_or_tx_hash: String,
}

#[tokio::main]
async fn main() -> web3::Result<()> {
    // Reading environment variables
    dotenv().ok();
    let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set");
    let network = std::env::var("NETWORK").unwrap_or("unknown".to_string());

    // Reading the single command line argument
    let args = Cli::parse();
    let calldata = &args.calldata_or_tx_hash;

    let mut unprefixed = calldata.clone();
    if unprefixed.chars().nth(1) == Some('x') || unprefixed.chars().nth(1) == Some('X') {
        unprefixed.remove(0);
        unprefixed.remove(0);
    }
    
    if unprefixed.len() == 64 {
        // It's probably a transaction hash => fetch calldata
        println!("\nWorking on {} network...", network.yellow());

        let calldata = ethutils::get_calldata(unprefixed, rpc_url.to_string()).await;
        match calldata {
            Ok(calldata) => {
                println!("Fetched calldata: {} bytes", calldata.len() / 2);
                let parsed = memoparser::parse_calldata(hex::decode(calldata).unwrap(), Some(rpc_url.to_string()));
                match parsed {
                    Ok(parsed) => println!("{}", parsed),
                    Err(err) => println!("{}: {}", "ERROR".red(), err),
                }
            },
            Err(err) => {
                println!("{}: {}", "ERROR".red(), err);
            }
        }
    } else {
        let parsed = memoparser::parse_calldata(hex::decode(calldata).unwrap(), Some(rpc_url.to_string()));
        match parsed {
            Ok(parsed) => println!("{}", parsed),
            Err(err) => println!("{}: {}", "ERROR".red(), err),
        }
    }

    Ok(())
}