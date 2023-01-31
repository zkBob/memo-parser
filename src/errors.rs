
use std::fmt::Display;
use colored::Colorize;

#[derive(Debug)]
pub enum MemoParserError {
    ParseError(String),
    FetchError(String),
    InternalError(String),
}

impl Display for MemoParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoParserError::ParseError(message) => write!(f, "{}: {}", "cannot parse calldata".red(), message),
            MemoParserError::FetchError(message) => write!(f, "{}: {}", "cannot fetch calldata".red(), message),
            MemoParserError::InternalError(message) => write!(f, "{}: {}", "internal error".red(), message),
        }
    }
}