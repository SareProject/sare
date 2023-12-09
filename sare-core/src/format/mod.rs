pub mod encryption;
pub mod header;
pub mod keys;
pub mod signature;

#[derive(Debug)]
pub enum FormatError {
    FailedToDecode,
}
