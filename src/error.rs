#[derive(Debug)]
pub struct SigningError {
    pub cause: SigningErrorCause,
}

#[derive(Debug)]
pub enum SigningErrorCause {
    HttpErrorAws { code: u32, response: String },
    InvalidKeyLength(String),
}
