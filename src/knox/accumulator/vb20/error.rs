/// An accumulator error
#[derive(Clone, Debug)]
pub struct Error {
    /// The string message
    pub message: String,
    /// The code number of the error
    pub code: usize,
}

impl Error {
    /// Create a message from a number and string
    pub fn from_msg(code: usize, message: &str) -> Self {
        Self {
            code,
            message: String::from(message),
        }
    }
}