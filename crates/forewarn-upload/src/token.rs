//! The bearer token of an upload (UPL-7), never written in a debug form or an error (UPL-4).

use std::fmt;

/// A bearer token of visible ASCII characters (UPL-7); its debug form writes nothing of it (UPL-4).
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

/// A token refused before anything is sent, naming no character of it (UPL-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidToken {
    Empty,
    /// A character outside `!` to `~`.
    Character,
}

impl fmt::Display for InvalidToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the token is empty"),
            Self::Character => f.write_str(
                "the token holds a character other than the visible ASCII characters `!` to `~`",
            ),
        }
    }
}

impl std::error::Error for InvalidToken {}

impl Token {
    /// Checks a token (UPL-7).
    ///
    /// # Errors
    /// [`InvalidToken`] for an empty token, or one holding a character outside `!` to `~`.
    pub fn new(token: String) -> Result<Self, InvalidToken> {
        if token.is_empty() {
            Err(InvalidToken::Empty)
        } else if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            Err(InvalidToken::Character)
        } else {
            Ok(Self(token))
        }
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(***)")
    }
}
