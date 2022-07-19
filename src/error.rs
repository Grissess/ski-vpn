#[derive(Debug)]
pub enum ErrorKind {
    InvalidBits(u8),
    NoRoute(std::net::Ipv4Addr),
    InvalidDataType,
}

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    SQLite(sqlite::Error),
    SKI(ski::error::Error),
    VPN(ErrorKind),
}

macro_rules! impl_from {
    ($type:ty, $variant:tt) => {
        impl From<$type> for Error {
            fn from(e: $type) -> Self { Self::$variant(e) }
        }
    }
}

impl_from!(std::io::Error, IO);
impl_from!(sqlite::Error, SQLite);
impl_from!(ski::error::Error, SKI);
impl_from!(ErrorKind, VPN);

pub type Result<T> = std::result::Result<T, Error>;
