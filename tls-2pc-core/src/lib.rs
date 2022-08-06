#[cfg(feature = "ghash")]
pub mod ghash;
#[cfg(feature = "handshake")]
pub mod handshake;
pub mod msgs;

#[cfg(feature = "c1")]
pub static CIRCUIT_1: &'static [u8] = std::include_bytes!("../circuits/c1.bin");
#[cfg(feature = "c2")]
pub static CIRCUIT_2: &'static [u8] = std::include_bytes!("../circuits/c2.bin");
#[cfg(feature = "c3")]
pub static CIRCUIT_3: &'static [u8] = std::include_bytes!("../circuits/c3.bin");
#[cfg(feature = "c4")]
pub static CIRCUIT_4: &'static [u8] = std::include_bytes!("../circuits/c4.bin");
#[cfg(feature = "c5")]
pub static CIRCUIT_5: &'static [u8] = std::include_bytes!("../circuits/c5.bin");
#[cfg(feature = "c6")]
pub static CIRCUIT_6: &'static [u8] = std::include_bytes!("../circuits/c6.bin");
#[cfg(feature = "c7")]
pub static CIRCUIT_7: &'static [u8] = std::include_bytes!("../circuits/c7.bin");