// Implementation heavily lifted from https://github.com/nlitsme/vimdecrypt.

//!# A simple crate to decrypt Vim encrypted files.

#![deny(
    missing_docs,
    missing_debug_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]

use blowfish;
use blowfish::BlockCipher;
use failure::Fail;
use generic_array::GenericArray;
use sha2;
use sha2::Digest;
use std::fmt;

/// Error codes that can be returned by this library.
#[derive(Fail, Debug, Copy, Clone)]
pub enum Error {
    /// Unknown VimCrypt method. Only 01-03 are supported, i.e. up to Vim 8.
    #[fail(display = "Unknown VimCrypt header.")]
    UnknownCryptMethod,
}

/// Result type returned by this library.
pub type Result<T> = ::std::result::Result<T, Error>;

/// The method used to encrypt this data.
#[derive(Debug)]
pub enum CryptMethod {
    /// The 'zip' method.
    Zip,

    /// The 'blowfish' method.
    Blowfish,

    /// The 'blowfish2' method.
    Blowfish2,
}

impl fmt::Display for CryptMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            CryptMethod::Zip => "zip",
            CryptMethod::Blowfish => "blowfish",
            CryptMethod::Blowfish2 => "blowfish2",
        };
        write!(f, "{}", s)
    }
}

impl CryptMethod {
    fn from_header(data: &[u8]) -> Result<Self> {
        match &data[0..12] {
            b"VimCrypt~01!" => Ok(CryptMethod::Zip),
            b"VimCrypt~02!" => Ok(CryptMethod::Blowfish),
            b"VimCrypt~03!" => Ok(CryptMethod::Blowfish2),
            _ => Err(Error::UnknownCryptMethod),
        }
    }
}

fn make_crc_table(seed: u32) -> Vec<u32> {
    fn calc_entry(mut v: u32, seed: u32) -> u32 {
        for _ in 0..8 {
            v = (v >> 1) ^ (if v & 1 != 0 { seed } else { 0 })
        }
        v
    }

    (0..256).map(|b| calc_entry(b, seed)).collect()
}

fn zip_decrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let crc_table = make_crc_table(0xedb8_8320);

    let crc32 = |crc, byte: u8| crc_table[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    let mut keys = [0x1234_5678, 0x2345_6789, 0x3456_7890];
    let update_keys = |keys: &mut [u32], byte| {
        keys[0] = crc32(keys[0], byte);
        keys[1] = (keys[1] + (keys[0] & 0xFF)).wrapping_mul(134_775_813) + 1;
        keys[2] = crc32(keys[2], (keys[1] >> 24) as u8);
    };

    for c in password.chars() {
        update_keys(&mut keys, c as u8);
    }

    let mut plain_text = Vec::with_capacity(data.len());
    for b in data {
        let xor = (keys[2] | 2) & 0xFFFF;
        let xor = ((xor * (xor ^ 1)) >> 8) & 0xFF;
        let b = b ^ (xor as u8);
        plain_text.push(b);
        update_keys(&mut keys, b);
    }
    Ok(plain_text)
}

fn sha256(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::default();
    hasher.input(password);
    hasher.input(salt);
    hasher.result().to_vec()
}

fn to_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    strs.join("")
}

fn hashpw(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut key = sha256(password.as_bytes(), salt);
    for _ in 0..1000 {
        key = sha256(to_hex_string(&key).as_bytes(), salt);
    }
    key
}

fn wordswap(a: &mut [u8]) {
    assert_eq!(a.len(), 8);
    a.swap(0, 3);
    a.swap(1, 2);
    a.swap(4, 7);
    a.swap(5, 6);
}

fn blowfish_decrypt(all_data: &[u8], password: &str) -> Result<Vec<u8>> {
    let salt = &all_data[0..8];
    let iv = &all_data[8..16];
    let data = all_data[16..].to_vec();

    let key = hashpw(password, salt);
    let bf = blowfish::Blowfish::new_varkey(&key).unwrap();

    let mut xor = iv.to_vec();
    wordswap(&mut xor);
    bf.encrypt_block(GenericArray::from_mut_slice(&mut xor));
    wordswap(&mut xor);
    let mut plaintext = Vec::new();
    for o in 0..data.len() {
        if o >= 64 && o % 8 == 0 {
            xor = data[o - 64..(o - 64 + 8).min(data.len())].to_vec();
            wordswap(&mut xor);
            bf.encrypt_block(&mut GenericArray::from_mut_slice(&mut xor));
            wordswap(&mut xor);
        }
        plaintext.push(xor[o % 8] ^ data[o]);
    }
    Ok(plaintext)
}

fn blowfish2_decrypt(all_data: &[u8], password: &str) -> Result<Vec<u8>> {
    let salt = &all_data[0..8];
    let mut iv = all_data[8..16].to_vec();
    let data = all_data[16..].to_vec();

    let key = hashpw(password, salt);
    let bf = blowfish::Blowfish::new_varkey(&key).unwrap();

    let mut xor = vec![8; 0];
    let mut plaintext = Vec::new();
    for o in 0..data.len() {
        if o % 8 == 0 {
            wordswap(&mut iv);
            bf.encrypt_block(&mut GenericArray::from_mut_slice(&mut iv));
            wordswap(&mut iv);
            xor = iv;
            iv = data[o..(o + 8).min(data.len())].to_vec();
        }
        plaintext.push(xor[o % 8] ^ data[o]);
    }
    Ok(plaintext)
}

/// Decrypts `data` using `password`. The `data` blob needs to start with the magic bytes of Vim
/// crypt files, i.e. `VimCrypt~`.
///
/// # Errors
///
/// Returns `Error::UnknownCrpytMethod` if the header is invalid.
/// A wrong password is not an error case, the returned value will just be scrambled.
pub fn decrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let method = CryptMethod::from_header(&data[0..12])?;
    let data = match method {
        CryptMethod::Zip => zip_decrypt(&data[12..], password)?,
        CryptMethod::Blowfish => blowfish_decrypt(&data[12..], password)?,
        CryptMethod::Blowfish2 => blowfish2_decrypt(&data[12..], password)?,
    };
    Ok(data)
}

/// Returns the CryptMethod that was used on this file.
pub fn get_crypt_method(data: &[u8]) -> Result<CryptMethod> {
    Ok(CryptMethod::from_header(&data[0..12])?)
}
