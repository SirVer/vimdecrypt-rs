// Implementation heavily lifted from https://github.com/nlitsme/vimdecrypt.

#[macro_use]
extern crate failure;
extern crate blowfish;
extern crate generic_array;
extern crate sha2;

use blowfish::BlockCipher;
use generic_array::GenericArray;
use sha2::Digest;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[derive(Debug)]
enum CryptMethod {
    Zip,
    Blowfish,
    Blowfish2,
}

impl CryptMethod {
    fn from_header(data: &[u8]) -> Result<Self> {
        match &data[0..12] {
            b"VimCrypt~01!" => Ok(CryptMethod::Zip),
            b"VimCrypt~02!" => Ok(CryptMethod::Blowfish),
            b"VimCrypt~03!" => Ok(CryptMethod::Blowfish2),
            _ => bail!("Unknown VimCrypt header."),
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

pub fn zip_decrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let crc_table = make_crc_table(0xedb88320);

    let crc32 = |crc, byte: u8| crc_table[((crc ^ (byte as u32)) & 0xff) as usize] ^ (crc >> 8);
    let mut keys = [0x12345678u32, 0x23456789u32, 0x34567890u32];
    let update_keys = |keys: &mut [u32], byte| {
        keys[0] = crc32(keys[0], byte);
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF;
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

pub fn to_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    strs.join("")
}

fn hashpw(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut key = sha256(password.as_bytes(), salt);
    for _ in 0..1000 {
        key = sha256(to_hex_string(&key).as_bytes(), salt);
    }
    key.into()
}

fn wordswap(a: &mut [u8]) {
    assert_eq!(a.len(), 8);
    a.swap(0, 3);
    a.swap(1, 2);
    a.swap(4, 7);
    a.swap(5, 6);
}

pub fn blowfish_decrypt(all_data: &[u8], password: &str) -> Result<Vec<u8>> {
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
        plaintext.push(xor[(o % 8) as usize] ^ data[o]);
    }
    Ok(plaintext)
}

pub fn blowfish2_decrypt(all_data: &[u8], password: &str) -> Result<Vec<u8>> {
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
        plaintext.push(xor[(o % 8) as usize] ^ data[o]);
    }
    Ok(plaintext)
}

pub fn decrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let method = CryptMethod::from_header(&data[0..12])?;
    let data = match method {
        CryptMethod::Zip => zip_decrypt(&data[12..], password)?,
        CryptMethod::Blowfish => blowfish_decrypt(&data[12..], password)?,
        CryptMethod::Blowfish2 => blowfish2_decrypt(&data[12..], password)?,
    };
    Ok(data)
}
