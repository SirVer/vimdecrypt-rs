use sha2;
use vimdecrypt;

use sha2::Digest;
use std::fs;

const PASSWORD: &str = "blubberfish";
const GOLDEN_SHA: &str = "349923fdc426f96a6459dfe7a9665804c17ce6e27d0c6516e161bff00d31d3ab";

fn sha256_digest(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::default();
    hasher.update(data);
    let bytes = hasher.finalize().to_vec();
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    strs.join("")
}

fn decrypt_and_hash(file: &str) -> String {
    let data = fs::read(file).expect("Could not read input file.");
    let cleartxt = vimdecrypt::decrypt(&data, &PASSWORD).expect("Decryption failed.");
    sha256_digest(&cleartxt)
}

#[test]
fn test_pkzip() {
    assert_eq!(decrypt_and_hash("data/lorem_pkzip.txt"), GOLDEN_SHA);
}

#[test]
fn test_blowfish() {
    assert_eq!(decrypt_and_hash("data/lorem_blowfish.txt"), GOLDEN_SHA);
}

#[test]
fn test_blowfish2() {
    assert_eq!(decrypt_and_hash("data/lorem_blowfish2.txt"), GOLDEN_SHA);
}
