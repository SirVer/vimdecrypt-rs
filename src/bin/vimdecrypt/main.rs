use clap::Parser;
use std::fs;
use std::path::PathBuf;

/// Decrypts files encrpyted with Vim.
#[derive(Parser, Debug)]
#[clap(name = "vimdecrypt", author = "Holger H. Rapp <SirVer@gmx.de>")]
struct Args {
    /// The files to process.
    #[clap(value_name = "FILE")]
    input: Vec<PathBuf>,

    /// Do not decrypt files, instead print out which 'cryptmethod' they are using.
    #[clap(short)]
    test: bool,
}

fn main() {
    let args = Args::from_args();
    if args.input.is_empty() {
        panic!("Requires input arguments!");
    }

    let mut password = None;

    for input in &args.input {
        let data = fs::read(input).expect("Could not read input file.");
        if args.test {
            println!(
                "{} {}",
                input.to_string_lossy(),
                vimdecrypt::get_crypt_method(&data).unwrap()
            );
        } else {
            if password.is_none() {
                password = Some(rpassword::prompt_password("Password: ").unwrap());
            }
            let result =
                vimdecrypt::decrypt(&data, password.as_ref().unwrap()).expect("Decryption failed.");
            println!("{}", String::from_utf8(result).unwrap());
        }
    }
}
