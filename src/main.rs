extern crate clap;
extern crate rpassword;
extern crate vimdecrypt;

use std::fs;

fn parse_arguments() -> clap::ArgMatches<'static> {
    clap::App::new("vimdecrypt")
        .version("1.0")
        .author("Holger H. Rapp <SirVer@gmx.de>")
        .about("Decrypts files encrypted with Vim.")
        .arg(
            clap::Arg::with_name("input")
                .index(1)
                .required(true)
                .value_name("FILE")
                .help("The file to decrypt.")
                .takes_value(true),
        )
        .get_matches()
}

fn main() {
    let args = parse_arguments();

    let data = fs::read(args.value_of("input").unwrap()).expect("Could not read input file.");

    let password = rpassword::prompt_password_stdout("Password: ").unwrap();

    let result = vimdecrypt::decrypt(&data, &password).expect("Decryption failed.");
    println!("{}", String::from_utf8(result).unwrap());
}
