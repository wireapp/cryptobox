use std::env;
use std::num::ParseIntError;

use proteus::message::Envelope;

fn hex_str_to_bytes(val: &str) -> Vec<u8> {
    let b: Result<Vec<u8>, ParseIntError> = (0..val.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&val[i..i + 2], 16))
        .collect();
    b.expect("Error parsing hex string")
}

fn print_envelope(env: &Envelope) -> String {
    format!(
        "Envelope {{\n  version: {}\n  mac: {:x?}\n  message: {:x?}\n  message_enc: {:x?}\n}}",
        env.version(),
        env.mac().clone().into_bytes(),
        ":(", // env.message(),
        ":(",
    )
}

const TEST_INPUT: &'static str = "a3000101a10058202ce629de396eae75ac68ea1960927f1f8bfb1800784aeba1b1edd7da7f73407002587401a500508ddd1ef84f4268b86d168deb8220c6ef0100020103a1005820dc1fb8e290d774fdd5788da9c3cc729fc6a49a674fb5d742cf705a413d071bd304583450ec6e2c71a3792f399f4f572b91ad263a624185b68da6f75c0374bea8ca85ec00747959fe69463d7eb8e526cfbefe9023199691";

fn main() {
    let args: Vec<_> = env::args().collect();
    let data = match args.len() {
        2 => &args[1],
        _ => {
            println!(
                "Please provide the serialised data as input on the cli.\nUsing default value ..."
            );
            TEST_INPUT
        }
    };

    println!("Parsing {}\n ...", data);
    let data_bytes = hex_str_to_bytes(&data);
    let env = match Envelope::deserialise(&data_bytes) {
        Ok(v) => v,
        Err(e) => panic!("Couldn't deserialise: \'{}\'", e),
    };
    println!("envelope: {:x?}", env);
}
