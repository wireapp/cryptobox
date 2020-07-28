use std::{env, fs, fs::File, fs::ReadDir, io::Read, num::ParseIntError, path::Path};

use cryptobox::{store::Store, CBox, CBoxSession};
use proteus::message::{Envelope, Message};

fn hex_str_to_bytes(val: &str) -> Vec<u8> {
    let b: Result<Vec<u8>, ParseIntError> = (0..val.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&val[i..i + 2], 16))
        .collect();
    b.expect("Error parsing hex string")
}

fn prettify(val: &str) {
    println!("Parsing {}\n ...", val);
    let data_bytes = hex_str_to_bytes(val);
    let env = match Envelope::deserialise(&data_bytes) {
        Ok(v) => v,
        Err(e) => panic!("Couldn't deserialise: \'{}\'", e),
    };
    println!("envelope: {:?}", env);
}

fn get_session<S: Store + std::fmt::Debug>(cbox: &CBox<S>, session_id: &str) -> CBoxSession<S> {
    match cbox.session_load(session_id.to_string()) {
        Ok(r) => match r {
            Some(s) => s,
            None => panic!("Couldn't load session {:?}", session_id),
        },
        Err(e) => panic!("Failed to open session :(\n{:?}", e),
    }
}

fn get_sessions_dir(path: &str) -> ReadDir {
    fs::read_dir(Path::new(path).join("sessions")).unwrap()
}

fn decrypt(path: &str, data: &str) {
    println!("Opening Cryptobox {}\n ...", path);
    let cbox = match CBox::file_open(&Path::new(path)) {
        Ok(c) => c,
        Err(e) => panic!("Couldn't load cryptobox session."),
    };

    let data_bytes = hex_str_to_bytes(data);
    println!("Parsing message ...");
    let env = match Envelope::deserialise(&data_bytes) {
        Ok(v) => v,
        Err(e) => panic!("Couldn't deserialise: \'{}\'", e),
    };
    let msg_session_tag = match env.message() {
        Message::Plain(m) => m.session_tag,
        Message::Keyed(_) => {
            panic!("I can only handle plain messages at the moment. Got a PreKeyMessage.")
        }
    };

    let sessions_dir = get_sessions_dir(&path);
    for session in sessions_dir {
        let session_path = session.unwrap().path();
        let session_id = session_path.file_stem().unwrap().to_str().unwrap();
        let mut session = get_session(&cbox, session_id);
        if session.session.session_tag != msg_session_tag {
            // println!("This is not the session you're looking for ...");
            continue;
        }
        println!("Found session for message {:?} ...", msg_session_tag);
        println!("Opening session {:?} ...", session_id);
        println!("Loaded session: {:?}", session);
        println!("Trying to decrypt ...");
        let msg = match session.decrypt(&data_bytes) {
            Ok(r) => r,
            Err(e) => {
                println!("Failed to decrypt :(\n{:?}", e);
                break;
            }
        };
        println!("Decrypted {:?}", msg);
    }
}

fn print_cbox(path: &str) {
    println!("Opening sessions in {}\n ...", path);
    let cbox = match CBox::file_open(&Path::new(path)) {
        Ok(c) => c,
        Err(e) => panic!("Couldn't load cryptobox session."),
    };
    println!("Loaded CBox {:?}", cbox);
    println!("Identity {:?}", cbox.identity());

    let sessions_dir = get_sessions_dir(path);
    for session in sessions_dir {
        let session_path = session.unwrap().path();
        let session_id = session_path.file_stem().unwrap().to_str().unwrap();
        println!("Trying to open session {:?} ...", session_id);
        let mut session = get_session(&cbox, session_id);
        println!("Loaded session: {:?}", session);
        println!("\n ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ----");
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let cmd = std::env::args()
        .nth(1)
        .expect("Usage: cargo run prettify|decrypt|pretty_cbox <input ...>");
    let first_arg = std::env::args()
        .nth(2)
        .expect("I require at least one argument!");

    match cmd.as_str() {
        "prettify" => prettify(&first_arg),
        "pretty_cbox" => print_cbox(&first_arg),
        "decrypt" => {
            let msg = std::env::args()
                .nth(3)
                .expect("Please provide the serialised data as input on the cli.");
            decrypt(&first_arg, &msg);
        }
        _ => panic!("Unknown command {:?}", cmd),
    }
}
