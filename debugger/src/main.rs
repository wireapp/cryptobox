use std::{
    env, fs, fs::File, fs::ReadDir, io::BufRead, io::BufReader, io::Read, num::ParseIntError,
    path::Path,
};

use cryptobox::{store::Store, CBox, CBoxError, CBoxSession};
use proteus::message::{Envelope, Message};

#[derive(Copy, Debug, Clone)]
enum Error {
    NoSession,
}

fn hex_str_to_bytes(val: &str) -> Vec<u8> {
    let b: Result<Vec<u8>, ParseIntError> = (0..val.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&val[i..std::cmp::min(val.len(), i + 2)], 16))
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

fn get_cbox_session<S: Store + std::fmt::Debug>(
    cbox: &CBox<S>,
    path: &str,
    data_bytes: &[u8],
    write: bool,
) -> Result<CBoxSession<S>, Error> {
    println!("Parsing message ...");
    let env = match Envelope::deserialise(&data_bytes) {
        Ok(v) => v,
        Err(e) => panic!("Couldn't deserialise: \'{}\'", e),
    };
    let msg_session_tag = match env.message() {
        Message::Plain(m) => m.session_tag,
        Message::Keyed(_) => {
            panic!("I can only handle plain messages at the moment. Got a PreKeyMessage.")
            // println!("This is a PreKeyMessage. I'll try to create a session from it.");
            // cbox.session_from_message("");
        }
    };

    println!("Looking for session to decrypt the message ...");
    let sessions_dir = get_sessions_dir(&path);
    for session in sessions_dir {
        let session_path = session.unwrap().path();
        let session_id = session_path.file_stem().unwrap().to_str().unwrap();
        let session = get_session(&cbox, session_id);
        if session.session.session_tag != msg_session_tag {
            // println!("This is not the session you're looking for ...");
            continue;
        }
        println!("Found session for message {:?} ...", msg_session_tag);
        println!("Opening session {:?} ...", session_id);
        // println!("Loaded session: {:?}", session);
        return Ok(session);
    }
    println!("I didn't find a session for this message to decrypt :(");
    Err(Error::NoSession)
}

fn decrypt_multiple(path: &str, data: &[Vec<u8>], write: bool) {
    println!("Opening Cryptobox {}\n ...", path);
    let cbox = match CBox::file_open(&Path::new(path)) {
        Ok(c) => c,
        Err(e) => panic!("Couldn't load cryptobox session."),
    };

    for bytes in data.iter() {
        println!("\n --- Decrypting next dump ... ---");
        let mut session = match get_cbox_session(&cbox, path, &bytes, write) {
            Ok(s) => s,
            Err(e) => {
                println!("{:?}", e);
                continue;
            }
        };
        let _ = decrypt_with_cbox_session(&cbox, &mut session, path, &bytes, false);
    }
}

fn decrypt_with_cbox_session<S: Store + std::fmt::Debug>(
    cbox: &CBox<S>,
    cbox_session: &mut CBoxSession<S>,
    path: &str,
    data_bytes: &[u8],
    write: bool,
) -> Result<(), CBoxError<S>> {
    let msg = match cbox_session.decrypt(&data_bytes) {
        Ok(r) => r,
        Err(e) => {
            println!("Failed to decrypt :(\n{:?}", e);
            return Err(e);
        }
    };
    println!("Decrypted {:?}", msg);
    // unsafe {
    //     println!(
    //         "Decrypted string: {:?}",
    //         std::str::from_utf8_unchecked(&msg)
    //     );
    // }
    if write {
        // Write the updated session back.
        // Note that you can't decrypt the same message again after this.
        let _ = cbox.session_save(cbox_session);
    }
    Ok(())
}

fn decrypt_with_cbox<S: Store + std::fmt::Debug>(
    cbox: &CBox<S>,
    path: &str,
    data_bytes: &[u8],
    write: bool,
) {
    let mut session = get_cbox_session(cbox, path, data_bytes, write).unwrap();
    decrypt_with_cbox_session(cbox, &mut session, path, data_bytes, write);
}

fn decrypt(path: &str, data: &str, write: bool) {
    println!("Opening Cryptobox {}\n ...", path);
    let cbox = match CBox::file_open(&Path::new(path)) {
        Ok(c) => c,
        Err(e) => panic!("Couldn't load cryptobox session."),
    };

    let data_bytes = hex_str_to_bytes(data);
    decrypt_with_cbox(&cbox, path, &data_bytes, write);
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
        let session = get_session(&cbox, session_id);
        println!("Loaded session: {:?}", session);
        println!("\n ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ----");
    }
}

fn read_dumps(file: &str) -> Vec<Vec<u8>> {
    let file = fs::File::open(file).unwrap();
    let mut out = Vec::<Vec<u8>>::new();
    for line in BufReader::new(file).lines() {
        let line = line.unwrap();
        out.push(hex_str_to_bytes(&line));
    }
    out
}

fn main() {
    let cmd = std::env::args()
        .nth(1)
        .expect("Usage: cargo run prettify|decrypt|pretty_cbox|decrypt_file <input ...>");
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
            let write = std::env::args().nth(4).unwrap_or_default();
            let write = write == "write";
            decrypt(&first_arg, &msg, write);
        }
        "decrypt_file" => {
            let dumps = std::env::args()
                .nth(3)
                .expect("Please provide a file on the cli with the dumps.");
            let write = std::env::args().nth(4).unwrap_or_default();
            let write = write == "write";
            let dumps = read_dumps(&dumps);
            decrypt_multiple(&first_arg, &dumps, write);
        }
        _ => panic!("Unknown command {:?}", cmd),
    }
}
