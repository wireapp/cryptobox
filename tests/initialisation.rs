extern crate cryptobox;
extern crate proteus;

use std::{env::temp_dir, fs::create_dir};

use cryptobox::{CBox, CBoxError};
use proteus::keys::PreKeyId;

#[test]
fn simple_init() {
    // A generates a prekey
    let mut cbox_a_path = temp_dir();
    cbox_a_path.push("CBoxA");
    let _ = create_dir(cbox_a_path.clone()); // This throws an error if the path exists already. We don't care.
    let cbox_a = CBox::file_open(cbox_a_path).expect("Error creating cbox for A");
    let pre_key = cbox_a
        .new_prekey(PreKeyId::new(5))
        .expect("Error generating prekey");

    // B create session with `pre_key`.
    let mut cbox_b_path = temp_dir();
    cbox_b_path.push("CBoxB");
    let _ = create_dir(cbox_b_path.clone()); // This throws an error if the path exists already. We don't care.
    let cbox_b = CBox::file_open(cbox_b_path).expect("Error creating cbox for B");
    let mut session_b_a = cbox_b
        .session_from_prekey("b-a".to_string(), &pre_key.serialise().unwrap())
        .expect("Error creating session from prekey");

    let m_from_b_to_a = b"Hello A it's B here with prekey 5";
    let m_b_a = session_b_a
        .encrypt(m_from_b_to_a)
        .expect("Error encrypting message from B to A");

    // C create session with `pre_key`.
    let mut cbox_c_path = temp_dir();
    cbox_c_path.push("CBoxC");
    let _ = create_dir(cbox_c_path.clone()); // This throws an error if the path exists already. We don't care.
    let cbox_c = CBox::file_open(cbox_c_path).expect("Error creating cbox for C");
    let mut session_c_a = cbox_c
        .session_from_prekey("c-a".to_string(), &pre_key.serialise().unwrap())
        .expect("Error creating session from prekey");

    let m_from_c_to_a = b"Hello A it's C here with prekey 5";
    let m_c_a = session_c_a
        .encrypt(m_from_c_to_a)
        .expect("Error encrypting message from C to A");

    // D create session with `pre_key`.
    let mut cbox_d_path = temp_dir();
    cbox_d_path.push("CBoxD");
    let _ = create_dir(cbox_d_path.clone()); // This throws an error if the path exists already. We don't care.
    let cbox_c = CBox::file_open(cbox_d_path).expect("Error creating cbox for D");
    let mut session_d_a = cbox_c
        .session_from_prekey("d-a".to_string(), &pre_key.serialise().unwrap())
        .expect("Error creating session from prekey");

    let m_from_d_to_a = b"Hello A it's D here with prekey 5";
    let m_d_a = session_d_a
        .encrypt(m_from_d_to_a)
        .expect("Error encrypting message from D to A");

    // A reads message form B and establishes session
    let (mut session_a_b, m_from_b) = cbox_a
        .session_from_message("a-b".to_string(), &m_b_a)
        .expect("Error creating session with message from B");
    assert_eq!(&m_from_b_to_a[..], &m_from_b[..]);

    // A reads message form C and establishes session
    // This will work because the cbox wasn't saved.
    let (_session_a_c, m_from_c) = cbox_a
        .session_from_message("a-c".to_string(), &m_c_a)
        .expect("Error creating session with message from C");
    assert_eq!(&m_from_c_to_a[..], &m_from_c[..]);

    // Now we save the cbox sessions
    cbox_a
        .session_save(&mut session_a_b)
        .expect("Error saving session");
    // We don't need to save session_a_c really. The prekey is deleted already.

    // Reading another prekey message will fail now.
    // It should be a proteus::session::Error::PreKeyNotFound but there's no
    // PartialEq anywhere...
    assert!(cbox_a
        .session_from_message("a-d".to_string(), &m_d_a)
        .err()
        .is_some());
}
