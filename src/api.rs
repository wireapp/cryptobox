// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use libc::*;
use libproteus::keys::*;
use libproteus::message::Envelope;
use libproteus::session::*;
use libproteus::DecodeError;
use libproteus;
use log;
use std::boxed::Box;
use std::error::Error;
use std::ffi::{CStr, CString, NulError};
use std::path::Path;
use std::slice;
use std::str;
use store::api::{Store, StorageError, StorageResult};
use store::file::FileStore;

/// Variant of std::try! that returns the unwrapped error.
macro_rules! try_unwrap {
    ($expr:expr) => (match $expr {
        Ok(val)  => val,
        Err(err) => return From::from(err)
    })
}

// CBox /////////////////////////////////////////////////////////////////////

#[no_mangle]
pub struct CBox {
    store: Box<Store>,
    ident: IdentityKeyPair
}

impl CBox {
    fn session(&self, sid: &str) -> Result<Session, CBoxResult> {
        match try!(self.store.load_session(&self.ident, sid)) {
            Some(s) => Ok(s),
            None    => Err(CBoxResult::NoSession)
        }
    }
}

#[no_mangle]
pub unsafe extern
fn cbox_file_open(c_path: *const c_char, c_box: *mut *mut CBox) -> CBoxResult {
    libproteus::init();
    let name  = try_unwrap!(str::from_utf8(CStr::from_ptr(c_path).to_bytes()));
    let path  = Path::new(name);
    let store = try_unwrap!(FileStore::new(path));
    let ident = try_unwrap!(store.load_identity().and_then(|id| {
        match id {
            Some(i) => Ok(i),
            None    => {
                let id = IdentityKeyPair::new();
                try!(store.save_identity(&id));
                Ok(id)
            }
        }
    }));
    let cbox = CBox { store: Box::new(store), ident: ident };
    *c_box = Box::into_raw(Box::new(cbox));
    CBoxResult::Success
}

#[no_mangle]
pub unsafe extern
fn cbox_close(b: *mut CBox) {
    Box::from_raw(b);
}

#[no_mangle]
pub unsafe extern
fn cbox_new_prekey(c_box: *mut CBox, c_id: c_ushort, c_bundle: *mut *mut CBoxVec) -> CBoxResult {
    let cbox = &*c_box;

    let pk = PreKey::new(PreKeyId::new(c_id));

    try_unwrap!(cbox.store.add_prekey(&pk));

    let bundle = PreKeyBundle::new(cbox.ident.public_key, &pk).encode();
    *c_bundle  = CBoxVec::from_vec(bundle);

    CBoxResult::Success
}

// Session ID ///////////////////////////////////////////////////////////////

struct SID {
    string:  String,
    cstring: CString
}

impl SID {
    unsafe fn from_raw(c_sid: *const c_char) -> Result<SID, CBoxResult> {
        let st = CStr::from_ptr(c_sid).to_bytes();
        let cs = try!(CString::new(st));
        let ss = try!(str::from_utf8(cs.as_bytes()).map(String::from));
        Ok(SID { string: ss, cstring: cs })
    }

    fn as_c_ptr(&self) -> *const c_char {
        (*self.cstring).as_ptr()
    }
}

// Session //////////////////////////////////////////////////////////////////

#[no_mangle]
pub struct CBoxSession<'r> {
    cbox:   &'r mut CBox,
    sess:   Session<'r>,
    sid:    SID,
    pstore: ReadOnlyPks<'r>
}

impl<'r> CBoxSession<'r> {
    unsafe fn new(c_box: *mut CBox, sid: SID, sess: Session<'r>, ls: ReadOnlyPks<'r>) -> CBoxSession<'r> {
        CBoxSession { cbox: &mut *c_box, sess: sess, sid: sid, pstore: ls }
    }
}

struct ReadOnlyPks<'r> {
    store:       &'r (Store + 'r),
    pub prekeys: Vec<PreKeyId>
}

impl<'r> ReadOnlyPks<'r> {
    pub fn new(store: &'r Store) -> ReadOnlyPks {
        ReadOnlyPks { store: store, prekeys: Vec::new() }
    }
}

impl<'r> PreKeyStore<StorageError> for ReadOnlyPks<'r> {
    fn prekey(&self, id: PreKeyId) -> StorageResult<Option<PreKey>> {
        self.store.prekey(id)
    }

    fn remove(&mut self, id: PreKeyId) -> StorageResult<()> {
        self.prekeys.push(id);
        Ok(())
    }
}

#[no_mangle]
pub unsafe extern
fn cbox_session_init_from_prekey(c_box:         *mut   CBox,
                                 c_sid:         *const c_char,
                                 c_prekey:      *const uint8_t,
                                 c_prekey_len:  uint32_t,
                                 c_session:     *mut *const CBoxSession) -> CBoxResult
{
    let cbox   = &*c_box;
    let sid    = try_unwrap!(SID::from_raw(c_sid));
    let prekey = try_unwrap!(dec_raw(&c_prekey, c_prekey_len as usize, PreKeyBundle::decode));
    let sess   = Session::init_from_prekey(&cbox.ident, prekey);
    let pstore = ReadOnlyPks::new(&*cbox.store);
    let csess  = CBoxSession::new(c_box, sid, sess, pstore);
    *c_session = Box::into_raw(Box::new(csess));
    CBoxResult::Success
}

#[no_mangle]
pub unsafe extern
fn cbox_session_init_from_message(c_box:        *mut CBox,
                                  c_sid:        *const c_char,
                                  c_cipher:     *const uint8_t,
                                  c_cipher_len: uint32_t,
                                  c_sess:       *mut *mut CBoxSession,
                                  c_plain:      *mut *mut CBoxVec) -> CBoxResult
{
    let cbox   = &*c_box;
    let sid    = try_unwrap!(SID::from_raw(c_sid));
    let env    = try_unwrap!(dec_raw(&c_cipher, c_cipher_len as usize, Envelope::decode));
    let mut ps = ReadOnlyPks::new(&*cbox.store);
    let (s, p) = try_unwrap!(Session::init_from_message(&cbox.ident, &mut ps, &env));
    let csess  = CBoxSession::new(c_box, sid, s, ps);
    *c_plain   = CBoxVec::from_vec(p);
    *c_sess    = Box::into_raw(Box::new(csess));
    CBoxResult::Success
}

#[no_mangle]
pub unsafe extern
fn cbox_session_get(c_box: *mut CBox, c_sid: *const c_char, c_sess: *mut *mut CBoxSession) -> CBoxResult {
    let cbox   = &*c_box;
    let sid    = try_unwrap!(SID::from_raw(c_sid));
    let sess   = try_unwrap!(cbox.session(&sid.string));
    let pstore = ReadOnlyPks::new(&*cbox.store);
    let csess  = CBoxSession::new(c_box, sid, sess, pstore);
    *c_sess    = Box::into_raw(Box::new(csess));
    CBoxResult::Success
}

#[no_mangle]
pub unsafe extern
fn cbox_session_id(c_sess: *const CBoxSession) -> *const c_char {
    (*c_sess).sid.as_c_ptr()
}

#[no_mangle]
pub unsafe extern
fn cbox_session_save(c_sess: *mut CBoxSession) -> CBoxResult {
    let sess = &mut *c_sess;
    let cbox = &mut *sess.cbox;
    try_unwrap!(cbox.store.save_session(&sess.sid.string, &sess.sess));
    for k in sess.pstore.prekeys.iter() {
        try_unwrap!(cbox.store.remove(*k));
    }
    sess.pstore.prekeys.clear();
    CBoxResult::Success
}

#[no_mangle]
pub unsafe extern
fn cbox_session_close(c_sess: *mut CBoxSession) {
    Box::from_raw(c_sess as *mut CBoxSession);
}

#[no_mangle]
pub unsafe extern
fn cbox_encrypt(c_sess:      *mut CBoxSession,
                c_plain:     *const uint8_t,
                c_plain_len: uint32_t,
                c_cipher:    *mut *mut CBoxVec)
{
    let sref   = &mut *c_sess;
    let plain  = slice::from_raw_parts(c_plain, c_plain_len as usize);
    let cipher = sref.sess.encrypt(plain).encode();
    *c_cipher  = CBoxVec::from_vec(cipher);
}

#[no_mangle]
pub unsafe extern
fn cbox_decrypt(c_sess:       *mut CBoxSession,
                c_cipher:     *const uint8_t,
                c_cipher_len: uint32_t,
                c_plain:      *mut *mut CBoxVec) -> CBoxResult
{
    let session = &mut *c_sess;
    let env     = try_unwrap!(dec_raw(&c_cipher, c_cipher_len as usize, Envelope::decode));
    let plain   = try_unwrap!(session.sess.decrypt(&mut session.pstore, &env));
    *c_plain    = CBoxVec::from_vec(plain);
    CBoxResult::Success
}

#[no_mangle]
pub unsafe extern
fn cbox_fingerprint_local(c_box: *const CBox, buf: *mut *mut CBoxVec) {
    let fp = (*c_box).ident.public_key.fingerprint();
    *buf = CBoxVec::from_vec(fp.into_bytes());
}

#[no_mangle]
pub unsafe extern
fn cbox_fingerprint_remote(s: *const CBoxSession, buf: *mut *mut CBoxVec) {
    let fp = (*s).sess.remote_identity().fingerprint();
    *buf = CBoxVec::from_vec(fp.into_bytes());
}

// CBoxVec /////////////////////////////////////////////////////////////////////

#[no_mangle]
pub struct CBoxVec {
    vec: Vec<u8>
}

impl CBoxVec {
    unsafe fn from_vec(v: Vec<u8>) -> *mut CBoxVec {
        Box::into_raw(Box::new(CBoxVec { vec: v }))
    }
}

#[no_mangle]
pub unsafe extern fn cbox_vec_free(v: *mut CBoxVec) {
    Box::from_raw(v);
}

#[no_mangle]
pub unsafe extern fn cbox_vec_data(v: *const CBoxVec) -> *const uint8_t {
    (*v).vec.as_ptr()
}

#[no_mangle]
pub unsafe extern fn cbox_vec_len(v: *const CBoxVec) -> uint32_t {
    (*v).vec.len() as uint32_t
}

// CBoxResult ///////////////////////////////////////////////////////////////

#[repr(C)]
#[no_mangle]
#[derive(Clone, Copy, Debug)]
pub enum CBoxResult {
    Success               = 0,
    StorageError          = 1,
    NoSession             = 2,
    DecodeError           = 3,
    RemoteIdentityChanged = 4,
    InvalidSignature      = 5,
    InvalidMessage        = 6,
    DuplicateMessage      = 7,
    TooDistantFuture      = 8,
    OutdatedMessage       = 9,
    Utf8Error             = 10,
    NulError              = 11
}

impl<E: Error> From<DecryptError<E>> for CBoxResult {
    fn from(err: DecryptError<E>) -> CBoxResult {
        match err {
            DecryptError::RemoteIdentityChanged   => CBoxResult::RemoteIdentityChanged,
            DecryptError::InvalidSignature        => CBoxResult::InvalidSignature,
            DecryptError::InvalidMessage          => CBoxResult::InvalidMessage,
            DecryptError::DuplicateMessage        => CBoxResult::DuplicateMessage,
            DecryptError::TooDistantFuture        => CBoxResult::TooDistantFuture,
            DecryptError::OutdatedMessage         => CBoxResult::OutdatedMessage,
            DecryptError::PreKeyStoreError(ref e) => {
                log::error(e);
                CBoxResult::StorageError
            }
        }
    }
}

impl From<StorageError> for CBoxResult {
    fn from(e: StorageError) -> CBoxResult {
        log::error(&e);
        CBoxResult::StorageError
    }
}

impl From<str::Utf8Error> for CBoxResult {
    fn from(e: str::Utf8Error) -> CBoxResult {
        log::error(&e);
        CBoxResult::Utf8Error
    }
}

impl From<DecodeError> for CBoxResult {
    fn from(e: DecodeError) -> CBoxResult {
        log::error(&e);
        CBoxResult::DecodeError
    }
}

impl From<NulError> for CBoxResult {
    fn from(e: NulError) -> CBoxResult {
        log::error(&e);
        CBoxResult::NulError
    }
}

// Util /////////////////////////////////////////////////////////////////////

#[no_mangle]
pub unsafe extern fn cbox_random_bytes(_: *const CBox, n: uint32_t) -> *mut CBoxVec {
    CBoxVec::from_vec(rand_bytes(n as usize))
}

unsafe fn dec_raw<A, F>(ptr: & *const c_uchar, len: usize, f: F) -> Result<A, DecodeError>
where F: Fn(&[u8]) -> Result<A, DecodeError> {
    f(slice::from_raw_parts(*ptr, len))
}
