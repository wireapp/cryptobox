// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

extern crate byteorder;
extern crate cbor;
extern crate proteus;

pub mod store;
mod identity;

pub use identity::Identity;

use proteus::keys::{self, IdentityKeyPair, PreKey, PreKeyBundle, PreKeyId};
use proteus::message::Envelope;
use proteus::session::{DecryptError, PreKeyStore, Session};
use proteus::{DecodeError, EncodeError};
use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::mem;
use std::path::Path;
use store::api::{Store, StorageError, StorageResult};
use store::file::FileStore;

// CBox /////////////////////////////////////////////////////////////////////

pub type CBoxResult<A> = Result<A, CBoxError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    Complete,
    Public
}

pub struct CBox<S> {
    ident: IdentityKeyPair,
    store: S
}

impl CBox<FileStore> {
    pub fn file_open(path: &Path) -> CBoxResult<CBox<FileStore>> {
        proteus::init();
        let store = try!(FileStore::new(path));
        let ident = match try!(store.load_identity()) {
            Some(Identity::Sec(i)) => i.into_owned(),
            Some(Identity::Pub(_)) => return Err(CBoxError::IdentityError),
            None => {
                let ident = IdentityKeyPair::new();
                try!(store.save_identity(&Identity::Sec(Cow::Borrowed(&ident))));
                ident
            }
        };
        Ok(CBox { ident: ident, store: store })
    }

    pub fn file_open_with(path: &Path, ident: IdentityKeyPair, mode: IdentityMode) -> CBoxResult<CBox<FileStore>> {
        proteus::init();
        let store = try!(FileStore::new(path));
        match try!(store.load_identity()) {
            Some(Identity::Sec(local)) => {
                if ident.public_key != local.public_key {
                    return Err(CBoxError::IdentityError)
                }
                if mode == IdentityMode::Public {
                    try!(store.save_identity(&Identity::Pub(Cow::Borrowed(&ident.public_key))))
                }
            }
            Some(Identity::Pub(local)) => {
                if ident.public_key != *local {
                    return Err(CBoxError::IdentityError)
                }
                if mode == IdentityMode::Complete {
                    try!(store.save_identity(&Identity::Sec(Cow::Borrowed(&ident))))
                }
            }
            None => match mode {
                IdentityMode::Public =>
                    try!(store.save_identity(&Identity::Pub(Cow::Borrowed(&ident.public_key)))),
                IdentityMode::Complete =>
                    try!(store.save_identity(&Identity::Sec(Cow::Borrowed(&ident))))
            }
        }
        Ok(CBox { ident: ident, store: store })
    }
}

impl<S: Store> CBox<S> {
    pub fn session_from_message(&self, sid: String, envelope: &[u8]) -> CBoxResult<(CBoxSession<S>, Vec<u8>)> {
        let env    = try!(Envelope::deserialise(envelope));
        let mut st = ReadOnlyStore::new(&self.store);
        let (s, p) = try!(Session::init_from_message(&self.ident, &mut st, &env));
        Ok((CBoxSession { sident: sid, store: st, session: s }, p))
    }

    pub fn session_load(&self, sid: String) -> CBoxResult<Option<CBoxSession<S>>> {
        match try!(self.store.load_session(&self.ident, &sid)) {
            None    => Ok(None),
            Some(s) => Ok(Some(CBoxSession {
                sident:  sid,
                store:   ReadOnlyStore::new(&self.store),
                session: s
            }))
        }
    }

    pub fn session_save(&self, s: &mut CBoxSession<S>) -> CBoxResult<()> {
        try!(self.store.save_session(&s.sident, &s.session));
        for p in s.removed_prekeys() {
            try!(self.store.delete_prekey(p))
        }
        Ok(())
    }

    pub fn session_delete(&self, sid: &str) -> CBoxResult<()> {
        try!(self.store.delete_session(sid));
        Ok(())
    }

    pub fn new_prekey(&self, id: PreKeyId) -> CBoxResult<PreKeyBundle> {
        let pk = PreKey::new(id);
        try!(self.store.add_prekey(&pk));
        Ok(PreKeyBundle::new(self.ident.public_key, &pk))
    }
}

impl<S> CBox<S> {
    pub fn session_from_prekey(&self, sid: String, key: &[u8]) -> CBoxResult<CBoxSession<S>> {
        let prekey = try!(PreKeyBundle::deserialise(key));
        Ok(CBoxSession {
            sident:  sid,
            store:   ReadOnlyStore::new(&self.store),
            session: Session::init_from_prekey(&self.ident, prekey)
        })
    }

    pub fn identity(&self) -> &IdentityKeyPair {
        &self.ident
    }

    pub fn fingerprint(&self) -> String {
        self.ident.public_key.fingerprint()
    }

    pub fn random_bytes(&self, n: usize) -> Vec<u8> {
        keys::rand_bytes(n)
    }
}

// Session //////////////////////////////////////////////////////////////////

pub struct CBoxSession<'r, S: 'r> {
    sident:  String,
    store:   ReadOnlyStore<'r, S>,
    session: Session<'r>
}

impl<'r, S: Store> CBoxSession<'r, S> {
    pub fn encrypt(&mut self, plain: &[u8]) -> CBoxResult<Vec<u8>> {
        Ok(try!(self.session.encrypt(plain).and_then(|m| m.serialise())))
    }

    pub fn decrypt(&mut self, cipher: &[u8]) -> CBoxResult<Vec<u8>> {
        let env = try!(Envelope::deserialise(cipher));
        let txt = try!(self.session.decrypt(&mut self.store, &env));
        Ok(txt)
    }

    pub fn removed_prekeys(&mut self) -> Vec<PreKeyId> {
        mem::replace(&mut self.store.removed, Vec::new())
    }
}

impl<'r, S> CBoxSession<'r, S> {
    pub fn identifier(&self) -> &str {
        &self.sident
    }

    pub fn fingerprint_local(&self) -> String {
        self.session.local_identity().fingerprint()
    }

    pub fn fingerprint_remote(&self) -> String {
        self.session.remote_identity().fingerprint()
    }
}

// ReadOnlyStore ////////////////////////////////////////////////////////////

struct ReadOnlyStore<'r, S: 'r> {
    store:   &'r S,
    removed: Vec<PreKeyId>
}

impl<'r, S> ReadOnlyStore<'r, S> {
    pub fn new(s: &'r S) -> ReadOnlyStore<'r, S> {
        ReadOnlyStore { store: s, removed: Vec::new() }
    }
}

impl<'r, S: Store> PreKeyStore for ReadOnlyStore<'r, S> {
    type Error = StorageError;

    fn prekey(&mut self, id: PreKeyId) -> StorageResult<Option<PreKey>> {
        if self.removed.contains(&id) {
            Ok(None)
        } else {
            self.store.load_prekey(id)
        }
    }

    fn remove(&mut self, id: PreKeyId) -> StorageResult<()> {
        self.removed.push(id);
        Ok(())
    }
}

// CBoxError ////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum CBoxError {
    DecryptError(DecryptError<StorageError>),
    StorageError(StorageError),
    DecodeError(DecodeError),
    EncodeError(EncodeError),
    IdentityError
}

impl fmt::Display for CBoxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            CBoxError::DecryptError(ref e) => write!(f, "CBoxError: decrypt error: {}", e),
            CBoxError::StorageError(ref e) => write!(f, "CBoxError: storage error: {}", *e),
            CBoxError::DecodeError(ref e)  => write!(f, "CBoxError: decode error: {}", *e),
            CBoxError::EncodeError(ref e)  => write!(f, "CBoxError: encode error: {}", *e),
            CBoxError::IdentityError       => write!(f, "CBoxError: identity error")
        }
    }
}

impl Error for CBoxError {
    fn description(&self) -> &str {
        "CBoxError"
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CBoxError::StorageError(ref e) => Some(e),
            CBoxError::DecodeError(ref e)  => Some(e),
            CBoxError::EncodeError(ref e)  => Some(e),
            _                              => None
        }
    }
}

impl From<DecryptError<StorageError>> for CBoxError {
    fn from(err: DecryptError<StorageError>) -> CBoxError {
        CBoxError::DecryptError(err)
    }
}

impl From<StorageError> for CBoxError {
    fn from(e: StorageError) -> CBoxError {
        CBoxError::StorageError(e)
    }
}

impl From<DecodeError> for CBoxError {
    fn from(e: DecodeError) -> CBoxError {
        CBoxError::DecodeError(e)
    }
}

impl From<EncodeError> for CBoxError {
    fn from(e: EncodeError) -> CBoxError {
        CBoxError::EncodeError(e)
    }
}
