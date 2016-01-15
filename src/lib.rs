// Copyright (C) 2015 Wire Swiss GmbH <support@wire.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

extern crate byteorder;
extern crate cbor;
extern crate proteus;

pub mod store;
mod identity;

pub use identity::Identity;

use cbor::{Config, Encoder, Decoder};
use proteus::keys::{self, IdentityKeyPair, PreKey, PreKeyBundle, PreKeyId, Signature};
use proteus::message::Envelope;
use proteus::session::{DecryptError, PreKeyStore, Session};
use proteus::{DecodeError, EncodeError};
use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::io::Cursor;
use std::mem;
use std::path::Path;
use store::Store;
use store::file::{FileStore, FileStoreError};

// CBox /////////////////////////////////////////////////////////////////////

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
    pub fn file_open(path: &Path) -> Result<CBox<FileStore>, CBoxError<FileStore>> {
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

    pub fn file_open_with(path: &Path, ident: IdentityKeyPair, mode: IdentityMode) -> Result<CBox<FileStore>, CBoxError<FileStore>> {
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
    pub fn session_from_prekey(&self, sid: String, key: &[u8]) -> Result<CBoxSession<S>, CBoxError<S>> {
        let prekey = try!(PreKeyBundle::deserialise(key));
        Ok(CBoxSession {
            sident:  sid,
            store:   ReadOnlyStore::new(&self.store),
            session: Session::init_from_prekey(&self.ident, prekey)
        })
    }

    pub fn session_from_message(&self, sid: String, envelope: &[u8]) -> Result<(CBoxSession<S>, Vec<u8>), CBoxError<S>> {
        let env    = try!(Envelope::deserialise(envelope));
        let mut st = ReadOnlyStore::new(&self.store);
        let (s, p) = try!(Session::init_from_message(&self.ident, &mut st, &env));
        Ok((CBoxSession { sident: sid, store: st, session: s }, p))
    }

    pub fn session_load(&self, sid: String) -> Result<Option<CBoxSession<S>>, CBoxError<S>> {
        match self.store.load_session(&self.ident, &sid) {
            Ok(None)    => Ok(None),
            Ok(Some(s)) => Ok(Some(CBoxSession {
                sident:  sid,
                store:   ReadOnlyStore::new(&self.store),
                session: s
            })),
            Err(e) => Err(CBoxError::StorageError(e))
        }
    }

    pub fn session_save(&self, s: &mut CBoxSession<S>) -> Result<(), CBoxError<S>> {
        try!(self.store.save_session(&s.sident, &s.session).map_err(CBoxError::StorageError));
        for p in s.removed_prekeys() {
            try!(self.store.delete_prekey(p).map_err(CBoxError::StorageError));
        }
        Ok(())
    }

    pub fn session_delete(&self, sid: &str) -> Result<(), CBoxError<S>> {
        try!(self.store.delete_session(sid).map_err(CBoxError::StorageError));
        Ok(())
    }

    pub fn new_prekey(&self, id: PreKeyId) -> Result<PreKeyBundle, CBoxError<S>> {
        let pk = PreKey::new(id);
        try!(self.store.add_prekey(&pk).map_err(CBoxError::StorageError));
        Ok(PreKeyBundle::new(self.ident.public_key, &pk))
    }

    pub fn sign(&self, d: &[u8]) -> Result<Vec<u8>, CBoxError<S>> {
        let     s = self.ident.secret_key.sign(d);
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        try!(s.encode(&mut e));
        Ok(e.into_writer().into_inner())
    }

    pub fn verify(&self, s: &[u8], d: &[u8]) -> Result<bool, CBoxError<S>> {
        let dec = &mut Decoder::new(Config::default(), Cursor::new(s));
        let sig = try!(Signature::decode(dec));
        Ok(self.ident.public_key.public_key.verify(&sig, d))
    }
}

impl<S> CBox<S> {
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
    pub fn encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>, CBoxError<S>> {
        Ok(try!(self.session.encrypt(plain).and_then(|m| m.serialise())))
    }

    pub fn decrypt(&mut self, cipher: &[u8]) -> Result<Vec<u8>, CBoxError<S>> {
        let env = try!(Envelope::deserialise(cipher));
        let txt = try!(self.session.decrypt(&mut self.store, &env));
        Ok(txt)
    }

    pub fn removed_prekeys(&mut self) -> Vec<PreKeyId> {
        mem::replace(&mut self.store.removed, Vec::new())
    }

    pub fn verify_remote(&self, s: &[u8], d: &[u8]) -> Result<bool, CBoxError<S>> {
        let dec = &mut Decoder::new(Config::default(), Cursor::new(s));
        let sig = try!(Signature::decode(dec));
        Ok(self.session.remote_identity().public_key.verify(&sig, d))
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
    type Error = S::Error;

    fn prekey(&mut self, id: PreKeyId) -> Result<Option<PreKey>, S::Error> {
        if self.removed.contains(&id) {
            Ok(None)
        } else {
            self.store.load_prekey(id)
        }
    }

    fn remove(&mut self, id: PreKeyId) -> Result<(), S::Error> {
        self.removed.push(id);
        Ok(())
    }
}

// CBoxError ////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum CBoxError<S: Store> {
    DecryptError(DecryptError<S::Error>),
    StorageError(S::Error),
    DecodeError(DecodeError),
    EncodeError(EncodeError),
    IdentityError
}

impl<S: Store> fmt::Display for CBoxError<S> {
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

impl<S: Store + fmt::Debug> Error for CBoxError<S> {
    fn description(&self) -> &str {
        "CBoxError"
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CBoxError::DecryptError(ref e) => Some(e),
            CBoxError::StorageError(ref e) => Some(e),
            CBoxError::DecodeError(ref e)  => Some(e),
            CBoxError::EncodeError(ref e)  => Some(e),
            CBoxError::IdentityError       => None
        }
    }
}

impl From<FileStoreError> for CBoxError<FileStore> {
    fn from(e: FileStoreError) -> CBoxError<FileStore> {
        CBoxError::StorageError(e)
    }
}

impl<S: Store> From<DecryptError<S::Error>> for CBoxError<S> {
    fn from(e: DecryptError<S::Error>) -> CBoxError<S> {
        CBoxError::DecryptError(e)
    }
}

impl<S: Store> From<DecodeError> for CBoxError<S> {
    fn from(e: DecodeError) -> CBoxError<S> {
        CBoxError::DecodeError(e)
    }
}

impl<S: Store> From<EncodeError> for CBoxError<S> {
    fn from(e: EncodeError) -> CBoxError<S> {
        CBoxError::EncodeError(e)
    }
}
