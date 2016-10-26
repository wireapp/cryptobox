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

use std::sync::{Arc, RwLock};

use error::CBoxError;
use proteus::keys::{IdentityKeyPair, PreKey, PreKeyId};
use proteus::message::Envelope;
use proteus::session::{PreKeyStore, Session};
use store::Store;

pub struct CBoxSession<S> {
    ptr: Arc<(String, RwLock<SessionImpl<S>>)>
}

pub fn new_session<S>(id: String, store: ReadOnlyStore<S>, s: Session<Arc<IdentityKeyPair>>) -> CBoxSession<S> {
    let session = SessionImpl {
        closed:  false,
        store:   store,
        session: s,
    };
    CBoxSession {
        ptr: Arc::new((id, RwLock::new(session)))
    }
}

pub fn close_session<S>(cbs: &CBoxSession<S>) {
    let mut s = cbs.ptr.1.write().unwrap();
    s.closed = true
}

impl<S: Store> CBoxSession<S> {
    pub fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>, CBoxError<S>> {
        let mut s = self.ptr.1.write().unwrap();
        s.encrypt(plain)
    }

    pub fn decrypt(&self, cipher: &[u8]) -> Result<Vec<u8>, CBoxError<S>> {
        let mut s = self.ptr.1.write().unwrap();
        s.decrypt(cipher)
    }

    pub fn save(&self) -> Result<(), CBoxError<S>> {
        let mut s = self.ptr.1.write().unwrap();
        s.save(&self.ptr.0)
    }

    pub fn identifier(&self) -> &str {
        &self.ptr.0
    }

    pub fn fingerprint_local(&self) -> String {
        let s = self.ptr.1.read().unwrap();
        s.fingerprint_local()
    }

    pub fn fingerprint_remote(&self) -> String {
        let s = self.ptr.1.read().unwrap();
        s.fingerprint_remote()
    }
}

impl<S> Clone for CBoxSession<S> {
    fn clone(&self) -> CBoxSession<S> {
        CBoxSession {
            ptr: self.ptr.clone()
        }
    }
}

struct SessionImpl<S> {
    closed:  bool,
    store:   ReadOnlyStore<S>,
    session: Session<Arc<IdentityKeyPair>>
}

impl<S: Store> SessionImpl<S> {
    fn encrypt(&mut self, plain: &[u8]) -> Result<Vec<u8>, CBoxError<S>> {
        if self.closed {
            return Err(CBoxError::SessionClosed)
        }
        Ok(self.session.encrypt(plain).and_then(|m| m.serialise())?)
    }

    fn decrypt(&mut self, cipher: &[u8]) -> Result<Vec<u8>, CBoxError<S>> {
        if self.closed {
            return Err(CBoxError::SessionClosed)
        }
        let env = Envelope::deserialise(cipher)?;
        let txt = self.session.decrypt(&mut self.store, &env)?;
        Ok(txt)
    }

    fn save(&mut self, id: &str) -> Result<(), CBoxError<S>> {
        if self.closed {
            return Err(CBoxError::SessionClosed)
        }
        self.store.store.save_session(id, &self.session).map_err(CBoxError::StorageError)?;
        for p in &self.store.removed {
            self.store.store.delete_prekey(*p).map_err(CBoxError::StorageError)?;
        }
        self.store.removed.clear();
        Ok(())
    }

    fn fingerprint_local(&self) -> String {
        self.session.local_identity().fingerprint()
    }

    fn fingerprint_remote(&self) -> String {
        self.session.remote_identity().fingerprint()
    }
}


pub struct ReadOnlyStore<S> {
    store:   Arc<S>,
    removed: Vec<PreKeyId>
}

impl<S> ReadOnlyStore<S> {
    pub fn new(s: Arc<S>) -> ReadOnlyStore<S> {
        ReadOnlyStore {
            store:   s,
            removed: Vec::new()
        }
    }
}

impl<S: Store> PreKeyStore for ReadOnlyStore<S> {
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

