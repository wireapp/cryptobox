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

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex};

use error::CBoxError;
use identity::{Identity, IdentityMode};
use proteus;
use proteus::keys::{IdentityKeyPair, PreKey, PreKeyBundle, PreKeyId};
use proteus::message::Envelope;
use proteus::session::Session;
use session::{CBoxSession, new_session, close_session, ReadOnlyStore};
use store::Store;

pub struct CBox<S> {
    ident:    Arc<IdentityKeyPair>,
    store:    Arc<S>,
    sessions: Arc<Mutex<HashMap<String, CBoxSession<S>>>>
}

impl<S: Store> CBox<S> {
    pub fn open(store: S) -> Result<CBox<S>, CBoxError<S>>
        where CBoxError<S>: From<<S as Store>::Error>
    {
        if !proteus::init() {
            return Err(CBoxError::InitError)
        }
        let ident = match store.load_identity()? {
            Some(Identity::Sec(i)) => i.into_owned(),
            Some(Identity::Pub(_)) => return Err(CBoxError::IdentityError),
            None => {
                let ident = IdentityKeyPair::new();
                store.save_identity(Identity::Sec(Cow::Borrowed(&ident)))?;
                ident
            }
        };
        Ok(CBox {
            ident:    Arc::new(ident),
            store:    Arc::new(store),
            sessions: Arc::new(Mutex::new(HashMap::new()))
        })
    }

    pub fn open_with(store: S, ident: IdentityKeyPair, mode: IdentityMode) -> Result<CBox<S>, CBoxError<S>>
        where CBoxError<S>: From<<S as Store>::Error>
    {
        if !proteus::init() {
            return Err(CBoxError::InitError)
        }
        match store.load_identity()? {
            Some(Identity::Sec(local)) => {
                if ident.public_key != local.public_key {
                    return Err(CBoxError::IdentityError)
                }
                if mode == IdentityMode::Public {
                    store.save_identity(Identity::Pub(Cow::Borrowed(&ident.public_key)))?
                }
            }
            Some(Identity::Pub(local)) => {
                if ident.public_key != *local {
                    return Err(CBoxError::IdentityError)
                }
                if mode == IdentityMode::Complete {
                    store.save_identity(Identity::Sec(Cow::Borrowed(&ident)))?
                }
            }
            None => match mode {
                IdentityMode::Public =>
                    store.save_identity(Identity::Pub(Cow::Borrowed(&ident.public_key)))?,
                IdentityMode::Complete =>
                    store.save_identity(Identity::Sec(Cow::Borrowed(&ident)))?
            }
        }
        Ok(CBox {
            ident:    Arc::new(ident),
            store:    Arc::new(store),
            sessions: Arc::new(Mutex::new(HashMap::new()))
        })
    }

    pub fn session_from_prekey(&self, id: String, key: PreKeyBundle) -> Result<CBoxSession<S>, CBoxError<S>> {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.entry(id.clone()) {
            Entry::Occupied(e) => Ok(e.get().clone()),
            Entry::Vacant(e)   => {
                let session = Session::init_from_prekey(self.ident.clone(), key)?;
                let ropks   = ReadOnlyStore::new(self.store.clone());
                let cbs     = new_session(id, ropks, session);
                Ok(e.insert(cbs).clone())
            }
        }
    }

    pub fn session_from_message(&self, id: &str, msg: &[u8]) -> Result<(CBoxSession<S>, Vec<u8>), CBoxError<S>> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(s) = sessions.get(id) {
            let data = s.decrypt(msg)?;
            return Ok((s.clone(), data))
        }
        let env = Envelope::deserialise(msg)?;
        let mut ropks = ReadOnlyStore::new(self.store.clone());
        let (s, p) = Session::init_from_message(self.ident.clone(), &mut ropks, &env)?;
        let cbs = new_session(id.into(), ropks, s);
        sessions.insert(id.into(), cbs.clone());
        Ok((cbs, p))
    }

    pub fn session(&self, id: &str) -> Result<Option<CBoxSession<S>>, CBoxError<S>> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(s) = sessions.get(id) {
            return Ok(Some(s.clone()))
        }
        match self.store.load_session(self.ident.clone(), id) {
            Ok(Some(s)) => {
                let ropks = ReadOnlyStore::new(self.store.clone());
                let cbs   = new_session(id.into(), ropks, s);
                sessions.insert(id.into(), cbs.clone());
                Ok(Some(cbs))
            }
            Ok(None) => Ok(None),
            Err(e)   => Err(CBoxError::StorageError(e))
        }
    }

    pub fn session_close(&self, s: &CBoxSession<S>) {
        let mut sessions = self.sessions.lock().unwrap();
        close_session(s);
        sessions.remove(s.identifier());
    }

    pub fn session_delete(&self, id: &str) -> Result<(), CBoxError<S>> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(s) = sessions.remove(id) {
            close_session(&s)
        }
        self.store.delete_session(id).map_err(CBoxError::StorageError)?;
        Ok(())
    }

    pub fn clear(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        for s in sessions.drain() {
            close_session(&s.1)
        }
    }

    pub fn new_prekey(&self, id: PreKeyId) -> Result<PreKeyBundle, CBoxError<S>> {
        let pk = PreKey::new(id);
        self.store.add_prekey(&pk).map_err(CBoxError::StorageError)?;
        Ok(PreKeyBundle::new(self.ident.as_ref().public_key.clone(), &pk))
    }

    pub fn identity(&self) -> &IdentityKeyPair {
        self.ident.as_ref()
    }

    pub fn fingerprint(&self) -> String {
        self.ident.as_ref().public_key.fingerprint()
    }
}

impl<S> Clone for CBox<S> {
    fn clone(&self) -> CBox<S> {
        CBox {
            ident:    self.ident.clone(),
            store:    self.store.clone(),
            sessions: self.sessions.clone()
        }
    }
}

