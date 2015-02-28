// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use libproteus::{DecodeError, DecodeSessionError};
use libproteus::keys::{PreKey, IdentityKeyPair};
use libproteus::session::{Session, PreKeyStore};
use std::error::{Error, FromError};
use std::fmt;
use std::io;

// API //////////////////////////////////////////////////////////////////////

pub type StorageResult<T> = Result<T, StorageError>;

pub trait Store: PreKeyStore<StorageError> {
    fn load_session<'r>(&self, li: &'r IdentityKeyPair, id: &str) -> StorageResult<Option<Session<'r>>>;
    fn save_session(&self, id: &str, s: &Session) -> StorageResult<()>;
    fn load_identity(&self) -> StorageResult<Option<IdentityKeyPair>>;
    fn save_identity(&self, id: &IdentityKeyPair) -> StorageResult<()>;
    fn add_prekey(&self, key: &PreKey) -> StorageResult<()>;
}

// Errors ///////////////////////////////////////////////////////////////////

pub struct StorageError {
    pub cause: Box<Error + 'static>
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "StorageError: {}", self.cause)
    }
}

impl Error for StorageError {
    fn description(&self) -> &str {
        "StorageError"
    }

    fn cause(&self) -> Option<&Error> {
        Some(&*self.cause)
    }
}

impl FromError<io::Error> for StorageError {
    fn from_error(e: io::Error) -> StorageError {
        StorageError { cause: Box::new(e) }
    }
}

impl FromError<DecodeError> for StorageError {
    fn from_error(e: DecodeError) -> StorageError {
        StorageError { cause: Box::new(e) }
    }
}

impl FromError<DecodeSessionError> for StorageError {
    fn from_error(e: DecodeSessionError) -> StorageError {
        StorageError { cause: Box::new(e) }
    }
}
