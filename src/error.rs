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

use std::error::Error;
use std::fmt;

use proteus::{self, DecodeError, EncodeError};
use store::Store;
use store::file::{FileStore, FileStoreError};

#[derive(Debug)]
pub enum CBoxError<S: Store> {
    ProteusError(proteus::session::Error<S::Error>),
    StorageError(S::Error),
    DecodeError(DecodeError),
    EncodeError(EncodeError),
    IdentityError,
    InitError,
    SessionClosed
}

impl<S: Store> fmt::Display for CBoxError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            CBoxError::ProteusError(ref e) => write!(f, "CBoxError: proteus error: {}", e),
            CBoxError::StorageError(ref e) => write!(f, "CBoxError: storage error: {}", *e),
            CBoxError::DecodeError(ref e)  => write!(f, "CBoxError: decode error: {}", *e),
            CBoxError::EncodeError(ref e)  => write!(f, "CBoxError: encode error: {}", *e),
            CBoxError::IdentityError       => write!(f, "CBoxError: identity error"),
            CBoxError::InitError           => write!(f, "CBoxError: initialisation error"),
            CBoxError::SessionClosed       => write!(f, "CBoxError: session closed")
        }
    }
}

impl<S: Store + fmt::Debug> Error for CBoxError<S> {
    fn description(&self) -> &str {
        "CBoxError"
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CBoxError::ProteusError(ref e) => Some(e),
            CBoxError::StorageError(ref e) => Some(e),
            CBoxError::DecodeError(ref e)  => Some(e),
            CBoxError::EncodeError(ref e)  => Some(e),
            _                              => None
        }
    }
}

impl From<FileStoreError> for CBoxError<FileStore> {
    fn from(e: FileStoreError) -> CBoxError<FileStore> {
        CBoxError::StorageError(e)
    }
}

impl<S: Store> From<proteus::session::Error<S::Error>> for CBoxError<S> {
    fn from(e: proteus::session::Error<S::Error>) -> CBoxError<S> {
        CBoxError::ProteusError(e)
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

