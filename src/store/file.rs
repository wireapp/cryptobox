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

use byteorder::{self, BigEndian, ReadBytesExt, WriteBytesExt};
use identity::Identity;
use proteus::{DecodeError, EncodeError};
use proteus::keys::{PreKey, PreKeyId, IdentityKeyPair};
use proteus::session::Session;
use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write, ErrorKind};
use std::path::{Path, PathBuf};
use super::*;

#[derive(Copy, Clone, Eq, PartialEq)]
struct Version(u16);

const CURRENT_VERSION: Version = Version(1);

// FileStore ////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct FileStore {
    root_dir:     PathBuf,
    session_dir:  PathBuf,
    prekey_dir:   PathBuf,
    identity_dir: PathBuf
}

impl FileStore {
    pub fn new(root: &Path) -> FileStoreResult<FileStore> {
        let fs = FileStore {
            root_dir:     PathBuf::from(root),
            session_dir:  root.join("sessions"),
            prekey_dir:   root.join("prekeys"),
            identity_dir: root.join("identities")
        };

        match try!(FileStore::read_version(&fs.root_dir)) {
            Some(v) => { try!(FileStore::migrate(v)); return Ok(fs) },
            None    => ()
        }

        if !dir_exists(&fs.session_dir) {
            try!(fs::create_dir(&fs.session_dir));
        }
        if !dir_exists(&fs.prekey_dir) {
            try!(fs::create_dir(&fs.prekey_dir));
        }
        if !dir_exists(&fs.identity_dir) {
            try!(fs::create_dir(&fs.identity_dir));
        } else {
            // Legacy: Migrate old "local_identity"
            let p = fs.identity_dir.join("local_identity");
            // 1. load old identity
            match try!(load_file(&p)) {
                None    => (),
                Some(b) => {
                    let kp = try!(IdentityKeyPair::deserialise(&b));
                    let i = Identity::Sec(Cow::Borrowed(&kp));
                    // 2. write new local identity
                    try!(fs.save_identity(&i));
                    // 3. delete old identity
                    try!(remove_file(&p));
                }
            };
        }

        try!(FileStore::write_version(&fs.root_dir, CURRENT_VERSION));

        Ok(fs)
    }

    fn read_version(root: &PathBuf) -> FileStoreResult<Option<Version>> {
        let p = root.join("version");
        match try!(open_file(&p)) {
            Some(mut f) => {
                let v = try!(f.read_u16::<BigEndian>());
                Ok(Some(Version(v)))
            }
            None => Ok(None)
        }
    }

    fn write_version(root: &PathBuf, Version(v): Version) -> FileStoreResult<()> {
        let p = root.join("version");
        let mut b = [0;2];
        try!(b.as_mut().write_u16::<BigEndian>(v));
        write_file(&p, &b, true)
    }

    fn migrate(_: Version) -> io::Result<()> {
        // Future migrations for v < CURRENT_VERSION go here
        Ok(())
    }
}

impl Store for FileStore {
    type Error = FileStoreError;

    fn load_session<'r>(&self, li: &'r IdentityKeyPair, id: &str) -> FileStoreResult<Option<Session<'r>>> {
        let path = self.session_dir.join(id);
        match try!(load_file(&path)) {
            Some(b) => Ok(Some(try!(Session::deserialise(li, &b)))),
            None    => Ok(None)
        }
    }

    fn save_session(&self, id: &str, s: &Session) -> FileStoreResult<()> {
        let path = self.session_dir.join(id);
        write_file(&path, &try!(s.serialise()), false)
    }

    fn delete_session(&self, id: &str) -> FileStoreResult<()> {
        let path = self.session_dir.join(id);
        remove_file(&path)
    }

    fn load_identity<'s>(&self) -> FileStoreResult<Option<Identity<'s>>> {
        let path = self.identity_dir.join("local");
        match try!(load_file(&path)) {
            Some(b) => Identity::deserialise(&b).map_err(From::from).map(Some),
            None    => Ok(None)
        }
    }

    fn save_identity(&self, id: &Identity) -> FileStoreResult<()> {
        let path = self.identity_dir.join("local");
        write_file(&path, &try!(id.serialise()), true)
    }

    fn add_prekey(&self, key: &PreKey) -> FileStoreResult<()> {
        let path = self.prekey_dir.join(&key.key_id.value().to_string());
        write_file(&path, &try!(key.serialise()), true)
    }

    fn load_prekey(&self, id: PreKeyId) -> FileStoreResult<Option<PreKey>> {
        let path = self.prekey_dir.join(&id.value().to_string());
        match try!(load_file(&path)) {
            Some(b) => PreKey::deserialise(&b).map_err(From::from).map(Some),
            None    => Ok(None)
        }
    }

    fn delete_prekey(&self, id: PreKeyId) -> FileStoreResult<()> {
        let path = self.prekey_dir.join(&id.value().to_string());
        remove_file(&path)
    }
}

fn open_file(p: &Path) -> FileStoreResult<Option<File>> {
    File::open(p).map(Some)
        .or_else(|e|
            if e.kind() == ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            }
        ).map_err(From::from)
}

fn load_file(p: &Path) -> FileStoreResult<Option<Vec<u8>>> {
    let file = match try!(open_file(p)) {
        Some(f) => f,
        None    => return Ok(None)
    };

    let mut buf = io::BufReader::new(file);
    let mut dat = Vec::new();

    try!(buf.read_to_end(&mut dat));
    Ok(Some(dat))
}

fn write_file(p: &Path, bytes: &[u8], sync: bool) -> FileStoreResult<()> {
    fn write(path: &Path, bytes: &[u8], sync: bool) -> io::Result<()> {
        let mut file = try!(File::create(&path));
        let mut rs = file.write_all(bytes);
        if sync {
            rs = rs.and(file.sync_all());
        }
        rs.or_else(|e| {
            let _ = fs::remove_file(&path);
            Err(e)
        })
    }
    let path = p.with_extension("tmp");
    try!(write(&path, bytes, sync));
    fs::rename(&path, p).map_err(From::from)
}

fn remove_file(p: &Path) -> FileStoreResult<()> {
    fs::remove_file(p)
        .or_else(|e|
            if e.kind() == ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        ).map_err(From::from)
}

fn dir_exists(p: &Path) -> bool {
    fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

// FileStoreError ///////////////////////////////////////////////////////////

pub type FileStoreResult<A> = Result<A, FileStoreError>;

#[derive(Debug)]
pub enum FileStoreError {
    Io(io::Error),
    Decode(DecodeError),
    Encode(EncodeError),
    ByteOrder(byteorder::Error)
}

impl fmt::Display for FileStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            FileStoreError::Io(ref e)        => write!(f, "FileStoreError: I/O error: {}", e),
            FileStoreError::Decode(ref e)    => write!(f, "FileStoreError: Decode error: {}", e),
            FileStoreError::Encode(ref e)    => write!(f, "FileStoreError: Encode error: {}", e),
            FileStoreError::ByteOrder(ref e) => write!(f, "FileStoreError: ByteOrder error: {}", e)
        }
    }
}

impl Error for FileStoreError {
    fn description(&self) -> &str {
        "FileStoreError"
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            FileStoreError::Io(ref e)        => Some(e),
            FileStoreError::Decode(ref e)    => Some(e),
            FileStoreError::Encode(ref e)    => Some(e),
            FileStoreError::ByteOrder(ref e) => Some(e)
        }
    }
}

impl From<io::Error> for FileStoreError {
    fn from(e: io::Error) -> FileStoreError {
        FileStoreError::Io(e)
    }
}

impl From<DecodeError> for FileStoreError {
    fn from(e: DecodeError) -> FileStoreError {
        FileStoreError::Decode(e)
    }
}

impl From<EncodeError> for FileStoreError {
    fn from(e: EncodeError) -> FileStoreError {
        FileStoreError::Encode(e)
    }
}

impl From<byteorder::Error> for FileStoreError {
    fn from(e: byteorder::Error) -> FileStoreError {
        FileStoreError::ByteOrder(e)
    }
}
