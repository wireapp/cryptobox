// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use libproteus::keys::{PreKey, PreKeyId, IdentityKeyPair, rand_bytes};
use libproteus::session::{Session, PreKeyStore};
use rustc_serialize::hex::ToHex;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{self, Read, Write, ErrorKind};
use super::api::*;

#[derive(Debug)]
pub struct FileStore {
    root_dir:     PathBuf,
    session_dir:  PathBuf,
    prekey_dir:   PathBuf,
    identity_dir: PathBuf
}

impl FileStore {
    pub fn new(root: &Path) -> StorageResult<FileStore> {
        let fs = FileStore {
            root_dir:     PathBuf::from(root),
            session_dir:  root.join("sessions"),
            prekey_dir:   root.join("prekeys"),
            identity_dir: root.join("identities")
        };

        if !dir_exists(&fs.session_dir) {
            try!(fs::create_dir(&fs.session_dir));
        }
        if !dir_exists(&fs.prekey_dir) {
            try!(fs::create_dir(&fs.prekey_dir));
        }
        if !dir_exists(&fs.identity_dir) {
            try!(fs::create_dir(&fs.identity_dir));
        }

        Ok(fs)
    }

}

impl Store for FileStore {
    fn load_session<'r>(&self, li: &'r IdentityKeyPair, id: &str) -> StorageResult<Option<Session<'r>>> {
        let path = self.session_dir.join(id);
        match try!(load_file(&path)) {
            Some(b) => Ok(Some(try!(Session::decode(li, &b)))),
            None    => Ok(None)
        }
    }

    fn save_session(&self, id: &str, s: &Session) -> StorageResult<()> {
        let path = self.session_dir.join(id);
        save(&path, &s.encode())
    }

    fn load_identity(&self) -> StorageResult<Option<IdentityKeyPair>> {
        let path = self.identity_dir.join("local_identity");
        match try!(load_file(&path)) {
            Some(b) => IdentityKeyPair::decode(&b).map_err(From::from).map(Some),
            None    => Ok(None)
        }
    }

    fn save_identity(&self, id: &IdentityKeyPair) -> StorageResult<()> {
        let path = self.identity_dir.join("local_identity");
        save(&path, &id.encode())
    }

    fn add_prekey(&self, key: &PreKey) -> StorageResult<()> {
        let path = self.prekey_dir.join(&key.key_id.value().to_string());
        save(&path, &key.encode())
    }
}

impl PreKeyStore<StorageError> for FileStore {
    fn prekey(&self, id: PreKeyId) -> StorageResult<Option<PreKey>> {
        let path = self.prekey_dir.join(&id.value().to_string());
        match try!(load_file(&path)) {
            Some(b) => PreKey::decode(&b).map_err(From::from).map(Some),
            None    => Ok(None)
        }
    }

    fn remove(&mut self, id: PreKeyId) -> StorageResult<()> {
        let path = self.prekey_dir.join(&id.value().to_string());
        fs::remove_file(&path)
            .or_else(|e|
                if e.kind() == ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            ).map_err(From::from)
    }
}

fn load_file(p: &Path) -> StorageResult<Option<Vec<u8>>> {
    if !file_exists(p) {
        return Ok(None)
    }

    let     file = try!(File::open(p));
    let mut buf  = io::BufReader::new(file);
    let mut dat  = Vec::new();

    try!(buf.read_to_end(&mut dat));
    Ok(Some(dat))
}

fn save(p: &Path, bytes: &[u8]) -> StorageResult<()> {
    fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = try!(File::create(&path));
        (file.write_all(bytes).and(file.sync_all())).or_else(|e| {
            let _ = fs::remove_file(&path);
            Err(e)
        })
    }
    let path = p.with_extension(&rand_bytes(4).to_hex());
    try!(write(&path, bytes));
    fs::rename(&path, p).map_err(From::from)
}

fn dir_exists(p: &Path) -> bool {
    fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

fn file_exists(p: &Path) -> bool {
    fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}
