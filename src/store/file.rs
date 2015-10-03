// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use identity::Identity;
use proteus::keys::{PreKey, PreKeyId, IdentityKeyPair};
use proteus::session::Session;
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{self, Read, Write, ErrorKind};
use super::api::*;

#[derive(Copy, Clone, Eq, PartialEq)]
struct Version(u16);

const CURRENT_VERSION: Version = Version(1);

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

    fn read_version(root: &PathBuf) -> StorageResult<Option<Version>> {
        let p = root.join("version");
        match try!(open_file(&p)) {
            Some(mut f) => {
                let v = try!(f.read_u16::<BigEndian>());
                Ok(Some(Version(v)))
            }
            None => Ok(None)
        }
    }

    fn write_version(root: &PathBuf, Version(v): Version) -> StorageResult<()> {
        let p = root.join("version");
        let mut b = [0;2];
        try!(b.as_mut().write_u16::<BigEndian>(v));
        write_file(&p, &b, true)
    }

    fn migrate(_: Version) -> StorageResult<()> {
        // Future migrations for v < CURRENT_VERSION go here
        Ok(())
    }
}

impl Store for FileStore {
    fn load_session<'r>(&self, li: &'r IdentityKeyPair, id: &str) -> StorageResult<Option<Session<'r>>> {
        let path = self.session_dir.join(id);
        match try!(load_file(&path)) {
            Some(b) => Ok(Some(try!(Session::deserialise(li, &b)))),
            None    => Ok(None)
        }
    }

    fn save_session(&self, id: &str, s: &Session) -> StorageResult<()> {
        let path = self.session_dir.join(id);
        write_file(&path, &try!(s.serialise()), false)
    }

    fn delete_session(&self, id: &str) -> StorageResult<()> {
        let path = self.session_dir.join(id);
        remove_file(&path)
    }

    fn load_identity<'s>(&self) -> StorageResult<Option<Identity<'s>>> {
        let path = self.identity_dir.join("local");
        match try!(load_file(&path)) {
            Some(b) => Identity::deserialise(&b).map_err(From::from).map(Some),
            None    => Ok(None)
        }
    }

    fn save_identity(&self, id: &Identity) -> StorageResult<()> {
        let path = self.identity_dir.join("local");
        write_file(&path, &try!(id.serialise()), true)
    }

    fn add_prekey(&self, key: &PreKey) -> StorageResult<()> {
        let path = self.prekey_dir.join(&key.key_id.value().to_string());
        write_file(&path, &try!(key.serialise()), true)
    }

    fn load_prekey(&self, id: PreKeyId) -> StorageResult<Option<PreKey>> {
        let path = self.prekey_dir.join(&id.value().to_string());
        match try!(load_file(&path)) {
            Some(b) => PreKey::deserialise(&b).map_err(From::from).map(Some),
            None    => Ok(None)
        }
    }

    fn delete_prekey(&self, id: PreKeyId) -> StorageResult<()> {
        let path = self.prekey_dir.join(&id.value().to_string());
        remove_file(&path)
    }
}

fn open_file(p: &Path) -> StorageResult<Option<File>> {
    File::open(p).map(Some)
        .or_else(|e|
            if e.kind() == ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            }
        ).map_err(From::from)
}

fn load_file(p: &Path) -> StorageResult<Option<Vec<u8>>> {
    let file = match try!(open_file(p)) {
        Some(f) => f,
        None    => return Ok(None)
    };

    let mut buf = io::BufReader::new(file);
    let mut dat = Vec::new();

    try!(buf.read_to_end(&mut dat));
    Ok(Some(dat))
}

fn write_file(p: &Path, bytes: &[u8], sync: bool) -> StorageResult<()> {
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

fn remove_file(p: &Path) -> StorageResult<()> {
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
