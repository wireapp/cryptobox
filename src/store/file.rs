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
#![allow(non_snake_case)]
//use serde_json;
//use serde_json::error::Error as SerdeError;
//use serde::{Deserialize, Serialize};
use identity::Identity;
use proteus::{DecodeError, EncodeError};
use proteus::keys::{PreKey, PreKeyId, IdentityKeyPair};
use proteus::session::Session;
use std::borrow::{Borrow};
use std::error::Error;
use std::fmt;
//use std::path::Path;
use postgres::error as PgError;
use super::*;
use Armconn;
use uuid::Uuid;

#[derive(Copy, Clone, Eq, PartialEq)]
struct Version(i64);

const CURRENT_VERSION: Version = Version(1);

// PGDBStore ////////////////////////////////////////////////////////////////



#[derive(Debug)]
pub struct FileStore {
    botID: Uuid,

    dbconn: Armconn
}


//let mutex = Arc::new(Mutex::new(conn));
//let c_mutex = mutex.clone();

impl FileStore {
    pub fn new(id: Uuid, conn: Armconn) -> FileStoreResult<FileStore> {


//        let conn = Connection::connect(sql, TlsMode::None)
//            .unwrap();



        let fs = FileStore {
//            botID:  root.file_stem().unwrap().to_str().unwrap().to_owned(),
            botID:  id,
            dbconn: conn
        };
        initCheckSessionsTable(&fs.dbconn);
        initCheckPrekeysTable(&fs.dbconn);
        initCheckVersionsTable(&fs.dbconn);
        initCheckDatasTable(&fs.dbconn);
        initCheckIdentitiesTable(&fs.dbconn);
        // Print out the balances.
        println!("Initial cbox:");
        match try!(FileStore::read_version(&fs.dbconn, &fs.botID)) {
            Some(v) => { try!(FileStore::migrate(v)); return Ok(fs) },
            None    => ()
        }
        try!(FileStore::write_version(&fs.dbconn, &fs.botID, CURRENT_VERSION));

        Ok(fs)
    }

    fn read_version(conn: &Armconn, bid: &Uuid) -> FileStoreResult<Option<Version>> {

        let mut v: i64 =0;
        for row in &conn.lock().unwrap().query("SELECT version FROM cbox.version WHERE botID=$1", &[&bid]).unwrap() {
            v = row.get(0);
//            println!("SELECT version : {:?}  FROM cbox.version WHERE botID=  {:?}", v, bid);
        }


        match v {
            0 =>  Ok(None),
            _ =>  Ok(Some(Version(v)))
        }
    }

    fn write_version(conn: &Armconn, bid: &Uuid, Version(v): Version) -> FileStoreResult<()> {
        conn.lock().unwrap().execute("INSERT INTO cbox.version (botID, version) VALUES ($1, $2)", &[&bid, &v]).unwrap();
        Ok(())
    }

    fn migrate(_: Version) -> FileStoreResult<()> {
        // Future migrations for v < CURRENT_VERSION go here
        Ok(())
    }
}

impl Store for FileStore {
    type Error = FileStoreError;

    fn load_session<I: Borrow<IdentityKeyPair>>(&self, li: I, id: &str) -> FileStoreResult<Option<Session<I>>> {

        let mut v: Option<Vec<u8>> =None;
        for row in &self.dbconn.lock().unwrap().query("SELECT sessionValue FROM cbox.session WHERE botID=$1 AND session=$2", &[&self.botID, &id]).unwrap() {
            v = row.get(0);
//            println!("SELECT sessionValue : {:?}  FROM cbox.session WHERE botID=  {:?}", v, bid);
        }

        match v {
            Some(b) => Ok(Some(try!(Session::deserialise(li, &b)))),
            None    => Ok(None)
        }
    }

    fn save_session<I: Borrow<IdentityKeyPair>>(&self, id: &str, s: &Session<I>) -> FileStoreResult<()> {
        self.dbconn.lock().unwrap().execute("UPSERT  INTO cbox.session (botID, session, sessionValue) VALUES ($1, $2, $3)",
                     &[&self.botID, &id, &try!(s.serialise())]).unwrap();
        Ok(())
    }

    fn delete_session(&self, id: &str) -> FileStoreResult<()> {
        self.dbconn.lock().unwrap().execute("DELETE FROM cbox.session WHERE botID=$1 AND session=$2",
                            &[&self.botID, &id]).unwrap();
        Ok(())
    }

    fn load_identity<'s>(&self) -> FileStoreResult<Option<Identity<'s>>> {

        let mut v: Option<Vec<u8>> =None;
        for row in &self.dbconn.lock().unwrap().query("SELECT identitiyLocal FROM cbox.identitiy WHERE botID=$1", &[&self.botID]).unwrap() {
            v = row.get(0);
//            println!("SELECT identitiyLocal : {:?}  FROM cbox.identitiy WHERE botID=  {:?}", v, bid);
        }

        match v {
            Some(b) => Identity::deserialise(&b).map_err(From::from).map(Some),
            None    => Ok(None)
        }
    }

    fn save_identity(&self, id: &Identity) -> FileStoreResult<()> {
        self.dbconn.lock().unwrap().execute("INSERT INTO cbox.identitiy (botID, identitiyLocal) VALUES ($1, $2)",
                            &[&self.botID, &try!(id.serialise())]).unwrap();
        Ok(())
    }



    fn load_state(&self) -> FileStoreResult<Option<Vec<u8>>>
//        where for<'de> T: Deserialize<'de>
    {

        let mut v: Option<Vec<u8>> =None;
        for row in &self.dbconn.lock().unwrap().query("SELECT data FROM cbox.data WHERE botID=$1", &[&self.botID]).unwrap() {
            v = row.get(0);
//            println!("SELECT data : {:?}  FROM cbox.datas WHERE botID=  {:?}", v, bid);
        }

        match v {
            Some(b) => Ok(Some(b)),
            None    => Ok(None)
        }
    }

    fn save_state(&self, data: &Vec<u8>) -> FileStoreResult<()>
//        where T: Serialize
    {
        self.dbconn.lock().unwrap().execute("UPSERT  INTO cbox.data (botID, data) VALUES ($1, $2)",
                            &[&self.botID, &data]).unwrap();
        Ok(())
    }


    fn add_prekey(&self, key: &PreKey) -> FileStoreResult<()> {
        let key32 =key.key_id.value() as i64; //as i16 for SMALLINT
        self.dbconn.lock().unwrap().execute("INSERT INTO cbox.prekey (botID, prekey, prekeyValue) VALUES ($1, $2, $3)",
                            &[&self.botID, &key32 , &try!(key.serialise())]).unwrap();
        Ok(())
    }

    fn load_prekey(&self, id: PreKeyId) -> FileStoreResult<Option<PreKey>> {
        let key32 =id.value() as i64;
        let mut v: Option<Vec<u8>> =None;
        for row in &self.dbconn.lock().unwrap().query("SELECT prekeyValue FROM cbox.prekey WHERE botID=$1 AND prekey=$2", &[&self.botID, &key32]).unwrap() {
            v = row.get(0);
//            println!("SELECT prekeyValue : {:?}  FROM cbox.prekey WHERE botID=  {:?}", v, bid);
        }

        match v {
            Some(b) => PreKey::deserialise(&b).map_err(From::from).map(Some),
            None    => Ok(None)
        }


    }

    fn delete_prekey(&self, id: PreKeyId) -> FileStoreResult<()> {
        let key32 =id.value() as i64;
        self.dbconn.lock().unwrap().execute("DELETE FROM cbox.prekey WHERE botID=$1 AND prekey=$2",
                            &[&self.botID, &key32]).unwrap();
        Ok(())
    }




}




fn initCheckSessionsTable(conn: &Armconn) {
    conn.lock().unwrap().execute(
        "CREATE TABLE IF NOT EXISTS cbox.session (
session          STRING  NOT NULL PRIMARY KEY,
botID    	     UUID,
sessionValue     BYTES,
createdAt        TIMESTAMP Default  now(),
updatedAt        TIMESTAMP Default  now(),
INDEX 		     botID_idx (botID)
) ;",&[],
    ).unwrap();
}

fn initCheckPrekeysTable(conn: &Armconn) {
    conn.lock().unwrap().execute(
        "CREATE TABLE IF NOT EXISTS cbox.prekey (
prekey      INT NOT NULL PRIMARY KEY,
botID    	UUID,
prekeyValue BYTES,
createdAt   TIMESTAMP Default  now(),
updatedAt   TIMESTAMP Default  now(),
INDEX 		botID_idx (botID)
) ;",&[],
    ).unwrap();
}
fn initCheckIdentitiesTable(conn: &Armconn) {
    conn.lock().unwrap().execute(
        "CREATE TABLE IF NOT EXISTS cbox.identitiy (
botID    	        UUID NOT NULL PRIMARY KEY,
identitiyLocal      BYTES,
createdAt           TIMESTAMP Default  now(),
updatedAt           TIMESTAMP Default  now()
) ;",&[],
    ).unwrap();
}
fn initCheckVersionsTable(conn: &Armconn) {
    conn.lock().unwrap().execute(
        "CREATE TABLE IF NOT EXISTS cbox.version (
botID    	UUID NOT NULL PRIMARY KEY,
version     INT,
createdAt   TIMESTAMP Default  now(),
updatedAt   TIMESTAMP Default  now()
) ;",&[],
    ).unwrap();
}

fn initCheckDatasTable(conn: &Armconn) {
    conn.lock().unwrap().execute(
        "CREATE TABLE IF NOT EXISTS cbox.data (
botID    	UUID NOT NULL PRIMARY KEY,
data        BYTES,
createdAt   TIMESTAMP Default  now(),
updatedAt   TIMESTAMP Default  now()
) ;",&[],
    ).unwrap();
}

// FileStoreError ///////////////////////////////////////////////////////////

pub type FileStoreResult<A> = Result<A, FileStoreError>;

#[derive(Debug)]
pub enum FileStoreError {
    Io(PgError::Error),
    Decode(DecodeError),
    Encode(EncodeError),
//    Serde(SerdeError),

}

impl fmt::Display for FileStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            FileStoreError::Io(ref e)     => write!(f, "FileStoreError: DB error: {}", e),
            FileStoreError::Decode(ref e) => write!(f, "FileStoreError: Decode error: {}", e),
            FileStoreError::Encode(ref e) => write!(f, "FileStoreError: Encode error: {}", e),
//            FileStoreError::Serde(ref e) => write!(f, "FileStoreError: Serde_json error: {}", e),
        }
    }
}

impl Error for FileStoreError {
    fn description(&self) -> &str {
        "FileStoreError"
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            FileStoreError::Io(ref e)     => Some(e),
            FileStoreError::Decode(ref e) => Some(e),
            FileStoreError::Encode(ref e) => Some(e),
//            FileStoreError::Serde(ref e) => Some(e),
        }
    }
}

impl From<PgError::Error> for FileStoreError {
    fn from(e: PgError::Error) -> FileStoreError {
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

//impl From<SerdeError> for FileStoreError {
//    fn from(e: SerdeError) -> FileStoreError {
//    FileStoreError::Serde(e)
//    }
//}
