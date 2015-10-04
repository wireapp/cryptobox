// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use identity::Identity;
use proteus::keys::{IdentityKeyPair, PreKey, PreKeyId};
use proteus::session::Session;

pub mod file;

pub trait Store {
    type Error: ::std::error::Error;

    fn load_session<'r>(&self, li: &'r IdentityKeyPair, id: &str) -> Result<Option<Session<'r>>, Self::Error>;
    fn save_session(&self, id: &str, s: &Session) -> Result<(), Self::Error>;
    fn delete_session(&self, id: &str) -> Result<(), Self::Error>;

    fn load_identity<'s>(&self) -> Result<Option<Identity<'s>>, Self::Error>;
    fn save_identity(&self, id: &Identity) -> Result<(), Self::Error>;

    fn load_prekey(&self, id: PreKeyId) -> Result<Option<PreKey>, Self::Error>;
    fn add_prekey(&self, key: &PreKey) -> Result<(), Self::Error>;
    fn delete_prekey(&self, id: PreKeyId) -> Result<(), Self::Error>;
}
