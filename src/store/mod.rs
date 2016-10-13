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

use std::borrow::Borrow;
use identity::Identity;
use proteus::keys::{IdentityKeyPair, PreKey, PreKeyId};
use proteus::session::Session;

pub mod file;

pub trait Store {
    type Error: ::std::error::Error;

    fn load_session<I: Borrow<IdentityKeyPair>>(&self, li: I, id: &str) -> Result<Option<Session<I>>, Self::Error>;
    fn save_session<I: Borrow<IdentityKeyPair>>(&self, id: &str, s: &Session<I>) -> Result<(), Self::Error>;
    fn delete_session(&self, id: &str) -> Result<(), Self::Error>;

    fn load_identity<'s>(&self) -> Result<Option<Identity<'s>>, Self::Error>;
    fn save_identity(&self, id: &Identity) -> Result<(), Self::Error>;

    fn load_prekey(&self, id: PreKeyId) -> Result<Option<PreKey>, Self::Error>;
    fn add_prekey(&self, key: &PreKey) -> Result<(), Self::Error>;
    fn delete_prekey(&self, id: PreKeyId) -> Result<(), Self::Error>;
}
