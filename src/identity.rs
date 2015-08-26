// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::{Decoder, Encoder, Config};
use cbor::skip::Skip;
use proteus::{DecodeError, EncodeError};
use proteus::keys::{IdentityKeyPair, IdentityKey};
use std::borrow::Cow;
use std::io;

pub enum Identity<'r> {
    Sec(Cow<'r, IdentityKeyPair>),
    Pub(Cow<'r, IdentityKey>)
}

impl<'r> Identity<'r> {
    pub fn serialise(&self) -> Result<Vec<u8>, EncodeError> {
        let mut e = Encoder::new(io::Cursor::new(Vec::new()));
        try!(self.encode(&mut e));
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise<'s>(b: &[u8]) -> Result<Identity<'s>, DecodeError> {
        Identity::decode(&mut Decoder::new(Config::default(), io::Cursor::new(b)))
    }

    fn encode<W: io::Write>(&self, e: &mut Encoder<W>) -> Result<(), EncodeError> {
        match *self {
            Identity::Sec(ref id) => {
                try!(e.u8(1));
                try!(e.object(1));
                try!(e.u8(0)); id.encode(e)
            }
            Identity::Pub(ref id) => {
                try!(e.u8(2));
                try!(e.object(1));
                try!(e.u8(0)); id.encode(e)
            }
        }
    }

    fn decode<'s, R: io::Read + Skip>(d: &mut Decoder<R>) -> Result<Identity<'s>, DecodeError> {
        match try!(d.u8()) {
            1 => {
                let n = try!(d.object());
                let mut keypair = None;
                for _ in 0 .. n {
                    match try!(d.u8()) {
                        0 => keypair = Some(Identity::Sec(Cow::Owned(try!(IdentityKeyPair::decode(d))))),
                        _ => try!(d.skip())
                    }
                }
                keypair.ok_or(DecodeError::MissingField("identity keypair"))
            }
            2 => {
                let n = try!(d.object());
                let mut key = None;
                for _ in 0 .. n {
                    match try!(d.u8()) {
                        0 => key = Some(Identity::Pub(Cow::Owned(try!(IdentityKey::decode(d))))),
                        _ => try!(d.skip())
                    }
                }
                key.ok_or(DecodeError::MissingField("identity key"))
            }
            t => Err(DecodeError::InvalidType(t, "unknown identity type"))
        }
    }
}
