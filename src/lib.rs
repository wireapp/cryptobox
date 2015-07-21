// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

#![feature(libc, box_raw)]

extern crate libc;
extern crate proteus;
extern crate rustc_serialize;

mod log;
mod store;

pub mod api;
