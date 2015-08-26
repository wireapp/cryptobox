// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use std::error::Error;

pub fn error<E: Error>(e: &E) {
    target::error(e)
}

// ANDROID //////////////////////////////////////////////////////////////////

#[cfg(target_os = "android")]
mod target {
    use libc::*;
    use std::error::Error;
    use std::ffi::*;

    const TAG: &'static [u8] = b"CryptoBox";
    const LEVEL_ERROR: c_int = 6;

    pub fn error<E: Error>(e: &E) {
        log(&format!("{}", e), LEVEL_ERROR)
    }

    fn log(msg: &str, lvl: c_int) {
        let tag = CString::new(TAG).unwrap();
        let msg = CString::new(msg.as_bytes()).unwrap_or(CString::new("<malformed log message>").unwrap());
        unsafe {
            __android_log_write(lvl, tag.as_ptr(), msg.as_ptr())
        };
    }

    #[link(name = "log")]
    extern {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }
}

// FALLBACK /////////////////////////////////////////////////////////////////

#[cfg(not(target_os = "android"))]
mod target {
    use std::error::Error;
    use std::io::{Write, stderr};

    pub fn error<E: Error>(e: &E) {
        writeln!(&mut stderr(), "ERROR: {}", e).unwrap();
    }
}
