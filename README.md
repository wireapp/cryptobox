# Cryptobox

`Cryptobox` provides a high-level C API with persistent storage for the [proteus](https://github.com/twittner/proteus) implementation of the [axolotl](https://github.com/trevp/axolotl/wiki) protocol.

It can be used to implement [end-to-end encryption](http://en.wikipedia.org/wiki/End-to-end_encryption) with [forward secrecy](http://en.wikipedia.org/wiki/Forward_secrecy), [future secrecy](https://whispersystems.org/blog/advanced-ratcheting/) and [deniability](http://en.wikipedia.org/wiki/Deniable_authentication) in an asynchronous environment.

**Disclaimer: This project is an early work-in-progress.**

## Dependencies

[Sodium](https://github.com/jedisct1/libsodium)

## API Overview

The following is an API overview. For detailed function signatures, refer to the [cbox.h](cbox.h) header file.

### CBox

A `CBox` is an opaque container for all the necessary key material of a single client (e.g. a single device of a user).
A `CBox` is allocated with a call to `cbox_file_open`. It takes a `path` as an argument which must be a valid file path
pointing to an existing directory. That directory becomes the root directory for all data stored by that `CBox` or any of the `CBoxSession`s
obtained from it.

> Note: Do not create multiple `CBox`es that operate on the same or overlapping directories.

Opened `CBox`es should typically be used for an extended period of time to obtain sessions and in turn
encrypt and decrypt messages.

> Note: Every call to `cbox_file_open` must be paired with a `cbox_close` to properly deallocate the `CBox`.

### CBoxSession

A `CBoxSession` represents a cryptographic session between two endpoints (e.g. devices).
Sessions are identified through a session ID, which is an opaque C string for
the `CryptoBox` API. A session ID should uniquely identify a remote client or device.

#### Obtaining an existing session

Before deciding to initialise a new session, a client typically tries to obtain an existing session
using `cbox_session_get`. If no session is found, the `CBOX_NO_SESSION` error code is returned.

#### Initialising a new session

If no session for a given session ID exists, a new session can be initialised either through
`cbox_session_init_from_prekey` or `cbox_session_init_from_message`.

A client who wants to send a message to another client with whom no session exists obtains a prekey from its peer
(directly or indirectly) and uses `cbox_session_init_from_prekey`.

A client who receives an encrypted message from another client with whom he has no existing session
uses `cbox_session_init_from_message`.

#### Encrypting and decrypting messages

Once a session is obtained it can be used to encrypt and decrypt messages via `cbox_session_encrypt`
and `cbox_session_decrypt`, respectively.

The encrypt and decrypt operations fill `CBoxVec` structures which provide access to the encrypted or decrypted
data via `cbox_vec_data` as well as its length through `cbox_vec_len`. Once the data has been consumed and is
no longer needed, a `CBoxVec` must be freed using `cbox_vec_free`.

> Note: Every call to `cbox_session_get`, `cbox_session_init_from_prekey` or `cbox_session_init_from_message`
must be paired with a `cbox_session_close` to properly deallocate the `CBoxSession`.

#### Saving a session

After successfully encrypting and/or decrypting one or more messages, a session can be saved
through `cbox_session_save`. Once a session is saved, the changes to the key material are
permanent, e.g. a decrypt operation cannot be repeated. It can therefore be advisable to
save a session only once the decrypted plaintext has been safely stored.

### Prekeys

In order to establish sessions, one client must be able to obtain a prekey from another.
To generate a prekey, `cbox_new_prekey` is used, which fills a `CBoxVec` with the public
key meterial of the newly generated prekey which can then be sent directly to another
client or uploaded to a server for others to download.

### Fingerprints

Public key fingerprints can be compared out-of-band to protect against MITM attacks.
The functions `cbox_fingerprint_local` and `cbox_fingerprint_remote` are provided for
that purpose.

## Thread-safety

The API is not thread-safe. However, distinct `CBox`es and `CBoxSession`s can be used
independently (and concurrently). It is up to client code or higher-level language bindings
to provide thread-safety as necessary for the desired usage pattern.

> Note: When sessions are used concurrently, it is important to make sure not to have
> two or more sessions with the same session ID in use at the same time.

## Error Handling

TODO

## Higher-level Language Bindings

### Java

A Java API through JNI with support for cross-compilation to Android is provided by [cryptobox-jni](https://github.com/romanb/cryptobox-jni).
