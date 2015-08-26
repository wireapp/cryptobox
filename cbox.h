#ifndef __CRYPTOBOX_H__
#define __CRYPTOBOX_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// CBoxVec //////////////////////////////////////////////////////////////////
// A heap-allocated vector of bytes.
typedef struct CBoxVec CBoxVec;

// Get a pointer to the contents of a byte vector.
uint8_t * cbox_vec_data(CBoxVec const * v);

// Get the length of a byte vector.
size_t cbox_vec_len(CBoxVec  const * v);

// Deallocate a byte vector.
void cbox_vec_free(CBoxVec * v);

// CBoxResult ///////////////////////////////////////////////////////////////
// The result of an operation that might fail.
typedef enum {
    CBOX_SUCCESS                 = 0,

    // An internal storage error occurred.
    CBOX_STORAGE_ERROR           = 1,

    // A CBoxSession was not found.
    CBOX_NO_SESSION              = 2,

    // An error occurred during binary decoding of a data structure.
    CBOX_DECODE_ERROR            = 3,

    // The (prekey-)message being decrypted contains a different
    // remote identity than previously received.
    CBOX_REMOTE_IDENTITY_CHANGED = 4,

    // The (prekey-)message being decrypted has an invalid signature.
    // This might indicate that the message has been tampered with.
    CBOX_INVALID_SIGNATURE       = 5,

    // The (prekey-)message being decrypted is invalid given the
    // current state of the CBoxSession.
    CBOX_INVALID_MESSAGE         = 6,

    // The (prekey-)message being decrypted is a duplicate and can
    // be safely discarded.
    CBOX_DUPLICATE_MESSAGE       = 7,

    // The (prekey-)message being decrypted is out of bounds for the
    // supported range of skipped / delayed messages.
    CBOX_TOO_DISTANT_FUTURE      = 8,

    // The (prekey-)message being decrypted is out of bounds for the
    // supported range of skipped / delayed messages.
    CBOX_OUTDATED_MESSAGE        = 9,

    // A string argument is not utf8-encoded.
    // This is typically a programmer error.
    CBOX_UTF8_ERROR              = 10,

    // A string argument is missing a NUL terminator.
    // This is typically a programmer error.
    CBOX_NUL_ERROR               = 11,

    // An error occurred during binary encoding of a data structure.
    CBOX_ENCODE_ERROR            = 12,

    // A CBox has been opened with an incomplete or mismatching identity.
    // This is typically a programmer error.
    CBOX_IDENTITY_ERROR          = 13
} CBoxResult;

// CBoxIdentityMode /////////////////////////////////////////////////////////

typedef enum {
    // The full identity is stored locally inside the CBox.
    CBOX_IDENTITY_COMPLETE = 0,

    // Only the public identity is stored locally inside the CBox.
    CBOX_IDENTITY_PUBLIC   = 1
} CBoxIdentityMode;

// CBox /////////////////////////////////////////////////////////////////////

typedef struct CBox CBox;

// Open a CBox.
CBoxResult cbox_file_open(char const * path, CBox ** b);

// Open a CBox using an existing external identity.
// ---
// `path` is a path to an existing directory. ...
//
// `ident` is the external identity to use.  An existing CBox with only
// a public local identity must always be opened with an external identity.
//
// `ident_len` is the length of `ident`.
//
// `mode` specifies the desired locally stored identity.
CBoxResult cbox_file_open_with(char const * path,
                               uint8_t const * ident,
                               size_t ident_len,
                               CBoxIdentityMode mode,
                               CBox ** b);

// Copies the serialised identity keypair from the given cryptobox.
CBoxResult cbox_identity_copy(CBox const * b, CBoxVec ** ident);

// Close a CBox, freeing the memory associated with it.
//
// Note: A box should only be closed after all sessions acquired through it
// have been closed. Any remaining open sessions that were obtained from the
// box can no longer be used with the exception of being closed via
// `cbox_session_close`.
void cbox_close(CBox * b);

// Prekeys //////////////////////////////////////////////////////////////////

// The ID of the "last resort" prekey, which is never removed.
extern const uint16_t CBOX_LAST_PREKEY_ID;

// Generate a new prekey, returning the public prekey for usage by a peer.
CBoxResult cbox_new_prekey(CBox * b, uint16_t id, CBoxVec ** prekey);

// CBoxSession //////////////////////////////////////////////////////////////
// A cryptographic session with a peer.
typedef struct CBoxSession CBoxSession;

// Initialise a session from a public prekey of a peer.
//
// This is the entry point for the sender of a message, if no session exists.
// ---
// `b` is the box in which the session is created. The session will be bound
//     to the lifetime of the box and can only be used until either the
//     session or the box is closed.
//
// `sid` is a unique ID to use for the new session.
//
// `peer_prekey` is the public prekey of the peer.
//
// `peer_prekey_len` is the length (in bytes) of the `peer_prekey`.
//
// `s` is the target pointer for the successfully initialised session.
CBoxResult
cbox_session_init_from_prekey(CBox * b,
                              char const * sid,
                              uint8_t const * peer_prekey,
                              size_t peer_prekey_len,
                              CBoxSession ** s);

// Initialise a session from a ciphertext message.
//
// This is the entry point for the recipient of a message, if no session exists.
// ---
// `b` is the box in which the session is created. The session will be bound
//     to the lifetime of the box and can only be used until either the
//     session or the box is closed.
//
// `sid` is a unique ID to use for the new session.
//
// `cipher` is the received ciphertext message.
//
// `cipher_len` is the length (in bytes) of `cipher`.
//
// `s` is the target pointer for the successfully initialised session.
//
// `plain` is the target pointer for the successfully decrypted message.
CBoxResult
cbox_session_init_from_message(CBox * b,
                               char const * sid,
                               uint8_t const * cipher,
                               size_t cipher_len,
                               CBoxSession ** s,
                               CBoxVec ** plain);

// Lookup a session by ID.
//
// If the session is not found, `CBOX_NO_SESSION` is returned.
// ---
// `b` is the box in which to look for the session. The session will be bound
//     to the lifetime of the box and can only be used until either the
//     session or the box is closed.
//
// `sid` is the session ID to look for.
//
// `s` is the target pointer for the session, if it is found.
CBoxResult cbox_session_get(CBox * b, char const * sid, CBoxSession ** s);

// Save a session.
//
// Saving a session makes any changes to the key material as a result of
// `cbox_encrypt` and `cbox_decrypt` permanent. Newly initialised sessions
// as a result of `cbox_session_init_from_message` and `cbox_session_init_from_prekey`
// are also only persisted when saved, to facilitate retries.
//
// Saving a session is highly ...
// ---
// `s` is the session to save.
CBoxResult cbox_session_save(CBoxSession * s);

// Get the ID of a session.
//
// Returns the ID of the given session, as it was given during initialisation.
// ---
// `s` is the session for which to retreive the ID.
char const * cbox_session_id(CBoxSession const * s);

// Close a session, freeing the memory associated with it.
//
// Note: After a session has been closed, it must no longer be used.
void cbox_session_close(CBoxSession * s);

// Delete an existing session.
//
// If the session does not exist, this function does nothing.
CBoxResult cbox_session_delete(CBox * b, char const * sid);

// Encrypt a plaaintext message.
//
// TODO
CBoxResult cbox_encrypt(CBoxSession * s, uint8_t const * plain, size_t plain_len, CBoxVec ** cipher);

// Decrypt a ciphertext nessage.
//
// TODO
CBoxResult cbox_decrypt(CBoxSession * s, uint8_t const * cipher, size_t cipher_len, CBoxVec ** plain);

// Get the public key fingerprint of the local identity.
//
// The fingerprint is represented as a hex-encoded byte vector.
// ---
// `b` is the box from which to obtain the fingerprint.
//
// `fp` is the target pointer for the fingerprint.
void cbox_fingerprint_local(CBox const * b, CBoxVec ** fp);

// Get the public key fingerprint of the remote identity associated with
// the given session.
// ---
// TODO
void cbox_fingerprint_remote(CBoxSession const * s, CBoxVec ** fp);

// Generate `len` cryptographically strong random bytes.
CBoxVec * cbox_random_bytes(CBox const * b, size_t len);


#ifdef __cplusplus
}
#endif


#endif // __CRYPTOBOX_H__
