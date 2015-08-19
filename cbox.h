#ifndef __CRYPTOBOX_H__
#define __CRYPTOBOX_H__

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


// CBoxVec //////////////////////////////////////////////////////////////////

typedef struct CBoxVec CBoxVec;

uint8_t * cbox_vec_data(CBoxVec const * v);
size_t    cbox_vec_len(CBoxVec  const * v);
void      cbox_vec_free(CBoxVec * v);

// CBoxResult ///////////////////////////////////////////////////////////////

typedef enum {
    CBOX_SUCCESS                 = 0,
    CBOX_STORAGE_ERROR           = 1,
    CBOX_NO_SESSION              = 2,
    CBOX_DECODE_ERROR            = 3,
    CBOX_REMOTE_IDENTITY_CHANGED = 4,
    CBOX_INVALID_SIGNATURE       = 5,
    CBOX_INVALID_MESSAGE         = 6,
    CBOX_DUPLICATE_MESSAGE       = 7,
    CBOX_TOO_DISTANT_FUTURE      = 8,
    CBOX_OUTDATED_MESSAGE        = 9,
    CBOX_UTF8_ERROR              = 10,
    CBOX_NUL_ERROR               = 11,
    CBOX_ENCODE_ERROR            = 12
} CBoxResult;

// CBox /////////////////////////////////////////////////////////////////////

typedef struct CBox CBox;

CBoxResult cbox_file_open(char const * path, CBox ** b);
void       cbox_close(CBox * b);

// Prekeys //////////////////////////////////////////////////////////////////

extern const uint16_t CBOX_LAST_PREKEY_ID;

CBoxResult cbox_new_prekey(CBox * b, uint16_t id, CBoxVec ** prekey);

// CBoxSession //////////////////////////////////////////////////////////////

typedef struct CBoxSession CBoxSession;

CBoxResult
cbox_session_init_from_prekey(CBox * b,
                              char const * sid,
                              uint8_t const * peer_prekey,
                              size_t peer_prekey_len,
                              CBoxSession ** s);

CBoxResult
cbox_session_init_from_message(CBox * b,
                               char const * sid,
                               uint8_t const * cipher,
                               size_t cipher_len,
                               CBoxSession ** s,
                               CBoxVec ** plain);

CBoxResult   cbox_session_get(CBox * b, char const * sid, CBoxSession ** s);
CBoxResult   cbox_session_save(CBoxSession * s);
char const * cbox_session_id(CBoxSession const * s);
void         cbox_session_close(CBoxSession * s);
CBoxResult   cbox_session_delete(CBox * b, char const * sid);
CBoxResult   cbox_encrypt(CBoxSession * s, uint8_t const * plain, size_t plain_len, CBoxVec ** cipher);
CBoxResult   cbox_decrypt(CBoxSession * s, uint8_t const * cipher, size_t cipher_len, CBoxVec ** plain);
void         cbox_fingerprint_local(CBox const * b, CBoxVec ** buf);
void         cbox_fingerprint_remote(CBoxSession const * s, CBoxVec ** buf);
CBoxVec *    cbox_random_bytes(CBox const * b, size_t len);


#ifdef __cplusplus
}
#endif


#endif // __CRYPTOBOX_H__
