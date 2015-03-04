#ifdef __APPLE__
#include <unistd.h>
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cbox.h>

void print_hex(unsigned char const * dat, unsigned short len) {
    for (int i = 0; i < len; ++i) {
        printf("%02x ", dat[i]);
    }
    printf("\n");
}

void basics(CBox * alice_box, CBox * bob_box) {
    CBoxResult rc = CBOX_SUCCESS;

    // Bob prekey
    CBoxVec * bob_prekey = NULL;
    rc = cbox_new_prekey(bob_box, 1, &bob_prekey);
    assert(rc == CBOX_SUCCESS);

    // Alice
    CBoxSession * alice = NULL;
    rc = cbox_session_init_from_prekey(alice_box, "alice", cbox_vec_data(bob_prekey), cbox_vec_len(bob_prekey), &alice);
    assert(rc == CBOX_SUCCESS);
    rc = cbox_session_save(alice);
    assert(rc == CBOX_SUCCESS);
    uint8_t const hello_bob[] = "Hello Bob!";
    CBoxVec * cipher = NULL;
    cbox_encrypt(alice, hello_bob, sizeof(hello_bob), &cipher);
    assert(strncmp((char const *) hello_bob, (char const *) cbox_vec_data(cipher), cbox_vec_len(cipher)) != 0);

    // Bob
    CBoxSession * bob = NULL;
    CBoxVec * plain = NULL;
    rc = cbox_session_init_from_message(bob_box, "bob", cbox_vec_data(cipher), cbox_vec_len(cipher), &bob, &plain);
    assert(rc == CBOX_SUCCESS);
    cbox_session_save(bob);
    assert(strncmp((char const *) hello_bob, (char const *) cbox_vec_data(plain), cbox_vec_len(plain)) == 0);

    // Compare fingerprints
    CBoxVec * local = NULL;
    CBoxVec * remote = NULL;

    cbox_fingerprint_local(alice_box, &local);
    cbox_fingerprint_remote(bob, &remote);
    assert(strncmp((char const *) cbox_vec_data(local), (char const *) cbox_vec_data(remote), cbox_vec_len(remote)) == 0);
    cbox_vec_free(remote);
    cbox_vec_free(local);

    cbox_fingerprint_local(bob_box, &local);
    cbox_fingerprint_remote(alice, &remote);
    assert(strncmp((char const *) cbox_vec_data(local), (char const *) cbox_vec_data(remote), cbox_vec_len(remote)) == 0);
    cbox_vec_free(remote);
    cbox_vec_free(local);

    // Load the sessions again
    cbox_session_close(alice);
    cbox_session_close(bob);
    rc = cbox_session_get(alice_box, "alice", &alice);
    assert(rc == CBOX_SUCCESS);
    rc = cbox_session_get(bob_box, "bob", &bob);
    assert(rc == CBOX_SUCCESS);

    // Cleanup
    cbox_vec_free(cipher);
    cbox_vec_free(plain);
    cbox_vec_free(bob_prekey);

    cbox_session_close(alice);
    cbox_session_close(bob);
}

void prekey_removal(CBox * alice_box, CBox * bob_box) {
    CBoxResult rc = CBOX_SUCCESS;

    // Bob prekey
    CBoxVec * bob_prekey = NULL;
    rc = cbox_new_prekey(bob_box, 1, &bob_prekey);
    assert(rc == CBOX_SUCCESS);

    // Alice
    CBoxSession * alice = NULL;
    rc = cbox_session_init_from_prekey(alice_box, "alice", cbox_vec_data(bob_prekey), cbox_vec_len(bob_prekey), &alice);
    assert(rc == CBOX_SUCCESS);
    uint8_t const hello_bob[] = "Hello Bob!";
    CBoxVec * cipher = NULL;
    cbox_encrypt(alice, hello_bob, sizeof(hello_bob), &cipher);

    // Bob
    CBoxSession * bob = NULL;
    CBoxVec * plain = NULL;
    rc = cbox_session_init_from_message(bob_box, "bob", cbox_vec_data(cipher), cbox_vec_len(cipher), &bob, &plain);
    assert(rc == CBOX_SUCCESS);

    // Pretend something happened before Bob could save his session and he retries.
    // The prekey should not be removed (yet).
    cbox_session_close(bob);
    cbox_vec_free(plain);
    rc = cbox_session_init_from_message(bob_box, "bob", cbox_vec_data(cipher), cbox_vec_len(cipher), &bob, &plain);
    assert(rc == CBOX_SUCCESS);

    cbox_session_save(bob);

    // Now the prekey should be gone
    cbox_session_close(bob);
    cbox_vec_free(plain);
    rc = cbox_session_init_from_message(bob_box, "bob", cbox_vec_data(cipher), cbox_vec_len(cipher), &bob, &plain);
    assert(rc == CBOX_INVALID_MESSAGE);

    // Cleanup
    cbox_vec_free(bob_prekey);
    cbox_vec_free(cipher);
    cbox_session_close(alice);
}

int main() {
    // Setup Alice's & Bob's crypto boxes and identities
    char alice_tmp[] = "/tmp/cbox_test_aliceXXXXXX";
    char * alice_dir = mkdtemp(alice_tmp);
    assert(alice_dir != NULL);

    char bob_tmp[]   = "/tmp/cbox_test_bobXXXXXX";
    char * bob_dir = mkdtemp(bob_tmp);
    assert(bob_dir != NULL);

    printf("alice=\"%s\", bob=\"%s\"\n", alice_tmp, bob_tmp);

    CBoxResult rc = CBOX_SUCCESS;

    CBox * alice_box = NULL;
    rc = cbox_file_open(alice_dir, &alice_box);
    assert(rc == CBOX_SUCCESS);
    assert(alice_box != NULL);

    CBox * bob_box = NULL;
    rc = cbox_file_open(bob_dir, &bob_box);
    assert(rc == CBOX_SUCCESS);
    assert(bob_box != NULL);

    // Run test cases
    basics(alice_box, bob_box);
    prekey_removal(alice_box, bob_box);

    // Cleanup
    cbox_close(alice_box);
    cbox_close(bob_box);
}
