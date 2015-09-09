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

void test_basics(CBox * alice_box, CBox * bob_box) {
    printf("test_basics ... ");

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
    rc = cbox_encrypt(alice, hello_bob, sizeof(hello_bob), &cipher);
    assert(rc == CBOX_SUCCESS);
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

    // unknown session
    CBoxSession * unknown = NULL;
    rc = cbox_session_get(alice_box, "unknown", &unknown);
    assert(rc == CBOX_NO_SESSION);

    // Cleanup
    cbox_vec_free(cipher);
    cbox_vec_free(plain);
    cbox_vec_free(bob_prekey);

    cbox_session_close(alice);
    cbox_session_close(bob);

    printf("OK\n");
}

void test_prekey_removal(CBox * alice_box, CBox * bob_box) {
    printf("test_prekey_removal ... ");
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
    rc = cbox_encrypt(alice, hello_bob, sizeof(hello_bob), &cipher);
    assert(rc == CBOX_SUCCESS);

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

    printf("OK\n");
}

void test_random_bytes(CBox const * b) {
    printf("test_random_bytes ... ");
    CBoxVec * random = cbox_random_bytes(b, 16);
    cbox_vec_free(random);
    printf("OK\n");
}

void test_last_prekey(CBox * alice_box, CBox * bob_box) {
    printf("test_last_prekey ... ");
    CBoxVec * bob_prekey = NULL;
    CBoxResult rc = cbox_new_prekey(bob_box, CBOX_LAST_PREKEY_ID, &bob_prekey);
    assert(rc == CBOX_SUCCESS);

    // Alice
    CBoxSession * alice = NULL;
    rc = cbox_session_init_from_prekey(alice_box, "alice", cbox_vec_data(bob_prekey), cbox_vec_len(bob_prekey), &alice);
    cbox_vec_free(bob_prekey);
    assert(rc == CBOX_SUCCESS);
    uint8_t const hello_bob[] = "Hello Bob!";
    CBoxVec * cipher = NULL;
    rc = cbox_encrypt(alice, hello_bob, sizeof(hello_bob), &cipher);
    assert(rc == CBOX_SUCCESS);

    // Bob
    CBoxSession * bob = NULL;
    CBoxVec * plain = NULL;
    rc = cbox_session_init_from_message(bob_box, "bob", cbox_vec_data(cipher), cbox_vec_len(cipher), &bob, &plain);
    assert(rc == CBOX_SUCCESS);

    cbox_session_save(bob);
    cbox_session_close(bob);
    cbox_vec_free(plain);

    // Bob's last prekey is not removed
    rc = cbox_session_init_from_message(bob_box, "bob", cbox_vec_data(cipher), cbox_vec_len(cipher), &bob, &plain);
    assert(rc == CBOX_SUCCESS);

    cbox_vec_free(plain);
    cbox_vec_free(cipher);
    cbox_session_close(alice);
    cbox_session_close(bob);
    printf("OK\n");
}

void test_duplicate_msg(CBox * alice_box, CBox * bob_box) {
    printf("test_duplicate_msg ... ");
    CBoxVec * bob_prekey = NULL;
    CBoxResult rc = cbox_new_prekey(bob_box, 0, &bob_prekey);
    assert(rc == CBOX_SUCCESS);

    // Alice
    CBoxSession * alice = NULL;
    rc = cbox_session_init_from_prekey(alice_box, "alice", cbox_vec_data(bob_prekey), cbox_vec_len(bob_prekey), &alice);
    cbox_vec_free(bob_prekey);
    assert(rc == CBOX_SUCCESS);
    uint8_t const hello_bob[] = "Hello Bob!";
    CBoxVec * cipher = NULL;
    rc = cbox_encrypt(alice, hello_bob, sizeof(hello_bob), &cipher);
    assert(rc == CBOX_SUCCESS);

    // Bob
    CBoxSession * bob = NULL;
    CBoxVec * plain = NULL;
    rc = cbox_session_init_from_message(bob_box, "bob", cbox_vec_data(cipher), cbox_vec_len(cipher), &bob, &plain);
    assert(rc == CBOX_SUCCESS);
    cbox_vec_free(plain);

    rc = cbox_decrypt(bob, cbox_vec_data(cipher), cbox_vec_len(cipher), &plain);
    assert(rc == CBOX_DUPLICATE_MESSAGE);

    cbox_vec_free(cipher);
    cbox_session_close(alice);
    cbox_session_close(bob);
    printf("OK\n");
}

void test_delete_session(CBox * alice_box, CBox * bob_box) {
    printf("test_delete_session ... ");
    CBoxVec * bob_prekey = NULL;
    CBoxResult rc = cbox_new_prekey(bob_box, 0, &bob_prekey);
    assert(rc == CBOX_SUCCESS);

    CBoxSession * alice = NULL;
    rc = cbox_session_init_from_prekey(alice_box, "alice", cbox_vec_data(bob_prekey), cbox_vec_len(bob_prekey), &alice);
    cbox_vec_free(bob_prekey);
    assert(rc == CBOX_SUCCESS);

    rc = cbox_session_save(alice);
    assert(rc == CBOX_SUCCESS);
    cbox_session_close(alice);

    rc = cbox_session_delete(alice_box, "alice");
    assert(rc == CBOX_SUCCESS);

    rc = cbox_session_get(alice_box, "alice", &alice);
    assert(rc == CBOX_NO_SESSION);

    // no-op, session does not exist
    rc = cbox_session_delete(alice_box, "alice");
    assert(rc == CBOX_SUCCESS);
    printf("OK\n");
}

void test_box_reopen() {
    printf("test_box_reopen ... ");
    CBoxResult rc = CBOX_SUCCESS;
    char tmp[] = "/tmp/cbox_test_reopenXXXXXX";
    char * dir = mkdtemp(tmp);
    assert(dir != NULL);

    CBox * box = NULL;
    rc = cbox_file_open(dir, &box);
    assert(rc == CBOX_SUCCESS);
    assert(box != NULL);

    cbox_close(box);

    rc = cbox_file_open(dir, &box);
    assert(rc == CBOX_SUCCESS);
    assert(box != NULL);

    cbox_close(box);
    printf("OK\n");
}

void test_external_identity() {
    printf("test_external_identity ... ");
    CBoxResult rc = CBOX_SUCCESS;
    char tmp[] = "/tmp/cbox_test_external_identityXXXXXX";
    char * dir = mkdtemp(tmp);
    assert(dir != NULL);

    CBox * box = NULL;
    rc = cbox_file_open(dir, &box);
    assert(rc == CBOX_SUCCESS);
    assert(box != NULL);

    CBoxVec * id = NULL;
    rc = cbox_identity_copy(box, &id);
    assert(rc == CBOX_SUCCESS);
    assert(id != NULL);

    cbox_close(box);

    // "downgrade" to public local identity
    rc = cbox_file_open_with(dir, cbox_vec_data(id), cbox_vec_len(id), CBOX_IDENTITY_PUBLIC, &box);
    assert(rc == CBOX_SUCCESS);
    cbox_close(box);

    // not providing the full identity yields an error
    rc = cbox_file_open(dir, &box);
    assert(rc == CBOX_IDENTITY_ERROR);

    // open in externally managed mode
    rc = cbox_file_open_with(dir, cbox_vec_data(id), cbox_vec_len(id), CBOX_IDENTITY_PUBLIC, &box);
    assert(rc == CBOX_SUCCESS);
    assert(box != NULL);

    cbox_close(box);

    // "upgrade" to full local identity
    rc = cbox_file_open_with(dir, cbox_vec_data(id), cbox_vec_len(id), CBOX_IDENTITY_COMPLETE, &box);
    assert(rc == CBOX_SUCCESS);
    cbox_close(box);

    rc = cbox_file_open(dir, &box);
    assert(rc == CBOX_SUCCESS);
    cbox_close(box);

    cbox_vec_free(id);

    printf("OK\n");
}

void test_wrong_identity() {
    printf("test_wrong_identity ... ");
    CBoxResult rc = CBOX_SUCCESS;

    char tmp1[] = "/tmp/cbox_test_wrong_identityXXXXXX";
    char * dir1 = mkdtemp(tmp1);
    assert(dir1 != NULL);

    char tmp2[] = "/tmp/cbox_test_wrong_identityXXXXXX";
    char * dir2 = mkdtemp(tmp2);
    assert(dir2 != NULL);

    CBox * box1 = NULL;
    rc = cbox_file_open(dir1, &box1);
    assert(rc == CBOX_SUCCESS);
    assert(box1 != NULL);

    CBox * box2 = NULL;
    rc = cbox_file_open(dir2, &box2);
    assert(rc == CBOX_SUCCESS);
    assert(box2 != NULL);

    CBoxVec * id1 = NULL;
    rc = cbox_identity_copy(box1, &id1);
    assert(rc == CBOX_SUCCESS);
    assert(id1 != NULL);

    CBoxVec * id2 = NULL;
    rc = cbox_identity_copy(box2, &id2);
    assert(rc == CBOX_SUCCESS);
    assert(id2 != NULL);

    cbox_close(box1);
    cbox_close(box2);

    // Wrong identity triggers an error
    rc = cbox_file_open_with(dir1, cbox_vec_data(id2), cbox_vec_len(id2), CBOX_IDENTITY_PUBLIC, &box1);
    assert(rc == CBOX_IDENTITY_ERROR);
    rc = cbox_file_open_with(dir2, cbox_vec_data(id1), cbox_vec_len(id1), CBOX_IDENTITY_PUBLIC, &box2);
    assert(rc == CBOX_IDENTITY_ERROR);

    rc = cbox_file_open_with(dir1, cbox_vec_data(id1), cbox_vec_len(id1), CBOX_IDENTITY_PUBLIC, &box1);
    assert(rc == CBOX_SUCCESS);
    rc = cbox_file_open_with(dir2, cbox_vec_data(id2), cbox_vec_len(id2), CBOX_IDENTITY_PUBLIC, &box2);
    assert(rc == CBOX_SUCCESS);

    cbox_close(box1);
    cbox_close(box2);

    cbox_vec_free(id1);
    cbox_vec_free(id2);

    printf("OK\n");
}

int main() {
    // Setup Alice's & Bob's crypto boxes
    char alice_tmp[] = "/tmp/cbox_test_aliceXXXXXX";
    char * alice_dir = mkdtemp(alice_tmp);
    assert(alice_dir != NULL);

    char bob_tmp[] = "/tmp/cbox_test_bobXXXXXX";
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
    test_basics(alice_box, bob_box);
    test_prekey_removal(alice_box, bob_box);
    test_random_bytes(alice_box);
    test_last_prekey(alice_box, bob_box);
    test_duplicate_msg(alice_box, bob_box);
    test_delete_session(alice_box, bob_box);
    test_box_reopen();
    test_external_identity();
    test_wrong_identity();

    // Cleanup
    cbox_close(alice_box);
    cbox_close(bob_box);
}
