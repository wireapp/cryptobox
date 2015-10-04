#ifdef __APPLE__
#include <unistd.h>
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <assert.h>
#include <stdio.h>
#include <cbox.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>

double get_time() {
    struct timeval t;
    gettimeofday(&t, NULL);
    return t.tv_sec + t.tv_usec*1e-6;
}

void bench_session_save(CBox * alice_box, CBox * bob_box) {
    printf("bench_session_save ... ");

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

    // Bob
    CBoxSession * bob = NULL;
    CBoxVec * plain = NULL;
    rc = cbox_session_init_from_message(bob_box, "bob", cbox_vec_data(cipher), cbox_vec_len(cipher), &bob, &plain);
    assert(rc == CBOX_SUCCESS);

    double start = get_time();
    for (int i = 0; i < 1000; ++i) {
        cbox_session_save(bob);
    }
    double end = get_time();

    printf("OK (%fs)\n", end - start);
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

    // Run benchmarks
    bench_session_save(alice_box, bob_box);

    // Cleanup
    cbox_close(alice_box);
    cbox_close(bob_box);
}
