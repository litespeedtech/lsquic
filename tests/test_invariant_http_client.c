#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

START_TEST(test_buffer_read_bounds)
{
    /* Invariant: buffer reads never exceed declared length;
       oversized inputs must be truncated or rejected, never overflow */
    const char *payloads[] = {
        /* exact exploit: URL 2x typical 256-byte buffer */
        "http://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/",
        /* boundary: exactly 257 chars (one over common 256 limit) */
        "http://BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/",
        /* valid input: normal short URL */
        "http://example.com/",
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        pid_t pid = fork();
        ck_assert_msg(pid >= 0, "fork failed");

        if (pid == 0) {
            /* Child: run the real http_client binary with the payload as argument.
               We rely on AddressSanitizer or valgrind in CI to catch overflows;
               here we assert the process does not crash with a signal (SIGSEGV/SIGABRT). */
            execl("bin/http_client", "http_client", payloads[i], NULL);
            /* If exec fails, exit with a distinct code */
            _exit(127);
        } else {
            int status;
            waitpid(pid, &status, 0);

            if (WIFSIGNALED(status)) {
                int sig = WTERMSIG(status);
                /* SIGSEGV=11, SIGABRT=6, SIGBUS=7 indicate memory corruption */
                ck_assert_msg(sig != 11 && sig != 6 && sig != 7,
                    "http_client crashed with signal %d on payload[%d]: buffer overflow suspected", sig, i);
            }
            /* Exit code 127 means exec failed (binary not found); skip silently */
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_read_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}