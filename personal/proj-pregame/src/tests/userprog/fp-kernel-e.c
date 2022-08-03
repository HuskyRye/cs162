/* Verifies that the compute_e system call is implemented correctly */

#include <float.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

const char* test_name = "fp-kernel-e";

void test_main(void) {
  msg("Computing e...");
  double e_res = compute_e(10);
  if (abs(e_res - E_VAL) < TOL) {
    msg("Success!");
    exit(162);
  } else {
    msg("Got e=%f, expected e=%f", e_res, E_VAL);
    exit(126);
  }
}
