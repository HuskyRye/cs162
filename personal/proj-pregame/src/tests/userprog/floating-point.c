/* Ensures that basic floating point arithmetic works in a user program */

#include <float.h>
#include "tests/lib.h"
#include "tests/main.h"

const char* test_name = "floating-point";

void test_main(void) {
  msg("Computing e...");
  double e_res = sum_to_e(10);
  if (abs(e_res - E_VAL) < TOL) {
    msg("Success!");
    exit(162);
  } else {
    msg("Got e=%f, expected e=%f", e_res, E_VAL);
    exit(126);
  }
}
