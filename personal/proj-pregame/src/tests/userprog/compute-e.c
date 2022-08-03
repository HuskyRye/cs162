/* Child process run by floating point tests
   Uses Taylor definition to compute the Euler constant e */

#include <float.h>
#include "tests/lib.h"

const char* test_name = "compute-e";

int main(void) {
  double e_res = sum_to_e(10);
  if (abs(e_res - E_VAL) < TOL) {
    msg("Success!");
    exit(162);
  } else {
    msg("Got e=%f, expected e=%f", e_res, E_VAL);
    exit(126);
  }
}
