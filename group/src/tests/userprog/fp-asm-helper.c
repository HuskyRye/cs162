/* Child process that pushes to FPU registers */

#include "tests/lib.h"

#define NUM_VALUES 4
const char* test_name = "fp-asm-helper";
static int values[NUM_VALUES] = {12, 14, 16, 18};

int main(void) {
  push_values_to_fpu(values, NUM_VALUES);
  return 0;
}
