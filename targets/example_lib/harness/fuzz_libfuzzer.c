
#include <stdint.h>
#include <stddef.h>
#include "example_lib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    target_entry(data, size);
    return 0;
}