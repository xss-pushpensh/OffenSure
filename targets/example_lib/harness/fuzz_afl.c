
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include "example_lib.h"

int main(void) {
    uint8_t buf[4096];
    ssize_t n = read(0, buf, sizeof(buf));
    if (n <= 0) return 0;
    target_entry(buf, (size_t)n);
    return 0;
}