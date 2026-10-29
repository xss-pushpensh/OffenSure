#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// Vulnerability 1: Stack buffer overflow
int parse_name(const char *input) {
    char buf[32];
    if (!input) return -1;
    strcpy(buf, input);   // UNSAFE
    return (int)strlen(buf);
}

// Vulnerability 2: Integer overflow leading to heap overflow
int allocate_buffer(uint32_t size) {
    uint32_t real = size + 16;   // UNSAFE
    char *p = malloc(real);
    if (!p) return -1;
    memset(p, 'A', size);
    free(p);
    return 0;
}

// Vulnerability 3: Null pointer deref
int deref_check(int *ptr) {
    return *ptr;   // UNSAFE if ptr is NULL
}

// Vulnerability 4: Use after free
int use_after_free(void) {
    char *p = malloc(64);
    if (!p) return -1;
    free(p);
    p[0] = 'X';   // UNSAFE
    return 0;
}

// Entry point used by fuzzer
int target_entry(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    char input[256] = {0};
    size_t n = size < 255 ? size : 255;
    memcpy(input, data, n);

    switch (data[0] % 4) {
        case 0: return parse_name(input);
        case 1: return allocate_buffer((uint32_t)size * 1000000u);
        case 2: {
            int *p = (size > 4) ? NULL : (int*)input;
            return deref_check(p);
        }
        case 3: return use_after_free();
    }
    return 0;
}
