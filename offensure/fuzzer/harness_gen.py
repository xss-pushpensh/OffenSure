"""Fuzzing harness generator for C targets."""
from pathlib import Path
from jinja2 import Template

LIBFUZZER_TEMPLATE = """
#include <stdint.h>
#include <stddef.h>
#include "{{ header }}"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    target_entry(data, size);
    return 0;
}
"""

AFL_TEMPLATE = """
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include "{{ header }}"

int main(void) {
    uint8_t buf[4096];
    ssize_t n = read(0, buf, sizeof(buf));
    if (n <= 0) return 0;
    target_entry(buf, (size_t)n);
    return 0;
}
"""

def generate_harness(target_dir: str, header: str, out_dir: str = None) -> dict:
    target = Path(target_dir)
    out = Path(out_dir) if out_dir else target / "harness"
    out.mkdir(parents=True, exist_ok=True)

    libfuzzer = out / "fuzz_libfuzzer.c"
    afl = out / "fuzz_afl.c"

    libfuzzer.write_text(Template(LIBFUZZER_TEMPLATE).render(header=header))
    afl.write_text(Template(AFL_TEMPLATE).render(header=header))

    return {"libfuzzer": str(libfuzzer), "afl": str(afl), "out_dir": str(out)}
