"""Auto-patch recommender for common CWE classes."""
PATCH_RULES = {
    "CWE-121": {
        "description": "Replace strcpy with strncpy and bounds check.",
        "diff": """\
-    strcpy(buf, input);
+    if (strlen(input) >= sizeof(buf)) return -1;
+    strncpy(buf, input, sizeof(buf) - 1);
+    buf[sizeof(buf) - 1] = '\\0';
""",
    },
    "CWE-122": {
        "description": "Check integer overflow before addition.",
        "diff": """\
-    uint32_t real = size + 16;
+    if (size > UINT32_MAX - 16) return -1;
+    uint32_t real = size + 16;
""",
    },
    "CWE-416": {
        "description": "Remove use after free.",
        "diff": """\
-    free(p);
-    p[0] = 'X';
+    p[0] = 'X';
+    free(p);
""",
    },
    "CWE-476": {
        "description": "Add NULL check before dereference.",
        "diff": """\
-    return *ptr;
+    if (!ptr) return -1;
+    return *ptr;
""",
    },
    "CWE-190": {
        "description": "Add integer overflow guard.",
        "diff": """\
-    uint32_t real = size + 16;
+    if (size > UINT32_MAX - 16) return -1;
+    uint32_t real = size + 16;
""",
    },
}

def suggest_patch(cwe: str) -> dict:
    rule = PATCH_RULES.get(cwe)
    if not rule:
        return {"cwe": cwe, "available": False, "description": "No auto-patch rule for this CWE yet."}
    return {"cwe": cwe, "available": True, "description": rule["description"], "diff": rule["diff"]}
