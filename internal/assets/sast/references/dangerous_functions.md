---
name: dangerous-functions
description: Inherently unsafe C/C++ functions that lack bounds checking. CWE-676, CWE-120. Immediate architectural red flags.
---

# Dangerous Functions (CWE-676 / CWE-120)

Certain C standard library functions perform no bounds checking by design. Their presence in code that handles external input is an automatic finding — the only question is whether the specific call site is reachable with attacker-controlled data. Treat each occurrence as a candidate until proven safe by a strict audit.

## The Forbidden List

| Function | Danger | Safe Replacement |
|----------|--------|-----------------|
| `gets(buf)` | No length limit — always exploitable | `fgets(buf, sizeof(buf), stdin)` |
| `strcpy(dst, src)` | Copies until NUL — dst may be shorter than src | `strlcpy(dst, src, sizeof(dst))` or `snprintf` |
| `strcat(dst, src)` | Appends until NUL — no dst length check | `strlcat(dst, src, sizeof(dst))` |
| `sprintf(buf, fmt, ...)` | No output length limit | `snprintf(buf, sizeof(buf), fmt, ...)` |
| `vsprintf(buf, fmt, va)` | Same as sprintf | `vsnprintf(buf, sizeof(buf), fmt, va)` |
| `scanf("%s", buf)` | Reads unlimited characters into buf | `scanf("%255s", buf)` or `fgets` |
| `sscanf(str, "%s", buf)` | Same issue in string-to-string parse | Add width: `sscanf(str, "%255s", buf)` |
| `strncpy(dst, src, n)` | Does NOT guarantee NUL termination when src ≥ n | `strlcpy` or manually null-terminate |
| `strncat(dst, src, n)` | `n` is max chars to append, NOT dst size | `strlcat` or compute remaining bytes correctly |
| `realpath(path, resolved)` | `resolved` must be `PATH_MAX` bytes; on glibc, can pass NULL (safe) | Pass `NULL` as resolved on Linux, or allocate `PATH_MAX` |
| `mktemp(template)` | TOCTOU — use `mkstemp` instead | `mkstemp(template)` |

## How to Detect

### Quick grep (run inside container)

```bash
docker exec <container> sh -c "
  grep -rn 'gets\b\|strcpy\b\|strcat\b\|sprintf\b\|vsprintf\b\|scanf\b\|sscanf\b' \
    --include='*.c' --include='*.cpp' \
    /app 2>/dev/null | grep -v '//.*gets\|//.*strcpy' | head -60
"
```

**strncpy without explicit null-termination:**
```bash
docker exec <container> sh -c "
  grep -rn 'strncpy' --include='*.c' --include='*.cpp' /app 2>/dev/null \
  | head -30
"
```
For each `strncpy(dst, src, n)` hit, check the lines immediately following: is there a `dst[n-1] = '\0'` or `dst[sizeof(dst)-1] = '\0'`? If not: LIKELY finding.

**Locate `gets` specifically (always CONFIRMED):**
```bash
docker exec <container> sh -c "grep -rn '\bgets\s*(' --include='*.c' --include='*.cpp' /app"
```

### Binary-level check (if source is unavailable)

```bash
docker exec <container> sh -c "
  nm <binary> 2>/dev/null | grep -E ' gets$| strcpy$| strcat$| sprintf$'
  objdump -d <binary> 2>/dev/null | grep -E 'call.*<gets>|call.*<strcpy>|call.*<strcat>'
"
```

## Vulnerability Patterns

### `gets` — always exploitable (CWE-676)

```c
char line[80];
printf("Enter command: ");
gets(line);   // reads STDIN until newline, no length check
```
Send 90 bytes → overflows `line` into the next stack frame. `gets` was removed from C11 and should never appear in new code.

### `strcpy` — overflow when src > dst

```c
void set_hostname(const char *name) {
    char buf[64];
    strcpy(buf, name);   // fine if name ≤ 63 bytes; overflow otherwise
    register_host(buf);
}
```
If `name` comes from a config file or network packet, this is exploitable.

### `sprintf` into fixed buffer

```c
char path[256];
sprintf(path, "/var/data/%s/%s", user, filename);  // user + filename could exceed 256
open(path, O_RDONLY);
```
An attacker who controls both `user` and `filename` can overflow `path` and also inject `..` for path traversal (dual-class finding).

### `scanf("%s")` from stdin

```c
char token[32];
scanf("%s", token);   // no width — reads until whitespace, no bound
```
Input `AAAA...A` (33+ chars) overflows `token`.

### `strncpy` without null termination

```c
char dst[16];
strncpy(dst, src, 16);   // if src ≥ 16 chars, dst[15] != '\0'
printf("%s", dst);        // prints past end of dst into adjacent stack memory
```

## Exploitation

Most dangerous-function findings are exploitable via simple oversized input:

```bash
# strcpy/gets/scanf overflow — send a long string
docker exec <container> sh -c "python3 -c \"print('A'*500)\" | ./<binary>"
# Expected: Segmentation fault (exit code 139)

# sprintf overflow via argument — if binary takes CLI args
docker exec <container> sh -c "./<binary> \$(python3 -c \"print('A'*300)\")"
# Expected: SIGSEGV or stack canary abort (exit code 134 for SIGABRT)
```

Check the exit code:
- `139` = SIGSEGV (segfault) — memory corruption confirmed
- `134` = SIGABRT — typically stack smashing detected by GCC's canary

## Judge Verdicts

**CONFIRMED:** `gets(buf)` anywhere in reachable code — always exploitable regardless of context.

**CONFIRMED:** `strcpy(dst, src)` / `sprintf(dst, ...)` where `src` or the format arguments derive from external input (network, file, argv) and `dst` has a fixed compile-time size.

**LIKELY:** Same functions where the source is an internal string but the string's length depends on a prior computation that could be influenced by input.

**NEEDS CONTEXT:** `strcpy(dst, src)` where `src` is a compile-time string literal — safe only if `sizeof(dst) > strlen(src)`.

**FALSE POSITIVE:** `sprintf(buf, "%d", constant_int)` — no overflow possible for small integers, but flag as technical debt anyway.
