---
name: format-string
description: Format string vulnerability detection — printf/syslog with user-controlled format argument. CWE-134.
---

# Format String Vulnerabilities (CWE-134)

A format string vulnerability occurs when user-controlled data is passed as the **format** argument to a `printf`-family function rather than as a value argument. The attacker can use `%x`/`%p` specifiers to read arbitrary stack memory (information disclosure) and `%n` to write to arbitrary addresses (arbitrary code execution). Unlike buffer overflows these are often overlooked during code review because the code "looks fine" — it calls `printf`, after all.

## Where to Look

**Direct `printf(user_input)` — the canonical pattern:**
```c
printf(msg);          // VULNERABLE if msg is user-controlled
fprintf(fp, msg);
syslog(priority, msg);
err(1, msg);
warn(msg);
```

**Indirect via wrapper functions:**
```c
void log_error(char *msg) {
    fprintf(stderr, msg);  // if callers pass user data here
}
```

**`snprintf` misuse:**
```c
snprintf(buf, sizeof(buf), user_fmt, arg1, arg2);  // user_fmt is the problem
```
Note: `snprintf(buf, n, "%s", user_input)` is SAFE — `user_input` is a value, not the format.

**`syslog` (common in daemons):**
```c
syslog(LOG_ERR, user_message);   // VULNERABLE
syslog(LOG_ERR, "%s", user_message);  // safe
```

## How to Detect

### Static grep

**printf/fprintf with non-literal first (format) argument:**
```bash
docker exec <container> sh -c "
  grep -rn 'printf\s*([^\"]\|fprintf\s*(\w\+,\s*[^\"]\|syslog\s*([^,]\+,\s*[^\"]\|err\s*([^,]\+,\s*[^\"]' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null | head -40
"
```
Any `printf(var)` where `var` is a variable name rather than a string literal is a candidate.

**Focused search for the most common pattern:**
```bash
docker exec <container> sh -c "
  grep -rn 'printf\s*(\s*\w\+\s*)' --include='*.c' --include='*.cpp' /app 2>/dev/null
  grep -rn 'fprintf\s*(\s*\w\+\s*,\s*\w\+\s*)' --include='*.c' --include='*.cpp' /app 2>/dev/null
  grep -rn 'syslog\s*([^,]*,\s*\w\+\s*)' --include='*.c' --include='*.cpp' /app 2>/dev/null
"
```

**Wrapper function hunting — find helper functions that call printf with their argument directly:**
```bash
docker exec <container> sh -c "
  grep -rn 'printf\|syslog\|warn\b\|err\b' --include='*.c' --include='*.cpp' /app 2>/dev/null \
  | grep -v '\"' | head -30
"
```

## Vulnerability Patterns

### Direct printf(user_input)

```c
char *msg = get_request_param("message");  // from network
printf(msg);    // CRITICAL: msg is the format string
```
Attacker sends `%x.%x.%x.%x` → receives stack memory values.
Attacker sends `%7$n` → writes to the 7th argument on the stack.

### syslog with user data

```c
// daemon logging user-provided error descriptions
syslog(LOG_ERR, request->description);   // VULNERABLE
```
Many daemons log error messages verbatim. If the message comes from a client, it's exploitable.

### Wrapper function hides the bug

```c
void die(char *fmt) {
    fprintf(stderr, fmt);   // fmt is the format string
    exit(1);
}

// caller:
die(user_supplied_error_string);  // indirect format string
```

### snprintf with user-controlled format

```c
char buf[256];
snprintf(buf, sizeof(buf), user_fmt);   // VULNERABLE despite using snprintf
// vs:
snprintf(buf, sizeof(buf), "%s", user_fmt);  // SAFE — user_fmt is a value
```

## Exploitation

**Information disclosure via %x/%p:**
```bash
# If the binary reads a line and prints it back (e.g., echo server or error reporter):
docker exec <container> sh -c "
  echo '%p.%p.%p.%p.%p.%p.%p.%p' | ./<binary>
"
# Expected: output like '0x7fff...0x4012ab...' — stack/heap pointers leaked
# Confirms format string vulnerability
```

**Canary bypass indicator:**
```bash
docker exec <container> sh -c "
  python3 -c \"print('%p.' * 20)\" | ./<binary>
"
# Look for a repeating value that looks like a stack canary (often appears at a fixed offset)
```

**Write via %n (CONFIRMED RCE primitive):**
`%n` writes the number of bytes written so far to the address stored in the corresponding argument. Combined with format string positional arguments (`%7$n`) this gives an arbitrary write primitive. Full exploitation requires ASLR leak first (via `%p`).

## Judge Verdicts

**CONFIRMED:** `printf(var)` or `fprintf(fp, var)` or `syslog(prio, var)` where `var` is a variable that receives data from an external source (network, file, environment, stdin, argv).

**CONFIRMED:** Any wrapper function that calls `printf`/`fprintf`/`syslog` with its string argument directly as the format parameter, and that wrapper is called with user-controlled input.

**LIKELY:** `printf(var)` where `var` is an internal string but its content is derived (even partially) from external input upstream.

**NEEDS CONTEXT:** `printf(var)` in a context where `var` is a result of `strdup`/`strndup` of a string that appears to be a static error message — check whether the upstream source can be attacker-controlled.

**FALSE POSITIVE:** `printf("%s", user_input)` — user input is a value argument, not the format. Completely safe.
