---
name: sensitive-memory-exposure
description: Sensitive data (passwords, keys, tokens) left uncleared in memory or leaked via over-read; cleartext credential storage in memory-mapped files or core dumps. CWE-226, CWE-200, CWE-401, CWE-404.
---

# Sensitive Memory Exposure (CWE-226 / CWE-200 / CWE-401 / CWE-404)

OWASP Secure Coding Practices mandates: *"Overwrite any sensitive information stored in allocated memory at all exit points from the function."* This class covers three related failures in native code:

1. **Sensitive data not zeroed** — passwords, private keys, session tokens survive in process memory after the function returns; readable via `/proc/<pid>/mem`, crash dumps, swap, or a subsequent heap allocation in the same process.
2. **Memory/resource leaks** — `malloc` without `free`, `open` without `close`, socket handles not released; in long-running daemons this is a DoS vector and can expose stale data.
3. **Over-read leaks** — reading past the intended end of a buffer exposes adjacent memory contents (passwords, keys, heap metadata) to the caller.

## Where to Look

**Credential/key handling code:**
- Functions named `login`, `authenticate`, `verify_password`, `decrypt`, `load_key`, `read_secret`
- Any `strdup`, `strndup`, or `malloc` of a password or key, without subsequent `memset`/`explicit_bzero`/`memset_s` before `free`

**Early-return paths:**
- Functions that validate input and return early on error — the `free`/zeroing at the bottom is skipped

**File descriptor management:**
- `open()` / `socket()` / `accept()` results that don't have a matching `close()` on every return path
- `fopen()` without `fclose()` on all branches

**Memory mapped files:**
- `mmap()` containing sensitive config/keys, not `munmap()`'d and not `madvise(MADV_WIPEONFORK)`

**Heap allocations in loops:**
- `malloc` inside a loop or recursive function with early-continue/return — the pointer overwritten without freeing

## How to Detect

### Missing zero before free

```bash
docker exec <container> sh -c "
  grep -rn 'password\|passwd\|secret\|private_key\|api_key\|token' \
    --include='*.c' --include='*.cpp' -l /app 2>/dev/null | head -10
"
```
For each file, check whether the variable is zeroed before `free`:
```bash
docker exec <container> sh -c "
  grep -n 'free\|explicit_bzero\|memset_s\|memset.*0\|OPENSSL_cleanse' \
    /app/<file>.c | head -20
"
```
If `free(password_buf)` appears without a preceding `memset`/`explicit_bzero` in the same function scope: **CONFIRMED CWE-226**.

**Note:** Plain `memset(buf, 0, len); free(buf)` is nominally correct but may be elided by the compiler. `explicit_bzero()` or `memset_s()` are the correct functions — they are guaranteed not to be optimized away.

### File descriptor leaks

```bash
docker exec <container> sh -c "
  grep -rn 'open\s*(\|socket\s*(\|accept\s*(' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null | grep -v '//' | head -30
"
```
For each `open()`/`socket()` call, verify there is a `close()` on every return path — including error paths.

### Go — credential string not zeroed

```bash
docker exec <container> sh -c "
  grep -rn 'password\|secret\|token\|privateKey\|apiKey' \
    --include='*.go' /app 2>/dev/null | head -20
"
```
In Go, strings are immutable — you cannot zero them. The correct pattern is to use a `[]byte` slice for credentials and explicitly zero it: `for i := range secret { secret[i] = 0 }`. A `string` holding a password cannot be zeroed and persists until GC'd (which may be never, and may end up in a heap dump). Look for passwords stored as `string` rather than `[]byte`.

### Rust — sensitive data not zeroed

```bash
docker exec <container> sh -c "
  grep -rn 'password\|secret\|private_key\|api_key' \
    --include='*.rs' /app 2>/dev/null | head -20
"
```
In Rust, the `zeroize` crate provides `Zeroize` and `ZeroizeOnDrop`. Any struct holding a sensitive field should derive `ZeroizeOnDrop`. Without it, the data remains in memory until it's overwritten by chance.

### Check if core dumps are enabled (leaks secrets on crash)

```bash
docker exec <container> sh -c "ulimit -c"
# If not 0, a crash will produce a core file containing full process memory
# (passwords, private keys, etc.)
docker exec <container> sh -c "
  grep -rn 'prctl.*PR_SET_DUMPABLE\|RLIMIT_CORE' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null | head -5
"
```

### Over-read leak (CWE-200 via memory over-read)

```bash
docker exec <container> sh -c "
  grep -rn 'memcpy\|memmove\|strncpy\|send\|write' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null \
  | grep -v '//\|sizeof' | head -30
"
```
Look for length arguments derived from user-supplied values without validation — sending more bytes than were written allows an attacker to read adjacent heap/stack memory (Heartbleed class).

## Vulnerability Patterns

### Password left in heap after free (CWE-226)

```c
char *password = strdup(user_input);
// ... authenticate(password) ...
free(password);   // BUG: heap block contents not zeroed — still readable via /proc/pid/mem,
                  // swap, core dump, or next malloc() returning the same block
```
**Fix:**
```c
explicit_bzero(password, strlen(password));  // guaranteed not optimized away
free(password);
```

### Early-return skips zero+free (CWE-226)

```c
int login(const char *input) {
    char *key = load_private_key("/etc/ssl/private.pem");
    if (key == NULL) return -1;
    
    int rc = crypto_sign(input, key);
    if (rc != 0) return -1;   // BUG: key not zeroed/freed on early return
    
    explicit_bzero(key, key_len);   // only reached on success path
    free(key);
    return 0;
}
```

### File descriptor leak causing DoS (CWE-404)

```c
void serve_request(const char *path) {
    int fd = open(path, O_RDONLY);
    if (!validate_path(path)) return;   // BUG: fd leaked — descriptor table exhausted after ~1024 requests
    
    send_file(fd);
    close(fd);
}
```

### Heartbleed-style over-read (CWE-200)

```c
// Attacker sends: claimed_len = 500, actual data = 1 byte
void handle_keepalive(char *payload, uint16_t claimed_len) {
    char *response = malloc(claimed_len);
    memcpy(response, payload, claimed_len);   // BUG: copies 499 bytes of adjacent heap memory
    send(sock, response, claimed_len, 0);     // leaks heap contents to attacker
}
```

### Go — password as string (cannot be zeroed)

```go
type AuthRequest struct {
    Password string   // BUG: string cannot be zeroed; persists in heap until GC
}

func Authenticate(req AuthRequest) bool {
    // req.Password cannot be explicitly cleared after use
    return bcrypt.CompareHashAndPassword(hash, []byte(req.Password)) == nil
}
```
**Fix:** Accept `[]byte` for sensitive fields and zero after use:
```go
defer func() { for i := range req.Password { req.Password[i] = 0 } }()
```

## Exploitation

**Read live process memory via /proc (requires same-user or root):**
```bash
docker exec <container> sh -c "
  pid=\$(pgrep -x <binary>)
  # Dump heap region
  grep heap /proc/\$pid/maps
  dd if=/proc/\$pid/mem bs=1 skip=<heap_start_decimal> count=65536 2>/dev/null \
    | strings | grep -E '[a-zA-Z0-9+/]{20,}'   # find base64 / passwords / keys
"
```

**Verify fd leak — check open fd count over time:**
```bash
docker exec <container> sh -c "
  for i in \$(seq 1 100); do
    wget -qO/dev/null http://localhost:<port>/<leaky_endpoint> 2>/dev/null
  done
  pid=\$(pgrep -x <binary>)
  ls /proc/\$pid/fd | wc -l
"
# Expected (leak): fd count grows proportionally → server will crash after ~1024 requests
```

**Heartbleed-class over-read:**
```bash
docker exec <container> sh -c "
  python3 -c \"
import socket, struct
s = socket.socket(); s.connect(('127.0.0.1', <port>))
# craft a message claiming length=500 but sending 1 byte of real data
s.send(struct.pack('>H', 500) + b'A')
data = s.recv(500)
print(repr(data))
\"
"
# Expected: response contains bytes beyond the 1-byte payload → adjacent heap data leaked
```

## Judge Verdicts

**CONFIRMED:** `malloc`/`strdup` of a variable named `password`, `secret`, `key`, or `token` with `free()` but no preceding `memset`/`explicit_bzero`.

**CONFIRMED:** `open()`/`socket()` result with a code path (early return, error branch) that reaches a function exit without a matching `close()`.

**CONFIRMED:** Length field from untrusted input used directly in `memcpy` destination size to read from a fixed-size or smaller source buffer (over-read).

**LIKELY:** Go `string` field holding a credential with no explicit byte-level clearing before the variable goes out of scope.

**NEEDS CONTEXT:** `memset(buf, 0, len)` before `free` — correct intent but verify the compiler didn't optimize it out. Prefer `explicit_bzero`/`memset_s`.

**FALSE POSITIVE:** Credential buffer is stack-allocated (`char password[256]`) and the function returns normally — stack frame is overwritten by the next function call. Still a weak guarantee; prefer explicit zero before return.
