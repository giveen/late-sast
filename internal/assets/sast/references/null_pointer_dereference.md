---
name: null-pointer-dereference
description: NULL/nil pointer dereference causing crashes or denial of service. CWE-476. #13 on CWE Top 25 (2025).
---

# NULL Pointer Dereference (CWE-476)

A NULL pointer dereference crashes the process when the program reads or writes through a pointer that is NULL (or nil in Go/Rust). In embedded systems or kernels it can lead to privilege escalation. In user-space servers it produces denial of service. In Go, a nil pointer panic terminates the goroutine (and often the whole server) just as surely as a segfault in C. Ranked #13 on the 2025 CWE Top 25.

## Where to Look

**C/C++ — unchecked return values:**
- `malloc()` returns NULL on allocation failure — most code assumes success
- `fopen()` returns NULL if the file doesn't exist or is unreadable
- `strdup()`, `strndup()` return NULL on alloc failure
- `getenv()` returns NULL if the variable is unset
- `strtok()` returns NULL when no more tokens remain

**C/C++ — pointer chains without intermediate checks:**
- `a->b->c` where `a->b` might be NULL
- Function return values used immediately: `get_config()->value` where `get_config()` can return NULL

**Go — nil pointer panics:**
- Interface values that are nil and then dereferenced
- Pointer fields in structs accessed without nil check
- Map lookups returning a struct pointer: `config := configs[key]` → `config.Field` panics if `key` not found (returns zero value, nil pointer)
- Type assertions without comma-ok: `v := iface.(concreteType)` panics if iface is nil or wrong type

**Rust — raw pointer dereferences in `unsafe`:**
- `unsafe { *ptr }` where `ptr` might be null
- FFI function return values used without null check
- `as_ptr()` results passed back through FFI and dereferenced

## How to Detect

### C/C++ — grep for unchecked malloc/fopen

```bash
docker exec <container> sh -c "
  grep -rn 'malloc\|calloc\|fopen\|strdup\|getenv' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null | head -40
"
```
For each hit, check whether the return value is tested for NULL before use. Pattern:
```c
char *buf = malloc(n);
// MISSING: if (!buf) { handle_error(); return; }
memcpy(buf, src, n);   // NPD if malloc returned NULL
```

**Function return values used in chained expressions:**
```bash
docker exec <container> sh -c "
  grep -rn '->.*->' --include='*.c' --include='*.cpp' /app 2>/dev/null | head -30
"
```
Any `a->b->c` chain is a candidate — if `a->b` can be NULL, this crashes.

### Go — grep for direct field access on potentially-nil pointers

```bash
docker exec <container> sh -c "
  grep -rn '\bnil\b' --include='*.go' /app 2>/dev/null | grep -v '//\|!= nil\|== nil' | head -20
"
```

**Unsafe type assertions:**
```bash
docker exec <container> sh -c "
  grep -rn '\.\([A-Z][a-zA-Z]*\)' --include='*.go' /app 2>/dev/null \
  | grep -v 'ok\b' | head -30
"
```
`v := iface.(Type)` without `v, ok := iface.(Type); if !ok` is a crash if the interface has the wrong concrete type.

**Map index returning pointer:**
```bash
docker exec <container> sh -c "
  grep -rn '\[.*\]\.' --include='*.go' /app 2>/dev/null | head -20
"
```
`m[key].Field` panics if `m[key]` returns a nil pointer.

### Go — look for unguarded `r.Body.Close()` style patterns

```bash
docker exec <container> sh -c "
  grep -rn '\.Close()\|\.Read(\|\.Write(' --include='*.go' /app 2>/dev/null \
  | grep -v 'if.*!= nil' | head -20
"
```

## Vulnerability Patterns

### C: unchecked malloc

```c
void handle_request(size_t len) {
    char *buf = malloc(len);
    // BUG: no NULL check
    memset(buf, 0, len);    // SIGSEGV if malloc returned NULL (OOM condition)
    recv(sock, buf, len, 0);
}
```

### C: chained pointer dereference

```c
struct Config *cfg = load_config(path);    // returns NULL if file missing
int timeout = cfg->network->timeout;       // NPD if cfg or cfg->network is NULL
```

### Go: nil interface panic

```go
func process(r *http.Request) {
    userID := r.Context().Value("userID")   // may return nil if key not set
    uid := userID.(string)                   // panic: interface conversion: interface is nil, not string
    log.Printf("user: %s", uid)
}
```

### Go: nil pointer in struct chain

```go
type Server struct {
    Config *Config
}

func (s *Server) MaxConns() int {
    return s.Config.MaxConnections    // panic if s.Config is nil
}
```

### Go: unguarded HTTP body use

```go
func handler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)     // fine
    _ = r.Body.Close()                // fine
    // but if r.Body is nil (e.g. GET with no body):
    // no crash here — io.ReadAll handles nil gracefully
    // However:
    decoder := json.NewDecoder(r.Body)  // if r.Body is nil after Close, panics
    decoder.Decode(&req)
}
```

## Exploitation

**DoS via nil dereference:**
```bash
# In C binary — trigger the code path where malloc would return NULL
# (e.g., request a very large allocation or exhaust memory first)
docker exec <container> sh -c "
  ulimit -v 1024   # limit virtual memory to 1 MB
  ./<binary> <normal_input>
  echo exit: $?
"
# Expected: exit code 139 (SIGSEGV) or 134 (SIGABRT) — crash = DoS

# In Go server — send a request that hits the nil dereference code path
docker exec <container> sh -c "
  wget -qO- --timeout=10 'http://localhost:<port>/<endpoint>' 2>&1
"
# Expected: server returns 500 Internal Server Error with panic message,
# or server process terminates (connection reset)
```

**Trigger via missing/empty fields:**
```bash
# Send a request with an omitted required field (key that maps to a nil pointer)
docker exec <container> sh -c "
  wget -qO- --timeout=10 \
    'http://localhost:<port>/api/endpoint' \
    --post-data='{}' \
    --header='Content-Type: application/json' 2>&1
"
# Expected: panic: runtime error: invalid memory address or nil pointer dereference
```

## Judge Verdicts

**CONFIRMED:** `malloc()` return value used in `memcpy`/`memset`/dereference without a NULL check, where the allocation size comes from user input (can be forced to fail via large allocation request).

**CONFIRMED:** Go type assertion `v := iface.(T)` without comma-ok, in a code path reachable with attacker-controlled input that could cause the interface to hold a nil or unexpected type.

**LIKELY:** Chained pointer dereference `a->b->c` where `a` or `a->b` is a result of a function that may legitimately return NULL (config lookup, map access, optional struct field).

**NEEDS CONTEXT:** `getenv()` result used without NULL check — if the calling code is only reached when the env var is guaranteed set (e.g., always set by a systemd unit file), it may be acceptable. Verify the deployment context.

**FALSE POSITIVE:** `malloc()` followed immediately by `if (!buf) return NULL;` — proper NULL guard is present.
