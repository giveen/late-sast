---
name: integer-overflow
description: Integer overflow, underflow, and sign confusion leading to incorrect allocation sizes or array bounds. CWE-190, CWE-191, CWE-680, CWE-369.
---

# Integer Overflow / Underflow

Integer overflows are a silent gateway to memory corruption. A value that wraps around (e.g., `UINT32_MAX + 1 == 0`) is typically harmless on its own — the danger arises when the wrapped value is used to size an allocation or as an array index: the binary allocates a tiny buffer, then copies a large amount of data into it, producing a heap overflow. In Go and Rust the overflow semantics differ but sign-confusion and conversion bugs still occur.

## Where to Look

**Allocation sizing from user input (C/C++)**
- `malloc(user_len * element_size)` — multiplication wraps on 32-bit or when `user_len` is `uint32_t` on 64-bit
- `malloc(hdr.count * sizeof(T))` — `count` from a network packet or file header
- `realloc(buf, old_size + user_delta)` — addition wrap

**Array / pointer indexing**
- `buf[user_index]` where `user_index` is unsigned but was received as signed; or sign extension from 16-bit to 32/64-bit
- Loop bound derived from user-controlled length field

**Arithmetic on sizes before bounds check**
- `if (offset + length > max)` — if `offset + length` wraps, the check passes but the subsequent access is OOB

**Go-specific: slice capacity arithmetic**
- `make([]T, n)` where `n` comes from an untrusted source and is not capped
- `append` in a hot loop without a bound — memory exhaustion DoS

**Rust-specific: `as` casting**
- `let n: usize = user_val as usize` where `user_val` is `i32` and could be negative — wraps to large `usize`
- Integer arithmetic in `unsafe` blocks

## How to Detect

### Static grep (C/C++)

**Multiplication used as allocation size:**
```bash
grep -rn 'malloc\s*(\|calloc\s*(' --include='*.c' --include='*.cpp' /app \
  | grep -E '\*|count|num|len|size'
```
Flag every `malloc(a * b)` where `a` or `b` is derived from external data.

**Unchecked addition before allocation:**
```bash
grep -rn 'malloc\s*(.*+' --include='*.c' --include='*.cpp' /app
```

**`realloc` with additive size:**
```bash
grep -rn 'realloc' --include='*.c' --include='*.cpp' /app
```

**Signed-to-unsigned conversion of input lengths:**
```bash
grep -rn 'unsigned.*=.*recv\|unsigned.*=.*read\|size_t.*=.*atoi\|size_t.*=.*strtol' \
  --include='*.c' --include='*.cpp' /app
```

### Taint trace

1. Identify integer sources: `recv()`/`read()` length field, `ntohs()`/`ntohl()` parsed header values, `atoi`/`strtoul` on argv/env
2. Follow to arithmetic operations (`*`, `+`, `-`, `<<`)
3. Check for overflow guard before the arithmetic — `if (a > SIZE_MAX / b)` or compiler built-in `__builtin_mul_overflow`
4. Follow to `malloc`/`calloc`/array index
5. If no guard: CONFIRMED

## Vulnerability Patterns

### Multiplication wrap → heap overflow (CWE-680)

```c
// Packet header: uint16_t count
uint16_t count = ntohs(hdr->count);      // max 65535
size_t sz = count * sizeof(record_t);    // on 32-bit: 65535 * 1024 = overflow!
char *buf = malloc(sz);                  // tiny allocation
memcpy(buf, data, count * sizeof(record_t));  // writes full count — heap overflow
```

`count = 65535`, `sizeof(record_t) = 1024` → `sz = 65535 * 1024 = 67,107,840` on 64-bit (fine) but `67,107,840 & 0xFFFFFFFF = 67,107,840` — wrap only occurs at specific thresholds. On 32-bit with `uint32_t count` at `UINT_MAX / sizeof(T) + 1` it wraps to 0 → `malloc(0)` returns a valid pointer → `memcpy` with full `count * sizeof(T)` overwrites everything.

**Safe pattern:**
```c
if (count > MAX_RECORDS || count > SIZE_MAX / sizeof(record_t)) { reject(); }
size_t sz = count * sizeof(record_t);
```

### Additive wrap → bypass bounds check

```c
uint32_t offset, length;
// both from user-controlled packet
if (offset + length > buf_size) return ERROR;  // UNSAFE: wrap bypasses this
memcpy(out, buf + offset, length);              // OOB read/write
```
If `offset = 0xFFFFFFFF` and `length = 1`, `offset + length = 0` (wraps) → check passes → `buf + 0xFFFFFFFF` → OOB.

**Safe pattern:**
```c
if (length > buf_size || offset > buf_size - length) return ERROR;
```

### Sign confusion

```c
int recv_len = recv(sock, buf, sizeof(buf), 0);  // returns -1 on error
if (recv_len > MAX) return ERROR;               // -1 > MAX is false — passes!
process(buf, recv_len);                         // recv_len = -1 → UB
```
Cast `recv_len` to `size_t` before comparison, or check `recv_len < 0` first.

### Go integer overflow

```go
n, _ := strconv.Atoi(r.FormValue("count"))
data := make([]byte, n*1024)  // n could be negative or very large
```
Negative `n` → runtime panic (slice with negative capacity). Very large `n` → OOM. Always validate: `if n <= 0 || n > MaxItems { ... }`.

## Exploitation

```bash
# Send a packet with count/length fields set to triggering overflow values
docker exec <container> sh -c "
  python3 -c \"
import struct, socket
# count=65537 on 32-bit * 1024 bytes => wraps to small allocation
pkt = struct.pack('>H', 65537) + b'A' * 8192
s = socket.create_connection(('127.0.0.1', <port>))
s.send(pkt)
resp = s.recv(256)
print(resp)
\" 2>&1
"
# Expected: SIGSEGV, malloc corruption message, or malformed response
```

## Judge Verdicts

**CONFIRMED:** `malloc(a * b)` or `malloc(a + b)` where `a` or `b` comes from network/file input and there is no overflow-safe guard.

**LIKELY:** Bounds check present but uses the potentially-wrapped value rather than checking for wrap before the arithmetic.

**NEEDS CONTEXT:** `calloc(a, b)` — `calloc` performs an internal overflow check on most platforms; inspect whether the platform is glibc ≥ 2.2 (safe) or a custom allocator.

**FALSE POSITIVE:** `malloc(n * sizeof(T))` where `n` is verified against a hard constant (`n <= MAX_ITEMS`) before the multiplication and `MAX_ITEMS * sizeof(T) <= SIZE_MAX`.
