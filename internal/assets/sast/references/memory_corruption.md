---
name: memory-corruption
description: Memory corruption testing — buffer overflows, out-of-bounds read/write. CWE-787, CWE-125, CWE-120, CWE-121, CWE-122.
---

# Memory Corruption

Memory corruption is the leading class of exploitable vulnerability in native-code (C/C++) binaries. An attacker who can corrupt heap or stack memory can typically achieve arbitrary code execution. Buffer overflows remain trivial to introduce and devastating in impact. Every array index and copy length derived from external input is a candidate.

## Where to Look

**Stack buffers**
- Fixed-size arrays (`char buf[256]`) receiving input from `gets`, `fgets`, `read`, `recv`, `scanf`, `strcpy`, `sprintf`
- Alloca-based buffers sized from user input

**Heap buffers**
- `malloc`/`calloc`/`realloc` with size derived from network/file input, then filled with a copy
- `new[]` in C++ with attacker-controlled count

**Array indexing**
- Signed-to-unsigned conversion of user-supplied indices
- Off-by-one: `<= len` instead of `< len` in loop bounds
- Negative-index writes via signed integer array subscript

**Out-of-bounds Read (information leak)**
- Heartbleed-style: length field in protocol larger than actual buffer allocated; code reads `length` bytes and sends them to attacker

## How to Detect

### Static grep patterns (C/C++)

**Unbounded copy into fixed buffer:**
```bash
grep -rn 'strcpy\|strcat\|gets\b\|sprintf\b\|vsprintf\b' --include='*.c' --include='*.cpp' /app
```

**memcpy/memmove with user-controlled size:**
```bash
grep -rn 'memcpy\|memmove\|bcopy' --include='*.c' --include='*.cpp' /app
```
Inspect each call: if the `n` argument is derived from network input, file data, or a user-supplied length field, it is a candidate.

**scanf without width specifier:**
```bash
grep -rn 'scanf.*%s' --include='*.c' --include='*.cpp' /app
```
`scanf("%s", buf)` is equivalent to `gets` — no bounds.

**Variable-length stack arrays from user input:**
```bash
grep -rn 'alloca\|char \w\+\[n\]\|char \w\+\[len\]\|char \w\+\[size\]' --include='*.c' --include='*.cpp' /app
```

### Taint trace

1. Find input sources: `recv()`, `read()`, `fread()`, `fgets()`, `getline()`, `argv[n]`, `getenv()`
2. Follow the data: does it flow into a length parameter for `memcpy`/`strcpy`/`sprintf`? Does it flow into an array index?
3. Check if there is a `len < sizeof(buf)` guard **before** the copy. If not: CONFIRMED.

## Vulnerability Patterns

### Classic Stack Buffer Overflow (CWE-121)

```c
void handle_name(int sock) {
    char name[128];
    int n = recv(sock, name, 4096, 0);  // reads up to 4096 into 128-byte buffer
    name[n] = '\0';
    process(name);
}
```
`recv` is told it can write 4096 bytes into a 128-byte stack buffer. Any input over 127 bytes overwrites the return address.

**Correct pattern:**
```c
int n = recv(sock, name, sizeof(name) - 1, 0);
```

### Heap Buffer Overflow (CWE-122)

```c
char *buf = malloc(hdr.length);    // hdr.length from network packet
memcpy(buf, data, hdr.data_size);  // hdr.data_size also from network — may exceed hdr.length
```
If `data_size > length`, the `memcpy` writes past the end of the heap allocation.

### Out-of-Bounds Read (CWE-125)

```c
// TLS record: type(1) + version(2) + length(2) + payload(length)
uint16_t payload_len = ntohs(*(uint16_t*)(pkt + 3));
memcpy(response, pkt + 5, payload_len);    // payload_len not bounded by actual packet size
send(sock, response, payload_len, 0);      // leaks heap memory to attacker
```

### Off-by-One (CWE-193 → CWE-787)

```c
char buf[64];
for (i = 0; i <= 64; i++) buf[i] = input[i];  // writes buf[64] — one past end
```

## Exploitation

**Stack overflow PoC** — send input longer than the declared buffer:
```bash
docker exec <container> sh -c "python3 -c \"print('A'*300)\" | ./<binary>"
# Expected: SIGSEGV (exit code 139) or abnormal exit — confirms stack smash
```

**Heap overflow PoC** — craft a packet/file with `length` header smaller than `data` body:
```bash
# Example for a binary that reads a 4-byte length-prefixed message:
docker exec <container> sh -c "
  python3 -c \"
import struct, socket
payload = b'A' * 512
hdr = struct.pack('>I', 16)   # claim 16 bytes but send 512
s = socket.create_connection(('127.0.0.1', <port>))
s.send(hdr + payload)
print(s.recv(256))
\"
"
# Expected: crash, SIGSEGV in /proc/<pid>/status, or corrupted response
```

## Judge Verdicts

**CONFIRMED:** Fixed-size buffer + copy function + no `sizeof` guard + user-controlled source/length.

**LIKELY:** Copy function with `n` derived from user input; bounds check present but logic appears bypassable (e.g., only checks against a config maximum, not allocation size).

**NEEDS CONTEXT:** `strncpy(dst, src, n)` where `n` appears to be `sizeof(dst)` — safe, but verify the source string is null-terminated and `n` is correct.

**FALSE POSITIVE:** `memcpy(dst, src, sizeof(dst))` where `src` is a compile-time constant and `sizeof(dst)` is correct.
