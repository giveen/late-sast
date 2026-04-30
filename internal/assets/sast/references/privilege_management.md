---
name: privilege-management
description: Privilege mismanagement in native binaries — running as root without dropping privileges, setuid misuse, overly-permissive file creation. CWE-250, CWE-272, CWE-732.
---

# Privilege Management (CWE-250 / CWE-272 / CWE-732)

Native binaries often run as root or with elevated capabilities to perform a privileged operation (bind to port 80, open raw sockets, write system files). The vulnerability occurs when the binary fails to drop those privileges once the sensitive operation is complete, leaving the entire program — and any vulnerability within it — operating with unnecessary power. A single buffer overflow or command injection in a root daemon becomes instant root shell.

## Where to Look

**Daemons and services**
- Any binary started by `systemd`, `init`, or `launchd` as root that serves external input
- Network-facing daemons (`bind()` to port < 1024 requires root; the binary should then drop)

**SUID/SGID binaries**
- Files with the setuid bit set: `find / -perm -4000 2>/dev/null`
- These run as the file's owner (often root) regardless of who executes them
- Dangerous if they call `system()`, `popen()`, or execute user-controlled paths

**Privilege escalation chains**
- Binaries that read a user-writable config file and then execute commands from it as root
- Binaries that `dlopen()` a path that includes user-writable directories

**File permission bugs (CWE-732)**
- `open(path, O_CREAT | O_WRONLY, 0666)` — world-writable file creation
- `mkdir(path, 0777)` — world-writable directory
- `umask(0)` at startup — removes all permission restrictions for subsequent file operations
- Temp files created in world-writable directories with predictable names (TOCTOU / symlink attack)

## How to Detect

### Find privilege drop (or absence thereof)

```bash
docker exec <container> sh -c "
  grep -rn 'setuid\|setgid\|seteuid\|setegid\|setreuid\|setresuid\|prctl\|cap_set' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null | head -30
"
```
If a binary runs as root but none of these calls appear: the binary never drops privileges → any exploitable vulnerability in it runs as root (CONFIRMED CWE-250).

**Check for root-only operations followed by setuid drop:**
```bash
docker exec <container> sh -c "
  grep -rn 'bind\s*(\|CAP_NET_BIND\|raw socket\|SOCK_RAW' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null
"
```
The pattern `bind(sock, ..., 80)` followed by `setuid(nobody_uid)` is correct. Missing the `setuid` call is the bug.

### SUID binary detection

```bash
docker exec <container> sh -c "find /app -perm -4000 -o -perm -2000 2>/dev/null"
docker exec <container> sh -c "find / -perm -4000 2>/dev/null | grep -v proc"
```

**In a SUID binary, check for `system()`/`popen()` or PATH-dependent calls:**
```bash
docker exec <container> sh -c "
  nm <binary> 2>/dev/null | grep ' system$\| popen$\| exec'
"
```
A SUID binary that calls `system()` where the command string can include relative paths (e.g., `system("ps aux")` without absolute path) is exploitable via `PATH` manipulation.

### File permission audit

```bash
docker exec <container> sh -c "
  grep -rn 'O_CREAT\|mkdir\s*(\|creat\s*(' --include='*.c' --include='*.cpp' /app 2>/dev/null \
  | grep -E '0666|0777|0644' | head -20
"
```

```bash
docker exec <container> sh -c "
  grep -rn 'umask\s*(0\|umask(000\|umask(0000' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null
"
```

### Go / Rust privilege checks

```bash
docker exec <container> sh -c "
  grep -rn 'os\.Getuid\|syscall\.Setuid\|syscall\.Setgid\|unix\.Setuid' \
    --include='*.go' /app 2>/dev/null | head -20
"
docker exec <container> sh -c "
  grep -rn 'nix::unistd::setuid\|nix::unistd::setgid\|libc::setuid' \
    --include='*.rs' /app 2>/dev/null | head -20
"
```

## Vulnerability Patterns

### Missing privilege drop after bind (CWE-250)

```c
int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    // bind to port 80 — requires root
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(sock, 128);
    // MISSING: setuid(nobody); setgid(nogroup); // should drop here
    
    while (1) {
        int client = accept(sock, NULL, NULL);
        handle_client(client);   // handles untrusted input — still running as root
    }
}
```

### SUID + PATH hijack

```c
// Binary installed as root with SUID bit
// /usr/local/bin/status (rwsr-xr-x root root)
int main() {
    system("ps aux | grep httpd");  // "ps" resolved via PATH — attacker can hijack PATH
}
```
Attacker creates `~/bin/ps` with payload, sets `PATH=~/bin:$PATH`, runs the SUID binary → root shell.

**Fix:** Use absolute paths: `system("/bin/ps aux | grep httpd")`. Better: `execv("/bin/ps", ...)`.

### World-writable file creation

```c
int fd = open("/var/run/myapp.pid", O_CREAT|O_WRONLY|O_TRUNC, 0666);
// Any user can overwrite the PID file → TOCTOU or symlink → write to arbitrary files
```

### `umask(0)` at startup

```c
int main() {
    umask(0);   // removes all default permission masking
    // Every subsequent open/mkdir uses the mode exactly as specified
    // open("config.txt", O_CREAT|O_WRONLY, 0644) → 0644 fine
    // but open("secret.key", O_CREAT|O_WRONLY, 0600) → still 0600 fine
    // However: if any path uses 0666, it becomes world-readable/writable
}
```

## Exploitation

```bash
# Verify the process runs as root:
docker exec <container> sh -c "ps aux | grep <binary>"
# If USER column is 'root', and the binary has any exploitable vuln: instant root shell.

# SUID PATH hijack PoC:
docker exec <container> sh -c "
  mkdir /tmp/hijack
  echo '#!/bin/sh
id > /tmp/hijack_proof' > /tmp/hijack/ps
  chmod +x /tmp/hijack/ps
  PATH=/tmp/hijack:$PATH ./<suid_binary>
  cat /tmp/hijack_proof
"
# Expected: uid=0(root) ... — SUID escalation confirmed

# Verify no privilege drop:
docker exec <container> sh -c "strace -e trace=setuid,setgid,setreuid ./<binary> 2>&1 | head -20"
# Expected: no setuid/setgid calls → CONFIRMED missing privilege drop
```

## Judge Verdicts

**CONFIRMED:** Daemon runs as root + no `setuid`/`setgid`/`prctl(PR_SET_KEEPCAPS)` call found + binary handles external network input or reads user-supplied files.

**CONFIRMED:** SUID binary calls `system()` or `popen()` with a non-absolute-path command string.

**LIKELY:** Binary creates files with mode `0666` in a user-accessible directory.

**NEEDS CONTEXT:** Binary calls `setuid(uid)` — verify the `uid` value is a non-root unprivileged user (> 0 and not overridable by config).

**FALSE POSITIVE:** Binary runs as root only to write a log file, then immediately calls `setuid(nobody_uid)` before entering the request loop.
