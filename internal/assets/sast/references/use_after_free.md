---
name: use-after-free
description: Use-after-free and double-free vulnerability detection. CWE-416, CWE-415.
---

# Use-After-Free / Double-Free

Use-after-free (UAF) occurs when a program dereferences a pointer after the pointed-to memory has been freed. Attackers who can influence the heap layout can cause a later allocation to reuse the freed slot, then trigger the stale pointer to read or write into the now-reallocated object — achieving information disclosure or arbitrary code execution. Double-free triggers heap metadata corruption, often giving equivalent primitives.

## Where to Look

**Explicit `free()` / `delete` patterns**
- Any `free(ptr)` where `ptr` is still stored in a reachable variable (not immediately NULL-ed or overwritten)
- `delete` / `delete[]` in C++ where the destructor stores back-pointers or callbacks referencing `this`

**Container/cache eviction**
- Items removed from a linked list or array without clearing external references to them
- Cache invalidation that frees objects while other threads hold raw pointers

**Error paths**
- Cleanup code on error branches that frees objects, while the main path continues referencing them
- Exception-driven cleanup (`std::exception`) that destroys objects whose raw pointers are still live

**Callbacks and event loops**
- Objects freed inside an event handler while still registered in the dispatcher
- Signal handlers freeing allocations referenced from the main execution thread

## How to Detect

### Static grep patterns

**Find all free() calls and check for subsequent uses:**
```bash
grep -n 'free(' --include='*.c' --include='*.cpp' -r /app
```
For each hit, check whether the pointer variable is set to `NULL` immediately after:
```c
free(ptr);        // bad — ptr still holds the address
ptr = NULL;       // good — prevents accidental deref
```

**Double-free — look for multiple free() calls on the same variable in the same function:**
```bash
# Read each function that calls free; check if the same variable appears twice
grep -A20 'free(' --include='*.c' --include='*.cpp' -r /app | grep -B5 'free('
```

**C++ destructor + raw pointer fields:**
```bash
grep -n '~\w\+\(\|delete ' --include='*.cpp' -r /app
```
In each destructor, trace whether `delete`d members have pointers stored elsewhere.

### Taint trace approach

1. Identify all `malloc`/`calloc`/`new` calls. Note the variable that receives the pointer.
2. Find the matching `free`/`delete`. Record its location.
3. Search for any use of the pointer variable after the free (load, store, call through pointer).
4. If a use exists: CONFIRMED UAF.
5. Search for any additional `free` on the same variable without an intervening `malloc`: CONFIRMED double-free.

## Vulnerability Patterns

### Simple UAF

```c
struct Request *req = malloc(sizeof(*req));
req->buf = malloc(4096);
process(req);         // may set a global g_req = req
free(req->buf);
free(req);            // req freed

// ... later ...
g_req->buf[0] = 'X';  // UAF: g_req still points to freed memory
```

### Error-path UAF

```c
Item *item = create_item(data);
if (!register_item(item)) {
    free(item);       // freed on error
    return -1;
}
// callers may still hold a stale copy of `item` if register_item
// stored it somewhere before failing
```

### Double-free

```c
void cleanup(char *s) {
    free(s);
}

void process(char *input) {
    char *s = strdup(input);
    if (bad_input(s)) {
        cleanup(s);
        free(s);   // double-free: s already freed by cleanup()
        return;
    }
    // ...
}
```

### C++ destructor race

```cpp
class Session {
    char *token_;
    Dispatcher *disp_;  // shared
public:
    ~Session() {
        disp_->unregister(this);  // removes from dispatcher
        delete[] token_;           // frees token
    }
};
// If another thread fires an event referencing this Session after disp_->unregister
// returns but before ~Session finishes, UAF on token_ or the Session itself.
```

## Exploitation

UAF exploitation typically requires heap grooming: allocate objects of the same size to fill the freed slot, then trigger the stale pointer dereference.

**Black-box crash-based PoC:**
```bash
# Send a sequence of requests designed to trigger alloc → free → alloc (same size) → deref
docker exec <container> sh -c "
  # Request 1: create object, get its ID
  # Request 2: delete/free the object
  # Request 3: create new object of same size (occupies freed slot)
  # Request 4: use the original ID — triggers UAF if pointers not cleared
  echo 'See manual PoC in description'
"
# Expected: SIGSEGV, heap corruption error, or inconsistent state response
```

**ASAN confirmation** (if binary is compiled with AddressSanitizer):
```bash
docker exec <container> sh -c "ASAN_OPTIONS=halt_on_error=1 ./<binary> < <crafted_input> 2>&1 | grep 'heap-use-after-free\|double-free'"
```

## Judge Verdicts

**CONFIRMED:** Free followed by dereference of same pointer; no intervening re-assignment to NULL or valid address; not behind a lock that prevents concurrent access.

**LIKELY:** Free in one function; pointer stored in a global or struct visible to another path; no evidence of NULL check before use in the other path.

**NEEDS CONTEXT:** Pointer freed and then checked for NULL before next use (suggests developer awareness; verify the check is actually load-bearing).

**FALSE POSITIVE:** `free(ptr); ptr = NULL;` immediately before the pointer goes out of scope; or smart pointer (`std::unique_ptr`, `std::shared_ptr`) with no raw `.get()` escape.
