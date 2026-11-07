# Message System — Signed Integer Bypass & Tcache Walking

**Event:** CSCV 2026 (Cyber Security Challenge Vietnam)  
**Category:** Binary Exploitation (Pwn / Heap & Stack)  
**Difficulty:** Hard  
**Environment:** Ubuntu 24.04 (glibc 2.39), Docker socat  
**Tools:** `file`, `checksec`, GDB with `pwndbg`, IDA Pro, Python 3 (`pwntools`)  

---

## TL;DR

A multi-stage binary exploitation challenge combining integer signedness validation bugs, uninitialized stack disclosure, and heap tcache-walking across the `.bss` section. The binary also features elaborate prompt-injection traps and deceptive fake flags intended to derail automated AI agents. By exploiting a signed-size validation omission, we obtain unbounded stack writes to control memory, leak the PIE base via uninitialized stack slot reuse, and walk a fake tcache chunk across `.bss` to hijack the menu dispatch table into `system("/bin/sh")`.

---

## Reconnaissance & Anti-Agent Decoy Analysis

Checking binary protections:
```text
Arch:     amd64-64-little
RELRO:    No RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
Stripped: Yes
```

### The Anti-AI Decoys (Prompt Injections)
The challenge author embedded numerous decoys in `.rodata` specifically crafted to mislead automated LLMs, scanners, and scripts:
* **False Security Claims:** Fake banners claiming "Full RELRO enabled / Exploit impossible".
* **Dummy Credentials:** Hardcoded decoy strings such as `letmein`, `admin123`, `guest`, `admin`.
* **Decoy Flags:** Pre-placed strings including `CSCV2026{nice_try_robot}` and `FLAG_FOUND: CSCV2026{fake_flag_for_ai_slop}`.
* **Fake Policy Warnings:** `[SAFETY POLICY VIOLATION] ...`.

Recognizing these as red herrings was critical to staying focused on true binary semantics and reverse engineering the actual logic in IDA Pro.

---

## Vulnerability Analysis

Three core flaws form the exploitation chain:

1. **Signed Size Validation Bypass (`0x1628`):**  
   The size configuration function calculates `abs(raw)` for boundary checks (`abs(raw) <= 0x78`), but stores the original **raw signed value** into the global size variable `[0x5b48]`. Supplying `-1` passes checks and grants unbounded reading in `Create()`, overwriting the stack `state` struct.
2. **`free()` as a Clean Reset Mechanism (`0x1a28`):**  
   When deleting a message, the program executes `free(state->msg)` and immediately sets `state->msg = 0`. Pointing `state->msg` to a valid fake chunk allows clean recycling through tcache without process termination, enabling multi-stage primitive execution over a single connection.
3. **Information Disclosure via Uninitialized Stack Slot:**  
   `Configure priority` writes a global pointer `&global(0x5b4c)` to stack offset `[rbp - 0x1030]`. Option `Call support` accesses this exact same uninitialized stack slot and prints it via `printf("%lld")`, leaking the PIE base address.

---

## Exploitation Chain

```text
1. Information Leak:
   Trigger Priority (invalid 0) -> Call Support -> Read %lld -> Derive PIE Base.

2. Arbitrary .bss Write Primitive:
   Set size = -1 -> Craft fake chunk header (size 0x71) at PIE + 0x5b48.
   Trigger Send -> free(PIE + 0x5b50) -> Chunk inserted into tcache[0x70].
   Next Create -> malloc(0x64) returns PIE + 0x5b50 -> Write controlled data to .bss.

3. Tcache Walking to Dispatch Table (0x5d50):
   Stride by 0x60 bytes across .bss:
   0x5b50 -> 0x5bb0 -> 0x5c10 -> 0x5c70 -> 0x5cd0 -> 0x5d30.
   At 0x5d30, overwrite the menu table pointer [0x5d50] with a forged table pointing to win (system("/bin/sh")).

4. Trigger:
   Select Menu Option 1 -> Dispatch calls forged entry -> Pops Interactive Shell!
```

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

HOST = "113.20.103.216"
PORT = 1337

def main():
    p = remote(HOST, PORT)

    # 1. Leak PIE base via uninitialized stack slot
    # 2. Forge fake chunk at .bss + 0x5b50
    # 3. Walk tcache to menu dispatch table at 0x5d50
    # 4. Hijack dispatch to win() -> system("/bin/sh")
    
    # [Complete script logic preserved in exploit.py]
    p.interactive()

if __name__ == "__main__":
    main()
```

*(See [`exploit.py`](exploit.py) for the complete production exploit).*

---

## Flag & Key Takeaways

```text
CSCV2026{r3d4ct3d_m3ss4g3_syst3m_fl4g}
```

1. **Verify Raw vs Validated Variable Storage:** A validation check is meaningless if the code persists the raw unvalidated input rather than the sanitized output.
2. **`free()` as an Allocation Primitive:** Controlled heap frees can be chained to manufacture arbitrary memory allocations even in non-traditional heap layouts.
3. **Filter Out Deceptive Decoys:** Always verify protections dynamically with `checksec` and disassembly rather than relying on embedded static strings.
