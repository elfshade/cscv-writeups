# MARIONETTE — Custom VM Bytecode OOB Write & State Forgery

**Event:** CSCV 2026 (Cyber Security Challenge Vietnam)  
**Category:** Binary Exploitation (VM Pwn)  
**Difficulty:** Hard  
**Tools:** IDA Pro, GDB with `pwndbg`, Python 3 (`pwntools`)  
**Network Protocol:** Custom 15-byte Big-Endian Header authenticated via FNV1a-64 MAC  

---

## TL;DR

An advanced binary exploitation challenge centered on a custom virtual machine bytecode interpreter. The network protocol enforces frame-by-frame FNV1a-64 MAC authentication. The vulnerability lies in the `SHUFFLE (0x60)` opcode: while the read path properly sanitizes negative modulo values, the write path omits this check. This signed modulo discrepancy yields an **Out-Of-Bounds (OOB) write** before the slot pool array. By hijacking the pool's internal pointer, we forge arbitrary read/write capabilities, recover runtime crypto session state, bypass seccomp and `PROT_NONE` protections, and execute the hidden `FINALE (0x66)` opcode to decrypt the flag.

---

## Architecture & Network Protocol

Each network frame begins with a 15-byte big-endian header:
```text
+----------+----------+----------+----------+-----------------------+
| Type(1B) | Seq (4B) | MAC (8B) | Len (2B) | Payload (Variable)    |
+----------+----------+----------+----------+-----------------------+
```
* **Authentication:** Each frame computes `MAC = FNV1a64(seq || prev_mac || payload)`. Frames with mismatched signatures are dropped immediately.
* **VM Core:** The interpreter runs a rich instruction set including buffer allocation (`NEWBUF`), stack operations (`PUSH`, `POP`), closures (`CALLCLO`), and two hidden instructions: `FINALE (0x66)` and `ADMIN (0x99)`.

---

## Vulnerability: Signed Modulo Discrepancy in `SHUFFLE`

The slot pool manages object references using an internal buffer `p`:
* `[p]` = Magic
* `[p + 8]` = Pointer to active slot array (`p + 0x18`)
* `[p + 0x10]` = Slot count

When invoking `SHUFFLE (0x60)` with an index `idx`:
```c
int rdx = idx % count; // Signed modulo: can evaluate to negative!

// Mode 0 (Read Path): Normalized
if (mode == 0) {
    int rsi = (rdx >= 0) ? rdx : (count + rdx);
    push(slot_array[rsi]);
}
// Mode 1 (Write Path): UNCHECKED!
else if (mode == 1) {
    slot_array[rdx] = value; // Out-Of-Bounds Write when rdx < 0!
}
```

By providing `rdx = -2`, the write targets `p + 0x18 + (-2 * 8) = p + 8`.  
**We overwrite the slot array pointer itself!**

---

## Exploitation Plan (Completed in 1 Session)

```text
1. Heap Leak:
   SHUFFLE Mode 0 reads slot[0] -> Obtains base object pointer O.
   Derive session struct: sess = O - 0xfa0; pool = O - 0xe0.

2. Expand Window:
   Send multiple NEWBUF operations to grow count -> Expands write reach to ±0xC0 bytes.

3. Establish Arbitrary Read/Write:
   Overwrite slot array pointer with session struct addresses.
   Read internal secrets from [sess + 0xab0], [sess + 0xba0], and session tokens.

4. Forge Valid PPTS Object:
   Craft a valid PPTS object in heap memory:
   [A] = Magic, [A+8] = Capacity, [A+18] = Data pointer, [A+30] = Session token.

5. Execute Hidden FINALE Opcode (0x66):
   The flag in memory is locked under mprotect(PROT_NONE) and protected by seccomp.
   Passing the mathematically derived key into FINALE unlocks mprotect and decrypts the flag into our buffer.

6. Output Flag:
   Invoke PRINTS to read out the decrypted plaintext.
```

---

## Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
HOST = "113.20.103.216"
PORT = 9999

def main():
    p = remote(HOST, PORT)

    # 1. Handshake and compute initial FNV1a64 frame MAC
    # 2. Trigger SHUFFLE negative modulo write to redirect slot pointer
    # 3. Read session state and forge PPTS object
    # 4. Trigger FINALE(0x66) to decrypt flag
    
    # [Full bytecode payload implemented in exploit.py]
    p.interactive()

if __name__ == "__main__":
    main()
```

*(See [`exploit.py`](exploit.py) for the complete production exploit).*

---

## Flag & Key Takeaways

```text
CSCV2026{r3d4ct3d_m4r10n3tt3_fl4g_h4sh}
```

1. **Signed Modulo is a Frequent Pitfall:** In C/C++, `(-1) % n` yields `-1`, not `n - 1`. Always verify both read and write branches when array indexing uses modulo.
2. **Inspect Memory Protections (`PROT_NONE` & `seccomp`):** Attempting to jump directly to an apparent `fopen` target resulted in a `SIGSYS` crash. Analyzing seccomp filters prevented chasing decoys.
3. **State Extraction Over RNG Simulation:** When cryptographic RNG seeds are inaccessible, arbitrary read primitives can recover the internal state directly.
