# CSCV 2026 — Cyber Security Challenge Vietnam Writeups

My vulnerability analysis, architectural research, and exploit scripts from **CSCV 2026** (Cyber Security Challenge Vietnam).  
Focus: **Advanced Binary Exploitation (Pwn)**, **Custom VM Bytecode Internals**, and **GPU-Accelerated Windows Reverse Engineering**.

As a 2nd-year computer science student exploring modern exploitation techniques, these writeups document my hands-on methodology—dissecting deceptive anti-agent prompt-injection defenses, reverse engineering proprietary stateful protocols, and turning logic bugs into stable, reproducible exploit chains.

Flags and platform tokens are redacted on purpose.

---

## Challenge Index

| # | Challenge | Category | Difficulty | Highlights & Core Techniques | Writeup |
|---|---|---|---|---|---|
| 1 | **Message System** | Binary Exploitation | Hard | Signed integer size validation bypass, uninitialized stack disclosure (PIE leak), tcache walking across `.bss`, and bypassing anti-AI prompt injection traps | [Writeup](message-system/README.md) |
| 2 | **MARIONETTE** | Binary Exploitation | Hard | Stateful custom VM bytecode interpreter, FNV1a-64 MAC packet authentication, negative signed modulo OOB write, PPTS object forgery, and `FINALE` decryption | [Writeup](marionette/README.md) |
| 3 | **Phantom** | Reverse Engineering | Hard | Windows x86-64 PE, affine keystream string deobfuscation, dynamic API export hashing (`rol 7`), OpenCL GPU hardware attestation (Intel Iris Xe), MBA obfuscation, and surgical binary patching | [Writeup](phantom/README.md) |

---

## Toolchain & Research Environment

* **Target OS / Environment:** Ubuntu 24.04 LTS (glibc 2.39), Docker container isolation
* **Decompilation & Binary Analysis:** IDA Pro 9.0, `objdump`, `readelf`
* **Dynamic Tracing & Debugging:** GDB with `pwndbg`
* **Exploitation Framework:** Python 3 with `pwntools`
* **Network & Protocol Reversing:** Raw socket communication, custom framing and cryptographic hashing (FNV1a-64)
