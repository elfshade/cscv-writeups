#!/usr/bin/env python3
"""
CSCV 2026 - Phantom (chall.exe)
String Decryption Utility

This script recovers obfuscated strings from the .rdata section of chall.exe.
The binary employs an affine XOR cipher in sub_140001480 and sub_140001B0F:
    key[i] = (37 * i - 91) & 0xFF
    plaintext[i] = ciphertext[i] ^ key[i]
"""

import sys
import os

def decrypt_affine_xor(data: bytes) -> bytes:
    """Decrypt a byte sequence using the affine linear keystream."""
    out = bytearray()
    for i, b in enumerate(data):
        k = (37 * i - 91) & 0xFF
        out.append(b ^ k)
    return bytes(out)

def main():
    target_file = sys.argv[1] if len(sys.argv) > 1 else "/home/thang/ctf-agent/cscv-2026/chall.exe"
    if not os.path.exists(target_file):
        print(f"[-] Target binary not found: {target_file}")
        return

    with open(target_file, "rb") as f:
        binary = f.read()

    print(f"[*] Analyzing {target_file} (Size: {len(binary):,} bytes)...")

    # Mapping of target encrypted string offsets in .rdata (Raw file offsets)
    # RVA = VA - 0x140000000; Raw = RVA - 0x1000 + 0x400 = RVA - 0xC00
    string_targets = [
        ("0x140E82010 (Library 1)", 0x00E80410, 10),
        ("0x140E82020 (Library 2)", 0x00E80420, 10),
        ("0x140E8202A (Vendor Name)", 0x00E8042A, 5),
        ("0x140E8202F (Kernel 0)", 0x00E8042F, 2),
        ("0x140E82031 (Kernel 1)", 0x00E80431, 2),
        ("0x140E82038 (Default IP)", 0x00E80438, 9),
        ("0x140E82041 (Default Port)", 0x00E80441, 5),
        ("0x140E82046 (Kernel 2)", 0x00E80446, 2),
        ("0x140E82048 (Kernel 3)", 0x00E80448, 2),
        ("0x140E82060 (HW Profile 1)", 0x00E80460, 34),
        ("0x140E82082 (HW Profile 2)", 0x00E80482, 6),
        ("0x140E82088 (HW Profile 3)", 0x00E80488, 5),
        ("0x140E8208D (HW Profile 4)", 0x00E8048D, 6),
        ("0x140E82093 (HW Profile 5)", 0x00E80493, 5),
    ]

    print("\n[+] Recovered Obfuscated Strings:")
    print("-" * 65)
    for label, offset, length in string_targets:
        enc_bytes = binary[offset : offset + length]
        dec_bytes = decrypt_affine_xor(enc_bytes)
        try:
            ascii_repr = dec_bytes.decode("ascii")
        except UnicodeDecodeError:
            ascii_repr = repr(dec_bytes)
        print(f"  {label:<28} | Raw: 0x{offset:08x} -> {ascii_repr}")

    # Reconstruct the expected hardware profile template
    print("-" * 65)
    hw_template = (
        decrypt_affine_xor(binary[0x00E80460 : 0x00E80460 + 34]).decode() + "<VEN_ID>" +
        decrypt_affine_xor(binary[0x00E80482 : 0x00E80482 + 6]).decode() + "<DEV_ID>" +
        decrypt_affine_xor(binary[0x00E80488 : 0x00E80488 + 5]).decode() + "<IP_VER>" +
        decrypt_affine_xor(binary[0x00E8048D : 0x00E8048D + 6]).decode() + "<DRIVER_VER>" +
        decrypt_affine_xor(binary[0x00E80493 : 0x00E80493 + 5]).decode() + "<COMPUTE_UNITS>"
    )
    print(f"[+] Reconstructed Hardware Profile Template:\n    {hw_template}\n")

if __name__ == "__main__":
    main()
