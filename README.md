# Building MACs from Scratch

This project explores how to implement Message Authentication Codes (MACs) "from scratch" in Python, starting from basic cryptographic building blocks rather than high-level convenience APIs.

It is planned as part of a broader "rebuilding cryptography from scratch" series that I’m writing about on my site and newsletter.

> Educational only — do not use this as-is in production. Prefer well‑tested library implementations when building real systems.

## AES-CMAC implementation

`cmac.py` re‑implements the CMAC construction on top of AES‑ECB provided by [PyCryptodome](https://pycryptodome.readthedocs.io/):

- Subkey generation (`_dbl`, `_generate_subkeys`) using GF(2¹²⁸) doubling and the CMAC constant `Rb = 0x87`.
- ISO/IEC 7816‑4 padding for partial final blocks (`_pad_7816_4`).
- CBC‑style chaining with an all‑zero IV.
- Correct handling of:
  - empty messages,
  - messages with a full final block,
  - messages with a partial final block.
- Cross‑checking against:
  - official NIST SP 800‑38B test vectors, and
  - PyCryptodome's built‑in `Crypto.Hash.CMAC`.

Core entry point:

- `aes_cmac(key: bytes, msg: bytes) -> bytes` — compute a 16‑byte CMAC tag for an arbitrary message.

### Background & links

- Series homepage: `https://www.dmytrohuz.com/p/rebuilding-cryptography-from-scratch`
- Author’s Substack: `https://www.dmytrohuz.com/`
- This repository will be referenced from a dedicated article about MACs (link to be added once published).

### Requirements

- Python 3.8+
- PyCryptodome:

```bash
python -m pip install pycryptodome
```

### Running the built‑in self‑test

`cmac.py` includes a small test harness that verifies the implementation:

- It checks several well‑known NIST CMAC test vectors.
- It cross‑checks each result against `Crypto.Hash.CMAC`.

Run:

```bash
python cmac.py
```

You should see:

```text
AES-CMAC OK (vectors + library cross-check passed)
```

### Using the MAC in your own code

You can import and call `aes_cmac` directly:

```python
from cmac import aes_cmac

key = b"\x00" * 16  # 16/24/32 bytes for AES-128/192/256
message = b"hello, world"

tag = aes_cmac(key, message)
print(tag.hex())
```

The function:

- Accepts AES keys of length 16, 24, or 32 bytes.
- Accepts arbitrary binary messages (`bytes`).
- Returns the 16‑byte CMAC tag as `bytes`.

To verify a tag, recompute `aes_cmac(key, message)` and compare it in constant‑time in real applications (Python’s `hmac.compare_digest` can help with that in production code).

### Code walkthrough (high level)

The implementation is intentionally explicit and readable so you can follow the CMAC design:

- `_xor` — byte‑wise XOR of two equal‑length byte strings.
- `_left_shift_1` — shift a 16‑byte block left by 1 bit (used by `_dbl`).
- `_dbl` — CMAC “doubling” in GF(2¹²⁸) to derive subkeys `K1` and `K2`.
- `_pad_7816_4` — ISO/IEC 7816‑4 padding for the last partial block.
- `_generate_subkeys` — computes `K1`/`K2` starting from `L = AES_K(0^128)`.
- `aes_cmac` — the main CMAC algorithm:
  - splits the message into 16‑byte blocks,
  - pads or not depending on final block length,
  - runs CBC‑style chaining with AES‑ECB,
  - outputs the final 16‑byte tag.
- `self_test` / `verify_against_library` — simple verification utilities, executed when you run `mac.py` as a script.

Use this repository as a reference when learning how a MAC can be built securely from a block cipher, and as a starting point for exploring other MAC constructions.
