"""
AES-CMAC (CMAC) — final implementation.

- Uses PyCryptodome for AES-ECB (the block primitive).
- Implements CMAC per NIST SP 800-38B:
    * Subkeys K1/K2 derived from L = AES_K(0^128)
    * CBC-style chaining with IV=0
    * Special last-block handling:
        - full last block  -> XOR K1
        - partial last block -> pad (7816-4) then XOR K2

Install:
    pip install pycryptodome
"""

from __future__ import annotations
from Crypto.Cipher import AES
from Crypto.Hash import CMAC as CMAC_LIB

BLOCK_SIZE = 16
RB = 0x87  # Rb for 128-bit CMAC


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR requires equal-length inputs.")
    return bytes(x ^ y for x, y in zip(a, b))


def _left_shift_1(block: bytes) -> bytes:
    """Shift a 128-bit block left by 1 bit."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Expected 16-byte block.")
    out = bytearray(BLOCK_SIZE)
    carry = 0
    for i in range(BLOCK_SIZE - 1, -1, -1):
        out[i] = ((block[i] << 1) & 0xFF) | carry
        carry = (block[i] >> 7) & 1
    return bytes(out)


def _pad_7816_4(partial: bytes) -> bytes:
    """
    ISO/IEC 7816-4 padding: append 0x80 then zeros to reach 16 bytes.
    Used only when the last block is partial (len < 16).
    """
    if len(partial) >= BLOCK_SIZE:
        raise ValueError("pad_7816_4 expects len(partial) < 16.")
    return partial + b"\x80" + b"\x00" * (BLOCK_SIZE - len(partial) - 1)


def _dbl(block: bytes) -> bytes:
    """
    GF(2^128) doubling used for CMAC subkeys.

    dbl(x) = (x<<1)           if MSB(x) = 0
             (x<<1) XOR Rb    if MSB(x) = 1
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("Expected 16-byte block.")
    shifted = _left_shift_1(block)
    if block[0] & 0x80:  # MSB(x) = 1
        shifted = shifted[:-1] + bytes([shifted[-1] ^ RB])
    return shifted


def _generate_subkeys(aes_ecb_encrypt) -> tuple[bytes, bytes]:
    """
    Subkeys:
      L  = AES_K(0^128)
      K1 = dbl(L)
      K2 = dbl(K1)
    """
    L = aes_ecb_encrypt(bytes(BLOCK_SIZE))

    K1 = _dbl(L)
    K2 = _dbl(K1)

    return K1, K2


def aes_cmac(key: bytes, msg: bytes) -> bytes:
    """
    Compute AES-CMAC tag (16 bytes).

    key: 16/24/32 bytes (AES-128/192/256)
    msg: arbitrary bytes
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes.")

    aes = AES.new(key, AES.MODE_ECB)

    def aes_ecb_encrypt(block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("AES-ECB expects 16-byte blocks.")
        return aes.encrypt(block)

    K1, K2 = _generate_subkeys(aes_ecb_encrypt)

    # Number of blocks (CMAC treats empty message as one partial block)
    n = (len(msg) + BLOCK_SIZE - 1) // BLOCK_SIZE
    if n == 0:
        n = 1

    # Split: first n-1 full blocks, and a last block (0..16 bytes)
    blocks = [msg[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE] for i in range(n - 1)]
    last = msg[(n - 1) * BLOCK_SIZE:]  # may be empty, partial, or full

    # Prepare final block with domain separation
    if len(last) == BLOCK_SIZE:
        m_last = _xor(last, K1)
    else:
        m_last = _xor(_pad_7816_4(last), K2)

    # CBC-like chaining with IV=0 on blocks[0..n-2]
    X = bytes(BLOCK_SIZE)
    for b in blocks:
        if len(b) != BLOCK_SIZE:
            raise ValueError("Internal error: non-full intermediate block.")
        X = aes_ecb_encrypt(_xor(X, b))

    # Final tag
    T = aes_ecb_encrypt(_xor(X, m_last))
    return T


# ---------------------------
# Verification helpers/tests
# ---------------------------

def _hx(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))


def verify_against_library(key: bytes, msg: bytes) -> None:
    """Cross-check our CMAC vs PyCryptodome's CMAC."""
    mine = aes_cmac(key, msg)
    lib = CMAC_LIB.new(key, ciphermod=AES)
    lib.update(msg)
    theirs = lib.digest()
    assert mine == theirs, (
        "CMAC mismatch!\n"
        f"mine   = {mine.hex()}\n"
        f"theirs = {theirs.hex()}"
    )


def self_test() -> None:
    """
    Known CMAC values for the famous NIST key + messages from SP 800-38B context.
    We *also* verify with PyCryptodome CMAC to avoid any “vector confusion”.
    """
    key = _hx("2b7e151628aed2a6abf7158809cf4f3c")

    msg1 = _hx("6bc1bee22e409f96e93d7e117393172a")  # 16 bytes
    msg2 = _hx("ae2d8a571e03ac9c9eb76fac45af8e51")  # 16 bytes
    msg3 = _hx("30c81c46a35ce411e5fbc1191a0a52ef")  # 16 bytes
    msg4 = _hx("f69f2445df4f9b17ad2b417be66c3710")  # 16 bytes

    tests = [
        (b"", "bb1d6929e95937287fa37d129b756746"),                       # 0
        (msg1, "070a16b46b4d4144f79bdd9dd04a287c"),                     # 16
        (msg1 + msg2, "ce0cbf1738f4df6428b1d93bf12081c9"),              # 32
        (msg1 + msg2 + msg3[:8], "dfa66747de9ae63030ca32611497c827"),   # 40
        (msg1 + msg2 + msg3 + msg4, "51f0bebf7e3b9d92fc49741779363cfe") # 64
    ]

    for m, expected_hex in tests:
        got = aes_cmac(key, m).hex()
        assert got == expected_hex, f"Vector mismatch: got {got}, expected {expected_hex}"
        verify_against_library(key, m)


if __name__ == "__main__":
    self_test()
    print("AES-CMAC OK (vectors + library cross-check passed)")
