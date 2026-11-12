"""GF(2^8) arithmetic for the Reed-Solomon erasure code (FEC backend).

A minimal, numpy-vectorised finite-field layer over GF(256) with the standard
AES polynomial 0x11B.  It provides scalar x vector multiplication (the hot path
for block coding) and matrix inversion, which is enough to build a systematic
Cauchy Reed-Solomon MDS code: any ``k`` of the ``n`` coded blocks reconstruct
the object, which is exactly what a one-way (no-ACK) link needs.
"""
from __future__ import annotations

import numpy as np

_POLY = 0x11B

# log / exp tables over the multiplicative group (generator 3)
_EXP = np.zeros(512, dtype=np.uint16)
_LOG = np.zeros(256, dtype=np.uint16)


def _build_tables() -> None:
    # 0x03 is the primitive element (generator) of GF(2^8)/0x11B; 0x02 is NOT.
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # multiply x by the generator 3:  x*3 = (x*2) XOR x
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= _POLY
        x = x2 ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def mul(a: int, b: int) -> int:
    """Multiply two field elements."""
    if a == 0 or b == 0:
        return 0
    return int(_EXP[_LOG[a] + _LOG[b]])


def inv(a: int) -> int:
    """Multiplicative inverse of a nonzero element."""
    if a == 0:
        raise ZeroDivisionError("inverse of 0 in GF(256)")
    return int(_EXP[255 - _LOG[a]])


def mul_scalar_vec(scalar: int, vec: np.ndarray) -> np.ndarray:
    """Multiply a scalar by a uint8 vector, element-wise, in GF(256)."""
    if scalar == 0:
        return np.zeros_like(vec)
    out = np.zeros_like(vec)
    nz = vec != 0
    out[nz] = _EXP[_LOG[scalar] + _LOG[vec[nz]]].astype(vec.dtype)
    return out


def matmul(mat: np.ndarray, blocks: np.ndarray) -> np.ndarray:
    """GF(256) product of an (r x k) matrix by a (k x S) block matrix -> (r x S)."""
    r, k = mat.shape
    S = blocks.shape[1]
    out = np.zeros((r, S), dtype=np.uint8)
    for i in range(r):
        acc = np.zeros(S, dtype=np.uint8)
        for j in range(k):
            c = int(mat[i, j])
            if c:
                acc ^= mul_scalar_vec(c, blocks[j])
        out[i] = acc
    return out


def mat_inv(mat: np.ndarray) -> np.ndarray:
    """Invert a square matrix over GF(256) via Gauss-Jordan elimination."""
    n = mat.shape[0]
    a = mat.astype(np.uint8).copy()
    inv_m = np.eye(n, dtype=np.uint8)
    for col in range(n):
        # find pivot
        piv = col
        while piv < n and a[piv, col] == 0:
            piv += 1
        if piv == n:
            raise np.linalg.LinAlgError("singular matrix over GF(256)")
        if piv != col:
            a[[col, piv]] = a[[piv, col]]
            inv_m[[col, piv]] = inv_m[[piv, col]]
        # normalise pivot row
        pinv = inv(int(a[col, col]))
        a[col] = mul_scalar_vec(pinv, a[col])
        inv_m[col] = mul_scalar_vec(pinv, inv_m[col])
        # eliminate other rows
        for row in range(n):
            if row == col:
                continue
            factor = int(a[row, col])
            if factor:
                a[row] ^= mul_scalar_vec(factor, a[col])
                inv_m[row] ^= mul_scalar_vec(factor, inv_m[col])
    return inv_m


def cauchy_matrix(rows: int, k: int) -> np.ndarray:
    """A rows x k Cauchy matrix over GF(256) (all square submatrices invertible).

    x_i are drawn from [0, rows), y_j from [rows, rows+k); the sets are disjoint
    so every x_i XOR y_j is nonzero, giving a well-defined super-regular matrix.
    """
    if rows + k > 256:
        raise ValueError("Cauchy matrix needs rows + k <= 256")
    m = np.zeros((rows, k), dtype=np.uint8)
    for i in range(rows):
        for j in range(k):
            xi = i
            yj = rows + j
            m[i, j] = inv(xi ^ yj)
    return m
