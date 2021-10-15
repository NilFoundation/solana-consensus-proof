## Merkle Tree Circuit {#circuit_merkle}
#### Introduction

Merkle Tree generation for set \f$\{H_{B_{n_1}}, ..., H_{B_{n_2}}\}\f$.
Let \f$k = \lceil \log(n_2 - n_1) \rceil\f$

1. \f$n = n_2 - n_1\f$
2. \f$2^k = n\f$
3. for \f$i\f$ from \f$0\f$ to \f$n - 1\f$:
   1. \f$T_i = H_i\f$ // just notation for simplicity, not a real part of the circuit
4. for \f$i\f$ from \f$0\f$ to \f$k - 1\f$:
   1. for \f$j\f$ from \f$0\f$ to \f$(n - 1) / 2\f$:
      1. \f$T'_i = \texttt{hash}(T_{2 \cdot  i}, T_{2 \cdot i + 1})\f$. // see Section \ref{section:poseidon}
   2. \f$n = \frac{n}{2}\f$
   3. for \f$j\f$ from \f$0\f$ to \f$n - 1\f$:
      1. \f$T_i = T'_i\f$. // just notation for simplicity, not a real part of the circuit