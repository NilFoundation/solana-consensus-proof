## Ed25519 Circuit {#circuit_eddsa}
#### Introduction

To verify a signature \f$(R,s)\f$ on message \f$M\f$ using public key \f$A\f$ and a generator \f$B\f$ do:
1. Prove that \f$s\f$ in the defined range.
2. \f$k ==\f$ SHA-512\f$(data||R||A||M)\f$ //See section \ref{sha512}
3. \f$8sB ?=? 8R + 8kA\f$ //See section \ref{ellcurve}

#### Elliptic Curve Arithmetics
Variable-base scalar multiplication circuit per bit \f$b\f$:
1. \f$b^2 = b\f$
2. \f$(y_1)  (2b - 1) = (y_2)\f$
3. \f$ (x_2 - x_3)  (\lambda_1) = (y_2 - y_3)\f$ 
4. \f$(B\lambda_1)  (\lambda_1) = (A + x_3 + x_2 + x_4)\f$ 
5. \f$(x_3 - x_4)  (\lambda_1 + \lambda_2) = (2y_3)\f$ 
6. \f$(B\lambda_2)  (\lambda_2) = (A + x_4 + x_3 + x_5)\f$
7. \f$ (x_3 - x_5)  (\lambda_2) = (y_5+ y_3)\f$

#### EC Point Addition Circuit

1. \f$(x_2 - x_1)  (y_3 + y_1) - (y_1 - y_2)  (x_1 - x_3) \f$
2. \f$ (x_1 + x_2 + x_3)  (x_1 - x_3)  (x_1 - x_3) - (y_3 + y_1)  (y_3 + y_1)\f$