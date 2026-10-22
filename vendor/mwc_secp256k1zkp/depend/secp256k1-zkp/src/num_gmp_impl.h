/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_NUM_REPR_IMPL_H
#define SECP256K1_NUM_REPR_IMPL_H

#include <string.h>
#include <stdlib.h>
#include <gmp.h>

#include "util.h"
#include "num.h"

static void secp256k1_num_sanity(const secp256k1_num *a, int * err) {
    if (*err)
        return;
    *err = (a==NULL) || (a->limbs > 2 * NUM_LIMBS) || !(a->limbs == 1 || (a->limbs > 1 && a->data[a->limbs-1] != 0));
}

static void secp256k1_num_copy(secp256k1_num *r, const secp256k1_num *a) {
    *r = *a;
}

#define SECP256K1_NUM_GET_BIN_TMP_SIZE (((2 * NUM_LIMBS * GMP_NUMB_BITS) + 7) / 8 + 1)
#define SECP256K1_NUM_SET_BIN_TMP_LIMBS (2 * NUM_LIMBS + 1)

static void secp256k1_num_get_bin(unsigned char *r, unsigned int rlen, const secp256k1_num *a, int * err) {
    unsigned char tmp[SECP256K1_NUM_GET_BIN_TMP_SIZE];
    int len = 0;
    int shift = 0;

    secp256k1_num_sanity(a, err);
    if (*err)
        return;

    if (a->limbs>1 || a->data[0] != 0) {
        len = mpn_get_str(tmp, 256, (mp_limb_t*)a->data, a->limbs);
    }
    while (shift < len && tmp[shift] == 0) shift++;
    *err = !(len-shift <= (int)rlen);
    if (*err)
        return;

    memset(r, 0, rlen - len + shift);
    if (len > shift) {
        memcpy(r + rlen - len + shift, tmp + shift, len - shift);
    }
    secp256k1_memclear(tmp, sizeof(tmp));
}

static void secp256k1_num_set_bin(secp256k1_num *r, const unsigned char *a, unsigned int alen, int * err) {
    int len;
    size_t max_limbs;
    mp_limb_t tmp[SECP256K1_NUM_SET_BIN_TMP_LIMBS];

    if (*err)
        return;

    if (! (alen > 0 && alen <= 64)) {
        *err = 1;
        return;
    }

    max_limbs = ((8 * (size_t)alen) + GMP_NUMB_BITS - 1) / GMP_NUMB_BITS;
    if (max_limbs > NUM_LIMBS*2) {
        *err = 1;
        return;
    }

    len = mpn_set_str(tmp, a, alen, 256);
    if (len == 0) {
        r->data[0] = 0;
        len = 1;
    } else {
        if ((size_t)len > NUM_LIMBS*2) {
            *err = 1;
            secp256k1_memclear(tmp, sizeof(tmp));
            return;
        }
        memcpy(r->data, tmp, len * sizeof(tmp[0]));
    }
    secp256k1_memclear(tmp, sizeof(tmp));
    VERIFY_CHECK(len <= NUM_LIMBS*2);
    r->limbs = len;
    r->neg = 0;
    while (r->limbs > 1 && r->data[r->limbs-1]==0) {
        r->limbs--;
    }
}

static void secp256k1_num_add_abs(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b, int * err) {
    const secp256k1_num *x = a;
    const secp256k1_num *y = b;
    mp_limb_t c;

    if (*err)
        return;

    /* mpn_add requires x->limbs >= y->limbs */
    if (x->limbs < y->limbs) {
        x = b;
        y = a;
    }

    if (! (x->limbs <= 2 * NUM_LIMBS && x->limbs + 1 <= 2 * NUM_LIMBS)) {
        *err = 1;
        return;
    }
    VERIFY_CHECK(y->limbs <= x->limbs);

    c = mpn_add(r->data, x->data, x->limbs, y->data, y->limbs);

    r->limbs = x->limbs;
    if (c != 0) {
        r->data[r->limbs++] = c;
    }
}

static void secp256k1_num_sub_abs(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b, int * err) {
    mp_limb_t c;

    if (*err)
        return;

    /* mpn_sub requires s1n >= s2n */
    if (a->limbs < b->limbs) {
        *err = 1;
        return;
    }

    /* Limb counts must fit in the backing storage */
    if (!(a->limbs >= 1 && b->limbs >= 1 && a->limbs <= 2 * NUM_LIMBS && b->limbs <= 2 * NUM_LIMBS)) {
        *err = 1;
        return;
    }

    c = mpn_sub(r->data, a->data, a->limbs, b->data, b->limbs);
    /*  Expected that a <= b.
     *  Note, if this failed, r will be changed, so caller must check err flag and drop it */
    if (c != 0) {
        *err = 1;
        return;
    }

    r->limbs = a->limbs;
    while (r->limbs > 1 && r->data[r->limbs-1]==0) {
        r->limbs--;
    }
}

static void secp256k1_num_mod(secp256k1_num *r, const secp256k1_num *m, int * err) {

    secp256k1_num_sanity(r, err);
    secp256k1_num_sanity(m, err);
    if (*err)
        return;

    /* In-place divisor/remainder aliasing is not allowed here. */
    if(r == m) {
        *err = 1;
        return;
    }

    /* Limb counts must fit the fixed backing arrays. */
    if (! (r->limbs >= 1 && m->limbs >= 1)) {
        *err = 1;
        return;
    }

    /* Division by zero must never happen. */
    if (m->limbs == 1 && m->data[0] == 0) {
        *err = 1;
        return;
    }

    /*
     * GMP division requires the most significant limb of the divisor
     * to be non-zero. For normalized secp256k1_num this should already hold.
     */
    if (m->data[m->limbs - 1] == 0) {
        *err = 1;
        return;
    }

    if (r->limbs >= m->limbs) {
        mp_limb_t t[2 * NUM_LIMBS];

        /*
         * mpn_tdiv_qr writes:
         *   - quotient to t
         *   - remainder to r->data
         *
         * Quotient size is nn - dn + 1 limbs, so t must be large enough.
         */
        if (r->limbs - m->limbs + 1 > 2 * NUM_LIMBS) {
            *err = 1;
            return;
        }

        mpn_tdiv_qr(t, r->data, 0, r->data, r->limbs, m->data, m->limbs);

        secp256k1_memclear(t, sizeof(t));

        /*
         * Remainder is always strictly less than divisor, so it uses
         * at most m->limbs limbs.
         */
        r->limbs = m->limbs;
        while (r->limbs > 1 && r->data[r->limbs - 1] == 0) {
            r->limbs--;
        }
    }

    /* canonicalize zero so the next step will work right */
    if (r->limbs == 1 && r->data[0] == 0) {
        r->neg = 0;
    }

    /*
     * Convert negative remainder representation into the canonical
     * non-negative residue class.
     */
    if (r->neg && (r->limbs > 1 || r->data[0] != 0)) {
        secp256k1_num tmp;

        /*
         * Since 0 < r < m here, m - r cannot borrow.
         * Copy r first so mpn_sub does not see a partially overlapping
         * subtrahend when the result grows to m->limbs.
         */
        secp256k1_num_copy(&tmp, r);
        secp256k1_num_sub_abs(r, m, &tmp, err);
        secp256k1_memclear(&tmp, sizeof(tmp));
        if (*err)
            return;
        r->neg = 0;
    }
}

/* Note, assuming that all checks are never fail */
static void secp256k1_num_mod_inverse(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *m, int * err) {
    int i;
    /* Allocation 2*NUM_LIMBS instead of NUM_LIMBS+1 for sanity checking correctness
     * mpn_gcdext needs room for VN+1 limbs in the coefficient output.
     * Keep that scratch separate from r->data, which stores only 2*NUM_LIMBS limbs.
     */
    mp_limb_t g[2*NUM_LIMBS];
    mp_limb_t s[2*NUM_LIMBS + 1];
    mp_limb_t u[2*NUM_LIMBS];
    mp_limb_t v[2*NUM_LIMBS];
    mp_size_t sn;
    mp_size_t gn;
    mp_size_t s_limbs;

    secp256k1_num_sanity(a, err);
    secp256k1_num_sanity(m, err);

    if (*err)
        return;

    /* Basic representation safety. */
    if (r == NULL) {
        *err = 1;
        return;
    }

    if (r==m) {
        *err = 1;
        return;
    }

    if (a->limbs < 1 || m->limbs < 1) {
        *err = 1;
        return;
    }

    /* This primitive only supports non-negative inputs. */
    if (a->neg || m->neg) {
        *err = 1;
        return;
    }

    /* Modulus must be non-zero and normalized. */
    if (m->limbs == 1 && m->data[0] == 0) {
        *err = 1;
        return;
    }
    if (!(m->data[m->limbs - 1] != 0)) {
        *err = 1;
        return;
    }

    /*
     * This implementation pads/truncates a into u[0..m->limbs-1], so it only
     * makes sense when |a| <= m in limb width. If your callers may pass larger
     * a, reduce first or assert the precondition explicitly.
     */
    if (a->limbs > m->limbs) {
        *err = 1;
        return;
    }

    /** mpn_gcdext computes: (G,S) = gcdext(U,V), where
     *  * G = gcd(U,V)
     *  * G = U*S + V*T
     *  * U has equal or more limbs than V, and V has no padding
     *  If we set U to be (a padded version of) a, and V = m:
     *    G = a*S + m*T
     *    G = a*S mod m
     *  Assuming G=1:
     *    S = 1/a mod m
     */
    for (i = 0; i < m->limbs; i++) {
        u[i] = (i < a->limbs) ? a->data[i] : 0;
        v[i] = m->data[i];
    }
    /*
     * Clear the unused tail as hygiene. Not strictly required for correctness
     * because only m->limbs limbs are passed, but it avoids stale-data hazards.
     */
    for (; i < 2*NUM_LIMBS; i++) {
        u[i] = 0;
        v[i] = 0;
        g[i] = 0;
    }

    sn = m->limbs + 1;
    gn = mpn_gcdext(g, s, &sn, u, m->limbs, v, m->limbs);
    /* Inverse exists only if gcd(a, m) == 1. */
    if (gn != 1 || g[0] != 1) {
        *err = 1;
        return;
    }

    /*
     * The returned coefficient S should fit within the modulus width.
     * sn may be negative; its absolute value is the limb count of |S|.
     */
    if (sn < -(mp_size_t)m->limbs || sn > (mp_size_t)m->limbs) {
        *err = 1;
        return;
    }

    if (sn == 0) {
        *err = 1;
        return;
    }

    s_limbs = (sn < 0) ? -sn : sn;
    if (sn < 0) {
        mp_limb_t c;

        /*
         * Convert a negative coefficient into the canonical
         * non-negative residue class m - |S|.
         *
         * mpn_sub requires first operand limb count >= second operand limb count.
         */
        if (s_limbs > m->limbs) {
            *err = 1;
            return;
        }

        /*
         * Use s directly as the subtrahend so mpn_sub does not see
         * a partially overlapping source/destination region.
         *
         * mpn_sub return borrow, either 0 or 1.
         */
        c = mpn_sub(r->data, m->data, m->limbs, s, s_limbs);
        if (c != 0) {
            *err = 1;
            return;
        }

        r->limbs = m->limbs;
        while (r->limbs > 1 && r->data[r->limbs - 1] == 0) {
            r->limbs--;
        }
    } else {
        /*
         * Positive coefficient; it already represents the canonical inverse.
         * Normalize the reported limb count.
         */
        memcpy(r->data, s, s_limbs * sizeof(s[0]));
        r->limbs = s_limbs;
        while (r->limbs > 1 && r->data[r->limbs - 1] == 0) {
            r->limbs--;
        }
    }
    r->neg = 0;

    secp256k1_memclear(g, sizeof(g));
    secp256k1_memclear(s, sizeof(s));
    secp256k1_memclear(u, sizeof(u));
    secp256k1_memclear(v, sizeof(v));
}

static int secp256k1_num_jacobi(const secp256k1_num *a, const secp256k1_num *b, int * err) {
    int ret;
    mpz_t ga, gb;
    /* Note: caller should guarantee that params are meet expectations  */
    secp256k1_num_sanity(a, err);
    secp256k1_num_sanity(b, err);

    if (*err)
        return 0;

    /* Internal representation bounds. */
    if (! (a->limbs >= 1 && b->limbs >= 1)) {
        *err = 1;
        return 0;
    }

    /*
     * Jacobi(a, b) requires b to be a positive odd integer.
     * Zero or negative modulus is invalid.
     */
    if (!(!b->neg && (b->limbs > 0) && (b->data[0] & 1))) {
        *err = 1;
        return 0;
    }

    /*
     * Normalized representation should not have a zero high limb.
     * Make that invariant explicit before import.
     */
    if (!(a->data[a->limbs - 1] != 0 || (a->limbs == 1 && a->data[0] == 0))) {
        *err = 1;
        return 0;
    }
    if (b->data[b->limbs - 1] == 0) {
        *err = 1;
        return 0;
    }

    mpz_inits(ga, gb, NULL);

    mpz_import(gb, b->limbs, -1, sizeof(mp_limb_t), 0, 0, b->data);
    mpz_import(ga, a->limbs, -1, sizeof(mp_limb_t), 0, 0, a->data);
    if (a->neg) {
        mpz_neg(ga, ga);
    }

    ret = mpz_jacobi(ga, gb);

    mpz_clears(ga, gb, NULL);

    return ret;
}

static int secp256k1_num_is_one(const secp256k1_num *a) {
    return (a->limbs == 1 && a->data[0] == 1 && !a->neg);
}

static int secp256k1_num_is_zero(const secp256k1_num *a) {
    return (a->limbs == 1 && a->data[0] == 0);
}

static int secp256k1_num_is_neg(const secp256k1_num *a) {
    return (a->limbs > 1 || a->data[0] != 0) && a->neg;
}

static int secp256k1_num_cmp(const secp256k1_num *a, const secp256k1_num *b, int * err) {
    secp256k1_num_sanity(a, err);
    secp256k1_num_sanity(b, err);

    if (*err)
        return 0;

    if (!(a->limbs >= 1 && b->limbs >= 1)) {
        *err = 1;
        return 0;
    }

    if (a->limbs > b->limbs) {
        return 1;
    }
    if (a->limbs < b->limbs) {
        return -1;
    }
    return mpn_cmp(a->data, b->data, a->limbs);
}

static int secp256k1_num_eq(const secp256k1_num *a, const secp256k1_num *b, int * err) {
    secp256k1_num_sanity(a, err);
    secp256k1_num_sanity(b, err);

    if (*err)
        return 0;

    if (!(a->limbs >= 1 && b->limbs >= 1)) {
        *err = 1;
        return 0;
    }

    if (a->limbs > b->limbs) {
        return 0;
    }
    if (a->limbs < b->limbs) {
        return 0;
    }
    if ((a->neg && !secp256k1_num_is_zero(a)) != (b->neg && !secp256k1_num_is_zero(b))) {
        return 0;
    }
    return mpn_cmp(a->data, b->data, a->limbs) == 0;
}

static void secp256k1_num_subadd(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b, int bneg, int * err) {
    int cmp;

    secp256k1_num_sanity(a, err);
    secp256k1_num_sanity(b, err);

    if (*err)
        return;

    if (r==NULL) {
        *err = 1;
        return;
    }
    if (!(a->limbs >= 1 && b->limbs >= 1)) {
        *err = 1;
        return;
    }

    bneg = !!bneg;

    if (!(b->neg ^ bneg ^ a->neg)) { /* a and b have the same sign */
        r->neg = a->neg;

        if (a->limbs >= b->limbs) {
            secp256k1_num_add_abs(r, a, b, err);
        } else {
            secp256k1_num_add_abs(r, b, a, err);
        }
        if (*err)
            return;
    } else {
        cmp = secp256k1_num_cmp(a, b, err);
        if (*err)
            return;

        if (cmp > 0) {
            r->neg = a->neg;
            secp256k1_num_sub_abs(r, a, b, err);
        } else if (cmp < 0) {
            r->neg = b->neg ^ bneg;
            secp256k1_num_sub_abs(r, b, a, err);
        } else {
            /* exact cancellation: result is canonical +0 */
            r->data[0] = 0;
            r->limbs = 1;
            r->neg = 0;
        }
        if (*err)
            return;
    }

    /* Canonicalize zero sign defensively. */
    if (r->limbs == 1 && r->data[0] == 0) {
        r->neg = 0;
    }
}

static void secp256k1_num_add(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b, int * err) {
    /* Note: caller should guarantee that params are meet expectations  */
    secp256k1_num_subadd(r, a, b, 0, err);
}

static void secp256k1_num_sub(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b, int * err) {
    /* Note: caller should guarantee that params are meet expectations  */
    secp256k1_num_subadd(r, a, b, 1, err);
}

static void secp256k1_num_mul(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b, int * err) {
    mp_limb_t tmp[2*NUM_LIMBS+1];
    /* Note: caller should guarantee that params are meet expectations  */
    secp256k1_num_sanity(a, err);
    secp256k1_num_sanity(b, err);

    if (*err)
        return;

    if (!(a->limbs >= 1 && b->limbs >= 1)) {
        *err = 1;
        return;
    }

    /*
     * mpn_mul writes an + bn limbs.
     * tmp must be large enough, and the final stored result must fit r->data.
     */
    if (a->limbs + b->limbs > 2*NUM_LIMBS+1) {
        *err = 1;
        return;
    }

    if ((a->limbs==1 && a->data[0]==0) || (b->limbs==1 && b->data[0]==0)) {
        r->limbs = 1;
        r->neg = 0;
        r->data[0] = 0;
        return;
    }

    /*
     * GMP expects the first operand to have at least as many limbs as the second
     * for some low-level routines. Keep the larger one first.
     */
    if (a->limbs >= b->limbs) {
        mpn_mul(tmp, a->data, a->limbs, b->data, b->limbs);
    } else {
        mpn_mul(tmp, b->data, b->limbs, a->data, a->limbs);
    }
    r->limbs = a->limbs + b->limbs;
    /* Normalize away a zero high limb if present. */
    if (r->limbs > 1 && tmp[r->limbs - 1]==0) {
        r->limbs--;
    }
    if (r->limbs > 2*NUM_LIMBS) {
        *err = 1;
        return;
    }
    mpn_copyi(r->data, tmp, r->limbs);
    r->neg = a->neg ^ b->neg;

    if (r->limbs == 1 && r->data[0] == 0) {
        r->neg = 0;
    }

    secp256k1_memclear(tmp, sizeof(tmp));
}

static void secp256k1_num_shift(secp256k1_num *r, int bits, int * err) {
    int limb_shift;
    int bit_shift;

    secp256k1_num_sanity(r, err);
    if (*err)
        return;

    if (!(r->limbs >= 1 && bits >= 0)) {
        *err = 1;
        return;
    }

    if (bits == 0) {
        return;
    }

    limb_shift = bits / GMP_NUMB_BITS;
    bit_shift = bits % GMP_NUMB_BITS;

    /*
     * If shifting by at least the full current width, the result is zero.
     */
    if (limb_shift >= r->limbs) {
        r->data[0] = 0;
        r->limbs = 1;
        r->neg = 0;
        return;
    }

    /*
     * First shift within limbs. mpn_rshift requires 1 <= count < GMP_NUMB_BITS.
     */
    if (bit_shift != 0) {
        mpn_rshift(r->data, r->data, r->limbs, bit_shift);
    }

    /*
     * Then shift by whole limbs.
     */
    if (limb_shift > 0) {
        int i;
        for (i = 0; i < r->limbs; i++) {
            int index = i + limb_shift;
            if (index < r->limbs) {
                r->data[i] = r->data[index];
            } else {
                r->data[i] = 0;
            }
        }
    }
    while (r->limbs > 1 && r->data[r->limbs - 1] == 0) {
        r->limbs--;
    }
    if (r->limbs == 1 && r->data[0] == 0) {
        r->neg = 0;
    }
}

static void secp256k1_num_negate(secp256k1_num *r) {
    if (secp256k1_num_is_zero(r)) {
        r->neg = 0;
    }
    else {
        r->neg ^= 1;
    }
}

#endif /* SECP256K1_NUM_REPR_IMPL_H */
