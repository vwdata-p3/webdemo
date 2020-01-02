
// -- crypto_(u)int{32,64}.h --

typedef unsigned int crypto_uint32;
typedef int crypto_int32;
typedef int64_t crypto_int64;
typedef uint64_t crypto_uint64;

// -- fe25519.h --

typedef struct
{
  crypto_int32 v[10];
}
fe25519;

extern const fe25519 fe25519_zero;
extern const fe25519 fe25519_one;
extern const fe25519 fe25519_two;

extern const fe25519 fe25519_sqrtm1;
extern const fe25519 fe25519_msqrtm1;
extern const fe25519 fe25519_m1;

//void fe25519_freeze(fe25519 *r);

void fe25519_unpack(fe25519 *r, const unsigned char x[32]);

void fe25519_pack(unsigned char r[32], const fe25519 *x);

int fe25519_iszero(const fe25519 *x);

int fe25519_isone(const fe25519 *x);

int fe25519_isnegative(const fe25519 *x);

int fe25519_iseq(const fe25519 *x, const fe25519 *y);

int fe25519_iseq_vartime(const fe25519 *x, const fe25519 *y);

void fe25519_cmov(fe25519 *r, const fe25519 *x, unsigned char b);

void fe25519_setone(fe25519 *r);

void fe25519_setzero(fe25519 *r);

void fe25519_neg(fe25519 *r, const fe25519 *x);

unsigned char fe25519_getparity(const fe25519 *x);

void fe25519_add(fe25519 *r, const fe25519 *x, const fe25519 *y);

void fe25519_double(fe25519 *r, const fe25519 *x);
void fe25519_triple(fe25519 *r, const fe25519 *x);

void fe25519_sub(fe25519 *r, const fe25519 *x, const fe25519 *y);

void fe25519_mul(fe25519 *r, const fe25519 *x, const fe25519 *y);

void fe25519_square(fe25519 *r, const fe25519 *x);
void fe25519_square_double(fe25519 *h,const fe25519 *f);

void fe25519_invert(fe25519 *r, const fe25519 *x);

void fe25519_pow2523(fe25519 *r, const fe25519 *x);

void fe25519_invsqrt(fe25519 *r, const fe25519 *x);

int fe25519_invsqrti(fe25519 *r, const fe25519 *x);

int fe25519_sqrti(fe25519 *r, const fe25519 *x);

void fe25519_sqrt(fe25519 *r, const fe25519 *x);

//void fe25519_print(const fe25519 *x);


// -- scalar.h --
#define GROUP_SCALAR_PACKEDBYTES 32

typedef struct 
{
  uint32_t v[32]; 
}
group_scalar;

extern const group_scalar group_scalar_zero;
extern const group_scalar group_scalar_one;

int group_scalar_unpack(group_scalar *r, const unsigned char x[GROUP_SCALAR_PACKEDBYTES]);
void group_scalar_pack(unsigned char s[GROUP_SCALAR_PACKEDBYTES], const group_scalar *r);

void group_scalar_setzero(group_scalar *r);
void group_scalar_setone(group_scalar *r);
//void group_scalar_setrandom(group_scalar *r); // Removed to avoid dependency on platform specific randombytes
void group_scalar_add(group_scalar *r, const group_scalar *x, const group_scalar *y);
void group_scalar_sub(group_scalar *r, const group_scalar *x, const group_scalar *y);
void group_scalar_negate(group_scalar *r, const group_scalar *x);
void group_scalar_mul(group_scalar *r, const group_scalar *x, const group_scalar *y);
void group_scalar_square(group_scalar *r, const group_scalar *x);
void group_scalar_invert(group_scalar *r, const group_scalar *x);

int  group_scalar_isone(const group_scalar *x);
int  group_scalar_iszero(const group_scalar *x);
int  group_scalar_equals(const group_scalar *x,  const group_scalar *y);


// Additional functions, not required by API
int  scalar_tstbit(const group_scalar *x, const unsigned int pos);
int  scalar_bitlen(const group_scalar *x);
void scalar_window3(signed char r[85], const group_scalar *x);
void scalar_window5(signed char r[51], const group_scalar *s);
void scalar_slide(signed char r[256], const group_scalar *s, int swindowsize);

void scalar_from64bytes(group_scalar *r, const unsigned char h[64]);


// -- group.h --

#define GROUP_GE_PACKEDBYTES 32

typedef struct
{	
	fe25519 x;
	fe25519 y;
	fe25519 z;
	fe25519 t;
} group_ge;

extern const group_ge group_ge_base;
extern const group_ge group_ge_neutral;

// Constant-time versions
int  group_ge_unpack(group_ge *r, const unsigned char x[GROUP_GE_PACKEDBYTES]);
void group_ge_pack(unsigned char r[GROUP_GE_PACKEDBYTES], const group_ge *x);

void group_ge_add(group_ge *r, const group_ge *x, const group_ge *y);
void group_ge_double(group_ge *r, const group_ge *x);
void group_ge_negate(group_ge *r, const group_ge *x);
void group_ge_scalarmult(group_ge *r, const group_ge *x, const group_scalar *s);
void group_ge_scalarmult_base(group_ge *r, const group_scalar *s);
void group_ge_multiscalarmult(group_ge *r, const group_ge *x, const group_scalar *s, unsigned long long xlen);
int  group_ge_equals(const group_ge *x, const group_ge *y);
int  group_ge_isneutral(const group_ge *x);

// Non-constant-time versions
void group_ge_add_publicinputs(group_ge *r, const group_ge *x, const group_ge *y);
void group_ge_double_publicinputs(group_ge *r, const group_ge *x);
void group_ge_negate_publicinputs(group_ge *r, const group_ge *x);
void group_ge_scalarmult_publicinputs(group_ge *r, const group_ge *x, const group_scalar *s);
void group_ge_scalarmult_base_publicinputs(group_ge *r, const group_scalar *s);
void group_ge_multiscalarmult_publicinputs(group_ge *r, const group_ge *x, const group_scalar *s, unsigned long long xlen);
int  group_ge_equals_publicinputs(const group_ge *x, const group_ge *y);
int  group_ge_isneutral_publicinputs(const group_ge *x);

// Not required by API
//void ge_print(const group_ge *x);

// -- end of the code based on the panda library --
//
void group_ge_from_jacobi_quartic(group_ge *x, 
		const fe25519 *s, const fe25519 *t);
void group_ge_elligator(group_ge *x, const fe25519 *r0);

void fe25519s_pack(unsigned char y[], const fe25519 x[], int n);
void fe25519s_unpack(fe25519 y[], const unsigned char x[], int n);

void group_scalars_pack(unsigned char y[], const group_scalar x[], int n);
void group_scalars_unpack(group_scalar y[], const unsigned char x[], 
		int error_codes[], int n);

void group_ges_pack(unsigned char y[], const group_ge x[], int n);
void group_ges_unpack(group_ge y[], const unsigned char x[], 
		int error_codes[], int n);

void group_ges_scalarmult_base(group_ge y[], const group_scalar x[], int n);
void group_ges_elligator(group_ge y[], const fe25519 x[], int n);

#define ELGAMAL_TRIPLE_PACKEDBYTES 96

typedef struct
{
	group_ge blinding;
	group_ge core;
	group_ge target;
} elgamal_triple;

int elgamal_triple_unpack(elgamal_triple *r, 
		const unsigned char x[ELGAMAL_TRIPLE_PACKEDBYTES]);
void elgamal_triple_pack(unsigned char r[ELGAMAL_TRIPLE_PACKEDBYTES], 
		const elgamal_triple *x);

void elgamal_triple_decrypt(group_ge *y, const elgamal_triple *x,
		const group_scalar *key);
void elgamal_triple_encrypt(elgamal_triple *y, const group_ge *x,
		const group_ge *key, const group_scalar *r);

void elgamal_triple_rsk(elgamal_triple *y, const elgamal_triple *x,
		const group_scalar *k, const group_scalar *s,
		const group_scalar *r);

void elgamal_triples_unpack(elgamal_triple r[], const unsigned char x[],
		int error_codes[], int n);
void elgamal_triples_pack(unsigned char r[], const elgamal_triple x[], int n);

void elgamal_triples_rsk(
		group_ge blinding_out[], group_ge core_out[],
		const group_ge blinding_in[], const group_ge core_in[],
		group_ge *target_out, const group_ge *target_in,
		const group_scalar *k, const group_scalar *s, 
		const group_scalar r[], int n);

void elgamal_triples_decrypt(group_ge y[], const elgamal_triple x[],
		const group_scalar *key, int n);
void elgamal_triples_encrypt(elgamal_triple y[], const group_ge x[],
		const group_ge *key, const group_scalar r[], int n);

// given scalar x fills the array y such that y[i] = B x**(2**i).
void component_public_part(group_ge y[253], const group_scalar *x);


/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2013, Con Kolivas <kernel@kolivas.org>
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

//#include "config.h"
//#include "miner.h"

//#ifndef SHA2_H
//#define SHA2_H

#define SHA256_DIGEST_SIZE 32 // ( 256 / 8)
#define SHA256_BLOCK_SIZE 64 // ( 512 / 8)

// [ moved some #defines to ristretto.c that cffi can't deal with ]

typedef struct {
    unsigned int tot_len;
    unsigned int len;
    unsigned char block[128]; // 2 * SHA256_BLOCK_SIZE
    uint32_t h[8];
} sha256_ctx;

extern uint32_t sha256_k[64];

void sha256_init(sha256_ctx * ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len);
void sha256_final(sha256_ctx *ctx, unsigned char *digest);
void sha256(const unsigned char *message, unsigned int len,
            unsigned char *digest);

//#endif /* !SHA2_H */

// end of C. Kolivas' sha256 implementation

#define DHT_PROOF_PACKEDBYTES 96

void dht_proof_create( 
                unsigned char x[96], 
                const group_scalar *a, 
                const unsigned char a_packed[32], 
                const unsigned char A_packed[32], 
                const group_scalar *m, // either m or M must be non-NULL 
                const group_ge *M, 
                const unsigned char M_packed[32], 
                const group_ge *N, 
                const unsigned char N_packed[32]);

typedef struct {
	int number_of_factors; // =: N
	unsigned char *partial_products; // size:  32 * max(N-2,0)
	unsigned char *dht_proofs; // size:  96 * max(N-1,0)
} product_proof;

int dht_proof_is_valid_for(
		const unsigned char x[96],
		const group_ge *A,
		const group_ge *M,
		const group_ge *N,
		const unsigned char A_packed[32],
		const unsigned char M_packed[32],
		const unsigned char N_packed[32]);

void product_proof_create(
		product_proof *y, // y->number_of_factors should be set
				  // and y->{partial_products,dht_proofs}
				  // should be preallocated.
		const group_scalar factors_scalar[],
		const unsigned char factors_scalars_packed[],
		const unsigned char factors_packed[]);

int product_proof_is_valid_for(
		const product_proof *y,
		const group_ge factors[],
		const unsigned char factors_packed[],
		const group_ge *product,
		const unsigned char product_packed[]);

typedef struct {
	product_proof product_proof;
	unsigned char component[32];
} certified_component;

void certified_component_create(
		certified_component *y, // y->product_proof should already be
					// be prepared as for 
					// product_proof_create
		const unsigned char base_powers_packed[8096], // 253 * 32
		const group_scalar *base_scalar,
		const group_scalar *exponent);

int certified_component_is_valid_for(
		const certified_component *y,
		const unsigned char base_powers_packed[8096],
		const group_scalar *exponent);

