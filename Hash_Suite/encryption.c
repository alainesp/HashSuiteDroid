// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2012 by Alain Espinosa

#include "common.h"

///////////////////////////////////////////////////////////////////////////////////////////
// Public key implementation
///////////////////////////////////////////////////////////////////////////////////////////
/*
version 20081011
Matthew Dempsky
Public domain.
Derived from public domain code by D. J. Bernstein.
*/
PRIVATE const unsigned char base[32] = {9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

PRIVATE void add(uint32_t out[32], const uint32_t a[32], const uint32_t b[32])
{
  uint32_t j;
  uint32_t u;
  u = 0;
  for (j = 0; j < 31; ++j)
  {
	  u += a[j] + b[j];
	  out[j] = u & 255;
	  u >>= 8; 
  }
  u += a[31] + b[31];
  out[31] = u;
}
PRIVATE void sub(uint32_t out[32],const uint32_t a[32],const uint32_t b[32])
{
  uint32_t j;
  uint32_t u;
  u = 218;
  for (j = 0;j < 31;++j) {
    u += a[j] + 65280 - b[j];
    out[j] = u & 255;
    u >>= 8;
  }
  u += a[31] - b[31];
  out[31] = u;
}
PRIVATE void squeeze(uint32_t a[32])
{
  uint32_t j;
  uint32_t u;
  u = 0;
  for (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u & 127;
  u = 19 * (u >> 7);
  for (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u;
}
PRIVATE void mult(uint32_t out[32],const uint32_t a[32],const uint32_t b[32])
{
  uint32_t i;
  uint32_t j;
  uint32_t u;

  for (i = 0;i < 32;++i) {
    u = 0;
    for (j = 0;j <= i;++j) u += a[j] * b[i - j];
    for (j = i + 1;j < 32;++j) u += 38 * a[j] * b[i + 32 - j];
    out[i] = u;
  }
  squeeze(out);
}
PRIVATE void mult121665(uint32_t out[32],const uint32_t a[32])
{
  uint32_t j;
  uint32_t u;

  u = 0;
  for (j = 0;j < 31;++j) { u += 121665 * a[j]; out[j] = u & 255; u >>= 8; }
  u += 121665 * a[31]; out[31] = u & 127;
  u = 19 * (u >> 7);
  for (j = 0;j < 31;++j) { u += out[j]; out[j] = u & 255; u >>= 8; }
  u += out[j]; out[j] = u;
}
PRIVATE void square(uint32_t out[32],const uint32_t a[32])
{
  uint32_t i;
  uint32_t j;
  uint32_t u;

  for (i = 0;i < 32;++i)
  {
    u = 0;
    for (j = 0;j < i - j;++j)
		u += a[j] * a[i - j];

    for (j = i + 1;j < i + 32 - j;++j)
		u += 38 * a[j] * a[i + 32 - j];

    u *= 2;
    if ((i & 1) == 0)
	{
      u += a[i / 2] * a[i / 2];
      u += 38 * a[i / 2 + 16] * a[i / 2 + 16];
    }
    out[i] = u;
  }
  squeeze(out);
}
PRIVATE void select_curve(uint32_t p[64],uint32_t q[64],const uint32_t r[64],const uint32_t s[64],uint32_t b)
{
  uint32_t j;
  uint32_t t;
  uint32_t bminus1;

  bminus1 = b - 1;
  for (j = 0;j < 64;++j) {
    t = bminus1 & (r[j] ^ s[j]);
    p[j] = s[j] ^ t;
    q[j] = r[j] ^ t;
  }
}
PUBLIC int crypto_scalarmult_curve25519(unsigned char *shared_key, const unsigned char *secret_key, const unsigned char *public_key)
{
  uint32_t work[96];
  unsigned char e[32];
  uint32_t i;
  uint32_t xzm1[64];
  uint32_t xzm[64];
  uint32_t xzmb[64];
  uint32_t xzm1b[64];
  uint32_t xznb[64];
  uint32_t xzn1b[64];
  uint32_t a0[64];
  uint32_t a1[64];
  uint32_t b0[64];
  uint32_t b1[64];
  uint32_t c1[64];
  uint32_t r[32];
  uint32_t s[32];
  uint32_t t[32];
  uint32_t u[32];
  uint32_t b;
  int pos;

  for (i = 0;i < 32;++i)
	  e[i] = secret_key[i];

  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;

  for (i = 0;i < 32;++i)
	  work[i] = public_key[i];

  //mainloop(work,e);
  for (i = 0;i < 32;++i) xzm1[i] = work[i];
  xzm1[32] = 1;
  for (i = 33;i < 64;++i) xzm1[i] = 0;

  xzm[0] = 1;
  for (i = 1;i < 64;++i) xzm[i] = 0;

  for (pos = 254;pos >= 0;--pos)
  {
    b = e[pos / 8] >> (pos & 7);
    b &= 1;
    select_curve(xzmb,xzm1b,xzm,xzm1,b);
    add(a0,xzmb,xzmb + 32);
    sub(a0 + 32,xzmb,xzmb + 32);
    add(a1,xzm1b,xzm1b + 32);
    sub(a1 + 32,xzm1b,xzm1b + 32);
    square(b0,a0);
    square(b0 + 32,a0 + 32);
    mult(b1,a1,a0 + 32);
    mult(b1 + 32,a1 + 32,a0);
    add(c1,b1,b1 + 32);
    sub(c1 + 32,b1,b1 + 32);
    square(r,c1 + 32);
    sub(s,b0,b0 + 32);
    mult121665(t,s);
    add(u,t,b0);
    mult(xznb,b0,b0 + 32);
    mult(xznb + 32,s,u);
    square(xzn1b,c1);
    mult(xzn1b + 32,r,work);
    select_curve(xzm,xzm1,xznb,xzn1b,b);
  }

  for (i = 0;i < 64;++i) work[i] = xzm[i];
  //end mainloop
  //recip(work + 32,work + 32);
  {
	  uint32_t z2[32];
	  uint32_t z9[32];
	  uint32_t z11[32];
	  uint32_t z2_5_0[32];
	  uint32_t z2_10_0[32];
	  uint32_t z2_20_0[32];
	  uint32_t z2_50_0[32];
	  uint32_t z2_100_0[32];
	  uint32_t t0[32];
	  uint32_t t1[32];

	  /* 2 */ square(z2, work + 32);
	  /* 4 */ square(t1, z2);
	  /* 8 */ square(t0, t1);
	  /* 9 */ mult(z9, t0, work + 32);
	  /* 11 */ mult(z11,z9,z2);
	  /* 22 */ square(t0,z11);
	  /* 2^5 - 2^0 = 31 */ mult(z2_5_0,t0,z9);

	  /* 2^6 - 2^1 */ square(t0,z2_5_0);
	  /* 2^7 - 2^2 */ square(t1,t0);
	  /* 2^8 - 2^3 */ square(t0,t1);
	  /* 2^9 - 2^4 */ square(t1,t0);
	  /* 2^10 - 2^5 */ square(t0,t1);
	  /* 2^10 - 2^0 */ mult(z2_10_0,t0,z2_5_0);

	  /* 2^11 - 2^1 */ square(t0,z2_10_0);
	  /* 2^12 - 2^2 */ square(t1,t0);
	  /* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { square(t0,t1); square(t1,t0); }
	  /* 2^20 - 2^0 */ mult(z2_20_0,t1,z2_10_0);

	  /* 2^21 - 2^1 */ square(t0,z2_20_0);
	  /* 2^22 - 2^2 */ square(t1,t0);
	  /* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { square(t0,t1); square(t1,t0); }
	  /* 2^40 - 2^0 */ mult(t0,t1,z2_20_0);

	  /* 2^41 - 2^1 */ square(t1,t0);
	  /* 2^42 - 2^2 */ square(t0,t1);
	  /* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { square(t1,t0); square(t0,t1); }
	  /* 2^50 - 2^0 */ mult(z2_50_0,t0,z2_10_0);

	  /* 2^51 - 2^1 */ square(t0,z2_50_0);
	  /* 2^52 - 2^2 */ square(t1,t0);
	  /* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
	  /* 2^100 - 2^0 */ mult(z2_100_0,t1,z2_50_0);

	  /* 2^101 - 2^1 */ square(t1,z2_100_0);
	  /* 2^102 - 2^2 */ square(t0,t1);
	  /* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { square(t1,t0); square(t0,t1); }
	  /* 2^200 - 2^0 */ mult(t1,t0,z2_100_0);

	  /* 2^201 - 2^1 */ square(t0,t1);
	  /* 2^202 - 2^2 */ square(t1,t0);
	  /* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
	  /* 2^250 - 2^0 */ mult(t0,t1,z2_50_0);

	  /* 2^251 - 2^1 */ square(t1,t0);
	  /* 2^252 - 2^2 */ square(t0,t1);
	  /* 2^253 - 2^3 */ square(t1,t0);
	  /* 2^254 - 2^4 */ square(t0,t1);
	  /* 2^255 - 2^5 */ square(t1,t0);
	  /* 2^255 - 21 */ mult(work + 32, t1,z11);
  }
  mult(work + 64,work,work + 32);
  //freeze(work + 64);
  {
	  uint32_t* a = work + 64;
	  uint32_t aorig[32];
	  uint32_t j;
	  uint32_t negative;
	  uint32_t minusp[32] = {19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128};

	  for (j = 0;j < 32;++j)
		  aorig[j] = a[j];
	  add(a, a, minusp);
	  negative = 0-((a[31] >> 7) & 1);
	  for (j = 0;j < 32;++j)
		  a[j] ^= negative & (aorig[j] ^ a[j]);
  }

  for (i = 0;i < 32;++i)
	  shared_key[i] = work[64 + i];
  return 0;
}
PUBLIC int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *secret_key)
{
	return crypto_scalarmult_curve25519(q, secret_key, base);
}
// end Public key implementation

///////////////////////////////////////////////////////////////////////////////////////////
// Salsa20 Encryption
///////////////////////////////////////////////////////////////////////////////////////////
#define ROUNDS 20

// Only works in "same-endian" machines
PUBLIC void salsa20_crypt_block(unsigned char* message, const uint32_t* nonce, const uint32_t* key, uint32_t counter)
{
	uint32_t x[16];
	int i;

	// Hashing key
	x[0] = 0x61707865;	x[5] = 0x3320646e;		x[10] = 0x79622d32;		x[15] = 0x6b206574;
	x[1] = key[0];		x[6] = nonce[0];		x[11] = key[4];
	x[2] = key[1];		x[7] = nonce[1];		x[12] = key[5];
	x[3] = key[2];		x[8] = counter;			x[13] = key[6];
	x[4] = key[3];		x[9] = 0;				x[14] = key[7];

	for (i = ROUNDS; i > 0; i -= 2)
	{
		x[4]  ^= ROTATE( x[0]+x[12],  7);
		x[8]  ^= ROTATE( x[4]+ x[0],  9);
		x[12] ^= ROTATE( x[8]+ x[4], 13);
		x[0]  ^= ROTATE(x[12]+ x[8], 18);
		x[9]  ^= ROTATE( x[5]+ x[1],  7);
		x[13] ^= ROTATE( x[9]+ x[5],  9);
		x[1 ] ^= ROTATE(x[13]+ x[9], 13);
		x[5 ] ^= ROTATE( x[1]+x[13], 18);
		x[14] ^= ROTATE(x[10]+ x[6],  7);
		x[2 ] ^= ROTATE(x[14]+x[10],  9);
		x[6 ] ^= ROTATE( x[2]+x[14], 13);
		x[10] ^= ROTATE( x[6]+ x[2], 18);
		x[3 ] ^= ROTATE(x[15]+x[11],  7);
		x[7 ] ^= ROTATE( x[3]+x[15],  9);
		x[11] ^= ROTATE( x[7]+ x[3], 13);
		x[15] ^= ROTATE(x[11]+ x[7], 18);
		x[1 ] ^= ROTATE( x[0]+ x[3],  7);
		x[2 ] ^= ROTATE( x[1]+ x[0],  9);
		x[3 ] ^= ROTATE( x[2]+ x[1], 13);
		x[0 ] ^= ROTATE( x[3]+ x[2], 18);
		x[6 ] ^= ROTATE( x[5]+ x[4],  7);
		x[7 ] ^= ROTATE( x[6]+ x[5],  9);
		x[4 ] ^= ROTATE( x[7]+ x[6], 13);
		x[5 ] ^= ROTATE( x[4]+ x[7], 18);
		x[11] ^= ROTATE(x[10]+ x[9],  7);
		x[8 ] ^= ROTATE(x[11]+x[10],  9);
		x[9 ] ^= ROTATE( x[8]+x[11], 13);
		x[10] ^= ROTATE( x[9]+ x[8], 18);
		x[12] ^= ROTATE(x[15]+x[14],  7);
		x[13] ^= ROTATE(x[12]+x[15],  9);
		x[14] ^= ROTATE(x[13]+x[12], 13);
		x[15] ^= ROTATE(x[14]+x[13], 18);
	}

	x[0 ] += 0x61707865;	x[5 ] += 0x3320646e;	x[10] += 0x79622d32;	x[15] += 0x6b206574;
	x[1 ] += key[0];		x[6 ] += nonce[0];		x[11] += key[4];
	x[2 ] += key[1];		x[7 ] += nonce[1];		x[12] += key[5];
	x[3 ] += key[2];		x[8 ] += counter;		x[13] += key[6];
	x[4 ] += key[3];		x[9 ] += 0;				x[14] += key[7];

	// Encrypt via XOR
	for (i = 0; i < 16; i++)
		((uint32_t*)message)[i] ^= x[i];
}