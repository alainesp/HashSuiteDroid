// This file is part of Hash Suite password cracker,
// Copyright (c) 2013-2020 by Alain Espinosa

#include "common.h"

//Initial values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476
#define INIT_E 0xC3D2E1F0

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

// SHA1
#define SHA1_RW(w0, w1, w2, w3)	(W[w0*simd_with+i] = ROTATE((W[w0*simd_with+i] ^ W[w1*simd_with+i] ^ W[w2*simd_with+i] ^ W[w3*simd_with+i]), 1))
PUBLIC void sha1_process_block_simd(uint32_t* state, uint32_t* W, uint32_t simd_with)
{
	for (uint32_t i = 0; i < simd_with; i++)
	{
		uint32_t A = state[i+0*simd_with];
		uint32_t B = state[i+1*simd_with];
		uint32_t C = state[i+2*simd_with];
		uint32_t D = state[i+3*simd_with];
		uint32_t E = state[i+4*simd_with];

		E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[0 *simd_with+i]; B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[1 *simd_with+i]; A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[2 *simd_with+i]; E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[3 *simd_with+i]; D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[4 *simd_with+i]; C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[5 *simd_with+i]; B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[6 *simd_with+i]; A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[7 *simd_with+i]; E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[8 *simd_with+i]; D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[9 *simd_with+i]; C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[10*simd_with+i]; B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[11*simd_with+i]; A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[12*simd_with+i]; E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[13*simd_with+i]; D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[14*simd_with+i]; C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[15*simd_with+i]; B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + SHA1_RW(0, 13,  8, 2); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + SHA1_RW(1, 14,  9, 3); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + SHA1_RW(2, 15, 10, 4); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + SHA1_RW(3,  0, 11, 5); C = ROTATE(C, 30);

		E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + SHA1_RW(4 , 1 , 12, 6); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + SHA1_RW(5 , 2 , 13, 7); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + SHA1_RW(6 , 3 , 14, 8); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + SHA1_RW(7 , 4 , 15, 9); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + SHA1_RW(8 , 5 , 0, 10); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + SHA1_RW(9 , 6 , 1, 11); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + SHA1_RW(10, 7 , 2, 12); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + SHA1_RW(11, 8 , 3, 13); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + SHA1_RW(12, 9 , 4, 14); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + SHA1_RW(13, 10, 5, 15); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + SHA1_RW(14, 11, 6,  0); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + SHA1_RW(15, 12, 7,  1); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + SHA1_RW(0 , 13, 8,  2); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + SHA1_RW(1 , 14, 9,  3); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + SHA1_RW(2 , 15, 10, 4); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + SHA1_RW(3 ,  0, 11, 5); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + SHA1_RW(4 ,  1, 12, 6); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + SHA1_RW(5 ,  2, 13, 7); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + SHA1_RW(6 ,  3, 14, 8); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + SHA1_RW(7 ,  4, 15, 9); C = ROTATE(C, 30);

		E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + SHA1_RW( 8,  5,  0, 10); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + SHA1_RW( 9,  6,  1, 11); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + SHA1_RW(10,  7,  2, 12); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + SHA1_RW(11,  8,  3, 13); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + SHA1_RW(12,  9,  4, 14); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + SHA1_RW(13, 10,  5, 15); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + SHA1_RW(14, 11,  6,  0); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + SHA1_RW(15, 12,  7,  1); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + SHA1_RW( 0, 13,  8,  2); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + SHA1_RW( 1, 14,  9,  3); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + SHA1_RW( 2, 15, 10,  4); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + SHA1_RW( 3,  0, 11,  5); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + SHA1_RW( 4,  1, 12,  6); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + SHA1_RW( 5,  2, 13,  7); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + SHA1_RW( 6,  3, 14,  8); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + SHA1_RW( 7,  4, 15,  9); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + SHA1_RW( 8,  5,  0, 10); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + SHA1_RW( 9,  6,  1, 11); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + SHA1_RW(10,  7,  2, 12); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + SHA1_RW(11,  8,  3, 13); C = ROTATE(C, 30);
																   
		E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + SHA1_RW(12,  9,  4, 14); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + SHA1_RW(13, 10,  5, 15); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + SHA1_RW(14, 11,  6,  0); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + SHA1_RW(15, 12,  7,  1); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + SHA1_RW( 0, 13,  8,  2); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + SHA1_RW( 1, 14,  9,  3); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + SHA1_RW( 2, 15, 10,  4); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + SHA1_RW( 3,  0, 11,  5); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + SHA1_RW( 4,  1, 12,  6); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + SHA1_RW( 5,  2, 13,  7); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + SHA1_RW( 6,  3, 14,  8); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + SHA1_RW( 7,  4, 15,  9); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + SHA1_RW( 8,  5,  0, 10); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + SHA1_RW( 9,  6,  1, 11); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + SHA1_RW(10,  7,  2, 12); C = ROTATE(C, 30);//
		E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + SHA1_RW(11,  8,  3, 13); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + SHA1_RW(12,  9,  4, 14); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + SHA1_RW(13, 10,  5, 15); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + SHA1_RW(14, 11,  6,  0); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + SHA1_RW(15, 12,  7,  1); C = ROTATE(C, 30);

		state[i+0*simd_with] += A;
		state[i+1*simd_with] += B;
		state[i+2*simd_with] += C;
		state[i+3*simd_with] += D;
		state[i+4*simd_with] += E;
	}
}

PUBLIC void hash_sha1(const char* message, char* hash)
{
	uint32_t nt_buffer[8];
	uint32_t W[16];
	uint32_t sha1_state[5];

	uint32_t len = (uint32_t)strlen(message);

	memset(nt_buffer, 0, sizeof(nt_buffer));
	memset(W, 0, sizeof(W));

	strcpy((char*)nt_buffer, message);
	((unsigned char*)nt_buffer)[len] = 0x80;

	SWAP_ENDIANNESS(W[0], nt_buffer[0]);
	SWAP_ENDIANNESS(W[1], nt_buffer[1]);
	SWAP_ENDIANNESS(W[2], nt_buffer[2]);
	SWAP_ENDIANNESS(W[3], nt_buffer[3]);
	SWAP_ENDIANNESS(W[4], nt_buffer[4]);
	SWAP_ENDIANNESS(W[5], nt_buffer[5]);
	SWAP_ENDIANNESS(W[6], nt_buffer[6]);

	W[15] = len << 3;

	sha1_state[0] = INIT_A;
	sha1_state[1] = INIT_B;
	sha1_state[2] = INIT_C;
	sha1_state[3] = INIT_D;
	sha1_state[4] = INIT_E;
	sha1_process_block_simd(sha1_state, W, 1);

	hash[0] = 0;
	for (uint32_t i = 0; i < 5; i++)
		sprintf(hash + strlen(hash), "%08x", sha1_state[i]);
}

PUBLIC void hmac_sha1_init_simd(uint32_t* key, uint32_t* key_lenghts, uint32_t simd_with, uint32_t multiplier, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W)
{
	uint32_t i;
	// ipad_state
	for (uint32_t simd_index = 0; simd_index < simd_with; simd_index++)
	{
		for (i = 0; i < key_lenghts[simd_index]; i++)
			W[i*simd_with+simd_index] = key[i*multiplier*simd_with+simd_index] ^ 0x36363636;
		for (; i < 16; i++)
			W[i*simd_with+simd_index] = 0x36363636;

		ipad_state[0*simd_with+simd_index] = INIT_A;
		ipad_state[1*simd_with+simd_index] = INIT_B;
		ipad_state[2*simd_with+simd_index] = INIT_C;
		ipad_state[3*simd_with+simd_index] = INIT_D;
		ipad_state[4*simd_with+simd_index] = INIT_E;
	}
	sha1_process_block_simd(ipad_state, W, simd_with);

	// opad_state
	for (uint32_t simd_index = 0; simd_index < simd_with; simd_index++)
	{
		for (i = 0; i < key_lenghts[simd_index]; i++)
			W[i*simd_with+simd_index] = key[i*multiplier*simd_with+simd_index] ^ 0x5C5C5C5C;
		for (; i < 16; i++)
			W[i*simd_with+simd_index] = 0x5C5C5C5C;

		opad_state[0*simd_with+simd_index] = INIT_A;
		opad_state[1*simd_with+simd_index] = INIT_B;
		opad_state[2*simd_with+simd_index] = INIT_C;
		opad_state[3*simd_with+simd_index] = INIT_D;
		opad_state[4*simd_with+simd_index] = INIT_E;
	}
	sha1_process_block_simd(opad_state, W, simd_with);
}
// Calculate W in each iteration
#define Q0  ( W[0 ] = ROTATE((sha1_hash[2 ] ^ sha1_hash[0 ]), 1) )
#define Q1  ( W[1 ] = ROTATE((sha1_hash[3 ] ^ sha1_hash[1 ]), 1) )
#define Q2  ( W[2 ] = ROTATE((0x2A0 ^ sha1_hash[4 ] ^ sha1_hash[2 ]), 1) )
#define Q3  ( W[3 ] = ROTATE((W[0 ] ^ 0x80000000 ^ sha1_hash[3 ]), 1) )
#define Q4  ( W[4 ] = ROTATE((W[1 ] ^ sha1_hash[4 ]), 1) )
#define Q5  ( W[5 ] = ROTATE((W[2 ] ^ 0x80000000), 1) )
#define Q6  ( W[6 ] = ROTATE((W[3 ] ), 1) )
#define Q7  ( W[7 ] = ROTATE((W[4 ] ^ 0x2A0), 1) )
#define Q8  ( W[8 ] = ROTATE((W[5 ] ^ W[0 ]), 1) )
#define Q9  ( W[9 ] = ROTATE((W[6 ] ^ W[1 ]), 1) )
#define Q10 ( W[10] = ROTATE((W[7 ] ^ W[2 ]), 1) )
#define Q11 ( W[11] = ROTATE((W[8 ] ^ W[3 ]), 1) )
#define Q12 ( W[12] = ROTATE((W[9 ] ^ W[4 ]), 1) )
#define Q13 ( W[13] = ROTATE((W[10] ^ W[5 ] ^ 0x2A0), 1) )
#define Q14 ( W[14] = ROTATE((W[11] ^ W[6 ] ^ W[0 ]), 1) )
#define Q15 ( W[15] = ROTATE((W[12] ^ W[7 ] ^ W[1 ] ^ 0x2A0), 1) )

#undef SHA1_RW
#define SHA1_RW(w0, w1, w2, w3)	(W[w0] = ROTATE((W[w0] ^ W[w1] ^ W[w2] ^ W[w3]), 1))
PUBLIC void sha1_process_block_hmac_sha1(const uint32_t state[5], uint32_t sha1_hash[5], uint32_t W[16])
{
	uint32_t A = state[0];
	uint32_t B = state[1];
	uint32_t C = state[2];
	uint32_t D = state[3];
	uint32_t E = state[4];

	E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + sha1_hash[0]; B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + sha1_hash[1]; A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + sha1_hash[2]; E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + sha1_hash[3]; D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + sha1_hash[4]; C = ROTATE(C, 30);
	E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + 0x80000000; B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2; A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2; E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2; D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2; C = ROTATE(C, 30);
	E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2; B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2; A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2; E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2; D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2; C = ROTATE(C, 30);
	E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + 0x2A0; B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + Q0; A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + Q1; E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + Q2; D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + Q3; C = ROTATE(C, 30);

	E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + Q4; B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + Q5; A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + Q6; E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + Q7; D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + Q8; C = ROTATE(C, 30);
	E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + Q9; B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + Q10; A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + Q11; E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + Q12; D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + Q13; C = ROTATE(C, 30);
	E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + Q14; B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + Q15; A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + SHA1_RW(0, 13, 8, 2); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + SHA1_RW(1, 14, 9, 3); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + SHA1_RW(2, 15, 10, 4); C = ROTATE(C, 30);
	E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + SHA1_RW(3, 0, 11, 5); B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + SHA1_RW(4, 1, 12, 6); A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + SHA1_RW(5, 2, 13, 7); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + SHA1_RW(6, 3, 14, 8); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + SHA1_RW(7, 4, 15, 9); C = ROTATE(C, 30);

	E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + SHA1_RW(8, 5, 0, 10); B = ROTATE(B, 30);
	D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + SHA1_RW(9, 6, 1, 11); A = ROTATE(A, 30);
	C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + SHA1_RW(10, 7, 2, 12); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + SHA1_RW(11, 8, 3, 13); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + SHA1_RW(12, 9, 4, 14); C = ROTATE(C, 30);
	E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + SHA1_RW(13, 10, 5, 15); B = ROTATE(B, 30);
	D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + SHA1_RW(14, 11, 6, 0); A = ROTATE(A, 30);
	C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + SHA1_RW(15, 12, 7, 1); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + SHA1_RW(0, 13, 8, 2); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + SHA1_RW(1, 14, 9, 3); C = ROTATE(C, 30);
	E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + SHA1_RW(2, 15, 10, 4); B = ROTATE(B, 30);
	D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + SHA1_RW(3, 0, 11, 5); A = ROTATE(A, 30);
	C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + SHA1_RW(4, 1, 12, 6); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + SHA1_RW(5, 2, 13, 7); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + SHA1_RW(6, 3, 14, 8); C = ROTATE(C, 30);
	E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + SHA1_RW(7, 4, 15, 9); B = ROTATE(B, 30);
	D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + SHA1_RW(8, 5, 0, 10); A = ROTATE(A, 30);
	C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + SHA1_RW(9, 6, 1, 11); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + SHA1_RW(10, 7, 2, 12); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + SHA1_RW(11, 8, 3, 13); C = ROTATE(C, 30);

	E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + SHA1_RW(12, 9, 4, 14); B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + SHA1_RW(13, 10, 5, 15); A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + SHA1_RW(14, 11, 6, 0); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + SHA1_RW(15, 12, 7, 1); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + SHA1_RW(0, 13, 8, 2); C = ROTATE(C, 30);
	E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + SHA1_RW(1, 14, 9, 3); B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + SHA1_RW(2, 15, 10, 4); A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + SHA1_RW(3, 0, 11, 5); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + SHA1_RW(4, 1, 12, 6); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + SHA1_RW(5, 2, 13, 7); C = ROTATE(C, 30);
	E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + SHA1_RW(6, 3, 14, 8); B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + SHA1_RW(7, 4, 15, 9); A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + SHA1_RW(8, 5, 0, 10); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + SHA1_RW(9, 6, 1, 11); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + SHA1_RW(10, 7, 2, 12); C = ROTATE(C, 30);
	E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + SHA1_RW(11, 8, 3, 13); B = ROTATE(B, 30);
	D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + SHA1_RW(12, 9, 4, 14); A = ROTATE(A, 30);
	C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + SHA1_RW(13, 10, 5, 15); E = ROTATE(E, 30);
	B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + SHA1_RW(14, 11, 6, 0); D = ROTATE(D, 30);
	A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + SHA1_RW(15, 12, 7, 1); C = ROTATE(C, 30);

	sha1_hash[0] = state[0] + A;
	sha1_hash[1] = state[1] + B;
	sha1_hash[2] = state[2] + C;
	sha1_hash[3] = state[3] + D;
	sha1_hash[4] = state[4] + E;
}

// MD4
PRIVATE void md4_process_block(uint32_t* state, const uint32_t* block)
{
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];

	/* Round 1 */
	a += (d ^ (b & (c ^ d))) + block[0] ; a = ROTATE(a, 3);
	d += (c ^ (a & (b ^ c))) + block[1] ; d = ROTATE(d, 7);
	c += (b ^ (d & (a ^ b))) + block[2] ; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))) + block[3] ; b = ROTATE(b, 19);

	a += (d ^ (b & (c ^ d))) + block[4] ; a = ROTATE(a, 3 );
	d += (c ^ (a & (b ^ c))) + block[5] ; d = ROTATE(d, 7 );
	c += (b ^ (d & (a ^ b))) + block[6] ; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))) + block[7] ; b = ROTATE(b, 19);

	a += (d ^ (b & (c ^ d))) + block[8] ; a = ROTATE(a, 3 );
	d += (c ^ (a & (b ^ c))) + block[9] ; d = ROTATE(d, 7 );
	c += (b ^ (d & (a ^ b))) + block[10]; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))) + block[11]; b = ROTATE(b, 19);

	a += (d ^ (b & (c ^ d))) + block[12]; a = ROTATE(a, 3 );
	d += (c ^ (a & (b ^ c))) + block[13]; d = ROTATE(d, 7 );
	c += (b ^ (d & (a ^ b))) + block[14]; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))) + block[15]; b = ROTATE(b, 19);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + block[0] + SQRT_2; a = ROTATE(a, 3 );
	d += ((a & (b | c)) | (b & c)) + block[4] + SQRT_2; d = ROTATE(d, 5 );
	c += ((d & (a | b)) | (a & b)) + block[8] + SQRT_2; c = ROTATE(c, 9 );
	b += ((c & (d | a)) | (d & a)) + block[12]+ SQRT_2; b = ROTATE(b, 13);

	a += ((b & (c | d)) | (c & d)) + block[1] + SQRT_2; a = ROTATE(a, 3 );
	d += ((a & (b | c)) | (b & c)) + block[5] + SQRT_2; d = ROTATE(d, 5 );
	c += ((d & (a | b)) | (a & b)) + block[9] + SQRT_2; c = ROTATE(c, 9 );
	b += ((c & (d | a)) | (d & a)) + block[13]+ SQRT_2; b = ROTATE(b, 13);

	a += ((b & (c | d)) | (c & d)) + block[2] + SQRT_2; a = ROTATE(a, 3 );
	d += ((a & (b | c)) | (b & c)) + block[6] + SQRT_2; d = ROTATE(d, 5 );
	c += ((d & (a | b)) | (a & b)) + block[10]+ SQRT_2; c = ROTATE(c, 9 );
	b += ((c & (d | a)) | (d & a)) + block[14]+ SQRT_2; b = ROTATE(b, 13);

	a += ((b & (c | d)) | (c & d)) + block[3] + SQRT_2; a = ROTATE(a, 3 );
	d += ((a & (b | c)) | (b & c)) + block[7] + SQRT_2; d = ROTATE(d, 5 );
	c += ((d & (a | b)) | (a & b)) + block[11]+ SQRT_2; c = ROTATE(c, 9 );
	b += ((c & (d | a)) | (d & a)) + block[15]+ SQRT_2; b = ROTATE(b, 13);

	/* Round 3 */
	a += (d ^ c ^ b) + block[0]  + SQRT_3; a = ROTATE(a, 3 );
	d += (c ^ b ^ a) + block[8]  + SQRT_3; d = ROTATE(d, 9 );
	c += (b ^ a ^ d) + block[4]  + SQRT_3; c = ROTATE(c, 11);
	b += (a ^ d ^ c) + block[12] + SQRT_3; b = ROTATE(b, 15);

	a += (d ^ c ^ b) + block[2]  + SQRT_3; a = ROTATE(a, 3 );
	d += (c ^ b ^ a) + block[10] + SQRT_3; d = ROTATE(d, 9 );
	c += (b ^ a ^ d) + block[6]  + SQRT_3; c = ROTATE(c, 11);
	b += (a ^ d ^ c) + block[14] + SQRT_3; b = ROTATE(b, 15);

	a += (d ^ c ^ b) + block[1]  + SQRT_3; a = ROTATE(a, 3 );
	d += (c ^ b ^ a) + block[9]  + SQRT_3; d = ROTATE(d, 9 );
	c += (b ^ a ^ d) + block[5]  + SQRT_3; c = ROTATE(c, 11);
	b += (a ^ d ^ c) + block[13] + SQRT_3; b = ROTATE(b, 15);

	a += (d ^ c ^ b) + block[3]  + SQRT_3; a = ROTATE(a, 3 );
	d += (c ^ b ^ a) + block[11] + SQRT_3; d = ROTATE(d, 9 );
	c += (b ^ a ^ d) + block[7]  + SQRT_3; c = ROTATE(c, 11);
	b += (a ^ d ^ c) + block[15] + SQRT_3; b = ROTATE(b, 15);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

// MD5
PUBLIC void md5_process_block(uint32_t* state, const uint32_t* block)
{
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];

	/* Round 1 */
	a += (d ^ (b & (c ^ d))) + block[0 ] + 0xd76aa478; a = ROTATE(a, 7) + b;
	d += (c ^ (a & (b ^ c))) + block[1 ] + 0xe8c7b756; d = ROTATE(d, 12) + a;
	c += (b ^ (d & (a ^ b))) + block[2 ] + 0x242070db; c = ROTATE(c, 17) + d;
	b += (a ^ (c & (d ^ a))) + block[3 ] + 0xc1bdceee; b = ROTATE(b, 22) + c;
									   
	a += (d ^ (b & (c ^ d))) + block[4 ] + 0xf57c0faf; a = ROTATE(a, 7) + b;
	d += (c ^ (a & (b ^ c))) + block[5 ] + 0x4787c62a; d = ROTATE(d, 12) + a;
	c += (b ^ (d & (a ^ b))) + block[6 ] + 0xa8304613; c = ROTATE(c, 17) + d;
	b += (a ^ (c & (d ^ a))) + block[7 ] + 0xfd469501; b = ROTATE(b, 22) + c;
									   
	a += (d ^ (b & (c ^ d))) + block[8 ] + 0x698098d8; a = ROTATE(a, 7) + b;
	d += (c ^ (a & (b ^ c))) + block[9 ] + 0x8b44f7af; d = ROTATE(d, 12) + a;
	c += (b ^ (d & (a ^ b))) + block[10] + 0xffff5bb1; c = ROTATE(c, 17) + d;
	b += (a ^ (c & (d ^ a))) + block[11] + 0x895cd7be; b = ROTATE(b, 22) + c;

	a += (d ^ (b & (c ^ d))) + block[12] + 0x6b901122; a = ROTATE(a, 7) + b;
	d += (c ^ (a & (b ^ c))) + block[13] + 0xfd987193; d = ROTATE(d, 12) + a;
	c += (b ^ (d & (a ^ b))) + block[14] + 0xa679438e; c = ROTATE(c, 17) + d;
	b += (a ^ (c & (d ^ a))) + block[15] + 0x49b40821; b = ROTATE(b, 22) + c;

	/* Round 2 */
	a += (c ^ (d & (b ^ c))) + block[1 ] + 0xf61e2562; a = ROTATE(a, 5) + b;
	d += (b ^ (c & (a ^ b))) + block[6 ] + 0xc040b340; d = ROTATE(d, 9) + a;
	c += (a ^ (b & (d ^ a))) + block[11] + 0x265e5a51; c = ROTATE(c, 14) + d;
	b += (d ^ (a & (c ^ d))) + block[0 ] + 0xe9b6c7aa; b = ROTATE(b, 20) + c;

	a += (c ^ (d & (b ^ c))) + block[5 ] + 0xd62f105d; a = ROTATE(a, 5) + b;
	d += (b ^ (c & (a ^ b))) + block[10] + 0x02441453; d = ROTATE(d, 9) + a;
	c += (a ^ (b & (d ^ a))) + block[15] + 0xd8a1e681; c = ROTATE(c, 14) + d;
	b += (d ^ (a & (c ^ d))) + block[4 ] + 0xe7d3fbc8; b = ROTATE(b, 20) + c;

	a += (c ^ (d & (b ^ c))) + block[9 ] + 0x21e1cde6; a = ROTATE(a, 5) + b;
	d += (b ^ (c & (a ^ b))) + block[14] + 0xc33707d6; d = ROTATE(d, 9) + a;
	c += (a ^ (b & (d ^ a))) + block[3 ] + 0xf4d50d87; c = ROTATE(c, 14) + d;
	b += (d ^ (a & (c ^ d))) + block[8 ] + 0x455a14ed; b = ROTATE(b, 20) + c;

	a += (c ^ (d & (b ^ c))) + block[13] + 0xa9e3e905; a = ROTATE(a, 5) + b;
	d += (b ^ (c & (a ^ b))) + block[2 ] + 0xfcefa3f8; d = ROTATE(d, 9) + a;
	c += (a ^ (b & (d ^ a))) + block[7 ] + 0x676f02d9; c = ROTATE(c, 14) + d;
	b += (d ^ (a & (c ^ d))) + block[12] + 0x8d2a4c8a; b = ROTATE(b, 20) + c;

	/* Round 3 */
	a += (b ^ c ^ d) + block[5 ] + 0xfffa3942; a = ROTATE(a, 4) + b;
	d += (a ^ b ^ c) + block[8 ] + 0x8771f681; d = ROTATE(d, 11) + a;
	c += (d ^ a ^ b) + block[11] + 0x6d9d6122; c = ROTATE(c, 16) + d;
	b += (c ^ d ^ a) + block[14] + 0xfde5380c; b = ROTATE(b, 23) + c;

	a += (b ^ c ^ d) + block[1 ] + 0xa4beea44; a = ROTATE(a, 4) + b;
	d += (a ^ b ^ c) + block[4 ] + 0x4bdecfa9; d = ROTATE(d, 11) + a;
	c += (d ^ a ^ b) + block[7 ] + 0xf6bb4b60; c = ROTATE(c, 16) + d;
	b += (c ^ d ^ a) + block[10] + 0xbebfbc70; b = ROTATE(b, 23) + c;

	a += (b ^ c ^ d) + block[13] + 0x289b7ec6; a = ROTATE(a, 4) + b;
	d += (a ^ b ^ c) + block[0 ] + 0xeaa127fa; d = ROTATE(d, 11) + a;
	c += (d ^ a ^ b) + block[3 ] + 0xd4ef3085; c = ROTATE(c, 16) + d;
	b += (c ^ d ^ a) + block[6 ] + 0x04881d05; b = ROTATE(b, 23) + c;

	a += (b ^ c ^ d) + block[9 ] + 0xd9d4d039; a = ROTATE(a, 4) + b;
	d += (a ^ b ^ c) + block[12] + 0xe6db99e5; d = ROTATE(d, 11) + a;
	c += (d ^ a ^ b) + block[15] + 0x1fa27cf8; c = ROTATE(c, 16) + d;
	b += (c ^ d ^ a) + block[2 ] + 0xc4ac5665; b = ROTATE(b, 23) + c;

	/* Round 4 */
	a += (c ^ (b | ~d)) + block[0 ] + 0xf4292244; a = ROTATE(a, 6) + b;
	d += (b ^ (a | ~c)) + block[7 ] + 0x432aff97; d = ROTATE(d, 10) + a;
	c += (a ^ (d | ~b)) + block[14] + 0xab9423a7; c = ROTATE(c, 15) + d;
	b += (d ^ (c | ~a)) + block[5 ] + 0xfc93a039; b = ROTATE(b, 21) + c;

	a += (c ^ (b | ~d)) + block[12] + 0x655b59c3; a = ROTATE(a, 6) + b;
	d += (b ^ (a | ~c)) + block[3 ] + 0x8f0ccc92; d = ROTATE(d, 10) + a;
	c += (a ^ (d | ~b)) + block[10] + 0xffeff47d; c = ROTATE(c, 15) + d;
	b += (d ^ (c | ~a)) + block[1 ] + 0x85845dd1; b = ROTATE(b, 21) + c;

	a += (c ^ (b | ~d)) + block[8 ] + 0x6fa87e4f; a = ROTATE(a, 6) + b;
	d += (b ^ (a | ~c)) + block[15] + 0xfe2ce6e0; d = ROTATE(d, 10) + a;
	c += (a ^ (d | ~b)) + block[6 ] + 0xa3014314; c = ROTATE(c, 15) + d;
	b += (d ^ (c | ~a)) + block[13] + 0x4e0811a1; b = ROTATE(b, 21) + c;

	a += (c ^ (b | ~d)) + block[4 ] + 0xf7537e82; a = ROTATE(a, 6) + b;
	d += (b ^ (a | ~c)) + block[11] + 0xbd3af235; d = ROTATE(d, 10) + a;
	c += (a ^ (d | ~b)) + block[2 ] + 0x2ad7d2bb; c = ROTATE(c, 15) + d;
	b += (d ^ (c | ~a)) + block[9 ] + 0xeb86d391; b = ROTATE(b, 21) + c;

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
PUBLIC void hash_md5(const char* message, char* hash)
{
	uint32_t md5_state[4];
	uint32_t nt_buffer[16];
	uint32_t len = (uint32_t)strlen(message);
	if (len > 55)
	{
		strcpy(hash, "-- Unsupported: More than 55 chars --");
		return;
	}

	memset(nt_buffer, 0, sizeof(nt_buffer));
	strcpy((char*)nt_buffer, message);
	((unsigned char*)nt_buffer)[len] = 0x80;
	nt_buffer[14] = len << 3;

	/* Round 1 */
	md5_state[0] = INIT_A;
	md5_state[1] = INIT_B;
	md5_state[2] = INIT_C;
	md5_state[3] = INIT_D;
	md5_process_block(md5_state, nt_buffer);

	hash[0] = 0;
	for (uint32_t i = 0; i < 4; i++)
	{
		SWAP_ENDIANNESS(md5_state[i], md5_state[i]);
		sprintf(hash + strlen(hash), "%08x", md5_state[i]);
	}
}
// NTLM
PUBLIC void hash_ntlm(const unsigned char* message, char* hash)
{
	uint32_t nt_buffer[16];
	uint32_t md4_state[4];

	uint32_t i;
	uint32_t message_lenght = (uint32_t)strlen((char*)message);
	if(message_lenght > 27)
	{
		strcpy(hash, "-- Unsupported: More than 27 chars --");
		return;
	}
	// Convert to Unicode
	memset(nt_buffer, 0, sizeof(nt_buffer));

	for(i = 0; i < message_lenght/2; i++)
		nt_buffer[i] = message[2*i] | message[2*i+1] << 16;

	nt_buffer[i] = (message_lenght%2) ? message[2*i] | 0x800000 : 0x80;
	nt_buffer[14] = message_lenght << 4;

	md4_state[0] = INIT_A;
	md4_state[1] = INIT_B;
	md4_state[2] = INIT_C;
	md4_state[3] = INIT_D;
	md4_process_block(md4_state, nt_buffer);

	hash[0] = 0;
	for (uint32_t i = 0; i < 4; i++)
	{
		SWAP_ENDIANNESS(md4_state[i], md4_state[i]);
		sprintf(hash + strlen(hash), "%08X", md4_state[i]);
	}
}

// SHA256
#define R_E(x) (ROTATE(x,26) ^ ROTATE(x,21) ^ ROTATE(x,7 ))
#define R_A(x) (ROTATE(x,30) ^ ROTATE(x,19) ^ ROTATE(x,10))
#define R0(x)  (ROTATE(x,25) ^ ROTATE(x,14) ^ (x>>3))
#define R1(x)  (ROTATE(x,15) ^ ROTATE(x,13) ^ (x>>10))
PUBLIC void sha256_process_block(uint32_t* state, uint32_t* W)
{
	uint32_t A = state[0];
	uint32_t B = state[1];
	uint32_t C = state[2];
	uint32_t D = state[3];
	uint32_t E = state[4];
	uint32_t F = state[5];
	uint32_t G = state[6];
	uint32_t H = state[7];

	/* Rounds */
	H += R_E(E) + (G ^ (E & (F ^ G))) + 0x428A2F98 + W[ 0]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	G += R_E(D) + (F ^ (D & (E ^ F))) + 0x71374491 + W[ 1]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	F += R_E(C) + (E ^ (C & (D ^ E))) + 0xB5C0FBCF + W[ 2]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	E += R_E(B) + (D ^ (B & (C ^ D))) + 0xE9B5DBA5 + W[ 3]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	D += R_E(A) + (C ^ (A & (B ^ C))) + 0x3956C25B + W[ 4]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	C += R_E(H) + (B ^ (H & (A ^ B))) + 0x59F111F1 + W[ 5]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	B += R_E(G) + (A ^ (G & (H ^ A))) + 0x923F82A4 + W[ 6]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	A += R_E(F) + (H ^ (F & (G ^ H))) + 0xAB1C5ED5 + W[ 7]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
	H += R_E(E) + (G ^ (E & (F ^ G))) + 0xD807AA98 + W[ 8]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	G += R_E(D) + (F ^ (D & (E ^ F))) + 0x12835B01 + W[ 9]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	F += R_E(C) + (E ^ (C & (D ^ E))) + 0x243185BE + W[10]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	E += R_E(B) + (D ^ (B & (C ^ D))) + 0x550C7DC3 + W[11]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	D += R_E(A) + (C ^ (A & (B ^ C))) + 0x72BE5D74 + W[12]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	C += R_E(H) + (B ^ (H & (A ^ B))) + 0x80DEB1FE + W[13]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	B += R_E(G) + (A ^ (G & (H ^ A))) + 0x9BDC06A7 + W[14]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC19BF174 + W[15]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));

	W[ 0] += R1(W[14]) + W[9 ] + R0(W[1 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xE49B69C1 + W[ 0]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 1] += R1(W[15]) + W[10] + R0(W[2 ]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xEFBE4786 + W[ 1]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[ 2] += R1(W[0 ]) + W[11] + R0(W[3 ]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x0FC19DC6 + W[ 2]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[ 3] += R1(W[1 ]) + W[12] + R0(W[4 ]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x240CA1CC + W[ 3]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[ 4] += R1(W[2 ]) + W[13] + R0(W[5 ]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x2DE92C6F + W[ 4]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[ 5] += R1(W[3 ]) + W[14] + R0(W[6 ]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4A7484AA + W[ 5]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[ 6] += R1(W[4 ]) + W[15] + R0(W[7 ]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5CB0A9DC + W[ 6]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[ 7] += R1(W[5 ]) + W[0 ] + R0(W[8 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x76F988DA + W[ 7]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
	W[ 8] += R1(W[6 ]) + W[1 ] + R0(W[9 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x983E5152 + W[ 8]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 9] += R1(W[7 ]) + W[2 ] + R0(W[10]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA831C66D + W[ 9]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[10] += R1(W[8 ]) + W[3 ] + R0(W[11]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0xB00327C8 + W[10]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[11] += R1(W[9 ]) + W[4 ] + R0(W[12]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0xBF597FC7 + W[11]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[12] += R1(W[10]) + W[5 ] + R0(W[13]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0xC6E00BF3 + W[12]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[13] += R1(W[11]) + W[6 ] + R0(W[14]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD5A79147 + W[13]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[14] += R1(W[12]) + W[7 ] + R0(W[15]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x06CA6351 + W[14]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[15] += R1(W[13]) + W[8 ] + R0(W[0 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x14292967 + W[15]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																    
	W[ 0] += R1(W[14]) + W[9 ] + R0(W[1 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x27B70A85 + W[ 0]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 1] += R1(W[15]) + W[10] + R0(W[2 ]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x2E1B2138 + W[ 1]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[ 2] += R1(W[0 ]) + W[11] + R0(W[3 ]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x4D2C6DFC + W[ 2]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[ 3] += R1(W[1 ]) + W[12] + R0(W[4 ]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x53380D13 + W[ 3]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[ 4] += R1(W[2 ]) + W[13] + R0(W[5 ]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x650A7354 + W[ 4]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[ 5] += R1(W[3 ]) + W[14] + R0(W[6 ]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x766A0ABB + W[ 5]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[ 6] += R1(W[4 ]) + W[15] + R0(W[7 ]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x81C2C92E + W[ 6]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[ 7] += R1(W[5 ]) + W[0 ] + R0(W[8 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x92722C85 + W[ 7]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
	W[ 8] += R1(W[6 ]) + W[1 ] + R0(W[9 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xA2BFE8A1 + W[ 8]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 9] += R1(W[7 ]) + W[2 ] + R0(W[10]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA81A664B + W[ 9]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[10] += R1(W[8 ]) + W[3 ] + R0(W[11]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0xC24B8B70 + W[10]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[11] += R1(W[9 ]) + W[4 ] + R0(W[12]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0xC76C51A3 + W[11]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[12] += R1(W[10]) + W[5 ] + R0(W[13]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0xD192E819 + W[12]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[13] += R1(W[11]) + W[6 ] + R0(W[14]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD6990624 + W[13]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[14] += R1(W[12]) + W[7 ] + R0(W[15]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0xF40E3585 + W[14]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[15] += R1(W[13]) + W[8 ] + R0(W[0 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x106AA070 + W[15]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																    
	W[ 0] += R1(W[14]) + W[9 ] + R0(W[1 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x19A4C116 + W[ 0]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 1] += R1(W[15]) + W[10] + R0(W[2 ]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x1E376C08 + W[ 1]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[ 2] += R1(W[0 ]) + W[11] + R0(W[3 ]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x2748774C + W[ 2]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[ 3] += R1(W[1 ]) + W[12] + R0(W[4 ]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x34B0BCB5 + W[ 3]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[ 4] += R1(W[2 ]) + W[13] + R0(W[5 ]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x391C0CB3 + W[ 4]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[ 5] += R1(W[3 ]) + W[14] + R0(W[6 ]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4ED8AA4A + W[ 5]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[ 6] += R1(W[4 ]) + W[15] + R0(W[7 ]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5B9CCA4F + W[ 6]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[ 7] += R1(W[5 ]) + W[0 ] + R0(W[8 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x682E6FF3 + W[ 7]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
	W[ 8] += R1(W[6 ]) + W[1 ] + R0(W[9 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x748F82EE + W[ 8]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 9] += R1(W[7 ]) + W[2 ] + R0(W[10]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x78A5636F + W[ 9]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[10] += R1(W[8 ]) + W[3 ] + R0(W[11]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x84C87814 + W[10]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[11] += R1(W[9 ]) + W[4 ] + R0(W[12]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x8CC70208 + W[11]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[12] += R1(W[10]) + W[5 ] + R0(W[13]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x90BEFFFA + W[12]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[13] += R1(W[11]) + W[6 ] + R0(W[14]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xA4506CEB + W[13]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[14] += R1(W[12]) + W[7 ] + R0(W[15]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0xBEF9A3F7 + W[14]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[15] += R1(W[13]) + W[8 ] + R0(W[0 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC67178F2 + W[15]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));

	state[0] += A;
	state[1] += B;
	state[2] += C;
	state[3] += D;
	state[4] += E;
	state[5] += F;
	state[6] += G;
	state[7] += H;
}
PUBLIC void hash_sha256(const char* message, char* hash)
{
	uint32_t state[8];
	uint32_t W[16];

	state[0] = 0x6A09E667;
	state[1] = 0xBB67AE85;
	state[2] = 0x3C6EF372;
	state[3] = 0xA54FF53A;
	state[4] = 0x510E527F;
	state[5] = 0x9B05688C;
	state[6] = 0x1F83D9AB;
	state[7] = 0x5BE0CD19;

	// Cycle
	uint64_t message_size = strlen(message);
	for (size_t i = 0; i < message_size / 64; i++, message += 64)
	{
		memcpy(W, message, 64);
		swap_endianness_array(W, 16);
		sha256_process_block(state, W);
	}

	// Last block
	memset(W, 0, 64);
	size_t last_size = message_size - (message_size / 64) * 64;
	memcpy(W, message, last_size);
	((unsigned char*)W)[last_size] = 0x80;
	if (last_size >= 56)
	{
		swap_endianness_array(W, 16);
		sha256_process_block(state, W);

		memset(W, 0, 56);
	}
	swap_endianness_array(W, 14);
	W[14] = (uint32_t)((message_size * 8) >> 32);
	W[15] = (uint32_t)((message_size * 8));
	sha256_process_block(state, W);

	// Convert to hexadecimal string
	hash[0] = 0;
	for (uint32_t i = 0; i < 8; i++)
		sprintf(hash + strlen(hash), "%08X", state[i]);
}

// SHA512
#undef R_E
#undef R_A
#undef R0
#undef R1
#define R_E(x) (ROTATE64(x,50) ^ ROTATE64(x,46) ^ ROTATE64(x,23))
#define R_A(x) (ROTATE64(x,36) ^ ROTATE64(x,30) ^ ROTATE64(x,25))
#define R0(x)  (ROTATE64(x,63) ^ ROTATE64(x,56) ^ (x>>7))
#define R1(x)  (ROTATE64(x,45) ^ ROTATE64(x,3 ) ^ (x>>6))
PUBLIC void sha512_process_block(uint64_t* state, uint64_t* W)
{
	uint64_t A = state[0];
	uint64_t B = state[1];
	uint64_t C = state[2];
	uint64_t D = state[3];
	uint64_t E = state[4];
	uint64_t F = state[5];
	uint64_t G = state[6];
	uint64_t H = state[7];

	/* Rounds */
	H += R_E(E) + (G ^ (E & (F ^ G))) + 0x428A2F98D728AE22ULL + W[ 0]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	G += R_E(D) + (F ^ (D & (E ^ F))) + 0x7137449123EF65CDULL + W[ 1]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	F += R_E(C) + (E ^ (C & (D ^ E))) + 0xB5C0FBCFEC4D3B2FULL + W[ 2]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	E += R_E(B) + (D ^ (B & (C ^ D))) + 0xE9B5DBA58189DBBCULL + W[ 3]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	D += R_E(A) + (C ^ (A & (B ^ C))) + 0x3956C25BF348B538ULL + W[ 4]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	C += R_E(H) + (B ^ (H & (A ^ B))) + 0x59F111F1B605D019ULL + W[ 5]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	B += R_E(G) + (A ^ (G & (H ^ A))) + 0x923F82A4AF194F9BULL + W[ 6]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	A += R_E(F) + (H ^ (F & (G ^ H))) + 0xAB1C5ED5DA6D8118ULL + W[ 7]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
	H += R_E(E) + (G ^ (E & (F ^ G))) + 0xD807AA98A3030242ULL + W[ 8]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	G += R_E(D) + (F ^ (D & (E ^ F))) + 0x12835B0145706FBEULL + W[ 9]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	F += R_E(C) + (E ^ (C & (D ^ E))) + 0x243185BE4EE4B28CULL + W[10]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	E += R_E(B) + (D ^ (B & (C ^ D))) + 0x550C7DC3D5FFB4E2ULL + W[11]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	D += R_E(A) + (C ^ (A & (B ^ C))) + 0x72BE5D74F27B896FULL + W[12]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	C += R_E(H) + (B ^ (H & (A ^ B))) + 0x80DEB1FE3B1696B1ULL + W[13]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	B += R_E(G) + (A ^ (G & (H ^ A))) + 0x9BDC06A725C71235ULL + W[14]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC19BF174CF692694ULL + W[15]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));

	W[ 0] += R1(W[14]) + W[9 ] + R0(W[1 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xE49B69C19EF14AD2ULL + W[ 0]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 1] += R1(W[15]) + W[10] + R0(W[2 ]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xEFBE4786384F25E3ULL + W[ 1]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[ 2] += R1(W[0 ]) + W[11] + R0(W[3 ]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x0FC19DC68B8CD5B5ULL + W[ 2]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[ 3] += R1(W[1 ]) + W[12] + R0(W[4 ]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x240CA1CC77AC9C65ULL + W[ 3]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[ 4] += R1(W[2 ]) + W[13] + R0(W[5 ]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x2DE92C6F592B0275ULL + W[ 4]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[ 5] += R1(W[3 ]) + W[14] + R0(W[6 ]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4A7484AA6EA6E483ULL + W[ 5]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[ 6] += R1(W[4 ]) + W[15] + R0(W[7 ]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5CB0A9DCBD41FBD4ULL + W[ 6]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[ 7] += R1(W[5 ]) + W[0 ] + R0(W[8 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x76F988DA831153B5ULL + W[ 7]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
	W[ 8] += R1(W[6 ]) + W[1 ] + R0(W[9 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x983E5152EE66DFABULL + W[ 8]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 9] += R1(W[7 ]) + W[2 ] + R0(W[10]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA831C66D2DB43210ULL + W[ 9]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[10] += R1(W[8 ]) + W[3 ] + R0(W[11]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0xB00327C898FB213FULL + W[10]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[11] += R1(W[9 ]) + W[4 ] + R0(W[12]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0xBF597FC7BEEF0EE4ULL + W[11]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[12] += R1(W[10]) + W[5 ] + R0(W[13]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0xC6E00BF33DA88FC2ULL + W[12]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[13] += R1(W[11]) + W[6 ] + R0(W[14]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD5A79147930AA725ULL + W[13]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[14] += R1(W[12]) + W[7 ] + R0(W[15]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x06CA6351E003826FULL + W[14]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[15] += R1(W[13]) + W[8 ] + R0(W[0 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x142929670A0E6E70ULL + W[15]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																    																						  
	W[ 0] += R1(W[14]) + W[9 ] + R0(W[1 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x27B70A8546D22FFCULL + W[ 0]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 1] += R1(W[15]) + W[10] + R0(W[2 ]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x2E1B21385C26C926ULL + W[ 1]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[ 2] += R1(W[0 ]) + W[11] + R0(W[3 ]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x4D2C6DFC5AC42AEDULL + W[ 2]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[ 3] += R1(W[1 ]) + W[12] + R0(W[4 ]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x53380D139D95B3DFULL + W[ 3]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[ 4] += R1(W[2 ]) + W[13] + R0(W[5 ]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x650A73548BAF63DEULL + W[ 4]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[ 5] += R1(W[3 ]) + W[14] + R0(W[6 ]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x766A0ABB3C77B2A8ULL + W[ 5]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[ 6] += R1(W[4 ]) + W[15] + R0(W[7 ]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x81C2C92E47EDAEE6ULL + W[ 6]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[ 7] += R1(W[5 ]) + W[0 ] + R0(W[8 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x92722C851482353BULL + W[ 7]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
	W[ 8] += R1(W[6 ]) + W[1 ] + R0(W[9 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xA2BFE8A14CF10364ULL + W[ 8]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 9] += R1(W[7 ]) + W[2 ] + R0(W[10]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA81A664BBC423001ULL + W[ 9]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[10] += R1(W[8 ]) + W[3 ] + R0(W[11]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0xC24B8B70D0F89791ULL + W[10]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[11] += R1(W[9 ]) + W[4 ] + R0(W[12]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0xC76C51A30654BE30ULL + W[11]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[12] += R1(W[10]) + W[5 ] + R0(W[13]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0xD192E819D6EF5218ULL + W[12]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[13] += R1(W[11]) + W[6 ] + R0(W[14]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD69906245565A910ULL + W[13]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[14] += R1(W[12]) + W[7 ] + R0(W[15]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0xF40E35855771202AULL + W[14]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[15] += R1(W[13]) + W[8 ] + R0(W[0 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x106AA07032BBD1B8ULL + W[15]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		
	W[ 0] += R1(W[14]) + W[9 ] + R0(W[1 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x19A4C116B8D2D0C8ULL + W[ 0]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 1] += R1(W[15]) + W[10] + R0(W[2 ]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x1E376C085141AB53ULL + W[ 1]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[ 2] += R1(W[0 ]) + W[11] + R0(W[3 ]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x2748774CDF8EEB99ULL + W[ 2]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[ 3] += R1(W[1 ]) + W[12] + R0(W[4 ]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x34B0BCB5E19B48A8ULL + W[ 3]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[ 4] += R1(W[2 ]) + W[13] + R0(W[5 ]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x391C0CB3C5C95A63ULL + W[ 4]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[ 5] += R1(W[3 ]) + W[14] + R0(W[6 ]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4ED8AA4AE3418ACBULL + W[ 5]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[ 6] += R1(W[4 ]) + W[15] + R0(W[7 ]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5B9CCA4F7763E373ULL + W[ 6]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[ 7] += R1(W[5 ]) + W[0 ] + R0(W[8 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x682E6FF3D6B2B8A3ULL + W[ 7]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
	W[ 8] += R1(W[6 ]) + W[1 ] + R0(W[9 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x748F82EE5DEFB2FCULL + W[ 8]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 9] += R1(W[7 ]) + W[2 ] + R0(W[10]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x78A5636F43172F60ULL + W[ 9]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[10] += R1(W[8 ]) + W[3 ] + R0(W[11]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x84C87814A1F0AB72ULL + W[10]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[11] += R1(W[9 ]) + W[4 ] + R0(W[12]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x8CC702081A6439ECULL + W[11]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[12] += R1(W[10]) + W[5 ] + R0(W[13]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x90BEFFFA23631E28ULL + W[12]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[13] += R1(W[11]) + W[6 ] + R0(W[14]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xA4506CEBDE82BDE9ULL + W[13]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[14] += R1(W[12]) + W[7 ] + R0(W[15]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0xBEF9A3F7B2C67915ULL + W[14]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[15] += R1(W[13]) + W[8 ] + R0(W[0 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC67178F2E372532BULL + W[15]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																																							  
	W[ 0] += R1(W[14]) + W[9 ] + R0(W[1 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xCA273ECEEA26619CULL + W[ 0]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 1] += R1(W[15]) + W[10] + R0(W[2 ]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xD186B8C721C0C207ULL + W[ 1]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[ 2] += R1(W[0 ]) + W[11] + R0(W[3 ]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0xEADA7DD6CDE0EB1EULL + W[ 2]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[ 3] += R1(W[1 ]) + W[12] + R0(W[4 ]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0xF57D4F7FEE6ED178ULL + W[ 3]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[ 4] += R1(W[2 ]) + W[13] + R0(W[5 ]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x06F067AA72176FBAULL + W[ 4]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[ 5] += R1(W[3 ]) + W[14] + R0(W[6 ]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x0A637DC5A2C898A6ULL + W[ 5]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[ 6] += R1(W[4 ]) + W[15] + R0(W[7 ]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x113F9804BEF90DAEULL + W[ 6]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[ 7] += R1(W[5 ]) + W[0 ] + R0(W[8 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x1B710B35131C471BULL + W[ 7]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
	W[ 8] += R1(W[6 ]) + W[1 ] + R0(W[9 ]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x28db77f523047d84ULL + W[ 8]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
	W[ 9] += R1(W[7 ]) + W[2 ] + R0(W[10]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x32caab7b40c72493ULL + W[ 9]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
	W[10] += R1(W[8 ]) + W[3 ] + R0(W[11]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x3c9ebe0a15c9bebcULL + W[10]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
	W[11] += R1(W[9 ]) + W[4 ] + R0(W[12]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x431d67c49c100d4cULL + W[11]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
	W[12] += R1(W[10]) + W[5 ] + R0(W[13]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x4cc5d4becb3e42b6ULL + W[12]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
	W[13] += R1(W[11]) + W[6 ] + R0(W[14]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x597f299cfc657e2aULL + W[13]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
	W[14] += R1(W[12]) + W[7 ] + R0(W[15]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5fcb6fab3ad6faecULL + W[14]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
	W[15] += R1(W[13]) + W[8 ] + R0(W[0 ]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x6c44198c4a475817ULL + W[15]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));

	state[0] += A;
	state[1] += B;
	state[2] += C;
	state[3] += D;
	state[4] += E;
	state[5] += F;
	state[6] += G;
	state[7] += H;
}
PUBLIC void hash_sha512(const char* message, char* hash)
{
	uint32_t nt_buffer[8];
	uint64_t W[16];
	uint64_t sha512_state[8];
	uint32_t tmp0, tmp1;

	uint32_t len = (uint32_t)strlen(message);

	memset(nt_buffer, 0, sizeof(nt_buffer));
	memset(W, 0, sizeof(W));

	strcpy((char*)nt_buffer, message);
	((unsigned char*)nt_buffer)[len] = 0x80;

	SWAP_ENDIANNESS(tmp0, nt_buffer[0]);
	SWAP_ENDIANNESS(tmp1, nt_buffer[1]);
	W[0] = (((uint64_t)tmp0) << 32) + tmp1;
	SWAP_ENDIANNESS(tmp0, nt_buffer[2]);
	SWAP_ENDIANNESS(tmp1, nt_buffer[3]);
	W[1] = (((uint64_t)tmp0) << 32) + tmp1;
	SWAP_ENDIANNESS(tmp0, nt_buffer[4]);
	SWAP_ENDIANNESS(tmp1, nt_buffer[5]);
	W[2] = (((uint64_t)tmp0) << 32) + tmp1;

	SWAP_ENDIANNESS(tmp0, nt_buffer[6]);
	W[3] = ((uint64_t)tmp0) << 32;
	W[15] = len << 3;

	sha512_state[0] = 0x6A09E667F3BCC908ULL;
	sha512_state[1] = 0xBB67AE8584CAA73BULL;
	sha512_state[2] = 0x3C6EF372FE94F82BULL;
	sha512_state[3] = 0xA54FF53A5F1D36F1ULL;
	sha512_state[4] = 0x510E527FADE682D1ULL;
	sha512_state[5] = 0x9B05688C2B3E6C1FULL;
	sha512_state[6] = 0x1F83D9ABFB41BD6BULL;
	sha512_state[7] = 0x5BE0CD19137E2179ULL;
	sha512_process_block(sha512_state, W);

	hash[0] = 0;
	for (uint32_t i = 0; i < 8; i++)
		sprintf(hash + strlen(hash), "%016llx", sha512_state[i]);
}

// Hash a file
#ifdef _WIN32
	#include <io.h>
#endif
PUBLIC void hash_file(void* void_data)
{
	HASH_FILE_DATA* data = (HASH_FILE_DATA*)void_data;
	int64_t file_size = 0;

	uint32_t md4_state[4];
	uint32_t md5_state[4];
	uint32_t sha1_state[5];
	uint32_t sha256_state[8];
	uint64_t sha512_state[8];

	unsigned char buffer[128+128+16];
	uint32_t W[16];
	uint32_t* buffer_uint = (uint32_t*)buffer;
	uint32_t bytes_read;

	FILE* file = fopen(data->filename, "rb");
	if (file)
	{
		int64_t lenght_of_file = _filelengthi64(fileno(file));
		// Init states
		md4_state [0] = INIT_A; md4_state [1] = INIT_B; md4_state [2] = INIT_C; md4_state [3] = INIT_D;
		md5_state [0] = INIT_A; md5_state [1] = INIT_B; md5_state [2] = INIT_C; md5_state [3] = INIT_D;
		sha1_state[0] = INIT_A; sha1_state[1] = INIT_B; sha1_state[2] = INIT_C; sha1_state[3] = INIT_D; sha1_state[4] = INIT_E;
		sha256_state[0] = 0x6A09E667;  sha512_state[0] = 0x6A09E667F3BCC908ULL;
		sha256_state[1] = 0xBB67AE85;  sha512_state[1] = 0xBB67AE8584CAA73BULL;
		sha256_state[2] = 0x3C6EF372;  sha512_state[2] = 0x3C6EF372FE94F82BULL;
		sha256_state[3] = 0xA54FF53A;  sha512_state[3] = 0xA54FF53A5F1D36F1ULL;
		sha256_state[4] = 0x510E527F;  sha512_state[4] = 0x510E527FADE682D1ULL;
		sha256_state[5] = 0x9B05688C;  sha512_state[5] = 0x9B05688C2B3E6C1FULL;
		sha256_state[6] = 0x1F83D9AB;  sha512_state[6] = 0x1F83D9ABFB41BD6BULL;
		sha256_state[7] = 0x5BE0CD19;  sha512_state[7] = 0x5BE0CD19137E2179ULL;	

		do
		{
			bytes_read = (uint32_t)fread(buffer, 1, 128, file);
			file_size += bytes_read;

			if (file_size & 0x00800000)
			{
				data->file_size = file_size;
				data->send_message(data->wnd_handle, (int)(file_size * 100 / lenght_of_file));
			}

			if (bytes_read >= 128)
			{
				// MD4
				md4_process_block(md4_state, buffer_uint);
				md4_process_block(md4_state, buffer_uint + 16);
				// MD5
				md5_process_block(md5_state, buffer_uint);
				md5_process_block(md5_state, buffer_uint + 16);

				// Big Endian formats
				swap_endianness_array(buffer_uint, 32);
				// SHA1
				memcpy(W, buffer, 64);
				sha1_process_block_simd(sha1_state, W, 1);
				memcpy(W, buffer + 64, 64);
				sha1_process_block_simd(sha1_state, W, 1);
				// SHA256
				memcpy(W, buffer, 64);
				sha256_process_block(sha256_state, W);
				memcpy(W, buffer + 64, 64);
				sha256_process_block(sha256_state, W);
				// SHA512
				for (uint32_t i = 0; i < 16; i++)
				{
					uint32_t tmp = buffer_uint[2 * i];
					buffer_uint[2 * i] = buffer_uint[2 * i + 1];
					buffer_uint[2 * i + 1] = tmp;
				}
				sha512_process_block(sha512_state, (uint64_t*)buffer_uint);
			}
			else// end of file
			{
				// Add 0x80
				buffer[bytes_read] = 0x80;
				memset(buffer + bytes_read + 1, 0, 128+16);

				uint32_t num_blocks = 1 + (bytes_read + 8) / 64;
				// Put lenght
				file_size <<= 3;
				((uint64_t*)buffer)[(num_blocks - 1) * 8 + 7] = file_size;

				for (uint32_t i = 0; i < num_blocks; i++)
				{
					md4_process_block(md4_state, buffer_uint + i * 16);
					md5_process_block(md5_state, buffer_uint + i * 16);
				}

				// Big Endian formats
				swap_endianness_array(buffer_uint, bytes_read / 4 + 1);

				uint32_t t = buffer_uint[(num_blocks - 1) * 16 + 14];
				buffer_uint[(num_blocks - 1) * 16 + 14] = buffer_uint[(num_blocks - 1) * 16 + 15];
				buffer_uint[(num_blocks - 1) * 16 + 15] = t;
				for (uint32_t i = 0; i < num_blocks; i++)
				{
					// SHA1
					memcpy(W, buffer + i * 64, 64);
					sha1_process_block_simd(sha1_state, W, 1);
					// SHA256
					memcpy(W, buffer + i * 64, 64);
					sha256_process_block(sha256_state, W);
				}

				// SHA512
				buffer_uint[(num_blocks - 1) * 16 + 14] = 0;
				buffer_uint[(num_blocks - 1) * 16 + 15] = 0;
				num_blocks = 1 + (bytes_read + 16) / 128;
				((uint64_t*)buffer_uint)[(num_blocks - 1) * 16 + 15] = file_size;
				for (uint32_t i = 0; i < (bytes_read / 8 + 1); i++)
				{
					uint32_t tmp = buffer_uint[2 * i];
					buffer_uint[2 * i] = buffer_uint[2 * i + 1];
					buffer_uint[2 * i + 1] = tmp;
				}
				for (uint32_t i = 0; i < num_blocks; i++)
					sha512_process_block(sha512_state, ((uint64_t*)buffer_uint) + 16 * i);

				bytes_read = 0;
			}
		}
		while (bytes_read);

		fclose(file);
		// Convert to hex
		data->md4_hash[0] = 0;
		for (uint32_t i = 0; i < 4; i++)
		{
			SWAP_ENDIANNESS(md4_state[i], md4_state[i]);
			sprintf(data->md4_hash + strlen(data->md4_hash), "%08X", md4_state[i]);
		}
		data->md5_hash[0] = 0;
		for (uint32_t i = 0; i < 4; i++)
		{
			SWAP_ENDIANNESS(md5_state[i], md5_state[i]);
			sprintf(data->md5_hash + strlen(data->md5_hash), "%08X", md5_state[i]);
		}
		data->sha1_hash[0] = 0;
		for (uint32_t i = 0; i < 5; i++)
			sprintf(data->sha1_hash+strlen(data->sha1_hash), "%08X", sha1_state[i]);
		data->sha256_hash[0] = 0;
		for (uint32_t i = 0; i < 8; i++)
			sprintf(data->sha256_hash+strlen(data->sha256_hash), "%08X", sha256_state[i]);
		data->sha512_hash[0] = 0;
		for (uint32_t i = 0; i < 8; i++)
			sprintf(data->sha512_hash+strlen(data->sha512_hash), "%016llX", sha512_state[i]);
	}

	data->file_size = file_size >> 3;
	data->send_message(data->wnd_handle, 100);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LM hashing
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE const unsigned char SBox[8 * 64] = {
	//S0
	7, 12, 2, 15, 4, 10, 11, 12, 11, 6, 7, 9, 13, 0, 4, 10, 2, 5, 8, 3, 15, 9, 6, 5, 8, 3, 1, 14, 1, 14, 13, 0, 0, 5, 15, 10, 7, 9, 2, 5, 14, 3, 1, 12, 11, 12, 8, 6, 15, 6, 3, 13, 4, 10, 9, 0, 2, 13, 4, 7, 8, 1, 14, 11,
	//S1
	240, 192, 128, 176, 96, 240, 208, 64, 16, 32, 112, 224, 192, 16, 32, 112, 144, 48, 224, 0, 48, 96, 0, 144, 64, 128, 176, 80, 160, 208, 80, 160, 0, 176, 112, 16, 80, 192, 32, 240, 224, 80, 208, 128, 176, 32, 128, 64, 160, 208, 16, 96, 144, 0, 192, 160, 48, 224, 96, 48, 64, 112, 240, 144,
	//S2
	5, 8, 0, 11, 11, 13, 6, 8, 6, 13, 12, 2, 1, 10, 15, 5, 11, 4, 14, 1, 8, 2, 5, 15, 12, 3, 2, 13, 6, 13, 9, 10, 9, 3, 7, 14, 2, 4, 9, 3, 15, 4, 10, 1, 12, 7, 0, 14, 0, 10, 9, 7, 11, 7, 0, 12, 6, 15, 5, 8, 1, 4, 14, 3,
	//S3
	224, 80, 176, 192, 176, 96, 16, 240, 0, 48, 96, 80, 96, 208, 240, 128, 128, 240, 32, 144, 64, 128, 224, 32, 208, 160, 128, 48, 48, 64, 80, 224, 112, 144, 208, 0, 192, 0, 160, 96, 144, 224, 0, 176, 80, 176, 192, 16, 16, 192, 64, 160, 160, 112, 48, 208, 32, 16, 112, 64, 240, 32, 144, 112,
	//S4
	4, 7, 2, 13, 1, 10, 15, 6, 14, 2, 5, 8, 11, 12, 6, 5, 2, 4, 8, 3, 12, 15, 3, 0, 13, 11, 14, 4, 7, 1, 0, 10, 3, 13, 4, 1, 10, 0, 9, 15, 5, 14, 11, 7, 0, 9, 12, 2, 8, 3, 13, 14, 15, 5, 10, 9, 6, 8, 1, 11, 9, 6, 7, 12,
	//S5
	48, 128, 80, 240, 80, 240, 32, 64, 144, 64, 224, 48, 96, 16, 144, 160, 0, 176, 96, 128, 192, 32, 176, 112, 112, 224, 0, 208, 160, 208, 192, 16, 144, 112, 32, 192, 240, 160, 64, 48, 64, 16, 144, 160, 48, 192, 240, 80, 224, 0, 208, 112, 32, 80, 128, 224, 128, 176, 96, 0, 208, 96, 16, 176,
	//S6
	2, 8, 13, 2, 12, 5, 3, 15, 4, 13, 7, 11, 9, 6, 14, 1, 15, 3, 0, 12, 10, 0, 5, 10, 1, 14, 11, 7, 6, 9, 8, 4, 11, 6, 0, 13, 7, 9, 12, 10, 13, 11, 14, 1, 10, 0, 3, 15, 2, 8, 9, 2, 4, 7, 15, 4, 8, 5, 5, 14, 1, 12, 6, 3,
	//S7
	176, 64, 128, 240, 96, 240, 80, 192, 16, 32, 176, 16, 208, 128, 224, 32, 80, 144, 48, 160, 160, 0, 0, 112, 192, 112, 96, 208, 48, 224, 144, 64, 224, 208, 64, 128, 144, 48, 32, 80, 32, 128, 112, 224, 112, 64, 16, 176, 0, 96, 240, 48, 240, 192, 192, 160, 80, 176, 144, 0, 160, 16, 96, 208
};

#define COPY_BIT(j,i)	if((c[i/8]) & (1 << (i%8))) hash[j/8] |= (1 << (j%8))

PRIVATE void auth_DEShash(unsigned char *hash, const unsigned char *key)
{
	unsigned char c0 = 142;
	unsigned char c1 = 12;
	unsigned char c2 = 55;
	unsigned char c3 = 41;
	unsigned char c4 = 25;
	unsigned char c5 = 69;
	unsigned char c6 = 64;
	unsigned char c7 = 33;

	unsigned char k0 = key[0];
	unsigned char k1 = key[1];
	unsigned char k2 = key[2];
	unsigned char k3 = key[3];
	unsigned char k4 = key[4];
	unsigned char k5 = key[5];
	unsigned char k6 = key[6];

	unsigned char c_param, k_param, c0_4, c2_2, c2_1;

	// 1
	c0_4 = c4 >> 4; c2_2 = c6 << 2; c2_1 = c6 >> 1;
	c_param = ((c7 & 17) << 1) + ( c6 & 24)                 	    + (c0_4 & 4)                        + (c5 >> 7); k_param = ((k1 << 4) & 32) + ((k5 >> 1) & 16) + ( k6 & 8)        + ( k3 & 4 )       + ((k1 >> 6) & 2)  + ((k5 >> 3) & 1) ; c0 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c6 & 17) << 1) + ( c7 & 24)                         + ((c5 & 8) >> 1)                   + (c4 & 1) ; k_param = ((k3 << 2) & 32) + ((k6 >> 2) & 16) + ((k0 << 3) & 8)  + ((k0 >> 4) & 4)  + ((k2 >> 6) & 2)  + ((k4 >> 3) & 1) ; c0 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c4 & 17)       + ((c5 >> 3) & 8) + (c2_2 & 4)      + ( c7 & 2)                  ; k_param = ((k2 << 3) & 32) + ((k6 >> 1) & 16) + ((k2 << 2) & 8)  + ((k0 >> 3) & 4)  + ( k4 & 2)        + ((k3 >> 1) & 1) ; c1 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c7 >> 1) & 33) + ( c4 & 18)       + (c2_2 & 8)      + ((c5 << 1) & 4)                              ; k_param = ((k2 << 5) & 32) + ((k0 >> 3) & 16) + ((k3 << 3) & 8)  + ((k1 << 2) & 4)  + ((k4 >> 3) & 2)  + ((k6 >> 4) & 1) ; c1 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c5 & 34)       + ((c6 >> 3) & 16) + (c0_4 & 8)      + ((c4 << 1) & 4)                   + (c7 >> 7); k_param = ((k4 >> 2) & 32) + ((k5 << 4) & 16) + ((k4 >> 2) & 8)  + ((k3 >> 5) & 4)  + ((k2 >> 3) & 2)  + ((k0 >> 4) & 1) ; c2 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c5 & 33)       + ((c7 >> 3) & 16) + ((c7 << 1) & 8) + ( c4 & 4)       + (c2_1 & 2)                 ; k_param = ((k5 >> 1) & 32) + ((k3 >> 1) & 16) + ( k0 & 8)        + ((k5 << 1) & 4)  + ((k3 >> 5) & 2)  + ((k2 >> 3) & 1) ; c2 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c6 & 36)       + ( c5 & 17)       + ((c7 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k2 >> 1) & 32) + ((k4 >> 2) & 16) + ((k6 << 3) & 8)  + ((k2 >> 3) & 4)  + ((k1 >> 1) & 2)  + ((k6 >> 2) & 1) ; c3 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c4 & 40)       + (c2_1 & 16)                        + ( c5 & 4)       + ((c5 >> 6) & 2) + (c7 & 1) ; k_param = ((k4 << 5) & 32) + ((k1 << 1) & 16) + ((k6 << 2) & 8)  + ((k1 >> 2) & 4)  + ((k3 >> 3) & 2)  + ((k6 >> 7) & 1) ; c3 ^= SBox[7 * 64 + c_param^k_param];
	//2
	c0_4 = c0 >> 4; c2_2 = c2 << 2; c2_1 = c2 >> 1;
	c_param = ((c3 << 1) & 34) + ( c2 & 24)                 	    + (c0_4 & 4)                        + (c1 >> 7); k_param = ((k0 >> 5) & 2 ) + ((k4 >> 2) & 1 ) + ((k5 << 1) & 8 ) + ((k2 << 1) & 4 ) + ( k4 & 16)       + ((k0 << 5) & 32); c4 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c2 << 1) & 34) + ( c3 & 24)                         + ((c1 & 8) >> 1)                   + (c0 & 1) ; k_param = ((k2 << 3) & 32) + ((k5 >> 1) & 16) + ((k0 >> 4) & 8 ) + ((k6 >> 2) & 4 ) + ((k1 >> 5) & 2 ) + ((k3 >> 2) & 1 ); c4 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c0 & 17)       + ((c1 >> 3) & 8) + (c2_2 & 4)      + ( c3 & 2)                  ; k_param = ((k6 >> 1) & 4 ) + ( k2 & 1 )       + ((k1 << 3) & 8 ) + ((k1 << 4) & 32) + ((k3 << 1) & 2 ) + ( k5 & 16)      ; c5 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c3 >> 1) & 33) + ( c0 & 18)       + (c2_2 & 8)      + ((c1 << 1) & 4)                              ; k_param = ((k5 >> 3) & 1 ) + ((k6 >> 1) & 16) + ((k6 >> 3) & 8 ) + ((k2 >> 2) & 32) + ((k1 >> 5) & 4 ) + ((k3 >> 2) & 2 ); c5 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c1 & 34)       + ((c2 >> 3) & 16) + (c0_4 & 8)      + ((c0 << 1) & 4)                   + (c3 >> 7); k_param = ((k1 >> 2) & 2 ) + ((k2 >> 4) & 4 ) + ((k3 >> 1) & 8 ) + ((k5 >> 3) & 16) + ((k3 >> 1) & 32) + ( k6 & 1)       ; c6 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c1 & 33)       + ((c3 >> 3) & 16) + ((c3 << 1) & 8) + ( c0 & 4)       + (c2_1 & 2)                 ; k_param = ( k4 & 32)       + ( k2 & 16)       + ((k3 >> 4) & 8 ) + ((k4 << 2) & 4 ) + ((k1 >> 2) & 1 ) + ((k2 >> 4) & 2 ); c6 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c2 & 36)       + ( c1 & 17)       + ((c3 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k5 >> 1) & 1 ) + ((k1 >> 2) & 4)  + ((k3 >> 1) & 16) + ((k6 >> 4) & 8 ) + ( k0 & 2)        + ( k1 & 32)      ; c7 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c0 & 40)       + (c2_1 & 16)                        + ( c1 & 4)       + ((c1 >> 6) & 2) + (c3 & 1) ; k_param = ((k4 >> 2) & 32) + ((k0 << 2) & 16) + ((k0 >> 1) & 4 ) + ((k5 << 3) & 8 ) + ((k5 >> 6) & 1 ) + ((k2 >> 2) & 2 ); c7 ^= SBox[7 * 64 + c_param^k_param];
	//3
	c0_4 = c4 >> 4; c2_2 = c6 << 2; c2_1 = c6 >> 1;
	c_param = ((c7 & 17) << 1) + ( c6 & 24)                 	    + (c0_4 & 4)                        + (c5 >> 7); k_param = ((k5 >> 2) & 2 ) + ( k2 & 1 )       + ((k1 >> 5) & 4 ) + ((k3 << 3) & 8 ) + ((k2 << 2) & 16) + ( k6 & 32)      ; c0 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c6 & 17) << 1) + ( c7 & 24)                         + ((c5 & 8) >> 1)                   + (c4 & 1) ; k_param = ((k0 << 5) & 32) + ((k3 << 1) & 16) + ( k4 & 4)        + ((k5 >> 1) & 8 ) + ((k6 >> 2) & 2)  + ( k1 & 1)       ; c0 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c4 & 17)       + ((c5 >> 3) & 8) + (c2_2 & 4)      + ( c7 & 2)                  ; k_param = ((k4 << 1) & 4 ) + ((k1 >> 6) & 1 ) + ((k0 >> 3) & 8 ) + ((k0 >> 2) & 32) + ((k5 >> 4) & 2)  + ((k3 << 2) & 16); c1 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c7 >> 1) & 33) + ( c4 & 18)       + (c2_2 & 8)      + ((c5 << 1) & 4)                              ; k_param = ((k3 >> 1) & 1 ) + ((k4 << 1) & 16) + ((k4 >> 1) & 8 ) + ( k0 & 32)       + ((k6 >> 2) & 4)  + ( k1 & 2)       ; c1 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c5 & 34)       + ((c6 >> 3) & 16) + (c0_4 & 8)      + ((c4 << 1) & 4)                   + (c7 >> 7); k_param = ((k6 >> 1) & 2 ) + ((k0 >> 2) & 4 ) + ((k1 << 1) & 8 ) + ((k3 >> 1) & 16) + ((k1 << 1) & 32) + ((k5 >> 6) & 1) ; c2 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c5 & 33)       + ((c7 >> 3) & 16) + ((c7 << 1) & 8) + ( c4 & 4)       + (c2_1 & 2)                 ; k_param = ((k2 << 2) & 32) + ((k0 << 2) & 16) + ((k1 >> 2) & 8 ) + ((k3 >> 4) & 4 ) + ((k6 >> 1) & 1)  + ((k0 >> 2) & 2) ; c2 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c6 & 36)       + ( c5 & 17)       + ((c7 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k4 >> 7) & 1 ) + ((k3 >> 5) & 4 ) + ((k1 << 1) & 16) + ((k4 >> 2) & 8 ) + ((k5 << 1) & 2)  + ((k6 << 5) & 32); c3 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c4 & 40)       + (c2_1 & 16)                        + ( c5 & 4)       + ((c5 >> 6) & 2) + (c7 & 1) ; k_param = ( k2 & 32)       + ((k5 << 3) & 16) + ((k2 >> 4) & 4 ) + ((k4 >> 3) & 8 ) + ((k3 >> 4) & 1)  + ( k0 & 2)       ; c3 ^= SBox[7 * 64 + c_param^k_param];
	//4
	c0_4 = c0 >> 4; c2_2 = c2 << 2; c2_1 = c2 >> 1;
	c_param = ((c3 << 1) & 34) + ( c2 & 24)                 	    + (c0_4 & 4)                        + (c1 >> 7); k_param = ( k3 & 2)        + ((k1 >> 6) & 1)  + ((k6 >> 2) & 4)  + ((k5 >> 2) & 8)  + ((k0 << 4) & 16) + ((k4 << 2) & 32); c4 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c2 << 1) & 34) + ( c3 & 24)                         + ((c1 & 8) >> 1)                   + (c0 & 1) ; k_param = ( k6 & 32)       + ((k1 << 3) & 16) + ((k2 << 2) & 4)  + ((k3 << 1) & 8)  + ( k4 & 2)        + ((k0 >> 6) & 1) ; c4 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c0 & 17)       + ((c1 >> 3) & 8) + (c2_2 & 4)      + ( c3 & 2)                  ; k_param = ((k6 >> 4) & 4)  + ((k6 >> 3) & 1)  +  (k5 & 8)        + ((k5 << 1) & 32) + ((k3 >> 2) & 2)  + ((k1 << 4) & 16); c5 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c3 >> 1) & 33) + ( c0 & 18)       + (c2_2 & 8)      + ((c1 << 1) & 4)                              ; k_param = ((k2 >> 7) & 1)  + ((k2 << 3) & 16) + ((k2 << 1) & 8)  + ((k5 << 3) & 32) + ( k4 & 4)        + ((k0 >> 6) & 2) ; c5 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c1 & 34)       + ((c2 >> 3) & 16) + (c0_4 & 8)      + ((c0 << 1) & 4)                   + (c3 >> 7); k_param = ((k4 << 1) & 2)  + ((k6 >> 5) & 4)  + ((k6 << 2) & 8)  + ((k1 << 1) & 16) + ((k3 >> 2) & 32) + ((k3 >> 4) & 1) ; c6 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c1 & 33)       + ((c3 >> 3) & 16) + ((c3 << 1) & 8) + ( c0 & 4)       + (c2_1 & 2)                 ; k_param = ((k0 << 4) & 32) + ((k5 << 3) & 16) + ((k6 << 3) & 8)  + ((k1 >> 2) & 4)  + ((k5 >> 7) & 1)  + ((k2 >> 5) & 2) ; c6 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c2 & 36)       + ( c1 & 17)       + ((c3 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k2 >> 5) & 1)  + ((k1 >> 3) & 4)  + ((k6 << 2) & 16) + ( k2 & 8)        + ((k4 >> 5) & 2)  + ((k5 >> 1) & 32); c7 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c0 & 40)       + (c2_1 & 16)                        + ( c1 & 4)       + ((c1 >> 6) & 2) + (c3 & 1) ; k_param = ((k0 << 2) & 32) + ((k4 >> 3) & 16) + ((k0 >> 2) & 4)  + ((k2 >> 1) & 8)  + ((k1 >> 2) & 1)  + ((k5 << 1) & 2) ; c7 ^= SBox[7 * 64 + c_param^k_param];
	//5
	c0_4 = c4 >> 4; c2_2 = c6 << 2; c2_1 = c6 >> 1;
	c_param = ((c7 & 17) << 1) + ( c6 & 24)                 	    + (c0_4 & 4)                        + (c5 >> 7); k_param = ((k2 >> 6) & 2)  + ((k6 >> 3) & 1)  + ( k4 & 4)        + ( k3 & 8)        + ((k6 >> 1) & 16) + ((k2 << 4) & 32); c0 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c6 & 17) << 1) + ( c7 & 24)                         + ((c5 & 8) >> 1)                   + (c4 & 1) ; k_param = ((k4 << 2) & 32) + ((k0 >> 3) & 16) + ((k1 >> 4) & 4)  + ((k1 << 3) & 8)  + ((k6 >> 5) & 2)  + ((k5 >> 3) & 1) ; c0 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c4 & 17)       + ((c5 >> 3) & 8) + (c2_2 & 4)      + ( c7 & 2)                  ; k_param = ((k4 >> 2) & 4)  + ((k4 >> 1) & 1)  + ((k3 << 2) & 8)  + ((k3 << 3) & 32) + ( k1 & 2)        + ((k0 >> 2) & 16); c1 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c7 >> 1) & 33) + ( c4 & 18)       + (c2_2 & 8)      + ((c5 << 1) & 4)                              ; k_param = ((k0 >> 5) & 1)  + ((k1 >> 3) & 16) + ((k0 << 3) & 8)  + ((k3 << 5) & 32) + ((k2 << 2) & 4)  + ((k5 >> 3) & 2) ; c1 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c5 & 34)       + ((c6 >> 3) & 16) + (c0_4 & 8)      + ((c4 << 1) & 4)                   + (c7 >> 7); k_param = ((k3 >> 5) & 2)  + ((k4 >> 3) & 4)  + ((k5 >> 4) & 8)  + ((k6 << 2) & 16) + ( k1 & 32)       + ((k1 >> 2) & 1) ; c2 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c5 & 33)       + ((c7 >> 3) & 16) + ((c7 << 1) & 8) + ( c4 & 4)       + (c2_1 & 2)                 ; k_param = ((k5 << 5) & 32) + ((k4 >> 3) & 16) + ((k5 >> 3) & 8)  + ((k3 >> 5) & 4)  + ((k3 >> 5) & 1)  + ((k0 >> 3) & 2) ; c2 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c6 & 36)       + ( c5 & 17)       + ((c7 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k0 >> 3) & 1)  + ((k6 << 2) & 4)  + ((k4 << 4) & 16) + ((k0 << 2) & 8)  + ((k2 >> 3) & 2)  + ((k3 << 1) & 32); c3 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c4 & 40)       + (c2_1 & 16)                        + ( c5 & 4)       + ((c5 >> 6) & 2) + (c7 & 1) ; k_param = ((k2 >> 1) & 32) + ((k2 >> 1) & 16) + ((k6 >> 5) & 4)  + ((k0 << 1) & 8)  + ((k6 >> 1) & 1)  + ((k4 >> 5) & 2) ; c3 ^= SBox[7 * 64 + c_param^k_param];
	//6
	c0_4 = c0 >> 4; c2_2 = c2 << 2; c2_1 = c2 >> 1;
	c_param = ((c3 << 1) & 34) + ( c2 & 24)                 	    + (c0_4 & 4)                        + (c1 >> 7); k_param = ((k0 >> 4) & 2)  + ((k4 >> 1) & 1)  + ((k2 << 2) & 4)  + ((k1 << 2) & 8)  + ((k4 << 1) & 16) + ((k1 >> 2) & 32); c4 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c2 << 1) & 34) + ( c3 & 24)                         + ((c1 & 8) >> 1)                   + (c0 & 1) ; k_param = ((k2 << 4) & 32) + ( k5 & 16)       + ((k6 >> 1) & 4)  + ((k0 >> 3) & 8)  + ((k4 >> 3) & 2)  + ((k3 >> 1) & 1) ; c4 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c0 & 17)       + ((c1 >> 3) & 8) + (c2_2 & 4)      + ( c3 & 2)                  ; k_param = ( k2 & 4)        + ((k6 >> 6) & 1)  + ((k2 >> 4) & 8)  + ((k1 << 5) & 32) + ((k0 >> 6) & 2)  + ((k5 << 1) & 16); c5 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c3 >> 1) & 33) + ( c0 & 18)       + (c2_2 & 8)      + ((c1 << 1) & 4)                              ; k_param = ((k5 >> 2) & 1)  + ( k6 & 16)       + ((k6 >> 2) & 8)  + ( k5 & 32)       + ((k1 >> 4) & 4)  + ((k3 >> 1) & 2) ; c5 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c1 & 34)       + ((c2 >> 3) & 16) + (c0_4 & 8)      + ((c0 << 1) & 4)                   + (c3 >> 7); k_param = ((k1 >> 3) & 2)  + ((k2 >> 1) & 4)  + ((k3 >> 2) & 8)  + ((k4 << 4) & 16) + ((k6 << 5) & 32) + ((k6 >> 1) & 1) ; c6 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c1 & 33)       + ((c3 >> 3) & 16) + ((c3 << 1) & 8) + ( c0 & 4)       + (c2_1 & 2)                 ; k_param = ((k4 >> 1) & 32) + ((k2 >> 1) & 16) + ((k3 >> 1) & 8)  + ((k1 >> 3) & 4)  + ((k1 >> 3) & 1)  + ((k6 >> 6) & 2) ; c6 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c2 & 36)       + ( c1 & 17)       + ((c3 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k2 >> 6) & 1)  + ((k5 >> 4) & 4)  + ((k3 >> 2) & 16) + ((k5 << 3) & 8)  + ((k0 >> 1) & 2)  + ((k1 << 3) & 32); c7 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c0 & 40)       + (c2_1 & 16)                        + ( c1 & 4)       + ((c1 >> 6) & 2) + (c3 & 1) ; k_param = ((k0 << 1) & 32) + ((k0 << 1) & 16) + ((k4 >> 3) & 4)  + ((k5 << 2) & 8)  + ((k5 >> 7) & 1)  + ((k2 >> 3) & 2) ; c7 ^= SBox[7 * 64 + c_param^k_param];
	//7																																								 
	c0_4 = c4 >> 4; c2_2 = c6 << 2; c2_1 = c6 >> 1;																													 
	c_param = ((c7 & 17) << 1) + ( c6 & 24)                 	    + (c0_4 & 4)                        + (c5 >> 7); k_param = ((k5 >> 1) & 2)  + ((k6 >> 6) & 1)  + ((k1 >> 4) & 4)  + ((k0 >> 4) & 8)  + ((k2 << 3) & 16) + ((k6 << 1) & 32); c0 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c6 & 17) << 1) + ( c7 & 24)                         + ((c5 & 8) >> 1)                   + (c4 & 1) ; k_param = ((k1 >> 2) & 32) + ((k3 << 2) & 16) + ((k4 << 1) & 4)  + ( k5 & 8)        + ((k2 >> 1) & 2)  + ((k2 >> 7) & 1) ; c0 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c4 & 17)       + ((c5 >> 3) & 8) + (c2_2 & 4)      + ( c7 & 2)                  ; k_param = ((k0 << 2) & 4)  + ((k4 >> 4) & 1)  + ((k0 >> 2) & 8)  + ((k0 >> 1) & 32) + ((k5 >> 3) & 2)  + ((k3 << 3) & 16); c1 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c7 >> 1) & 33) + ( c4 & 18)       + (c2_2 & 8)      + ((c5 << 1) & 4)                              ; k_param = ( k3 & 1)        + ((k4 << 2) & 16) + ( k4 & 8)        + ((k3 << 2) & 32) + ((k6 >> 1) & 4)  + ((k1 << 1) & 2) ; c1 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c5 & 34)       + ((c6 >> 3) & 16) + (c0_4 & 8)      + ((c4 << 1) & 4)                   + (c7 >> 7); k_param = ((k3 >> 6) & 2)  + ((k0 << 1) & 4)  + ( k1 & 8)        + ((k3 >> 2) & 16) + ((k5 >> 1) & 32) + ((k5 >> 7) & 1) ; c2 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c5 & 33)       + ((c7 >> 3) & 16) + ((c7 << 1) & 8) + ( c4 & 4)       + (c2_1 & 2)                 ; k_param = ((k2 << 1) & 32) + ((k0 << 1) & 16) + ((k1 << 1) & 8)  + ((k6 << 2) & 4)  + ((k6 >> 2) & 1)  + ((k4 >> 4) & 2) ; c2 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c6 & 36)       + ( c5 & 17)       + ((c7 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k0 >> 4) & 1)  + ((k3 >> 2) & 4)  + ( k1 & 16)       + ((k4 >> 3) & 8)  + ( k5 & 2)        + ((k6 << 4) & 32); c3 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c4 & 40)       + (c2_1 & 16)                        + ( c5 & 4)       + ((c5 >> 6) & 2) + (c7 & 1) ; k_param = ((k6 >> 2) & 32) + ((k2 >> 2) & 16) + ((k2 >> 1) & 4)  + ((k4 >> 4) & 8)  + ((k3 >> 5) & 1)  + ((k0 >> 1) & 2) ; c3 ^= SBox[7 * 64 + c_param^k_param];
	//8
	c0_4 = c0 >> 4; c2_2 = c2 << 2; c2_1 = c2 >> 1;
	c_param = ((c3 << 1) & 34) + ( c2 & 24)                 	    + (c0_4 & 4)                        + (c1 >> 7); k_param = ((k3 << 1) & 2)  + ((k4 >> 4) & 1)  + ((k6 >> 1) & 4)  + ((k5 >> 1) & 8)  + ((k1 >> 3) & 16) + ((k4 << 3) & 32); c4 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c2 << 1) & 34) + ( c3 & 24)                         + ((c1 & 8) >> 1)                   + (c0 & 1) ; k_param = ((k6 << 1) & 32) + ((k1 << 4) & 16) + ((k6 >> 4) & 4)  + ((k3 << 2) & 8)  + ((k0 << 1) & 2)  + ((k0 >> 5) & 1) ; c4 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c0 & 17)       + ((c1 >> 3) & 8) + (c2_2 & 4)      + ( c3 & 2)                  ; k_param = ((k6 >> 3) & 4)  + ((k2 >> 2) & 1)  + ((k5 << 1) & 8)  + ((k5 << 2) & 32) + ((k3 >> 1) & 2)  + ((k2 >> 3) & 16); c5 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c3 >> 1) & 33) + ( c0 & 18)       + (c2_2 & 8)      + ((c1 << 1) & 4)                              ; k_param = ((k5 >> 5) & 1)  + ((k2 << 4) & 16) + ((k2 << 2) & 8)  + ((k1 << 4) & 32) + ((k4 << 1) & 4)  + ((k0 >> 5) & 2) ; c5 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c1 & 34)       + ((c2 >> 3) & 16) + (c0_4 & 8)      + ((c0 << 1) & 4)                   + (c3 >> 7); k_param = ((k1 >> 4) & 2)  + ((k5 << 2) & 4)  + ((k6 << 1) & 8)  + ( k1 & 16)       + ((k3 << 1) & 32) + ((k3 >> 5) & 1) ; c6 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c1 & 33)       + ((c3 >> 3) & 16) + ((c3 << 1) & 8) + ( c0 & 4)       + (c2_1 & 2)                 ; k_param = ((k0 << 3) & 32) + ((k2 >> 2) & 16) + ((k6 << 2) & 8)  + ((k5 >> 4) & 4)  + ( k4 & 1)        + ((k2 >> 2) & 2) ; c6 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c2 & 36)       + ( c1 & 17)       + ((c3 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k6 >> 7) & 1)  + ( k1 & 4)        + ((k3 >> 3) & 16) + ((k2 >> 1) & 8)  + ((k4 >> 6) & 2)  + ((k5 >> 2) & 32); c7 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c0 & 40)       + (c2_1 & 16)                        + ( c1 & 4)       + ((c1 >> 6) & 2) + (c3 & 1) ; k_param = ( k4 & 32)       + ( k0 & 16)       + ((k0 << 1) & 4)  + ((k2 >> 2) & 8)  + ((k1 >> 3) & 1)  + ( k5 & 2)       ; c7 ^= SBox[7 * 64 + c_param^k_param];
	//9																																							  				    														  
	c0_4 = c4 >> 4; c2_2 = c6 << 2; c2_1 = c6 >> 1;																												  				    														  
	c_param = ((c7 & 17) << 1) + ( c6 & 24)                 	    + (c0_4 & 4)                        + (c5 >> 7); k_param = ((k6 >> 5) & 2)  + ((k3 >> 3) & 1)  + ( k5 & 4)        + ( k4 & 8)        + ((k0 >> 2) & 16) + ((k3 << 4) & 32); c0 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c6 & 17) << 1) + ( c7 & 24)                         + ((c5 & 8) >> 1)                   + (c4 & 1) ; k_param = ((k5 << 2) & 32) + ((k1 >> 3) & 16) + ((k5 >> 3) & 4)  + ((k2 << 3) & 8)  + ((k0 >> 6) & 2)  + ((k6 >> 3) & 1) ; c0 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c4 & 17)       + ((c5 >> 3) & 8) + (c2_2 & 4)      + ( c7 & 2)                  ; k_param = ((k5 >> 2) & 4)  + ((k1 >> 1) & 1)  + ((k4 << 2) & 8)  + ((k4 << 3) & 32) + ( k2 & 2)        + ((k1 >> 2) & 16); c1 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c7 >> 1) & 33) + ( c4 & 18)       + (c2_2 & 8)      + ((c5 << 1) & 4)                              ; k_param = ((k4 >> 4) & 1)  + ((k2 >> 3) & 16) + ((k1 << 3) & 8)  + ((k0 << 5) & 32) + ((k3 << 2) & 4)  + ((k6 >> 3) & 2) ; c1 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c5 & 34)       + ((c6 >> 3) & 16) + (c0_4 & 8)      + ((c4 << 1) & 4)                   + (c7 >> 7); k_param = ((k0 >> 3) & 2)  + ((k5 >> 5) & 4)  + ((k5 << 2) & 8)  + ((k0 << 1) & 16) + ((k2 << 2) & 32) + ((k2 >> 4) & 1) ; c2 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c5 & 33)       + ((c7 >> 3) & 16) + ((c7 << 1) & 8) + ( c4 & 4)       + (c2_1 & 2)                 ; k_param = ((k6 << 3) & 32) + ((k1 >> 1) & 16) + ((k5 << 3) & 8)  + ((k4 >> 3) & 4)  + ((k4 >> 7) & 1)  + ((k1 >> 1) & 2) ; c2 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c6 & 36)       + ( c5 & 17)       + ((c7 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k5 >> 6) & 1)  + ((k0 << 1) & 4)  + ((k2 >> 2) & 16) + ( k1 & 8)        + ((k3 >> 5) & 2)  + ((k4 >> 1) & 32); c3 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c4 & 40)       + (c2_1 & 16)                        + ( c5 & 4)       + ((c5 >> 6) & 2) + (c7 & 1) ; k_param = ((k3 << 1) & 32) + ((k6 << 4) & 16) + ((k6 << 1) & 4)  + ((k1 >> 1) & 8)  + ((k0 >> 2) & 1)  + ((k4 << 1) & 2) ; c3 ^= SBox[7 * 64 + c_param^k_param];
	//10																																						  				    														  
	c0_4 = c0 >> 4; c2_2 = c2 << 2; c2_1 = c2 >> 1;																												  				    														  
	c_param = ((c3 << 1) & 34) + ( c2 & 24)                 	    + (c0_4 & 4)                        + (c1 >> 7); k_param = ((k4 >> 3) & 2)  + ((k1 >> 1) & 1)  + ((k3 << 2) & 4)  + ((k2 << 2) & 8)  + ((k5 << 1) & 16) + ((k2 >> 2) & 32); c4 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c2 << 1) & 34) + ( c3 & 24)                         + ((c1 & 8) >> 1)                   + (c0 & 1) ; k_param = ((k3 << 4) & 32) + ( k6 & 16)       + ((k3 >> 1) & 4)  + ((k1 >> 3) & 8)  + ((k5 >> 3) & 2)  + ((k4 >> 1) & 1) ; c4 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c0 & 17)       + ((c1 >> 3) & 8) + (c2_2 & 4)      + ( c3 & 2)                  ; k_param = ( k3 & 4)        + ((k0 >> 7) & 1)  + ((k6 >> 3) & 8)  + ((k2 << 5) & 32) + ((k1 >> 6) & 2)  + ((k6 << 1) & 16); c5 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c3 >> 1) & 33) + ( c0 & 18)       + (c2_2 & 8)      + ((c1 << 1) & 4)                              ; k_param = ((k2 >> 2) & 1)  + ((k0 >> 1) & 16) + ((k0 >> 3) & 8)  + ( k6 & 32)       + ((k5 >> 3) & 4)  + ((k4 >> 1) & 2) ; c5 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c1 & 34)       + ((c2 >> 3) & 16) + (c0_4 & 8)      + ((c0 << 1) & 4)                   + (c3 >> 7); k_param = ((k6 >> 6) & 2)  + ((k3 >> 3) & 4)  + ((k4 >> 4) & 8)  + ((k2 >> 2) & 16) + ((k0 << 4) & 32) + ((k0 >> 2) & 1) ; c6 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c1 & 33)       + ((c3 >> 3) & 16) + ((c3 << 1) & 8) + ( c0 & 4)       + (c2_1 & 2)                 ; k_param = ((k4 << 5) & 32) + ((k6 << 4) & 16) + ((k4 >> 3) & 8)  + ((k2 >> 1) & 4)  + ((k2 >> 5) & 1)  + ( k6 & 2)       ; c6 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c2 & 36)       + ( c1 & 17)       + ((c3 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k3 >> 4) & 1)  + ((k5 << 2) & 4)  + ( k0 & 16)       + ((k6 << 1) & 8)  + ((k1 >> 3) & 2)  + ((k2 << 1) & 32); c7 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c0 & 40)       + (c2_1 & 16)                        + ( c1 & 4)       + ((c1 >> 6) & 2) + (c3 & 1) ; k_param = ((k1 << 3) & 32) + ((k5 >> 2) & 16) + ((k5 >> 5) & 4)  + ((k3 >> 4) & 8)  + ((k5 >> 1) & 1)  + ((k3 >> 5) & 2) ; c7 ^= SBox[7 * 64 + c_param^k_param];
	//11																																		
	c0_4 = c4 >> 4; c2_2 = c6 << 2; c2_1 = c6 >> 1;																								
	c_param = ((c7 & 17) << 1) + ( c6 & 24)                 	    + (c0_4 & 4)                        + (c5 >> 7); k_param = ((k2 >> 1) & 2)  + ((k0 >> 7) & 1)  + ((k5 >> 3) & 4)  + ((k1 >> 4) & 8)  + ((k3 << 3) & 16) + ( k0 & 32)      ; c0 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c6 & 17) << 1) + ( c7 & 24)                         + ((c5 & 8) >> 1)                   + (c4 & 1) ; k_param = ((k2 >> 2) & 32) + ((k4 << 2) & 16) + ((k1 << 1) & 4)  + ( k6 & 8)        + ((k3 >> 1) & 2)  + ((k6 >> 6) & 1) ; c0 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c4 & 17)       + ((c5 >> 3) & 8) + (c2_2 & 4)      + ( c7 & 2)                  ; k_param = ((k1 << 2) & 4)  + ((k5 >> 4) & 1)  + ((k4 >> 1) & 8)  + ((k1 >> 1) & 32) + ((k6 >> 3) & 2)  + ((k4 << 3) & 16); c1 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c7 >> 1) & 33) + ( c4 & 18)       + (c2_2 & 8)      + ((c5 << 1) & 4)                              ; k_param = ( k0 & 1)        + ((k5 << 2) & 16) + ( k5 & 8)        + ((k4 << 2) & 32) + ((k3 >> 1) & 4)  + ((k2 << 1) & 2) ; c1 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c5 & 34)       + ((c6 >> 3) & 16) + (c0_4 & 8)      + ((c4 << 1) & 4)                   + (c7 >> 7); k_param = ((k4 >> 4) & 2)  + ((k1 >> 1) & 4)  + ((k2 >> 2) & 8)  + ( k0 & 16)       + ((k5 << 5) & 32) + ((k5 >> 1) & 1) ; c2 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c5 & 33)       + ((c7 >> 3) & 16) + ((c7 << 1) & 8) + ( c4 & 4)       + (c2_1 & 2)                 ; k_param = ((k3 >> 1) & 32) + ((k5 >> 2) & 16) + ((k2 >> 1) & 8)  + ((k0 << 1) & 4)  + ((k0 >> 3) & 1)  + ((k5 >> 6) & 2) ; c2 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c6 & 36)       + ( c5 & 17)       + ((c7 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k1 >> 2) & 1)  + ((k4 >> 4) & 4)  + ((k6 >> 3) & 16) + ((k4 << 3) & 8)  + ((k3 >> 6) & 2)  + ((k0 << 3) & 32); c3 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c4 & 40)       + (c2_1 & 16)                        + ( c5 & 4)       + ((c5 >> 6) & 2) + (c7 & 1) ; k_param = ((k6 << 4) & 32) + ( k3 & 16)       + ((k3 >> 3) & 4)  + ((k1 >> 2) & 8)  + ((k4 >> 7) & 1)  + ((k1 >> 3) & 2) ; c3 ^= SBox[7 * 64 + c_param^k_param];
	//12																																						  				    														  
	c0_4 = c0 >> 4; c2_2 = c2 << 2; c2_1 = c2 >> 1;																												  				    														  
	c_param = ((c3 << 1) & 34) + ( c2 & 24)                 	    + (c0_4 & 4)                        + (c1 >> 7); k_param = ((k0 << 1) & 2)  + ((k5 >> 4) & 1)  + ((k3 >> 1) & 4)  + ((k6 >> 1) & 8)  + ((k2 >> 3) & 16) + ((k5 << 3) & 32); c4 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c2 << 1) & 34) + ( c3 & 24)                         + ((c1 & 8) >> 1)                   + (c0 & 1) ; k_param = ( k0 & 32)       + ((k2 << 4) & 16) + ((k0 >> 5) & 4)  + ((k4 << 2) & 8)  + ((k1 << 1) & 2)  + ((k4 >> 4) & 1) ; c4 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c0 & 17)       + ((c1 >> 3) & 8) + (c2_2 & 4)      + ( c3 & 2)                  ; k_param = ((k0 >> 4) & 4)  + ((k3 >> 2) & 1)  + ((k2 << 1) & 8)  + ((k6 << 2) & 32) + ((k4 >> 1) & 2)  + ((k6 >> 2) & 16); c5 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c3 >> 1) & 33) + ( c0 & 18)       + (c2_2 & 8)      + ((c1 << 1) & 4)                              ; k_param = ((k6 >> 5) & 1)  + ((k3 << 4) & 16) + ((k3 << 2) & 8)  + ((k2 << 4) & 32) + ((k1 << 1) & 4)  + ((k1 >> 5) & 2) ; c5 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c1 & 34)       + ((c2 >> 3) & 16) + (c0_4 & 8)      + ((c0 << 1) & 4)                   + (c3 >> 7); k_param = ((k2 >> 2) & 2)  + ( k6 & 4)        + ( k0 & 8)        + ((k6 >> 3) & 16) + ((k4 >> 1) & 32) + ((k4 >> 7) & 1) ; c6 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c1 & 33)       + ((c3 >> 3) & 16) + ((c3 << 1) & 8) + ( c0 & 4)       + (c2_1 & 2)                 ; k_param = ((k1 << 1) & 32) + ( k3 & 16)       + ((k0 << 1) & 8)  + ((k5 << 2) & 4)  + ((k2 >> 6) & 1)  + ((k3 >> 4) & 2) ; c6 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c2 & 36)       + ( c1 & 17)       + ((c3 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k6 >> 1) & 1)  + ((k2 >> 2) & 4)  + ((k4 >> 1) & 16) + ((k3 >> 3) & 8)  + ((k1 >> 4) & 2)  + ((k5 << 4) & 32); c7 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c0 & 40)       + (c2_1 & 16)                        + ( c1 & 4)       + ((c1 >> 6) & 2) + (c3 & 1) ; k_param = ((k5 >> 2) & 32) + ((k1 << 2) & 16) + ((k1 >> 1) & 4)  + ((k6 << 3) & 8)  + ((k2 >> 5) & 1)  + ((k3 >> 6) & 2) ; c7 ^= SBox[7 * 64 + c_param^k_param];
	//13																																						  				    														  
	c0_4 = c4 >> 4; c2_2 = c6 << 2; c2_1 = c6 >> 1;																												  				    														  
	c_param = ((c7 & 17) << 1) + ( c6 & 24)                 	    + (c0_4 & 4)                        + (c5 >> 7); k_param = ((k6 >> 4) & 2)  + ((k3 >> 2) & 1)  + ((k1 << 1) & 4)  + ((k4 << 1) & 8)  + ((k0 >> 1) & 16) + ((k3 << 5) & 32); c0 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c6 & 17) << 1) + ( c7 & 24)                         + ((c5 & 8) >> 1)                   + (c4 & 1) ; k_param = ((k5 << 3) & 32) + ((k1 >> 2) & 16) + ((k5 >> 2) & 4)  + ((k6 >> 3) & 8)  + ((k0 >> 5) & 2)  + ((k2 >> 2) & 1) ; c0 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c4 & 17)       + ((c5 >> 3) & 8) + (c2_2 & 4)      + ( c7 & 2)                  ; k_param = ((k5 >> 1) & 4)  + ( k1 & 1)        + ((k0 << 3) & 8)  + ((k4 << 4) & 32) + ((k2 << 1) & 2)  + ( k4 & 16)      ; c1 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c7 >> 1) & 33) + ( c4 & 18)       + (c2_2 & 8)      + ((c5 << 1) & 4)                              ; k_param = ((k4 >> 3) & 1)  + ((k5 >> 1) & 16) + ((k2 >> 4) & 8)  + ((k1 >> 2) & 32) + ((k0 >> 5) & 4)  + ((k6 >> 2) & 2) ; c1 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c5 & 34)       + ((c6 >> 3) & 16) + (c0_4 & 8)      + ((c4 << 1) & 4)                   + (c7 >> 7); k_param = ( k0 & 2)        + ((k4 << 2) & 4)  + ((k2 >> 3) & 8)  + ((k4 >> 1) & 16) + ((k2 << 1) & 32) + ((k2 >> 5) & 1) ; c2 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c5 & 33)       + ((c7 >> 3) & 16) + ((c7 << 1) & 8) + ( c4 & 4)       + (c2_1 & 2)                 ; k_param = ((k3 >> 2) & 32) + ((k1 << 2) & 16) + ((k5 << 2) & 8)  + ((k4 >> 4) & 4)  + ((k0 >> 4) & 1)  + ((k1 >> 2) & 2) ; c2 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c6 & 36)       + ( c5 & 17)       + ((c7 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k5 >> 7) & 1)  + ( k0 & 4)        + ((k2 << 1) & 16) + ((k1 >> 1) & 8)  + ((k6 << 1) & 2)  + ((k4 >> 2) & 32); c3 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c4 & 40)       + (c2_1 & 16)                        + ( c5 & 4)       + ((c5 >> 6) & 2) + (c7 & 1) ; k_param = ( k3 & 32)       + ((k6 << 3) & 16) + ( k6 & 4)        + ((k5 >> 3) & 8)  + ((k0 >> 3) & 1)  + ((k1 >> 4) & 2) ; c3 ^= SBox[7 * 64 + c_param^k_param];
	//14																																		
	c0_4 = c0 >> 4; c2_2 = c2 << 2; c2_1 = c2 >> 1;																								
	c_param = ((c3 << 1) & 34) + ( c2 & 24)                 	    + (c0_4 & 4)                        + (c1 >> 7); k_param = ((k4 >> 2) & 2)  + ( k1 & 1)        + ((k0 >> 5) & 4)  + ((k2 << 3) & 8)  + ((k5 << 2) & 16) + ( k5 & 32)      ; c4 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c2 << 1) & 34) + ( c3 & 24)                         + ((c1 & 8) >> 1)                   + (c0 & 1) ; k_param = ((k3 << 5) & 32) + ((k6 << 1) & 16) + ( k3 & 4)        + ((k4 >> 1) & 8)  + ((k5 >> 2) & 2)  + ( k0 & 1)       ; c4 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c0 & 17)       + ((c1 >> 3) & 8) + (c2_2 & 4)      + ( c3 & 2)                  ; k_param = ((k3 << 1) & 4)  + ((k0 >> 6) & 1)  + ((k6 >> 2) & 8)  + ((k6 >> 1) & 32) + ((k1 >> 5) & 2)  + ((k2 << 2) & 16); c5 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c3 >> 1) & 33) + ( c0 & 18)       + (c2_2 & 8)      + ((c1 << 1) & 4)                              ; k_param = ((k2 >> 1) & 1)  + ((k3 << 1) & 16) + ((k0 >> 2) & 8)  + ((k6 << 1) & 32) + ((k5 >> 2) & 4)  + ( k4 & 2)       ; c5 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c1 & 34)       + ((c2 >> 3) & 16) + (c0_4 & 8)      + ((c0 << 1) & 4)                   + (c3 >> 7); k_param = ((k5 << 1) & 2)  + ((k3 >> 4) & 4)  + ((k0 >> 1) & 8)  + ((k2 << 1) & 16) + ((k0 << 3) & 32) + ((k0 >> 3) & 1) ; c6 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c1 & 33)       + ((c3 >> 3) & 16) + ((c3 << 1) & 8) + ( c0 & 4)       + (c2_1 & 2)                 ; k_param = ( k1 & 32)       + ((k6 << 3) & 16) + ((k4 >> 4) & 8)  + ((k2 >> 2) & 4)  + ((k6 >> 7) & 1)  + ((k6 >> 1) & 2) ; c6 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c2 & 36)       + ( c1 & 17)       + ((c3 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k3 >> 5) & 1)  + ((k5 << 1) & 4)  + ((k0 << 3) & 16) + ((k3 >> 4) & 8)  + ((k5 >> 5) & 2)  + ( k2 & 32)      ; c7 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c0 & 40)       + (c2_1 & 16)                        + ( c1 & 4)       + ((c1 >> 6) & 2) + (c3 & 1) ; k_param = ((k1 << 2) & 32) + ((k5 >> 3) & 16) + ((k4 << 2) & 4)  + ((k3 >> 1) & 8)  + ((k2 >> 6) & 1)  + ((k6 << 1) & 2) ; c7 ^= SBox[7 * 64 + c_param^k_param];
	//15																																						  				    														  
	c0_4 = c4 >> 4; c2_2 = c6 << 2; c2_1 = c6 >> 1;																												  				    														  
	c_param = ((c7 & 17) << 1) + ( c6 & 24)                 	    + (c0_4 & 4)                        + (c5 >> 7); k_param = ( k2 & 2)        + ((k0 >> 6) & 1)  + ((k5 >> 2) & 4)  + ((k1 >> 3) & 8)  + ((k3 << 4) & 16) + ((k3 << 2) & 32); c0 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c6 & 17) << 1) + ( c7 & 24)                         + ((c5 & 8) >> 1)                   + (c4 & 1) ; k_param = ( k5 & 32)       + ((k4 << 3) & 16) + ((k1 << 2) & 4)  + ((k2 << 1) & 8)  + ( k3 & 2)        + ((k6 >> 5) & 1) ; c0 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c4 & 17)       + ((c5 >> 3) & 8) + (c2_2 & 4)      + ( c7 & 2)                  ; k_param = ((k2 >> 5) & 4)  + ((k5 >> 3) & 1)  + ( k4 & 8)        + ((k4 << 1) & 32) + ((k6 >> 2) & 2)  + ((k0 << 4) & 16); c1 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c7 >> 1) & 33) + ( c4 & 18)       + (c2_2 & 8)      + ((c5 << 1) & 4)                              ; k_param = ((k1 >> 7) & 1)  + ((k1 << 3) & 16) + ((k5 << 1) & 8)  + ((k4 << 3) & 32) + ( k3       & 4)  + ((k6 >> 5) & 2) ; c1 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c5 & 34)       + ((c6 >> 3) & 16) + (c0_4 & 8)      + ((c4 << 1) & 4)                   + (c7 >> 7); k_param = ((k4 >> 5) & 2)  + ((k1 >> 2) & 4)  + ((k6 >> 4) & 8)  + ((k0 << 3) & 16) + ((k5 << 4) & 32) + ((k2 >> 6) & 1) ; c2 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c5 & 33)       + ((c7 >> 3) & 16) + ((c7 << 1) & 8) + ( c4 & 4)       + (c2_1 & 2)                 ; k_param = ((k6 << 5) & 32) + ((k5 >> 3) & 16) + ((k2 >> 2) & 8)  + ( k0 & 4)        + ((k4 >> 5) & 1)  + ((k4 << 1) & 2) ; c2 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c6 & 36)       + ( c5 & 17)       + ((c7 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k1 >> 3) & 1)  + ((k4 >> 5) & 4)  + ((k5 << 4) & 16) + ((k1 >> 2) & 8)  + ((k3 >> 3) & 2)  + ((k0 << 2) & 32); c3 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c4 & 40)       + (c2_1 & 16)                        + ( c5 & 4)       + ((c5 >> 6) & 2) + (c7 & 1) ; k_param = ((k6 << 3) & 32) + ((k3 >> 1) & 16) + ((k3 >> 4) & 4)  + ((k1 << 1) & 8)  + ((k0 >> 4) & 1)  + ((k5 >> 5) & 2) ; c3 ^= SBox[7 * 64 + c_param^k_param];
	//16																																						  				    														  
	c0_4 = c0 >> 4; c2_2 = c2 << 2; c2_1 = c2 >> 1;																												  				    														  
	c_param = ((c3 << 1) & 34) + ( c2 & 24)                 	    + (c0_4 & 4)                        + (c1 >> 7); k_param = ((k1 << 1) & 2)  + ((k6 >> 4) & 1)  + ((k4 >> 1) & 4)  + ((k0 >> 2) & 8)  + ((k6 >> 2) & 16) + ((k2 << 3) & 32); c4 ^= SBox[0 * 64 + c_param^k_param];
	c_param = ((c2 << 1) & 34) + ( c3 & 24)                         + ((c1 & 8) >> 1)                   + (c0 & 1) ; k_param = ((k4 << 1) & 32) + ((k3 << 4) & 16) + ((k1 >> 5) & 4)  + ((k1 << 2) & 8)  + ((k2 << 1) & 2)  + ((k5 >> 4) & 1) ; c4 ^= SBox[1 * 64 + c_param^k_param];
	c_param = (c2_1 & 32)      + ( c0 & 17)       + ((c1 >> 3) & 8) + (c2_2 & 4)      + ( c3 & 2)                  ; k_param = ((k1 >> 4) & 4)  + ((k4 >> 2) & 1)  + ((k3 << 1) & 8)  + ((k3 << 2) & 32) + ((k5 >> 1) & 2)  + ((k0 >> 3) & 16); c5 ^= SBox[2 * 64 + c_param^k_param];
	c_param = ((c3 >> 1) & 33) + ( c0 & 18)       + (c2_2 & 8)      + ((c1 << 1) & 4)                              ; k_param = ((k0 >> 6) & 1)  + ((k0 << 4) & 16) + ((k4 << 2) & 8)  + ((k3 << 4) & 32) + ((k2 << 1) & 4)  + ((k5 >> 4) & 2) ; c5 ^= SBox[3 * 64 + c_param^k_param];
	c_param = ( c1 & 34)       + ((c2 >> 3) & 16) + (c0_4 & 8)      + ((c0 << 1) & 4)                   + (c3 >> 7); k_param = ((k3 >> 4) & 2)  + ((k0 >> 1) & 4)  + ((k5 >> 3) & 8)  + ((k6 << 3) & 16) + ((k4 << 5) & 32) + ((k1 >> 5) & 1) ; c6 ^= SBox[4 * 64 + c_param^k_param];
	c_param = ( c1 & 33)       + ((c3 >> 3) & 16) + ((c3 << 1) & 8) + ( c0 & 4)       + (c2_1 & 2)                 ; k_param = ((k6 >> 2) & 32) + ((k4 >> 2) & 16) + ((k1 >> 1) & 8)  + ( k6 & 4)        + ((k3 >> 4) & 1)  + ((k4 >> 6) & 2) ; c6 ^= SBox[5 * 64 + c_param^k_param];
	c_param = ( c2 & 36)       + ( c1 & 17)       + ((c3 >> 2) & 8)                   + (c0_4 & 2)                 ; k_param = ((k0 >> 2) & 1)  + ((k3 >> 4) & 4)  + ((k5 >> 3) & 16) + ((k0 >> 1) & 8)  + ((k2 >> 2) & 2)  + ((k3 >> 2) & 32); c7 ^= SBox[6 * 64 + c_param^k_param];
	c_param = ( c0 & 40)       + (c2_1 & 16)                        + ( c1 & 4)       + ((c1 >> 6) & 2) + (c3 & 1) ; k_param = ((k5 << 4) & 32) + ( k2 & 16)       + ((k2 >> 3) & 4)  + ((k0 << 2) & 8)  + ( k6 & 1)        + ((k4 >> 4) & 2) ; c7 ^= SBox[7 * 64 + c_param^k_param];

	// Final permutation
	unsigned char c[8];
	c[0] = c0;
	c[1] = c1;
	c[2] = c2;
	c[3] = c3;
	c[4] = c4;
	c[5] = c5;
	c[6] = c6;
	c[7] = c7;
	memset(hash, 0, 8);
	COPY_BIT(5 , 0 ); COPY_BIT(3 , 1 ); COPY_BIT(51, 2 ); COPY_BIT(49, 3 );
	COPY_BIT(37, 4 ); COPY_BIT(25, 5 ); COPY_BIT(15, 6 ); COPY_BIT(11, 7 );
	COPY_BIT(59, 8 ); COPY_BIT(61, 9 ); COPY_BIT(41, 10); COPY_BIT(47, 11);
	COPY_BIT(9 , 12); COPY_BIT(27, 13); COPY_BIT(13, 14); COPY_BIT(7 , 15);
	COPY_BIT(63, 16); COPY_BIT(45, 17); COPY_BIT(1 , 18); COPY_BIT(23, 19);
	COPY_BIT(31, 20); COPY_BIT(33, 21); COPY_BIT(21, 22); COPY_BIT(19, 23);
	COPY_BIT(57, 24); COPY_BIT(29, 25); COPY_BIT(43, 26); COPY_BIT(55, 27);
	COPY_BIT(39, 28); COPY_BIT(17, 29); COPY_BIT(53, 30); COPY_BIT(35, 31);

	COPY_BIT(4 , 32); COPY_BIT(2 , 33); COPY_BIT(50, 34); COPY_BIT(48, 35);
	COPY_BIT(36, 36); COPY_BIT(24, 37); COPY_BIT(14, 38); COPY_BIT(10, 39);
	COPY_BIT(58, 40); COPY_BIT(60, 41); COPY_BIT(40, 42); COPY_BIT(46, 43);
	COPY_BIT(8 , 44); COPY_BIT(26, 45); COPY_BIT(12, 46); COPY_BIT(6 , 47);
	COPY_BIT(62, 48); COPY_BIT(44, 49); COPY_BIT(0 , 50); COPY_BIT(22, 51);
	COPY_BIT(30, 52); COPY_BIT(32, 53); COPY_BIT(20, 54); COPY_BIT(18, 55);
	COPY_BIT(56, 56); COPY_BIT(28, 57); COPY_BIT(42, 58); COPY_BIT(54, 59);
	COPY_BIT(38, 60); COPY_BIT(16, 61); COPY_BIT(52, 62); COPY_BIT(34, 63);
}

PUBLIC void hash_lm(const char* message, char* hash)
{
	int i;
	int message_lenght = (int)strlen(message);
	unsigned char dst[8];
	unsigned char key[8];

	if(message_lenght == 0 || message_lenght > 14)
	{
		strcpy(hash, "AAD3B435B51404EEAAD3B435B51404EE");
		return;
	}

	memset(key, 0, sizeof(key));
	strncpy((char*)key, message, 7);
	key[7] = 0;
	_strupr(key);// Convert to upper case
	auth_DEShash(dst, key);
	for (i = 0; i < sizeof(dst); i++)
		sprintf(hash+2*i, "%02X", dst[7-i] & 0xFF);

	memset(key, 0, sizeof(key));
	if(message_lenght > 7)
	{
		strncpy((char*)key, message+7, 7);
		_strupr(key);// Convert to upper case
	}
	auth_DEShash(dst, key);
	for (i = 0; i < sizeof(dst); i++)
		sprintf(hash+16+2*i, "%02X", dst[7-i] & 0xFF);
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Password hashing with salt
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <ctype.h>

void dcc_ntlm_part_c_code(uint32_t* nt_buffer, uint32_t* crypt_result);
void dcc_salt_part_c_code(uint32_t* salt_buffer, uint32_t* crypt_result);
void dcc2_body_c_code(uint32_t* salt_buffer, uint32_t* crypt_result, uint32_t* sha1_hash, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W);
PRIVATE void generate_random_user(char* username)
{
	const char* name_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	size_t name_chars_size = strlen(name_chars);

	uint32_t len = rand() % 19 + 1;// Lenght between [1, 19]
	for (uint32_t i = 0; i < len; i++)
		username[i] = name_chars[rand() % name_chars_size];

	username[len] = 0;
}

PUBLIC void hash_dcc(const unsigned char* cleartext, char* hash)
{
	unsigned char username[32];
	generate_random_user(username);

	uint32_t crypt_result[12];
	uint32_t i;
	uint32_t nt_buffer[16 * 64];
	uint32_t salt_buffer[11];
	uint32_t len = (uint32_t)strlen((char*)cleartext);

	// nt_buffer
	memset(nt_buffer, 0, sizeof(nt_buffer));
	for (i = 0; i < len / 2; i++)
		nt_buffer[i * 64] = cleartext[2 * i] + (cleartext[2 * i + 1] << 16);

	nt_buffer[i * 64] = (len % 2) ? cleartext[2 * i] + 0x800000 : 0x80;
	nt_buffer[14 * 64] = len << 4;

	// Salt
	len = (uint32_t)strlen((char*)username);
	memset(salt_buffer, 0, sizeof(salt_buffer));
	for (i = 0; i < len / 2; i++)
		salt_buffer[i] = tolower(username[2 * i]) + (tolower(username[2 * i + 1]) << 16);

	salt_buffer[i] = (len % 2) ? tolower(username[2 * i]) + 0x800000 : 0x80;
	salt_buffer[10] = (8 + len) << 4;

	dcc_ntlm_part_c_code(nt_buffer, crypt_result);
	dcc_salt_part_c_code(salt_buffer, crypt_result);

	// Finish
	uint32_t a = crypt_result[8 + 0];
	uint32_t b = crypt_result[8 + 1];
	uint32_t c = crypt_result[8 + 2];
	uint32_t d = crypt_result[8 + 3];

	d = ROTATE(d + SQRT_3, 9);
	c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = ROTATE(c, 11);
	b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = ROTATE(b, 15);

	a += (b ^ c ^ d) + crypt_result[3] + SQRT_3; a = ROTATE(a, 3);
	d += (a ^ b ^ c) + salt_buffer[7] + SQRT_3; d = ROTATE(d, 9);
	c += (d ^ a ^ b) + salt_buffer[3] + SQRT_3; c = ROTATE(c, 11);
	b += (c ^ d ^ a) + SQRT_3; b = ROTATE(b, 15);

	SWAP_ENDIANNESS(a, a + INIT_A);
	SWAP_ENDIANNESS(b, b + INIT_B);
	SWAP_ENDIANNESS(c, c + INIT_C);
	SWAP_ENDIANNESS(d, d + INIT_D);

	sprintf(hash, "%s:%08x%08x%08x%08x", username, a, b, c, d);
}

PUBLIC void hash_dcc2(const unsigned char* cleartext, char* hash)
{
	unsigned char username[32];
	generate_random_user(username);

	uint32_t crypt_result[12], sha1_hash[5], opad_state[5], ipad_state[5], W[16];
	uint32_t i;
	uint32_t nt_buffer[16 * 64];
	uint32_t salt_buffer[11];
	uint32_t len = (uint32_t)strlen((char*)cleartext);

	// nt_buffer
	memset(nt_buffer, 0, sizeof(nt_buffer));
	for (i = 0; i < len / 2; i++)
		nt_buffer[i * 64] = cleartext[2 * i] + (cleartext[2 * i + 1] << 16);

	nt_buffer[i * 64] = (len % 2) ? cleartext[2 * i] + 0x800000 : 0x80;
	nt_buffer[14 * 64] = len << 4;

	// Salt
	len = (uint32_t)strlen((char*)username);
	memset(salt_buffer, 0, sizeof(salt_buffer));
	for (i = 0; i < len / 2; i++)
		salt_buffer[i] = tolower(username[2 * i]) + (tolower(username[2 * i + 1]) << 16);

	salt_buffer[i] = (len % 2) ? tolower(username[2 * i]) + 0x800000 : 0x80;
	salt_buffer[10] = (8 + len) << 4;

	dcc_ntlm_part_c_code(nt_buffer, crypt_result);
	dcc_salt_part_c_code(salt_buffer, crypt_result);
	dcc2_body_c_code(salt_buffer, crypt_result, sha1_hash, opad_state, ipad_state, W);

	uint32_t a = crypt_result[8 + 0];
	uint32_t b = crypt_result[8 + 1];
	uint32_t c = crypt_result[8 + 2];
	uint32_t d = crypt_result[8 + 3];

	sprintf(hash, "%s:%08x%08x%08x%08x", username, a, b, c, d);
}

PUBLIC void hash_ssha1(const char* cleartext, char* hash)
{
	uint32_t nt_buffer[14];
	uint32_t W[16];
	uint32_t sha1_state[5];
	// Salt
	unsigned char salt[16];
	uint32_t salt_len = 4 + rand() % 5;// from 4 to 8
	for (uint32_t i = 0; i < salt_len; i++)
		salt[i] = rand() & 0xff;

	uint32_t len = (uint32_t)strlen(cleartext);

	memset(nt_buffer, 0, sizeof(nt_buffer));
	strcpy((char*)nt_buffer, cleartext);
	memcpy(((char*)nt_buffer) + len, salt, salt_len);
	((unsigned char*)nt_buffer)[len + salt_len] = 0x80;

	// Copy to W
	for (uint32_t i = 0; i < 14; i++)
	{
		SWAP_ENDIANNESS(W[i], nt_buffer[i]);
	}
	W[14] = 0;
	W[15] = (len + salt_len) << 3;

	// Hash
	sha1_state[0] = INIT_A;
	sha1_state[1] = INIT_B;
	sha1_state[2] = INIT_C;
	sha1_state[3] = INIT_D;
	sha1_state[4] = INIT_E;
	sha1_process_block_simd(sha1_state, W, 1);

	// Encode as base64
	swap_endianness_array(sha1_state, 5);
	memcpy(W, sha1_state, 5 * sizeof(uint32_t));
	memcpy(W + 5, salt, salt_len);
	base64_encode_mime((unsigned char*)W, 5 * sizeof(uint32_t) + salt_len, hash);
}

//////////////////////////////////////////////////////////////////////////////////////////
// md5crypt
//////////////////////////////////////////////////////////////////////////////////////////
typedef struct {
	uint8_t salt[8];
	uint8_t saltlen;
	uint8_t prefix;		/** 0 when $1$ or 1 when $apr1$ or 2 for {smd5} which uses no prefix. **/
} crypt_md5_salt;
PRIVATE char* prefixs[] = { "$1$", "$apr1$", "" };
PRIVATE char* prefixs_show[] = { "$1$", "$apr1$", "{smd5}" };
PRIVATE void md5_one_block_c_code(uint32_t* state, const void* block)
{
	state[0] = INIT_A;
	state[1] = INIT_B;
	state[2] = INIT_C;
	state[3] = INIT_D;
	md5_process_block(state, block);
}
#define TO_BASE64(b1, b2, b3) \
	value = out[b3] | (out[b2] << 8) | (out[b1] << 16);\
	\
	pos[0] = itoa64[(value    ) & 63];\
	pos[1] = itoa64[(value>>6 ) & 63];\
	pos[2] = itoa64[(value>>12) & 63];\
	pos[3] = itoa64[(value>>18) & 63];\
	pos += 4;

PUBLIC void hash_md5crypt(const unsigned char* cleartext, char* hash)
{
	uint32_t md5_state[4];
	uint8_t buffer[64];
	uint32_t len = (uint32_t)strlen((char*)cleartext);

	crypt_md5_salt salt;
	salt.saltlen = 8;// rand() % 8;
	salt.prefix = rand() % 3;
	for (int i = 0; i < salt.saltlen; i++)
	{
		uint8_t salt_char = 1 + rand() % 255;
		while (salt_char == '$')
			salt_char = 1 + rand() % 255;
		salt.salt[i] = salt_char;
	}

	// 1st digest
	memset(buffer, 0, sizeof(buffer));
	uint32_t buffer_len = 0;
	memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
	memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
	memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
	buffer[buffer_len] = 0x80;
	((uint32_t*)buffer)[14] = buffer_len << 3;
	md5_one_block_c_code(md5_state, buffer);

	// 2nd digest
	memset(buffer, 0, sizeof(buffer));
	buffer_len = 0;
	memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
	memcpy(buffer + buffer_len, prefixs[salt.prefix], strlen(prefixs[salt.prefix])); buffer_len += (uint32_t)strlen(prefixs[salt.prefix]);
	memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
	memcpy(buffer + buffer_len, md5_state, len); buffer_len += len;
	for (uint32_t j = len; j > 0; j >>= 1, buffer_len++)
		buffer[buffer_len] = (j & 1) ? 0 : cleartext[0];
	buffer[buffer_len] = 0x80;
	((uint32_t*)buffer)[14] = buffer_len << 3;
	md5_one_block_c_code(md5_state, buffer);

	// Big cycle
	for (int i = 0; i < 1000; i++)
	{
		memset(buffer, 0, sizeof(buffer));
		uint32_t buffer_len = 0;

		if (i & 1)
		{
			memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
		}
		else
		{
			memcpy(buffer + buffer_len, md5_state, 16); buffer_len += 16;
		}
		if (i % 3)
		{
			memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
		}
		if (i % 7)
		{
			memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
		}
		if (i & 1)
		{
			memcpy(buffer + buffer_len, md5_state, 16); buffer_len += 16;
		}
		else
		{
			memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
		}

		buffer[buffer_len] = 0x80;
		((uint32_t*)buffer)[14] = buffer_len << 3;
		md5_one_block_c_code(md5_state, buffer);
	}

	sprintf(hash, "%s", prefixs_show[salt.prefix]);
	hash += strlen(hash);
	memcpy(hash, salt.salt, salt.saltlen);
	hash[salt.saltlen] = '$';

	char* pos = hash + salt.saltlen + 1;
	unsigned char* out = (unsigned char*)md5_state;
	uint32_t value;

	TO_BASE64(0, 6, 12);
	TO_BASE64(1, 7, 13);
	TO_BASE64(2, 8, 14);
	TO_BASE64(3, 9, 15);
	TO_BASE64(4, 10, 5);
	pos[0] = itoa64[out[11] & 63];
	pos[1] = itoa64[out[11] >> 6];
	pos[2] = 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
// sha256crypt
//////////////////////////////////////////////////////////////////////////////////////////
#define SHA256_INIT_STATE(state) \
	buffer_len = 0, num_blocks = 0;\
	state[0] = 0x6A09E667;\
	state[1] = 0xBB67AE85;\
	state[2] = 0x3C6EF372;\
	state[3] = 0xA54FF53A;\
	state[4] = 0x510E527F;\
	state[5] = 0x9B05688C;\
	state[6] = 0x1F83D9AB;\
	state[7] = 0x5BE0CD19;

#define SHA256_END_CTX(state) \
	buffer[buffer_len] = 0x80;\
	if (buffer_len >= 56)\
	{\
		memset(buffer + buffer_len + 1, 0, 128 - buffer_len - 1);\
		((uint32_t*)buffer)[16 + 15] = (num_blocks*64+buffer_len) << 3;\
		swap_endianness_array((uint32_t*)buffer, 16);\
		sha256_process_block(state, (uint32_t*)buffer);\
		swap_endianness_array((uint32_t*)(buffer + 64), 14);\
		sha256_process_block(state, (uint32_t*)(buffer + 64));\
	}\
	else\
	{\
		memset(buffer + buffer_len + 1, 0, 64 - buffer_len - 1);\
		((uint32_t*)buffer)[15] = (num_blocks*64+buffer_len) << 3;\
		swap_endianness_array((uint32_t*)buffer, 14);\
		sha256_process_block(state, (uint32_t*)buffer);\
	}\
	swap_endianness_array(state, 8);

typedef struct {
	uint32_t rounds;
	uint8_t salt[16];
	uint8_t saltlen;
} crypt_sha256_salt;
PUBLIC void hash_sha256crypt(const char* cleartext, char* hash)
{
	assert(strlen(cleartext) <= 32);

	uint32_t sha256_state[8], alt_state[8];
	HS_ALIGN(4) uint8_t buffer[64 + 64];
	uint32_t buffer_len, num_blocks;
	uint32_t key_len = (uint32_t)strlen(cleartext);

	// Generate random salt
	crypt_sha256_salt salt;
	salt.saltlen = 1 + rand() % 16;// [1,16]
	salt.rounds = 5000;// TODO: Manage this
	for (uint8_t i = 0; i < salt.saltlen; i++)
	{
		uint8_t salt_char = 1 + rand() % 255;
		while (salt_char == '$')
			salt_char = 1 + rand() % 255;
		salt.salt[i] = salt_char;
	}

	// 1st digest: Support buffer_len<=51
	SHA256_INIT_STATE(sha256_state);
	memcpy(buffer + buffer_len, cleartext, key_len); buffer_len += key_len;
	memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
	memcpy(buffer + buffer_len, cleartext, key_len); buffer_len += key_len;
	SHA256_END_CTX(sha256_state);

	// 2nd digest: Support buffer_len<=37
	SHA256_INIT_STATE(alt_state);
	memcpy(buffer + buffer_len, cleartext, key_len); buffer_len += key_len;
	memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
	memcpy(buffer + buffer_len, sha256_state, key_len); buffer_len += key_len;
	for (uint32_t j = key_len; j > 0; j >>= 1)
	{
		if (j & 1)
		{
			memcpy(buffer + buffer_len, sha256_state, 32);
			buffer_len += 32;
		}
		else
		{
			memcpy(buffer + buffer_len, cleartext, key_len);
			buffer_len += key_len;
		}
		if (buffer_len >= 64)
		{
			swap_endianness_array((uint32_t*)buffer, 16);
			sha256_process_block(alt_state, (uint32_t*)buffer);
			buffer_len -= 64;
			num_blocks++;
			memcpy(buffer, buffer + 64, buffer_len);
		}
	}
	SHA256_END_CTX(alt_state);

	// Start computation of P byte sequence.
	SHA256_INIT_STATE(sha256_state);
	for (uint32_t i = 0; i < key_len; i++)
	{
		memcpy(buffer + buffer_len, cleartext, key_len);
		buffer_len += key_len;
		if (buffer_len >= 64)
		{
			swap_endianness_array((uint32_t*)buffer, 16);
			sha256_process_block(sha256_state, (uint32_t*)buffer);
			buffer_len -= 64;
			num_blocks++;
			memcpy(buffer, buffer + 64, buffer_len);
		}
	}
	SHA256_END_CTX(sha256_state);
	char p_bytes[32];
	memcpy(p_bytes, sha256_state, key_len);
	// Start computation of S byte sequence.
	SHA256_INIT_STATE(sha256_state);
	for (uint32_t i = 0; i < (16u + ((unsigned char*)alt_state)[0]); i++)
	{
		memcpy(buffer + buffer_len, salt.salt, salt.saltlen);
		buffer_len += salt.saltlen;
		if (buffer_len >= 64)
		{
			swap_endianness_array((uint32_t*)buffer, 16);
			sha256_process_block(sha256_state, (uint32_t*)buffer);
			buffer_len -= 64;
			num_blocks++;
			memcpy(buffer, buffer + 64, buffer_len);
		}
	}
	SHA256_END_CTX(sha256_state);
	char s_bytes[16];
	memcpy(s_bytes, sha256_state, salt.saltlen);

	// Big cycle: Support buffer_len<=35
	for (uint32_t i = 0; i < salt.rounds; i++)
	{
		SHA256_INIT_STATE(sha256_state);

		if (i & 1)
		{
			memcpy(buffer + buffer_len, p_bytes, key_len); buffer_len += key_len;
		}
		else
		{
			memcpy(buffer + buffer_len, alt_state, 32); buffer_len += 32;
		}
		if (i % 3)
		{
			memcpy(buffer + buffer_len, s_bytes, salt.saltlen); buffer_len += salt.saltlen;
		}
		if (i % 7)
		{
			memcpy(buffer + buffer_len, p_bytes, key_len); buffer_len += key_len;
		}
		if (i & 1)
		{
			memcpy(buffer + buffer_len, alt_state, 32); buffer_len += 32;
		}
		else
		{
			memcpy(buffer + buffer_len, p_bytes, key_len); buffer_len += key_len;
		}

		SHA256_END_CTX(sha256_state);
		memcpy(alt_state, sha256_state, 32);
	}

	// Export hash
	sprintf(hash, "$5$rounds=%i$%.*s$", salt.rounds, salt.saltlen, salt.salt);
	char* pos = hash + strlen(hash);
	unsigned char* out = (unsigned char*)sha256_state;
	uint32_t value;

	TO_BASE64(0, 10, 20);
	TO_BASE64(21, 1, 11);
	TO_BASE64(12, 22, 2);
	TO_BASE64(3, 13, 23);
	TO_BASE64(24, 4, 14);
	TO_BASE64(15, 25, 5);
	TO_BASE64(6, 16, 26);
	TO_BASE64(27, 7, 17);
	TO_BASE64(18, 28, 8);
	TO_BASE64(9, 19, 29);
	//TO_BASE64(-, 31, 30);
	pos[0] = itoa64[out[30] & 63];
	pos[1] = itoa64[((out[30] >> 6) | (out[31] << 2)) & 63];
	pos[2] = itoa64[out[31] >> 4];
	pos[3] = 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
// WPA
//////////////////////////////////////////////////////////////////////////////////////////
typedef struct
{
	char          essid[36];
	unsigned char mac1[6];
	unsigned char mac2[6];
	unsigned char nonce1[32];
	unsigned char nonce2[32];
	unsigned char eapol[256];
	int           eapol_size;
	int           keyver;
	unsigned char keymic[16];
} hccap_t;

typedef struct
{
	uint32_t keymic[4];
	unsigned char prf_buffer[128];
	unsigned char eapol[256 + 64];
	uint32_t  eapol_blocks;
	int           keyver;
} hccap_bin;

extern uint32_t max_lenght;
void wpa_body_c_code(uint32_t* nt_buffer, uint32_t* essid_block, uint32_t* crypt_result, uint32_t* sha1_hash, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W);
void wpa_postprocess_c_code(hccap_bin* salt, uint32_t* crypt_result, uint32_t* sha1_hash, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W);
void convert_utf8_2_coalesc(const unsigned char* key, uint32_t* nt_buffer, uint32_t max_number, uint32_t len);

PRIVATE void convert2wpa_salt(hccap_t hccap, hccap_bin* salt)
{
	// Preproccess salt
	salt->keyver = hccap.keyver;
	// eapol
	salt->eapol_blocks = 1 + (hccap.eapol_size + 8) / 64;
	memcpy(salt->eapol, hccap.eapol, hccap.eapol_size);
	salt->eapol[hccap.eapol_size] = 0x80;
	memset(salt->eapol + hccap.eapol_size + 1, 0, sizeof(salt->eapol) - hccap.eapol_size - 1);
	uint32_t* eapol_ptr = ((uint32_t*)salt->eapol);
	if (hccap.keyver != 1)
		for (uint32_t i = 0; i < (sizeof(salt->eapol) / 4 - 2); i++)
		{
			SWAP_ENDIANNESS(eapol_ptr[i], eapol_ptr[i]);
		}
	eapol_ptr[16 * (salt->eapol_blocks - 1) + ((hccap.keyver == 1) ? 14 : 15)] = (64 + hccap.eapol_size) << 3;

	// prf_512 preprocess----------------------------------------------------
	memcpy(salt->prf_buffer, "Pairwise key expansion", 23);

	//insert_mac
	int k = memcmp(hccap.mac1, hccap.mac2, 6);
	if (k > 0) {
		memcpy(salt->prf_buffer + 23, hccap.mac2, 6);
		memcpy(salt->prf_buffer + 6 + 23, hccap.mac1, 6);
	}
	else {
		memcpy(salt->prf_buffer + 23, hccap.mac1, 6);
		memcpy(salt->prf_buffer + 6 + 23, hccap.mac2, 6);
	}
	//insert_nonce
	k = memcmp(hccap.nonce1, hccap.nonce2, 32);
	if (k > 0) {
		memcpy(salt->prf_buffer + 12 + 23, hccap.nonce2, 32);
		memcpy(salt->prf_buffer + 32 + 12 + 23, hccap.nonce1, 32);
	}
	else {
		memcpy(salt->prf_buffer + 12 + 23, hccap.nonce1, 32);
		memcpy(salt->prf_buffer + 32 + 12 + 23, hccap.nonce2, 32);
	}
	salt->prf_buffer[99] = 0;
	salt->prf_buffer[100] = 0x80;
	memset(salt->prf_buffer + 101, 0, sizeof(salt->prf_buffer) - 4 - 101);

	uint32_t* prf_buffer_ptr = ((uint32_t*)salt->prf_buffer);
	prf_buffer_ptr[16 + 15] = (64 + 100) << 3;

	for (uint32_t i = 0; i < 104 / 4; i++)
	{
		SWAP_ENDIANNESS(prf_buffer_ptr[i], prf_buffer_ptr[i]);
	}
	//------------------------------------------------------------------------------
}

PUBLIC void hash_wpa(const unsigned char* cleartext, unsigned char* hash)
{
	unsigned char username[32];
	generate_random_user(username);

	uint32_t crypt_result[10], sha1_hash[5], opad_state[5], ipad_state[5], W[16];
	uint32_t nt_buffer[17 * 64];
	uint32_t len = (uint32_t)strlen((char*)cleartext);

	// nt_buffer
	max_lenght = 63;
	memset(nt_buffer, 0, sizeof(nt_buffer));
	convert_utf8_2_coalesc(cleartext, nt_buffer, 64, len);
	uint32_t _0x80_index = len / 4 * 64;
	((unsigned char*)nt_buffer)[_0x80_index * 4 + (len & 3)] = 0;
	nt_buffer[16 * 64] = len << 3;
	len = (len + 3) / 4;
	for (uint32_t j = 0; j < len; j++)
	{
		SWAP_ENDIANNESS(nt_buffer[j * 64], nt_buffer[j * 64]);
	}

	// Salt
	hccap_t wpa_data;
	hccap_bin salt;
	strcpy(wpa_data.essid, (char*)username);
	unsigned char* r_data = ((unsigned char*)&wpa_data) + 36;
	for (uint32_t i = 0; i < (256 + 32 + 32 + 6 + 6); i++)
		r_data[i] = rand() & 0xff;
	wpa_data.eapol_size = rand() & 0x7f;
	wpa_data.keyver = (rand() & 1) + 1;

	convert2wpa_salt(wpa_data, &salt);
	// Convert essid_block
	uint32_t essid_block[16];
	uint32_t essid_len = (uint32_t)strlen(wpa_data.essid);
	strcpy((char*)essid_block, wpa_data.essid);
	memcpy(((char*)essid_block) + essid_len, "\x0\x0\x0\x1\x80", 5);
	memset(((char*)essid_block) + essid_len + 5, 0, 60 - (essid_len + 5));
	essid_block[15] = (64 + essid_len + 4) << 3;
	for (uint32_t k = 0; k < 14; k++)
	{
		SWAP_ENDIANNESS(essid_block[k], essid_block[k]);
	}

	// Execute the format
	wpa_body_c_code(nt_buffer, essid_block, crypt_result, sha1_hash, opad_state, ipad_state, W);
	wpa_postprocess_c_code(&salt, crypt_result, sha1_hash, opad_state, ipad_state, W);

	if (wpa_data.keyver != 1)
		for (uint32_t i = 0; i < 4; i++)
		{
			SWAP_ENDIANNESS(crypt_result[i], crypt_result[i]);
		}

	memcpy(wpa_data.keymic, crypt_result, 16);

	// Write hash
	sprintf((char*)hash, "%s#", username);
	unsigned char* base64 = hash + strlen((char*)hash);
	for (int i = 0; i < 118; i++)
	{
		base64[0] = itoa64[(r_data[0] >> 2)];
		base64[1] = itoa64[((r_data[0] & 0x3) << 4) | (r_data[1] >> 4)];
		base64[2] = itoa64[((r_data[1] & 0xf) << 2) | (r_data[2] >> 6)];
		base64[3] = itoa64[r_data[2] & 0x3f];

		r_data += 3;
		base64 += 4;
	}
	base64[0] = itoa64[(r_data[0] >> 2)];
	base64[1] = itoa64[((r_data[0] & 0x3) << 4) | (r_data[1] >> 4)];
	base64[2] = itoa64[((r_data[1] & 0xf) << 2)];
	base64[3] = 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
// Bcrypt
//////////////////////////////////////////////////////////////////////////////////////////
// Binary salt type, also keeps the number of rounds and hash sub-type.
typedef struct {
	uint32_t salt[4];
	uint32_t rounds;
	uint32_t sign_extension_bug;
} BF_salt;

typedef struct {
	uint32_t S[4][0x100];
	uint32_t P[18];
} BF_ctx;

extern BF_ctx BF_init_state;
void BF_decode(uint32_t* dst, const unsigned char* src, int size);

// The string is "OrpheanBeholderScryDoubt" on big-endian.
PRIVATE uint32_t BF_magic_w[6] = { 0x4F727068, 0x65616E42, 0x65686F6C, 0x64657253, 0x63727944, 0x6F756274 };

PRIVATE unsigned char BF_itoa64[64 + 1] =
"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

PRIVATE unsigned char BF_atoi64[0x60] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 0, 1,
	54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 64, 64, 64, 64, 64,
	64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 64, 64, 64, 64, 64,
	64, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 64, 64, 64, 64, 64
};
PRIVATE void BF_encode(unsigned char* dst, const uint32_t* src, int size)
{
	const unsigned char* sptr = (const unsigned char*)src;
	const unsigned char* end = sptr + size;
	unsigned char* dptr = (unsigned char*)dst;
	uint32_t c1, c2;

	do {
		c1 = *sptr++;
		*dptr++ = BF_itoa64[c1 >> 2];
		c1 = (c1 & 0x03) << 4;
		if (sptr >= end) {
			*dptr++ = BF_itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= c2 >> 4;
		*dptr++ = BF_itoa64[c1];
		c1 = (c2 & 0x0f) << 2;
		if (sptr >= end) {
			*dptr++ = BF_itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= c2 >> 6;
		*dptr++ = BF_itoa64[c1];
		*dptr++ = BF_itoa64[c2 & 0x3f];
	} while (sptr < end);
}

#define BYTE_0(word)	((word & 0xFF))
#define BYTE_1(word)	((word >> 8 ) & 0xFF)
#define BYTE_2(word)	((word >> 16) & 0xFF)
#define BYTE_3(word)	((word >> 24))

#define BF_ENCRYPT \
	L ^= subkeys[0 ]; \
	R ^= subkeys[1 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[2 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[3 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[4 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[5 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[6 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[7 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[8 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[9 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[10] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[11] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[12] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[13] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[14] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[15] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[16] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	tmp_swap = R;\
	R = L;\
	L = tmp_swap ^ subkeys[17];

PRIVATE void blowfish_body_c_code(uint32_t* subkeys, uint32_t* sboxs)
{
	uint32_t L = 0, R = 0, tmp_swap;
	for (int i = 0; i < 18; i += 2)
	{
		BF_ENCRYPT;
		subkeys[i] = L;
		subkeys[i + 1] = R;
	}
	for (int i = 0; i < 256 * 4; i += 2)
	{
		BF_ENCRYPT;
		sboxs[i] = L;
		sboxs[i + 1] = R;
	}
}
PRIVATE void bf_key(const char* key, BF_salt* salt, uint32_t* crypt_result)
{
	uint32_t* sboxs = (uint32_t*)malloc((4 * 256 + 18 + 18) * sizeof(uint32_t));

	uint32_t* subkeys = sboxs + 4 * 256;
	uint32_t* expanded_key = subkeys + 18;

	uint32_t L, R, tmp_swap;

	//blowfish_set_key(buffer, subkeys, expanded_key, NT_NUM_KEYS, salt->sign_extension_bug, NT_NUM_KEYS);
	const char* ptr = key;
	for (int i = 0; i < 18; i++)
	{
		uint32_t tmp = 0;
		for (int j = 0; j < 4; j++)
		{
			tmp <<= 8;
			if (salt->sign_extension_bug)
				tmp |= (int)(signed char)*ptr;
			else
				tmp |= (unsigned char)*ptr;

			if (!*ptr) ptr = key; else ptr++;
		}

		expanded_key[i] = tmp;
		subkeys[i] = BF_init_state.P[i] ^ tmp;
	}
	memcpy(sboxs, BF_init_state.S, sizeof(BF_init_state.S));

	L = R = 0;
	for (int i = 0; i < 18; i += 2)
	{
		L ^= salt->salt[(i & 2)];
		R ^= salt->salt[(i & 2) + 1];
		BF_ENCRYPT;
		subkeys[i] = L;
		subkeys[i + 1] = R;
	}
	for (int i = 0; i < 256 * 4; i += 2)
	{
		L ^= salt->salt[(i + 2) & 3];
		R ^= salt->salt[(i + 3) & 3];
		BF_ENCRYPT;
		sboxs[i] = L;
		sboxs[i + 1] = R;
	}

	// Expensive key schedule
	for (uint32_t round = 0; round < salt->rounds; round++)
	{
		// Key part
		for (int i = 0; i < 18; i++)
			subkeys[i] ^= expanded_key[i];

		blowfish_body_c_code(subkeys, sboxs);

		// Salt part
		for (int i = 0; i < 18; i++)
			subkeys[i] ^= salt->salt[i & 3];

		blowfish_body_c_code(subkeys, sboxs);
	}

	// Final part: Encrypt
	for (int i = 0; i < 6; i += 2)
	{
		L = BF_magic_w[i];
		R = BF_magic_w[i + 1];

		for (int j = 0; j < 64; j++)
		{
			BF_ENCRYPT;
		}

		crypt_result[i] = L;
		crypt_result[i + 1] = R;
	}
	/* This has to be bug-compatible with the original implementation, so only encode 23 of the 24 bytes. :-) */
	crypt_result[5] &= 0xFFFFFF00;

	free(sboxs);
}
PUBLIC void hash_bcrypt(const char* cleartext, unsigned char* hash)
{
	uint32_t crypt_result[6];
	BF_salt salt;
	int exponent = 5;

	salt.rounds = 1 << exponent;
	salt.sign_extension_bug = ((rand() & 3) == 3);
	for (uint32_t i = 0; i < 4 * 4; i++)
		((unsigned char*)&salt.salt)[i] = rand() & 0xff;

	bf_key(cleartext, &salt, crypt_result);

	sprintf((char*)hash, "$2%s$%02i$", salt.sign_extension_bug ? "x" : "y", exponent);
	swap_endianness_array(salt.salt, 6);
	BF_encode(hash + 7, salt.salt, 16);
	hash[7 + 22 - 1] = BF_itoa64[(int)BF_atoi64[(int)hash[7 + 22 - 1] - 0x20] & 0x30];

	/* This has to be bug-compatible with the original implementation, so
	 * only encode 23 of the 24 bytes. :-) */
	swap_endianness_array(crypt_result, 6);
	BF_encode(&hash[7 + 22], crypt_result, 23);
	hash[7 + 22 + 31] = '\0';
}
PRIVATE void apply_bcrypt_bug(const char* cleartext, unsigned char* hash, uint32_t* given_salt)
{
	uint32_t crypt_result[6];
	BF_salt salt;
	int exponent = 5;

	salt.rounds = 1 << exponent;
	salt.sign_extension_bug = 1;
	memcpy(salt.salt, given_salt, sizeof(salt.salt));

	bf_key(cleartext, &salt, crypt_result);

	sprintf((char*)hash, "$2%s$%02i$", salt.sign_extension_bug ? "x" : "y", exponent);
	swap_endianness_array(salt.salt, 6);
	BF_encode(hash + 7, salt.salt, 16);
	hash[7 + 22 - 1] = BF_itoa64[(int)BF_atoi64[(int)hash[7 + 22 - 1] - 0x20] & 0x30];

	/* This has to be bug-compatible with the original implementation, so
	* only encode 23 of the 24 bytes. :-) */
	swap_endianness_array(crypt_result, 6);
	BF_encode(&hash[7 + 22], crypt_result, 23);
	hash[7 + 22 + 31] = '\0';
}