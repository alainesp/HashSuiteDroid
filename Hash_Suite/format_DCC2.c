// This file is part of Hash Suite password cracker,
// Copyright (c) 2013-2014 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

#ifdef INCLUDE_DCC2

//Initial values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476
#define INIT_E 0xC3D2E1F0

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

#define PLAINTEXT_LENGTH	27
#define BINARY_SIZE			16
#define SALT_SIZE			(11*4)
#define NT_NUM_KEYS		    64

PRIVATE unsigned int get_binary(const unsigned char* ciphertext, void* binary, unsigned int* salt)
{
	unsigned int* out = (unsigned int*)binary;
	unsigned int i = 0;
	unsigned int temp;
	unsigned int salt_lenght = 0;
	char ciphertext_buffer[64];

	//length=11 for save memory
	memset(salt, 0, SALT_SIZE);
	// Lowercase username
	ciphertext = _strlwr( strcpy(ciphertext_buffer, ciphertext) );
	// Get salt length
	for(; ciphertext[salt_lenght] != ':'; salt_lenght++);
	// Convert salt-----------------------------------------------------
	for(; i < salt_lenght/2; i++)
		salt[i] = ((unsigned int)ciphertext[2*i]) | ((unsigned int)ciphertext[2*i+1]) << 16;

	salt[i] = (salt_lenght%2) ? ((unsigned int)ciphertext[2*i]) | 0x800000 : 0x80;
	salt[10] = (8 + salt_lenght) << 4;

	ciphertext += salt_lenght + 1;
	//end convert salt----------------------------------------------------

	for (i = 0; i < 4; i++)
	{
		temp  = (hex_to_num[ciphertext[i*8+0]])<<28;
 		temp |= (hex_to_num[ciphertext[i*8+1]])<<24;
		
		temp |= (hex_to_num[ciphertext[i*8+2]])<<20;
		temp |= (hex_to_num[ciphertext[i*8+3]])<<16;
		
		temp |= (hex_to_num[ciphertext[i*8+4]])<<12;
		temp |= (hex_to_num[ciphertext[i*8+5]])<<8;
		
		temp |= (hex_to_num[ciphertext[i*8+6]])<<4;
		temp |= (hex_to_num[ciphertext[i*8+7]])<<0;
		
		out[i] = temp;
	}
	
	return out[0];
}

#define LOAD_BIG_ENDIAN(x, data) x = rotate(data, 16U); x = ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
#define DCC2_R(w0, w1, w2, w3)	(W[w0*simd_with+i] = rotate((W[w0*simd_with+i] ^ W[w1*simd_with+i] ^ W[w2*simd_with+i] ^ W[w3*simd_with+i]), 1))
PRIVATE void sha1_process( unsigned int* state, unsigned int* W, unsigned int simd_with )
{
	for (unsigned int i = 0; i < simd_with; i++)
	{
		unsigned int A = state[i+0*simd_with];
		unsigned int B = state[i+1*simd_with];
		unsigned int C = state[i+2*simd_with];
		unsigned int D = state[i+3*simd_with];
		unsigned int E = state[i+4*simd_with];

		E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[0 *simd_with+i]; B = rotate(B, 30);
		D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[1 *simd_with+i]; A = rotate(A, 30);
		C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[2 *simd_with+i]; E = rotate(E, 30);
		B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[3 *simd_with+i]; D = rotate(D, 30);
		A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[4 *simd_with+i]; C = rotate(C, 30);
		E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[5 *simd_with+i]; B = rotate(B, 30);
		D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[6 *simd_with+i]; A = rotate(A, 30);
		C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[7 *simd_with+i]; E = rotate(E, 30);
		B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[8 *simd_with+i]; D = rotate(D, 30);
		A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[9 *simd_with+i]; C = rotate(C, 30);
		E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[10*simd_with+i]; B = rotate(B, 30);
		D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[11*simd_with+i]; A = rotate(A, 30);
		C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[12*simd_with+i]; E = rotate(E, 30);
		B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[13*simd_with+i]; D = rotate(D, 30);
		A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[14*simd_with+i]; C = rotate(C, 30);
		E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[15*simd_with+i]; B = rotate(B, 30);
		D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + DCC2_R(0, 13,  8, 2); A = rotate(A, 30);
		C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + DCC2_R(1, 14,  9, 3); E = rotate(E, 30);
		B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + DCC2_R(2, 15, 10, 4); D = rotate(D, 30);
		A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + DCC2_R(3,  0, 11, 5); C = rotate(C, 30);

		E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + DCC2_R(4 , 1 , 12, 6); B = rotate(B, 30);
		D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + DCC2_R(5 , 2 , 13, 7); A = rotate(A, 30);
		C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R(6 , 3 , 14, 8); E = rotate(E, 30);
		B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R(7 , 4 , 15, 9); D = rotate(D, 30);
		A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R(8 , 5 , 0, 10); C = rotate(C, 30);
		E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + DCC2_R(9 , 6 , 1, 11); B = rotate(B, 30);
		D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + DCC2_R(10, 7 , 2, 12); A = rotate(A, 30);
		C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R(11, 8 , 3, 13); E = rotate(E, 30);
		B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R(12, 9 , 4, 14); D = rotate(D, 30);
		A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R(13, 10, 5, 15); C = rotate(C, 30);
		E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + DCC2_R(14, 11, 6,  0); B = rotate(B, 30);
		D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + DCC2_R(15, 12, 7,  1); A = rotate(A, 30);
		C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R(0 , 13, 8,  2) ; E = rotate(E, 30);
		B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R(1 , 14, 9,  3); D = rotate(D, 30);
		A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R(2 , 15, 10, 4); C = rotate(C, 30);
		E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + DCC2_R(3 ,  0, 11, 5); B = rotate(B, 30);
		D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + DCC2_R(4 ,  1, 12, 6); A = rotate(A, 30);
		C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R(5 ,  2, 13, 7); E = rotate(E, 30);
		B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R(6 ,  3, 14, 8); D = rotate(D, 30);
		A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R(7 ,  4, 15, 9); C = rotate(C, 30);

		E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R(8, 5, 0, 10); B = rotate(B, 30);
		D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R(9, 6, 1, 11); A = rotate(A, 30);
		C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(10, 7, 2, 12); E = rotate(E, 30);
		B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(11, 8, 3, 13); D = rotate(D, 30);
		A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(12, 9, 4, 14); C = rotate(C, 30);
		E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R(13, 10, 5, 15); B = rotate(B, 30);
		D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R(14, 11, 6, 0); A = rotate(A, 30);
		C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(15, 12, 7, 1); E = rotate(E, 30);
		B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(0, 13, 8, 2) ; D = rotate(D, 30);
		A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(1, 14, 9, 3); C = rotate(C, 30);
		E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R(2, 15, 10, 4); B = rotate(B, 30);
		D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R(3, 0, 11, 5); A = rotate(A, 30);
		C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(4, 1, 12, 6); E = rotate(E, 30);
		B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(5, 2, 13, 7); D = rotate(D, 30);
		A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(6, 3, 14, 8); C = rotate(C, 30);
		E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R(7, 4, 15, 9); B = rotate(B, 30);
		D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R(8, 5, 0, 10); A = rotate(A, 30);
		C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(9, 6, 1, 11); E = rotate(E, 30);
		B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(10, 7, 2, 12); D = rotate(D, 30);
		A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(11, 8, 3, 13); C = rotate(C, 30);
																   
		E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R(12, 9, 4, 14); B = rotate(B, 30);
		D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(13, 10, 5, 15); A = rotate(A, 30);
		C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R(14, 11, 6, 0); E = rotate(E, 30);
		B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R(15, 12, 7, 1); D = rotate(D, 30);
		A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R(0, 13, 8, 2) ; C = rotate(C, 30);
		E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R(1, 14, 9, 3); B = rotate(B, 30);
		D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(2, 15, 10, 4); A = rotate(A, 30);
		C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R(3, 0, 11, 5); E = rotate(E, 30);
		B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R(4, 1, 12, 6); D = rotate(D, 30);
		A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R(5, 2, 13, 7); C = rotate(C, 30);
		E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R(6, 3, 14, 8); B = rotate(B, 30);
		D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(7, 4, 15, 9); A = rotate(A, 30);
		C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R(8, 5, 0, 10); E = rotate(E, 30);
		B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R(9, 6, 1, 11); D = rotate(D, 30);
		A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R(10, 7, 2, 12); C = rotate(C, 30);
		E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R(11, 8, 3, 13); B = rotate(B, 30);
		D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(12, 9, 4, 14); A = rotate(A, 30);
		C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R(13, 10, 5, 15); E = rotate(E, 30);
		B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R(14, 11, 6, 0); D = rotate(D, 30);
		A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R(15, 12, 7, 1); C = rotate(C, 30);

		state[i+0*simd_with] += A;
		state[i+1*simd_with] += B;
		state[i+2*simd_with] += C;
		state[i+3*simd_with] += D;
		state[i+4*simd_with] += E;
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef _M_X64
// Calculate W in each iteration
#define Q0  ( W[0 ] = rotate((sha1_hash[2 ] ^ sha1_hash[0 ]), 1) )
#define Q1  ( W[1 ] = rotate((sha1_hash[3 ] ^ sha1_hash[1 ]), 1) )
#define Q2  ( W[2 ] = rotate((0x2A0 ^ sha1_hash[4 ] ^ sha1_hash[2 ]), 1) )
#define Q3  ( W[3 ] = rotate((W[0 ] ^ 0x80000000 ^ sha1_hash[3 ]), 1) )
#define Q4  ( W[4 ] = rotate((W[1 ] ^ sha1_hash[4 ]), 1) )
#define Q5  ( W[5 ] = rotate((W[2 ] ^ 0x80000000), 1) )
#define Q6  ( W[6 ] = rotate((W[3 ] ), 1) )
#define Q7  ( W[7 ] = rotate((W[4 ] ^ 0x2A0), 1) )
#define Q8  ( W[8 ] = rotate((W[5 ] ^ W[0 ]), 1) )
#define Q9  ( W[9 ] = rotate((W[6 ] ^ W[1 ]), 1) )
#define Q10 ( W[10] = rotate((W[7 ] ^ W[2 ]), 1) )
#define Q11 ( W[11] = rotate((W[8 ] ^ W[3 ]), 1) )
#define Q12 ( W[12] = rotate((W[9 ] ^ W[4 ]), 1) )
#define Q13 ( W[13] = rotate((W[10] ^ W[5 ] ^ 0x2A0), 1) )
#define Q14 ( W[14] = rotate((W[11] ^ W[6 ] ^ W[0 ]), 1) )
#define Q15 ( W[15] = rotate((W[12] ^ W[7 ] ^ W[1 ] ^ 0x2A0), 1) )

#undef DCC2_R
#define DCC2_R(w0, w1, w2, w3)	(W[w0] = rotate((W[w0] ^ W[w1] ^ W[w2] ^ W[w3]), 1))

PRIVATE void sha1_process_sha1(const unsigned int state[5], unsigned int sha1_hash[5], unsigned int W[16] )
{
    unsigned int A = state[0];
    unsigned int B = state[1];
    unsigned int C = state[2];
    unsigned int D = state[3];
    unsigned int E = state[4];

    E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + sha1_hash[0]; B = rotate(B, 30);
    D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + sha1_hash[1]; A = rotate(A, 30);
    C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + sha1_hash[2]; E = rotate(E, 30);
    B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + sha1_hash[3]; D = rotate(D, 30);
    A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + sha1_hash[4]; C = rotate(C, 30);
    E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + 0x80000000  ; B = rotate(B, 30);
    D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2		       ; A = rotate(A, 30);
    C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2		       ; E = rotate(E, 30);
    B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2		       ; D = rotate(D, 30);
    A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2		       ; C = rotate(C, 30);
    E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2		       ; B = rotate(B, 30);
    D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2		       ; A = rotate(A, 30);
    C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2		       ; E = rotate(E, 30);
    B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2		       ; D = rotate(D, 30);
    A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2		       ; C = rotate(C, 30);
    E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + 0x2A0	   ; B = rotate(B, 30);
    D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 +  Q0		   ; A = rotate(A, 30);
    C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 +  Q1		   ; E = rotate(E, 30);
    B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 +  Q2		   ; D = rotate(D, 30);
    A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 +  Q3		   ; C = rotate(C, 30);

    E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + Q4 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + Q5 ; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + Q6 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + Q7 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + Q8 ; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + Q9 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + Q10; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + Q11; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + Q12; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + Q13; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + Q14; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + Q15; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R(0, 13, 8 , 2); E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R(1, 14, 9 , 3); D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R(2, 15, 10, 4); C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + DCC2_R(3, 0 , 11, 5); B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + DCC2_R(4, 1 , 12, 6); A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R(5, 2 , 13, 7); E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R(6, 3 , 14, 8); D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R(7, 4 , 15, 9); C = rotate(C, 30);

    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R(8 , 5 , 0 , 10); B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R(9 , 6 , 1 , 11); A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(10, 7 , 2 , 12); E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(11, 8 , 3 , 13); D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(12, 9 , 4 , 14); C = rotate(C, 30);
    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R(13, 10, 5 , 15); B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R(14, 11, 6 , 0 ); A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(15, 12, 7 , 1 ); E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(0 , 13, 8 , 2 ); D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(1 , 14, 9 , 3 ); C = rotate(C, 30);
    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R(2 , 15, 10, 4 ); B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R(3 , 0 , 11, 5 ); A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(4 , 1 , 12, 6 ); E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(5 , 2 , 13, 7 ); D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(6 , 3 , 14, 8 ); C = rotate(C, 30);
    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R(7 , 4 , 15, 9 ); B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R(8 , 5 , 0 , 10); A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(9 , 6 , 1 , 11); E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(10, 7 , 2 , 12); D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(11, 8 , 3 , 13); C = rotate(C, 30);
																   
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R(12, 9 , 4 , 14); B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(13, 10, 5 , 15); A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R(14, 11, 6 , 0 ); E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R(15, 12, 7 , 1 ); D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R(0 , 13, 8 , 2 ); C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R(1 , 14, 9 , 3 ); B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(2 , 15, 10, 4 ); A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R(3 , 0 , 11, 5 ); E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R(4 , 1 , 12, 6 ); D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R(5 , 2 , 13, 7 ); C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R(6 , 3 , 14, 8 ); B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(7 , 4 , 15, 9 ); A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R(8 , 5 , 0 , 10); E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R(9 , 6 , 1 , 11); D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R(10, 7 , 2 , 12); C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R(11, 8 , 3 , 13); B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(12, 9 , 4 , 14); A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R(13, 10, 5 , 15); E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R(14, 11, 6 , 0 ); D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R(15, 12, 7 , 1 ); C = rotate(C, 30);

    sha1_hash[0] = state[0] + A;
    sha1_hash[1] = state[1] + B;
    sha1_hash[2] = state[2] + C;
    sha1_hash[3] = state[3] + D;
    sha1_hash[4] = state[4] + E;
}

void dcc_ntlm_part_c_code(unsigned int* nt_buffer, unsigned int* crypt_result);
void dcc_salt_part_c_code(unsigned int* salt_buffer, unsigned int* crypt_result);
PRIVATE void crypt_ntlm_protocol_c_code(CryptParam* param)
{
	unsigned int * nt_buffer = (unsigned int* )calloc(16*NT_NUM_KEYS, sizeof(unsigned int));
	unsigned char* key       = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));

	unsigned int crypt_result[12],sha1_hash[5], opad_state[5], ipad_state[5], W[16];

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(unsigned int i = 0; i < NT_NUM_KEYS; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;
			dcc_ntlm_part_c_code(nt_buffer+i, crypt_result);

			// For all salts
			for(unsigned int j = 0; continue_attack && j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_c_code(salt_buffer, crypt_result);
				
				unsigned int a = crypt_result[8+0];
				unsigned int b = crypt_result[8+1];
				unsigned int c = crypt_result[8+2];
				unsigned int d = crypt_result[8+3];

				d = rotate(d + SQRT_3, 9);
				c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = rotate(c, 11);
				b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = rotate(b, 15);
													
				a += (b ^ c ^ d) +crypt_result[3] + SQRT_3; a = rotate(a, 3);
				d += (a ^ b ^ c) + salt_buffer[7] + SQRT_3; d = rotate(d, 9);
				c += (d ^ a ^ b) + salt_buffer[3] + SQRT_3; c = rotate(c, 11);
				b += (c ^ d ^ a)				  + SQRT_3; b = rotate(b, 15);

				a += INIT_A;
				b += INIT_B;
				c += INIT_C;
				d += INIT_D;

				//pbkdf2
				unsigned int salt_len = (salt_buffer[10] >> 3) - 16;
				LOAD_BIG_ENDIAN(a, a);
				LOAD_BIG_ENDIAN(b, b);
				LOAD_BIG_ENDIAN(c, c);
				LOAD_BIG_ENDIAN(d, d);

				// ipad_state
				W[0] = a ^ 0x36363636;
				W[1] = b ^ 0x36363636;
				W[2] = c ^ 0x36363636;
				W[3] = d ^ 0x36363636;
				memset(&W[4], 0x36, (16-4)*sizeof(unsigned int));

				ipad_state[0] = INIT_A;
				ipad_state[1] = INIT_B;
				ipad_state[2] = INIT_C;
				ipad_state[3] = INIT_D;
				ipad_state[4] = INIT_E;
				sha1_process( ipad_state, W, 1 );

				// opad_state
				W[0] = a ^ 0x5C5C5C5C;
				W[1] = b ^ 0x5C5C5C5C;
				W[2] = c ^ 0x5C5C5C5C;
				W[3] = d ^ 0x5C5C5C5C;
				memset(&W[4], 0x5C, (16-4)*sizeof(unsigned int));

				opad_state[0] = INIT_A;
				opad_state[1] = INIT_B;
				opad_state[2] = INIT_C;
				opad_state[3] = INIT_D;
				opad_state[4] = INIT_E;
				sha1_process( opad_state, W, 1 );

				memcpy(&sha1_hash, &ipad_state, 5*sizeof(unsigned int));

				// Process the salt
				memcpy(W, salt_buffer, salt_len);
				memcpy(((unsigned char*)W)+salt_len, "\x0\x0\x0\x1\x80", 5);
				memset(((unsigned char*)W)+salt_len+5, 0, 60 - (salt_len+5));
				W[15] = (64+salt_len+4) << 3;
				for (unsigned int k = 0; k < 14; k++)
				{
					LOAD_BIG_ENDIAN(W[k], W[k]);
				}
				sha1_process( sha1_hash, W, 1 );

				sha1_process_sha1( opad_state, sha1_hash, W);
				// Only copy first 16 bytes, since that is ALL this format uses
				memcpy(crypt_result+8, sha1_hash, 4*sizeof(unsigned int));

				for(unsigned int k = 1; k < 10240; k++)
				{
					sha1_process_sha1( ipad_state, sha1_hash, W);
					sha1_process_sha1( opad_state, sha1_hash, W);

					// Only XOR first 16 bytes, since that is ALL this format uses
					crypt_result[8+0] ^= sha1_hash[0];
					crypt_result[8+1] ^= sha1_hash[1];
					crypt_result[8+2] ^= sha1_hash[2];
					crypt_result[8+3] ^= sha1_hash[3];
				}

				// Search for a match
				unsigned int index = salt_index[j];

				// Partial match
				while(index != NO_ELEM)
				{
					unsigned int* bin = ((unsigned int*)binary_values) + index*4;

					// Total match
					if(crypt_result[8+0] == bin[0] && crypt_result[8+1] == bin[1] && crypt_result[8+2] == bin[2] && crypt_result[8+3] == bin[3])
						password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));
					
					index = same_salt_next[index];
				}
			}
		}
	}

	free(key);
	free(nt_buffer);
	finish_thread();
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include <emmintrin.h>

#define SSE2_AND(a,b)	_mm_and_si128(a,b)
#define SSE2_OR(a,b)	_mm_or_si128(a,b)
#define SSE2_XOR(a,b)	_mm_xor_si128(a,b)
#define SSE2_ADD(a,b)	_mm_add_epi32(a,b)

#define SSE2_3XOR(a,b,c)		SSE2_XOR(SSE2_XOR(a,b),c)
#define SSE2_4XOR(a,b,c,d)		SSE2_XOR(SSE2_XOR(a,b),SSE2_XOR(c,d))
#define SSE2_3ADD(a,b,c)		SSE2_ADD(SSE2_ADD(a,b),c)
#define SSE2_4ADD(a,b,c,d)		SSE2_ADD(SSE2_ADD(a,b),SSE2_ADD(c,d))
#define SSE2_5ADD(a,b,c,d,e)	SSE2_ADD(SSE2_ADD(SSE2_ADD(a,b),SSE2_ADD(c,d)),e)

#define SSE2_ROTATE(a,rot)	SSE2_OR(_mm_slli_epi32(a, rot), _mm_srli_epi32(a, 32-rot))

#define LOAD_BIG_ENDIAN_SSE2(x) x = SSE2_OR(_mm_slli_epi32(x, 16), _mm_srli_epi32(x, 16)); x = SSE2_ADD(_mm_slli_epi32(SSE2_AND(x, _mm_set1_epi32(0x00FF00FF)), 8), SSE2_AND(_mm_srli_epi32(x, 8), _mm_set1_epi32(0x00FF00FF)));
// Calculate W in each iteration
#undef DCC2_R
#define DCC2_R(w0, w1, w2, w3)	W[w0] = SSE2_ROTATE(SSE2_4XOR(W[w0], W[w1], W[w2], W[w3]), 1)

PRIVATE void sha1_process_sha1_sse2(const __m128i* state, __m128i* sha1_hash, __m128i* W)
{
    __m128i A = state[0];
    __m128i B = state[1];
    __m128i C = state[2];
    __m128i D = state[3];
    __m128i E = state[4];

	__m128i step_const = _mm_set1_epi32(SQRT_2);
    E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), step_const, sha1_hash[0]			); B = SSE2_ROTATE(B, 30);
    D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), step_const, sha1_hash[1]			); A = SSE2_ROTATE(A, 30);
    C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_XOR(B, SSE2_AND(E, SSE2_XOR(A, B))), step_const, sha1_hash[2]			); E = SSE2_ROTATE(E, 30);
    B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_XOR(A, SSE2_AND(D, SSE2_XOR(E, A))), step_const, sha1_hash[3]			); D = SSE2_ROTATE(D, 30);
    A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), step_const, sha1_hash[4]			); C = SSE2_ROTATE(C, 30);
    E = SSE2_4ADD(E, SSE2_ROTATE(A, 5), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), _mm_set1_epi32(SQRT_2+0x80000000) ); B = SSE2_ROTATE(B, 30);
    D = SSE2_4ADD(D, SSE2_ROTATE(E, 5), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), step_const						); A = SSE2_ROTATE(A, 30);
    C = SSE2_4ADD(C, SSE2_ROTATE(D, 5), SSE2_XOR(B, SSE2_AND(E, SSE2_XOR(A, B))), step_const						); E = SSE2_ROTATE(E, 30);
    B = SSE2_4ADD(B, SSE2_ROTATE(C, 5), SSE2_XOR(A, SSE2_AND(D, SSE2_XOR(E, A))), step_const						); D = SSE2_ROTATE(D, 30);
    A = SSE2_4ADD(A, SSE2_ROTATE(B, 5), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), step_const						); C = SSE2_ROTATE(C, 30);
    E = SSE2_4ADD(E, SSE2_ROTATE(A, 5), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), step_const						); B = SSE2_ROTATE(B, 30);
    D = SSE2_4ADD(D, SSE2_ROTATE(E, 5), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), step_const						); A = SSE2_ROTATE(A, 30);
    C = SSE2_4ADD(C, SSE2_ROTATE(D, 5), SSE2_XOR(B, SSE2_AND(E, SSE2_XOR(A, B))), step_const						); E = SSE2_ROTATE(E, 30);
    B = SSE2_4ADD(B, SSE2_ROTATE(C, 5), SSE2_XOR(A, SSE2_AND(D, SSE2_XOR(E, A))), step_const						); D = SSE2_ROTATE(D, 30);
    A = SSE2_4ADD(A, SSE2_ROTATE(B, 5), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), step_const						); C = SSE2_ROTATE(C, 30);
    E = SSE2_4ADD(E, SSE2_ROTATE(A, 5), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), _mm_set1_epi32(SQRT_2 + 0x2A0)	); B = SSE2_ROTATE(B, 30);
    W[0] = SSE2_ROTATE(SSE2_XOR(sha1_hash[2 ], sha1_hash[0 ]), 1)						; D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), step_const, W[0]); A = SSE2_ROTATE(A, 30);
    W[1] = SSE2_ROTATE(SSE2_XOR(sha1_hash[3 ], sha1_hash[1 ]), 1)						; C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_XOR(B, SSE2_AND(E, SSE2_XOR(A, B))), step_const, W[1]); E = SSE2_ROTATE(E, 30);
	W[2] = SSE2_ROTATE(SSE2_3XOR(_mm_set1_epi32(0x2A0), sha1_hash[4], sha1_hash[2]), 1) ; B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_XOR(A, SSE2_AND(D, SSE2_XOR(E, A))), step_const, W[2]); D = SSE2_ROTATE(D, 30);
	W[3] = SSE2_ROTATE(SSE2_3XOR(W[0], _mm_set1_epi32(0x80000000), sha1_hash[3]), 1)	; A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), step_const, W[3]); C = SSE2_ROTATE(C, 30);

	step_const = _mm_set1_epi32(SQRT_3);
	W[4 ] = SSE2_ROTATE(SSE2_XOR(W[1], sha1_hash[4 ]), 1) 						; E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[4 ]); B = SSE2_ROTATE(B, 30);
	W[5 ] = SSE2_ROTATE(SSE2_XOR(W[2], _mm_set1_epi32(0x80000000)), 1) 			; D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[5 ]); A = SSE2_ROTATE(A, 30);
	W[6 ] = SSE2_ROTATE(W[3], 1) 												; C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[6 ]); E = SSE2_ROTATE(E, 30);
	W[7 ] = SSE2_ROTATE(SSE2_XOR(W[4], _mm_set1_epi32(0x2A0)), 1) 				; B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[7 ]); D = SSE2_ROTATE(D, 30);
	W[8 ] = SSE2_ROTATE(SSE2_XOR(W[5], W[0]), 1) 								; A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[8 ]); C = SSE2_ROTATE(C, 30);
	W[9 ] = SSE2_ROTATE(SSE2_XOR(W[6], W[1]), 1) 								; E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[9 ]); B = SSE2_ROTATE(B, 30);
	W[10] = SSE2_ROTATE(SSE2_XOR(W[7], W[2]), 1) 								; D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[10]); A = SSE2_ROTATE(A, 30);
	W[11] = SSE2_ROTATE(SSE2_XOR(W[8], W[3] ), 1) 								; C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[11]); E = SSE2_ROTATE(E, 30);
	W[12] = SSE2_ROTATE(SSE2_XOR(W[9], W[4]), 1) 								; B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[12]); D = SSE2_ROTATE(D, 30);
	W[13] = SSE2_ROTATE(SSE2_3XOR(W[10], W[5], _mm_set1_epi32(0x2A0)), 1) 		; A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[13]); C = SSE2_ROTATE(C, 30);
	W[14] = SSE2_ROTATE(SSE2_3XOR(W[11], W[6], W[0]), 1) 						; E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[14]); B = SSE2_ROTATE(B, 30);
	W[15] = SSE2_ROTATE(SSE2_4XOR(W[12], W[7], W[1], _mm_set1_epi32(0x2A0)), 1) ; D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[15]); A = SSE2_ROTATE(A, 30);
    DCC2_R(0, 13,  8, 2); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[0]); E = SSE2_ROTATE(E, 30);
    DCC2_R(1, 14,  9, 3); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[1]); D = SSE2_ROTATE(D, 30);
    DCC2_R(2, 15, 10, 4); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[2]); C = SSE2_ROTATE(C, 30);
    DCC2_R(3,  0, 11, 5); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[3]); B = SSE2_ROTATE(B, 30);
    DCC2_R(4,  1, 12, 6); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[4]); A = SSE2_ROTATE(A, 30);
    DCC2_R(5,  2, 13, 7); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[5]); E = SSE2_ROTATE(E, 30);
    DCC2_R(6,  3, 14, 8); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[6]); D = SSE2_ROTATE(D, 30);
    DCC2_R(7,  4, 15, 9); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[7]); C = SSE2_ROTATE(C, 30);

	step_const = _mm_set1_epi32(0x8F1BBCDC);
    DCC2_R(8 ,  5,  0, 10); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))), step_const, W[8 ]); B = SSE2_ROTATE(B, 30);
    DCC2_R(9 ,  6,  1, 11); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))), step_const, W[9 ]); A = SSE2_ROTATE(A, 30);
    DCC2_R(10,  7,  2, 12); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_OR(SSE2_AND(E, A), SSE2_AND(B, SSE2_OR(E, A))), step_const, W[10]); E = SSE2_ROTATE(E, 30);
    DCC2_R(11,  8,  3, 13); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_OR(SSE2_AND(D, E), SSE2_AND(A, SSE2_OR(D, E))), step_const, W[11]); D = SSE2_ROTATE(D, 30);
    DCC2_R(12,  9,  4, 14); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))), step_const, W[12]); C = SSE2_ROTATE(C, 30);
    DCC2_R(13, 10,  5, 15); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))), step_const, W[13]); B = SSE2_ROTATE(B, 30);
    DCC2_R(14, 11,  6,  0); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))), step_const, W[14]); A = SSE2_ROTATE(A, 30);
    DCC2_R(15, 12,  7,  1); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_OR(SSE2_AND(E, A), SSE2_AND(B, SSE2_OR(E, A))), step_const, W[15]); E = SSE2_ROTATE(E, 30);
    DCC2_R(0 , 13,  8,  2); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_OR(SSE2_AND(D, E), SSE2_AND(A, SSE2_OR(D, E))), step_const, W[0 ]); D = SSE2_ROTATE(D, 30);
    DCC2_R(1 , 14,  9,  3); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))), step_const, W[1 ]); C = SSE2_ROTATE(C, 30);
    DCC2_R(2 , 15, 10,  4); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))), step_const, W[2 ]); B = SSE2_ROTATE(B, 30);
    DCC2_R(3 ,  0, 11,  5); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))), step_const, W[3 ]); A = SSE2_ROTATE(A, 30);
    DCC2_R(4 ,  1, 12,  6); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_OR(SSE2_AND(E, A), SSE2_AND(B, SSE2_OR(E, A))), step_const, W[4 ]); E = SSE2_ROTATE(E, 30);
    DCC2_R(5 ,  2, 13,  7); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_OR(SSE2_AND(D, E), SSE2_AND(A, SSE2_OR(D, E))), step_const, W[5 ]); D = SSE2_ROTATE(D, 30);
    DCC2_R(6 ,  3, 14,  8); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))), step_const, W[6 ]); C = SSE2_ROTATE(C, 30);
    DCC2_R(7 ,  4, 15,  9); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))), step_const, W[7 ]); B = SSE2_ROTATE(B, 30);
    DCC2_R(8 ,  5,  0, 10); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))), step_const, W[8 ]); A = SSE2_ROTATE(A, 30);
    DCC2_R(9 ,  6,  1, 11); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_OR(SSE2_AND(E, A), SSE2_AND(B, SSE2_OR(E, A))), step_const, W[9 ]); E = SSE2_ROTATE(E, 30);
    DCC2_R(10,  7,  2, 12); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_OR(SSE2_AND(D, E), SSE2_AND(A, SSE2_OR(D, E))), step_const, W[10]); D = SSE2_ROTATE(D, 30);
    DCC2_R(11,  8,  3, 13); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))), step_const, W[11]); C = SSE2_ROTATE(C, 30);
										
	step_const = _mm_set1_epi32(0xCA62C1D6);
    DCC2_R(12,  9,  4, 14); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[12]); B = SSE2_ROTATE(B, 30);
    DCC2_R(13, 10,  5, 15); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[13]); A = SSE2_ROTATE(A, 30);
    DCC2_R(14, 11,  6,  0); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[14]); E = SSE2_ROTATE(E, 30);
    DCC2_R(15, 12,  7,  1); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[15]); D = SSE2_ROTATE(D, 30);
    DCC2_R(0 , 13,  8,  2); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[0 ]); C = SSE2_ROTATE(C, 30);
    DCC2_R(1 , 14,  9,  3); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[1 ]); B = SSE2_ROTATE(B, 30);
    DCC2_R(2 , 15, 10,  4); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[2 ]); A = SSE2_ROTATE(A, 30);
    DCC2_R(3 ,  0, 11,  5); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[3 ]); E = SSE2_ROTATE(E, 30);
    DCC2_R(4 ,  1, 12,  6); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[4 ]); D = SSE2_ROTATE(D, 30);
    DCC2_R(5 ,  2, 13,  7); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[5 ]); C = SSE2_ROTATE(C, 30);
    DCC2_R(6 ,  3, 14,  8); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[6 ]); B = SSE2_ROTATE(B, 30);
    DCC2_R(7 ,  4, 15,  9); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[7 ]); A = SSE2_ROTATE(A, 30);
    DCC2_R(8 ,  5,  0, 10); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[8 ]); E = SSE2_ROTATE(E, 30);
    DCC2_R(9 ,  6,  1, 11); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[9 ]); D = SSE2_ROTATE(D, 30);
    DCC2_R(10,  7,  2, 12); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[10]); C = SSE2_ROTATE(C, 30);
    DCC2_R(11,  8,  3, 13); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[11]); B = SSE2_ROTATE(B, 30);
    DCC2_R(12,  9,  4, 14); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[12]); A = SSE2_ROTATE(A, 30);
    DCC2_R(13, 10,  5, 15); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[13]); E = SSE2_ROTATE(E, 30);
    DCC2_R(14, 11,  6,  0); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[14]); D = SSE2_ROTATE(D, 30);
    DCC2_R(15, 12,  7,  1); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[15]); C = SSE2_ROTATE(C, 30);

    sha1_hash[0] = SSE2_ADD(state[0], A);
    sha1_hash[1] = SSE2_ADD(state[1], B);
    sha1_hash[2] = SSE2_ADD(state[2], C);
    sha1_hash[3] = SSE2_ADD(state[3], D);
    sha1_hash[4] = SSE2_ADD(state[4], E);
}

void dcc_ntlm_part_sse2(__m128i* nt_buffer, __m128i* crypt_result);
void dcc_salt_part_sse2(unsigned int* salt_buffer, __m128i* crypt_result);
PRIVATE void dcc2_body_sse2(__m128i* crypt_result, unsigned int* salt_buffer, int mul, int index)
{
	__m128i* sha1_hash = crypt_result + 12*mul + 5*index;
	__m128i* opad_state = sha1_hash + 5*mul;
	__m128i* ipad_state = opad_state + 5*mul;
	__m128i* W = ipad_state + 5*mul + (16-5)*index;


	__m128i a = crypt_result[(8+0)*mul+index];
	__m128i b = crypt_result[(8+1)*mul+index];
	__m128i c = crypt_result[(8+2)*mul+index];
	__m128i d = crypt_result[(8+3)*mul+index];
	__m128i const_sse2 = _mm_set1_epi32(SQRT_3);

	d = SSE2_ADD(d, const_sse2); d = SSE2_ROTATE(d, 9);
	c = SSE2_4ADD(c, SSE2_3XOR(d, a, b), _mm_set1_epi32(salt_buffer[1]), const_sse2); c = SSE2_ROTATE(c, 11);
	b = SSE2_4ADD(b, SSE2_3XOR(c, d, a), _mm_set1_epi32(salt_buffer[9]), const_sse2); b = SSE2_ROTATE(b, 15);

	a = SSE2_4ADD(a, SSE2_3XOR(b, c, d),	crypt_result[3*mul+index]  , const_sse2); a = SSE2_ROTATE(a, 3);
	d = SSE2_4ADD(d, SSE2_3XOR(a, b, c), _mm_set1_epi32(salt_buffer[7]), const_sse2); d = SSE2_ROTATE(d, 9);
	c = SSE2_4ADD(c, SSE2_3XOR(d, a, b), _mm_set1_epi32(salt_buffer[3]), const_sse2); c = SSE2_ROTATE(c, 11);
	b = SSE2_3ADD(b, SSE2_3XOR(c, d, a)								   , const_sse2); b = SSE2_ROTATE(b, 15);

	a = SSE2_ADD(a, _mm_set1_epi32(INIT_A));
	b = SSE2_ADD(b, _mm_set1_epi32(INIT_B));
	c = SSE2_ADD(c, _mm_set1_epi32(INIT_C));
	d = SSE2_ADD(d, _mm_set1_epi32(INIT_D));

	//pbkdf2
	unsigned int salt_len = (salt_buffer[10] >> 3) - 16;
	LOAD_BIG_ENDIAN_SSE2(a);
	LOAD_BIG_ENDIAN_SSE2(b);
	LOAD_BIG_ENDIAN_SSE2(c);
	LOAD_BIG_ENDIAN_SSE2(d);

	// ipad_state
	const_sse2 = _mm_set1_epi32(0x36363636);
	W[0] = SSE2_XOR(a, const_sse2);
	W[1] = SSE2_XOR(b, const_sse2);
	W[2] = SSE2_XOR(c, const_sse2);
	W[3] = SSE2_XOR(d, const_sse2);
	memset(W+4, 0x36, (16-4)*sizeof(__m128i));

	ipad_state[0] = _mm_set1_epi32(INIT_A);
	ipad_state[1] = _mm_set1_epi32(INIT_B);
	ipad_state[2] = _mm_set1_epi32(INIT_C);
	ipad_state[3] = _mm_set1_epi32(INIT_D);
	ipad_state[4] = _mm_set1_epi32(INIT_E);
	sha1_process( (unsigned int*)ipad_state, (unsigned int*)W, 4 );

	// opad_state
	const_sse2 = _mm_set1_epi32(0x5C5C5C5C);
	W[0] = SSE2_XOR(a, const_sse2);
	W[1] = SSE2_XOR(b, const_sse2);
	W[2] = SSE2_XOR(c, const_sse2);
	W[3] = SSE2_XOR(d, const_sse2);
	memset(W+4, 0x5C, (16-4)*sizeof(__m128i));

	opad_state[0] = _mm_set1_epi32(INIT_A);
	opad_state[1] = _mm_set1_epi32(INIT_B);
	opad_state[2] = _mm_set1_epi32(INIT_C);
	opad_state[3] = _mm_set1_epi32(INIT_D);
	opad_state[4] = _mm_set1_epi32(INIT_E);
	sha1_process( (unsigned int*)opad_state, (unsigned int*)W, 4 );

	memcpy(sha1_hash, ipad_state, 5*sizeof(__m128i));

	// Process the salt
	memcpy(W, salt_buffer, salt_len);
	memcpy(((unsigned char*)W)+salt_len, "\x0\x0\x0\x1\x80", 5);
	memset(((unsigned char*)W)+salt_len+5, 0, 60 - (salt_len+5));
	W[14] = _mm_set1_epi32(0);
	W[15] = _mm_set1_epi32((64+salt_len+4) << 3);
	for (int k = 13; k >= 0; k--)
	{
		// Convert to BIG_ENDIAN
		unsigned int x = rotate(((unsigned int*)W)[k], 16U);
		x = ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
		W[k] = _mm_set1_epi32(x);
	}
	sha1_process( (unsigned int*)sha1_hash, (unsigned int*)W, 4 );

	sha1_process_sha1_sse2( opad_state, sha1_hash, W);
	// Only copy first 4 elements, since that is ALL this format uses
	crypt_result[(8+0)*mul+index] = sha1_hash[0];
	crypt_result[(8+1)*mul+index] = sha1_hash[1];
	crypt_result[(8+2)*mul+index] = sha1_hash[2];
	crypt_result[(8+3)*mul+index] = sha1_hash[3];
}
PRIVATE void crypt_ntlm_protocol_sse2(CryptParam* param)
{
	__m128i* nt_buffer = (__m128i*)_aligned_malloc(16*4*NT_NUM_KEYS, 16);
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));
	__m128i* crypt_result = (__m128i*)_aligned_malloc(sizeof(__m128i)*(12+5+5+5+16), 16);

	__m128i* sha1_hash = crypt_result + 12;
	__m128i* opad_state = sha1_hash + 5;
	__m128i* ipad_state = opad_state + 5;
	__m128i* W = ipad_state + 5;

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(unsigned int i = 0; i < NT_NUM_KEYS/4; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;
			dcc_ntlm_part_sse2(nt_buffer+i, crypt_result);

			// For all salts
			for(unsigned int j = 0; continue_attack && j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_sse2(salt_buffer, crypt_result);
				
				dcc2_body_sse2(crypt_result, salt_buffer, 1, 0);

				for(unsigned int k = 1; k < 10240; k++)
				{
					sha1_process_sha1_sse2( ipad_state, sha1_hash, W);
					sha1_process_sha1_sse2( opad_state, sha1_hash, W);

					// Only XOR first 16 bytes, since that is ALL this format uses
					crypt_result[8+0] = SSE2_XOR(crypt_result[8+0], sha1_hash[0]);
					crypt_result[8+1] = SSE2_XOR(crypt_result[8+1], sha1_hash[1]);
					crypt_result[8+2] = SSE2_XOR(crypt_result[8+2], sha1_hash[2]);
					crypt_result[8+3] = SSE2_XOR(crypt_result[8+3], sha1_hash[3]);
				}

				// Search for a match
				for (unsigned int k = 0; k < 4; k++)
				{
					unsigned int index = salt_index[j];
					// Partial match
					while(index != NO_ELEM)
					{
						unsigned int* bin = ((unsigned int*)binary_values) + index*4;

						// Total match
						if(crypt_result[8+0].m128i_u32[k] == bin[0] && crypt_result[8+1].m128i_u32[k] == bin[1] && crypt_result[8+2].m128i_u32[k] == bin[2] && crypt_result[8+3].m128i_u32[k] == bin[3])
							password_was_found(index, ntlm2utf8_key((unsigned int*)nt_buffer, key, NT_NUM_KEYS, i*4+k));
					
						index = same_salt_next[index];
					}
				}
			}
		}
	}

	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);
	finish_thread();
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
void dcc_ntlm_part_avx(void* nt_buffer, __m128i* crypt_result);
void dcc_salt_part_avx(void* salt_buffer, __m128i* crypt_result);
void sha1_process_sha1_avx(const void* state, void* sha1_hash, void* W);
#define NT_NUM_KEYS_AVX 256

PRIVATE void crypt_ntlm_protocol_avx(CryptParam* param)
{
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));
	unsigned int* nt_buffer	= (unsigned int*)_aligned_malloc(16*4*NT_NUM_KEYS_AVX, 32);
	__m128i* crypt_result = (__m128i*)_aligned_malloc(sizeof(__m128i)*2*(12+5+5+5+16), 32);

	__m128i* sha1_hash = crypt_result + 24;
	__m128i* opad_state = sha1_hash + 10;
	__m128i* ipad_state = opad_state + 10;
	__m128i* W = ipad_state + 10;

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS_AVX);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS_AVX, param->thread_id))
	{
		for(unsigned int i = 0; i < NT_NUM_KEYS_AVX/8; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;
			dcc_ntlm_part_avx(nt_buffer+8*i, crypt_result);

			// For all salts
			for(unsigned int j = 0; continue_attack && j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_avx(salt_buffer, crypt_result);

				dcc2_body_sse2(crypt_result, salt_buffer, 2, 0);
				dcc2_body_sse2(crypt_result, salt_buffer, 2, 1);

				for(unsigned int k = 1; k < 10240; k++)
				{
					sha1_process_sha1_avx( ipad_state, sha1_hash, W);
					sha1_process_sha1_avx( opad_state, sha1_hash, W);

					// Only XOR first 16 bytes, since that is ALL this format uses
					crypt_result[(8+0)*2+0] = SSE2_XOR(crypt_result[(8+0)*2+0], sha1_hash[0]);
					crypt_result[(8+1)*2+0] = SSE2_XOR(crypt_result[(8+1)*2+0], sha1_hash[1]);
					crypt_result[(8+2)*2+0] = SSE2_XOR(crypt_result[(8+2)*2+0], sha1_hash[2]);
					crypt_result[(8+3)*2+0] = SSE2_XOR(crypt_result[(8+3)*2+0], sha1_hash[3]);

					crypt_result[(8+0)*2+1] = SSE2_XOR(crypt_result[(8+0)*2+1], sha1_hash[5]);
					crypt_result[(8+1)*2+1] = SSE2_XOR(crypt_result[(8+1)*2+1], sha1_hash[6]);
					crypt_result[(8+2)*2+1] = SSE2_XOR(crypt_result[(8+2)*2+1], sha1_hash[7]);
					crypt_result[(8+3)*2+1] = SSE2_XOR(crypt_result[(8+3)*2+1], sha1_hash[8]);
				}

				for(unsigned int k = 0; k < 8; k++)
				{
					// Search for a match
					unsigned int index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						unsigned int* bin = ((unsigned int*)binary_values) + index * 4;
						unsigned int* crypt_bin = (unsigned int*)(crypt_result + 8 * 2);

						// Total match
						if(crypt_bin[k+8*0] == bin[0] && crypt_bin[k+8*1] == bin[1] && crypt_bin[k+8*2] == bin[2] && crypt_bin[k+8*3] == bin[3])
							password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS_AVX, 8*i+k));

						index = same_salt_next[index];
					}
				}
			}
		}
	}

	// Release resources
	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);

	finish_thread();
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include <immintrin.h>

void dcc_ntlm_part_avx2(void* nt_buffer, void* crypt_result);
void dcc_salt_part_avx2(void* salt_buffer, void* crypt_result);
void sha1_process_sha1_avx2(const void* state, void* sha1_hash, void* W);

#define AVX2_AND(a,b)		_mm256_and_si256(a,b)
#define AVX2_XOR(a,b)		_mm256_xor_si256(a,b)
#define AVX2_ADD(a,b)		_mm256_add_epi32(a,b)
#define AVX2_ROTATE(a,rot)	AVX2_XOR(_mm256_slli_epi32(a,rot), _mm256_srli_epi32(a,32-rot))
#define AVX2_4ADD(a,b,c,d)	AVX2_ADD(AVX2_ADD(a,b), AVX2_ADD(c,d))
#define AVX2_3ADD(a,b,c)	AVX2_ADD(AVX2_ADD(a,b), c)
#define AVX2_3XOR(a,b,c)	AVX2_XOR(AVX2_XOR(a,b), c)

#define LOAD_BIG_ENDIAN_AVX2(x) x = AVX2_XOR(_mm256_slli_epi32(x, 16), _mm256_srli_epi32(x, 16)); x = AVX2_ADD(_mm256_slli_epi32(AVX2_AND(x, _mm256_broadcastd_epi32(_mm_set1_epi32(0x00FF00FF))), 8), AVX2_AND(_mm256_srli_epi32(x, 8), _mm256_broadcastd_epi32(_mm_set1_epi32(0x00FF00FF))));

PRIVATE void dcc2_body_avx2(__m256i* crypt_result, unsigned int* salt_buffer, int index)
{
	__m256i* sha1_hash = crypt_result + 24 + 5*index;
	__m256i* opad_state = sha1_hash + 10;
	__m256i* ipad_state = opad_state + 10;
	__m256i* W = ipad_state + 10 + (16-5)*index;

	__m256i a = crypt_result[(8+0)*2+index];
	__m256i b = crypt_result[(8+1)*2+index];
	__m256i c = crypt_result[(8+2)*2+index];
	__m256i d = crypt_result[(8+3)*2+index];
	__m256i const_sse2;
	for (size_t i = 0; i < 8; i++)
		const_sse2.m256i_u32[i] = SQRT_3;

	d = AVX2_ADD(d, const_sse2); d = AVX2_ROTATE(d, 9);
	c = AVX2_4ADD(c, AVX2_3XOR(d, a, b), _mm256_broadcastd_epi32(_mm_set1_epi32(salt_buffer[1])), const_sse2); c = AVX2_ROTATE(c, 11);
	b = AVX2_4ADD(b, AVX2_3XOR(c, d, a), _mm256_broadcastd_epi32(_mm_set1_epi32(salt_buffer[9])), const_sse2); b = AVX2_ROTATE(b, 15);

	a = AVX2_4ADD(a, AVX2_3XOR(b, c, d),			crypt_result[3*2+index]						, const_sse2); a = AVX2_ROTATE(a, 3);
	d = AVX2_4ADD(d, AVX2_3XOR(a, b, c), _mm256_broadcastd_epi32(_mm_set1_epi32(salt_buffer[7])), const_sse2); d = AVX2_ROTATE(d, 9);
	c = AVX2_4ADD(c, AVX2_3XOR(d, a, b), _mm256_broadcastd_epi32(_mm_set1_epi32(salt_buffer[3])), const_sse2); c = AVX2_ROTATE(c, 11);
	b = AVX2_3ADD(b, AVX2_3XOR(c, d, a)															, const_sse2); b = AVX2_ROTATE(b, 15);

	a = AVX2_ADD(a, _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_A)));
	b = AVX2_ADD(b, _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_B)));
	c = AVX2_ADD(c, _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_C)));
	d = AVX2_ADD(d, _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_D)));

	//pbkdf2
	unsigned int salt_len = (salt_buffer[10] >> 3) - 16;
	LOAD_BIG_ENDIAN_AVX2(a);
	LOAD_BIG_ENDIAN_AVX2(b);
	LOAD_BIG_ENDIAN_AVX2(c);
	LOAD_BIG_ENDIAN_AVX2(d);

	// ipad_state
	for (size_t i = 0; i < 8; i++)
		const_sse2.m256i_u32[i] = 0x36363636;
	W[0] = AVX2_XOR(a, const_sse2);
	W[1] = AVX2_XOR(b, const_sse2);
	W[2] = AVX2_XOR(c, const_sse2);
	W[3] = AVX2_XOR(d, const_sse2);
	memset(W+4, 0x36, (16-4)*sizeof(__m256i));

	ipad_state[0] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_A));
	ipad_state[1] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_B));
	ipad_state[2] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_C));
	ipad_state[3] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_D));
	ipad_state[4] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_E));
	sha1_process( (unsigned int*)ipad_state, (unsigned int*)W, 8 );

	// opad_state
	for (size_t i = 0; i < 8; i++)
		const_sse2.m256i_u32[i] = 0x5C5C5C5C;
	W[0] = AVX2_XOR(a, const_sse2);
	W[1] = AVX2_XOR(b, const_sse2);
	W[2] = AVX2_XOR(c, const_sse2);
	W[3] = AVX2_XOR(d, const_sse2);
	memset(W+4, 0x5C, (16-4)*sizeof(__m256i));

	opad_state[0] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_A));
	opad_state[1] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_B));
	opad_state[2] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_C));
	opad_state[3] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_D));
	opad_state[4] = _mm256_broadcastd_epi32(_mm_set1_epi32(INIT_E));
	sha1_process( (unsigned int*)opad_state, (unsigned int*)W, 8 );

	memcpy(sha1_hash, ipad_state, 5*sizeof(__m256i));

	// Process the salt
	memcpy(W, salt_buffer, salt_len);
	memcpy(((unsigned char*)W)+salt_len, "\x0\x0\x0\x1\x80", 5);
	memset(((unsigned char*)W)+salt_len+5, 0, 60 - (salt_len+5));
	W[14] = _mm256_broadcastd_epi32(_mm_set1_epi32(0));
	W[15] = _mm256_broadcastd_epi32(_mm_set1_epi32((64+salt_len+4) << 3));
	for (int k = 13; k >= 0; k--)
	{
		// Convert to BIG_ENDIAN
		unsigned int x = rotate(((unsigned int*)W)[k], 16U);
		x = ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
		W[k] = _mm256_broadcastd_epi32(_mm_set1_epi32(x));
	}
	sha1_process( (unsigned int*)sha1_hash, (unsigned int*)W, 8 );
}

PRIVATE void crypt_ntlm_protocol_avx2(CryptParam* param)
{
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));
	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc(16 * 4 * NT_NUM_KEYS_AVX, 32);
	__m256i* crypt_result = (__m256i*)_aligned_malloc(sizeof(__m256i)*2*(12+5+5+5+16), 32);

	__m256i* sha1_hash = crypt_result + 24;
	__m256i* opad_state = sha1_hash + 10;
	__m256i* ipad_state = opad_state + 10;
	__m256i* W = ipad_state + 10;

	memset(nt_buffer, 0, 16 * 4 * NT_NUM_KEYS_AVX);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS_AVX, param->thread_id))
	{
		for(unsigned int i = 0; i < NT_NUM_KEYS_AVX/16; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;
			dcc_ntlm_part_avx2(nt_buffer+16*i, crypt_result);

			// For all salts
			for(unsigned int j = 0; continue_attack && j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_avx2(salt_buffer, crypt_result);

				dcc2_body_avx2(crypt_result, salt_buffer, 0);
				dcc2_body_avx2(crypt_result, salt_buffer, 1);

				sha1_process_sha1_avx2( opad_state, sha1_hash, W);
				// Only copy first 4 elements, since that is ALL this format uses
				crypt_result[(8+0)*2+0] = sha1_hash[0];
				crypt_result[(8+1)*2+0] = sha1_hash[1];
				crypt_result[(8+2)*2+0] = sha1_hash[2];
				crypt_result[(8+3)*2+0] = sha1_hash[3];

				crypt_result[(8+0)*2+1] = sha1_hash[5];
				crypt_result[(8+1)*2+1] = sha1_hash[6];
				crypt_result[(8+2)*2+1] = sha1_hash[7];
				crypt_result[(8+3)*2+1] = sha1_hash[8];

				for(unsigned int k = 1; k < 10240; k++)
				{
					sha1_process_sha1_avx2( ipad_state, sha1_hash, W);
					sha1_process_sha1_avx2( opad_state, sha1_hash, W);

					// Only XOR first 16 bytes, since that is ALL this format uses
					crypt_result[(8+0)*2+0] = _mm256_xor_si256(crypt_result[(8+0)*2+0], sha1_hash[0]);
					crypt_result[(8+1)*2+0] = _mm256_xor_si256(crypt_result[(8+1)*2+0], sha1_hash[1]);
					crypt_result[(8+2)*2+0] = _mm256_xor_si256(crypt_result[(8+2)*2+0], sha1_hash[2]);
					crypt_result[(8+3)*2+0] = _mm256_xor_si256(crypt_result[(8+3)*2+0], sha1_hash[3]);

					crypt_result[(8+0)*2+1] = _mm256_xor_si256(crypt_result[(8+0)*2+1], sha1_hash[5]);
					crypt_result[(8+1)*2+1] = _mm256_xor_si256(crypt_result[(8+1)*2+1], sha1_hash[6]);
					crypt_result[(8+2)*2+1] = _mm256_xor_si256(crypt_result[(8+2)*2+1], sha1_hash[7]);
					crypt_result[(8+3)*2+1] = _mm256_xor_si256(crypt_result[(8+3)*2+1], sha1_hash[8]);
				}

				for(unsigned int k = 0; k < 16; k++)
				{
					// Search for a match
					unsigned int index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						unsigned int* bin = ((unsigned int*)binary_values) + index * 4;
						unsigned int* crypt_bin = (unsigned int*)(crypt_result + 8 * 2);

						// Total match
						if(crypt_bin[k+16*0] == bin[0] && crypt_bin[k+16*1] == bin[1] && crypt_bin[k+16*2] == bin[2] && crypt_bin[k+16*3] == bin[3])
							password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS_AVX, 16*i+k));

						index = same_salt_next[index];
					}
				}
			}
		}
	}

	// Release resources
	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);

	finish_thread();
}
#endif

PRIVATE int bench_values[] = {1,4,16,64};
Format dcc2_format = {
	"DCC2"/*"MSCASH2"*/,
	"Domain Cache Credentials 2 (also know as MSCASH2).",
	PLAINTEXT_LENGTH,
	BINARY_SIZE,
	SALT_SIZE,
	4,
	bench_values,
	LENGHT(bench_values),
	get_binary,
#ifdef _M_X64
	{{CPU_CAP_AVX2, PROTOCOL_NTLM, crypt_ntlm_protocol_avx2}, {CPU_CAP_AVX, PROTOCOL_NTLM, crypt_ntlm_protocol_avx}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}},
#else
	{{CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}},
#endif
	{{PROTOCOL_CHARSET_OCL, NULL}, {PROTOCOL_CHARSET_OCL, NULL}, {PROTOCOL_CHARSET_OCL, NULL}, {PROTOCOL_CHARSET_OCL, NULL}}
};

#endif
