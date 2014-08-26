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

// Calculate W in each iteration
#define R0  ( W[0 ] = rotate((W[13] ^ W[8 ] ^ W[2 ] ^ W[0 ]), 1) )
#define R1  ( W[1 ] = rotate((W[14] ^ W[9 ] ^ W[3 ] ^ W[1 ]), 1) )
#define R2  ( W[2 ] = rotate((W[15] ^ W[10] ^ W[4 ] ^ W[2 ]), 1) )
#define R3  ( W[3 ] = rotate((W[0 ] ^ W[11] ^ W[5 ] ^ W[3 ]), 1) )
#define R4  ( W[4 ] = rotate((W[1 ] ^ W[12] ^ W[6 ] ^ W[4 ]), 1) )
#define R5  ( W[5 ] = rotate((W[2 ] ^ W[13] ^ W[7 ] ^ W[5 ]), 1) )
#define R6  ( W[6 ] = rotate((W[3 ] ^ W[14] ^ W[8 ] ^ W[6 ]), 1) )
#define R7  ( W[7 ] = rotate((W[4 ] ^ W[15] ^ W[9 ] ^ W[7 ]), 1) )
#define R8  ( W[8 ] = rotate((W[5 ] ^ W[0 ] ^ W[10] ^ W[8 ]), 1) )
#define R9  ( W[9 ] = rotate((W[6 ] ^ W[1 ] ^ W[11] ^ W[9 ]), 1) )
#define R10 ( W[10] = rotate((W[7 ] ^ W[2 ] ^ W[12] ^ W[10]), 1) )
#define R11 ( W[11] = rotate((W[8 ] ^ W[3 ] ^ W[13] ^ W[11]), 1) )
#define R12 ( W[12] = rotate((W[9 ] ^ W[4 ] ^ W[14] ^ W[12]), 1) )
#define R13 ( W[13] = rotate((W[10] ^ W[5 ] ^ W[15] ^ W[13]), 1) )
#define R14 ( W[14] = rotate((W[11] ^ W[6 ] ^ W[0 ] ^ W[14]), 1) )
#define R15 ( W[15] = rotate((W[12] ^ W[7 ] ^ W[1 ] ^ W[15]), 1) )

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
#define Q11 ( W[11] = rotate((W[8 ] ^ W[3 ] ), 1) )
#define Q12 ( W[12] = rotate((W[9 ] ^ W[4 ]), 1) )
#define Q13 ( W[13] = rotate((W[10] ^ W[5 ] ^ 0x2A0), 1) )
#define Q14 ( W[14] = rotate((W[11] ^ W[6 ] ^ W[0 ]), 1) )
#define Q15 ( W[15] = rotate((W[12] ^ W[7 ] ^ W[1 ] ^ 0x2A0), 1) )

PRIVATE void sha1_process( unsigned int state[5], const unsigned int data[16] )
{
    unsigned int W[16], A, B, C, D, E;

	LOAD_BIG_ENDIAN(W[ 0], data[ 0]);
	LOAD_BIG_ENDIAN(W[ 1], data[ 1]);
	LOAD_BIG_ENDIAN(W[ 2], data[ 2]);
	LOAD_BIG_ENDIAN(W[ 3], data[ 3]);
	LOAD_BIG_ENDIAN(W[ 4], data[ 4]);
	LOAD_BIG_ENDIAN(W[ 5], data[ 5]);
	LOAD_BIG_ENDIAN(W[ 6], data[ 6]);
	LOAD_BIG_ENDIAN(W[ 7], data[ 7]);
	LOAD_BIG_ENDIAN(W[ 8], data[ 8]);
	LOAD_BIG_ENDIAN(W[ 9], data[ 9]);
	LOAD_BIG_ENDIAN(W[10], data[10]);
	LOAD_BIG_ENDIAN(W[11], data[11]);
	LOAD_BIG_ENDIAN(W[12], data[12]);
	LOAD_BIG_ENDIAN(W[13], data[13]);
	W[14] = data[14];
	W[15] = data[15];


    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];

    E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[0 ]; B = rotate(B, 30);
    D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[1 ]; A = rotate(A, 30);
    C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[2 ]; E = rotate(E, 30);
    B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[3 ]; D = rotate(D, 30);
    A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[4 ]; C = rotate(C, 30);
    E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[5 ]; B = rotate(B, 30);
    D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[6 ]; A = rotate(A, 30);
    C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[7 ]; E = rotate(E, 30);
    B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[8 ]; D = rotate(D, 30);
    A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[9 ]; C = rotate(C, 30);
    E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[10]; B = rotate(B, 30);
    D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[11]; A = rotate(A, 30);
    C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[12]; E = rotate(E, 30);
    B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[13]; D = rotate(D, 30);
    A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[14]; C = rotate(C, 30);
    E += rotate(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[15]; B = rotate(B, 30);
    D += rotate(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 +   R0 ; A = rotate(A, 30);
    C += rotate(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 +   R1 ; E = rotate(E, 30);
    B += rotate(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 +   R2 ; D = rotate(D, 30);
    A += rotate(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 +   R3 ; C = rotate(C, 30);

    E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + R4 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + R5 ; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + R6 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + R7 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + R8 ; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + R9 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + R10; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + R11; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + R12; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + R13; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + R14; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + R15; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + R0 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + R1 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + R2 ; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + R3 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + R4 ; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + R5 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + R6 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + R7 ; C = rotate(C, 30);

    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + R8 ; B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + R9 ; A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + R10; E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + R11; D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + R12; C = rotate(C, 30);
    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + R13; B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + R14; A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + R15; E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + R0 ; D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + R1 ; C = rotate(C, 30);
    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + R2 ; B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + R3 ; A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + R4 ; E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + R5 ; D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + R6 ; C = rotate(C, 30);
    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + R7 ; B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + R8 ; A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + R9 ; E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + R10; D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + R11; C = rotate(C, 30);
																   
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + R12; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + R13; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + R14; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + R15; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + R0 ; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + R1 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + R2 ; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + R3 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + R4 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + R5 ; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + R6 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + R7 ; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + R8 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + R9 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + R10; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + R11; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + R12; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + R13; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + R14; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + R15; C = rotate(C, 30);

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
}
PRIVATE void sha1_process_sha1(const unsigned int state[5], unsigned int sha1_hash[5] )
{
    unsigned int W[16], A, B, C, D, E;

    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];

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
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + R0 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + R1 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + R2 ; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + SQRT_3 + R3 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + SQRT_3 + R4 ; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + SQRT_3 + R5 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + SQRT_3 + R6 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + SQRT_3 + R7 ; C = rotate(C, 30);

    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + R8 ; B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + R9 ; A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + R10; E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + R11; D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + R12; C = rotate(C, 30);
    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + R13; B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + R14; A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + R15; E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + R0 ; D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + R1 ; C = rotate(C, 30);
    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + R2 ; B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + R3 ; A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + R4 ; E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + R5 ; D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + R6 ; C = rotate(C, 30);
    E += rotate(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + R7 ; B = rotate(B, 30);
    D += rotate(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + R8 ; A = rotate(A, 30);
    C += rotate(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + R9 ; E = rotate(E, 30);
    B += rotate(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + R10; D = rotate(D, 30);
    A += rotate(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + R11; C = rotate(C, 30);
																   
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + R12; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + R13; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + R14; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + R15; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + R0 ; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + R1 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + R2 ; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + R3 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + R4 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + R5 ; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + R6 ; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + R7 ; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + R8 ; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + R9 ; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + R10; C = rotate(C, 30);
    E += rotate(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + R11; B = rotate(B, 30);
    D += rotate(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + R12; A = rotate(A, 30);
    C += rotate(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + R13; E = rotate(E, 30);
    B += rotate(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + R14; D = rotate(D, 30);
    A += rotate(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + R15; C = rotate(C, 30);

    sha1_hash[0] = state[0] + A;
    sha1_hash[1] = state[1] + B;
    sha1_hash[2] = state[2] + C;
    sha1_hash[3] = state[3] + D;
    sha1_hash[4] = state[4] + E;
}

void dcc_ntlm_part_x86(unsigned int* nt_buffer, unsigned int* crypt_result);
void dcc_salt_part_x86(unsigned int* salt_buffer, unsigned int* crypt_result);
PRIVATE void crypt_ntlm_protocol_x86(CryptParam* param)
{
	unsigned int i,j;
	
	unsigned int * nt_buffer = (unsigned int* )calloc(16*NT_NUM_KEYS, sizeof(unsigned int));
	unsigned char* key       = (unsigned char*)calloc(MAX_KEY_LENGHT, sizeof(unsigned char));
	unsigned int crypt_result[12];

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(i = 0; i < NT_NUM_KEYS; i++)
		{
			unsigned int* salt_buffer = (unsigned int*)salts_values;

			dcc_ntlm_part_x86(nt_buffer+i, crypt_result);

			// For all salts
			for(j = 0; j < num_diff_salts; j++, salt_buffer += 11)
			{
				unsigned int a,b,c,d,index;

				dcc_salt_part_x86(salt_buffer, crypt_result);
				
				a = crypt_result[8+0];
				b = crypt_result[8+1];
				c = crypt_result[8+2];
				d = crypt_result[8+3];

				d = rotate(d + SQRT_3, 9);
				c += (d ^ a ^ b) + salt_buffer[1]  + SQRT_3; c = rotate(c, 11);
				b += (c ^ d ^ a) + salt_buffer[9]  + SQRT_3; b = rotate(b, 15);
													
				a += (b ^ c ^ d) +crypt_result[3]  + SQRT_3; a = rotate(a, 3);
				d += (a ^ b ^ c) + salt_buffer[7]  + SQRT_3; d = rotate(d, 9);
				c += (d ^ a ^ b) + salt_buffer[3]  + SQRT_3; c = rotate(c, 11);
				b += (c ^ d ^ a) +		0		   + SQRT_3; b = rotate(b, 15);

				a += INIT_A;
				b += INIT_B;
				c += INIT_C;
				d += INIT_D;

				//pbkdf2
				{
					unsigned int sha1_hash[5], opad_state[5], ipad_state[5], pad[16];
					unsigned int salt_len = (salt_buffer[10] >> 3) - 16;

					for (unsigned int k = 0; k < 2; k++)
					{
						unsigned int mask = 0x36363636;
						unsigned int* state = ipad_state;
						if(k)
						{
							mask = 0x5C5C5C5C;
							state = opad_state;
						}
						pad[0] = a ^ mask;
						pad[1] = b ^ mask;
						pad[2] = c ^ mask;
						pad[3] = d ^ mask;
						memset(&pad[4], mask & 0xFF, sizeof(pad)-16);

						state[0] = INIT_A;
						state[1] = INIT_B;
						state[2] = INIT_C;
						state[3] = INIT_D;
						state[4] = INIT_E;
						sha1_process( state, pad );
					}
					memcpy(&sha1_hash, &ipad_state, sizeof(ipad_state));

					// Process the salt
					memcpy(pad, salt_buffer, salt_len);
					memcpy(((unsigned char*)pad)+salt_len, "\x0\x0\x0\x1\x80", 5);
					memset(((unsigned char*)pad)+salt_len+5, 0, 60 - (salt_len+5));
					pad[15] = (64+salt_len+4) << 3;
					sha1_process( sha1_hash, pad );

					sha1_process_sha1( opad_state, sha1_hash);
					// Only copy first 16 bytes, since that is ALL this format uses
					memcpy(crypt_result+8, sha1_hash, 16);

					for(unsigned int k = 1; k < 10240; k++)
					{
						sha1_process_sha1( ipad_state, sha1_hash);
						sha1_process_sha1( opad_state, sha1_hash);

						// Only XOR first 16 bytes, since that is ALL this format uses
						crypt_result[8+0] ^= sha1_hash[0];
						crypt_result[8+1] ^= sha1_hash[1];
						crypt_result[8+2] ^= sha1_hash[2];
						crypt_result[8+3] ^= sha1_hash[3];
					}
				}

				// Search for a match
				index = salt_index[j];

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
	{{CPU_CAP_AVX2, PROTOCOL_NTLM, crypt_ntlm_protocol_x86}, {CPU_CAP_AVX, PROTOCOL_NTLM, crypt_ntlm_protocol_x86}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_x86}},
#else
	{{CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_x86}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_x86}, {CPU_CAP_X86, PROTOCOL_NTLM, crypt_ntlm_protocol_x86}},
#endif
	{{PROTOCOL_CHARSET_OCL, NULL}, {PROTOCOL_CHARSET_OCL, NULL}, {PROTOCOL_CHARSET_OCL, NULL}, {PROTOCOL_CHARSET_OCL, NULL}}
};

#endif
