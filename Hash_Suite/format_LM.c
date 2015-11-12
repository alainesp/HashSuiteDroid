// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2015 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"
#include <stdlib.h>

#define PLAINTEXT_LENGTH	7
#define BINARY_SIZE			8
#define SALT_SIZE			0

#define COPY_BIT(i,j)	if(tmp[i/8] & (1 << (i%8))) out[j/8] |= (1 << (j%8))

PRIVATE int is_valid(char* user_name, char* rid, char* lm, char* ntlm)
{
	return FALSE;
}
// Implementation of LM hash
PRIVATE unsigned int get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	unsigned char* out = (unsigned char*)binary;
	unsigned char tmp[8];

	for(int i = 0; i < BINARY_SIZE; i++)
		tmp[BINARY_SIZE-i-1] = (hex_to_num[ciphertext[2*i]] << 4) | (hex_to_num[ciphertext[2*i+1]]);

	memset(out, 0, 8);

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

	return (out[0] | out[1] << 8 | out[2] << 16 | out[3] << 24);
}

PRIVATE unsigned int first_bit[256];
PUBLIC void fill_bits()
{
	unsigned int index;

	for(unsigned int i = 1; i < 256; i++)
	{
		_BitScanForward(&index, i);
		first_bit[i] = index;
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef _M_X64

#define X86_ALL_ONES	0xFFFFFFFFU
#define X86_ZERO		0

#define X86_AND_(a,b)	((a)&(b))
#define X86_OR(a,b)		((a)|(b))
#define X86_XOR_(a,b)	((a)^(b))
#define X86_NOT_(a)		(~(a))
#define X86_ANDN(a,b)	((~(b))&(a))

#define X86_WORD		unsigned int
#define X86_BIT_LENGHT	32

/*
* Generated S-box files.
*
* This software may be modified, redistributed, and used for any purpose,
* so long as its origin is acknowledged.
*
* Produced by Matthew Kwan - March 1998
*
* Optimized by Alain Espinosa - March 2011
*/
PRIVATE void s1_x86f(X86_WORD* a, X86_WORD* out)
{
	X86_WORD x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;

	x1  = X86_ANDN(a[2], a[4]);
	x2  = X86_XOR_(x1, a[3]);
	x3  = X86_ANDN(a[2], a[3]);
	x4  = X86_OR(x3, a[4]);
	x8  = X86_XOR_(a[2], a[3]);
	x5  = X86_AND_(a[5], x4);
	x6  = X86_XOR_(x2, x5);
	x9  = X86_ANDN(a[5], x8);
	x7  = X86_ANDN(a[3], a[4]);
	x12 = X86_OR(x6, x7);
	x10 = X86_AND_(X86_XOR_(a[4], x5), x8);
	x11 = X86_XOR_(X86_ANDN(a[4], a[3]), X86_OR(a[5], X86_XOR_(x3, x10)));
	x2  = X86_ANDN(x11, x2);									// last use of x2 -->reuse it

	out[1] = X86_XOR_(out[1], X86_XOR_(X86_XOR_(x6, X86_OR(a[1], X86_XOR_(x7, x9))), X86_NOT_(X86_AND_(a[0], X86_XOR_(x10, X86_OR(a[1], x11))))));

	x1 = X86_XOR_(X86_OR(x1, x5), x8);						// last use of x1 -->reuse it
	x8 = X86_ANDN(x11, X86_XOR_(x9, x1));						// previous last use of x8 -->reuse it
	x7 = X86_XOR_(X86_XOR_(x12, x2), X86_AND_(a[1], x8));	// previous last use of x7 -->reuse it

	out[3] = X86_XOR_(out[3], X86_XOR_(X86_XOR_(x1, X86_ANDN(a[1], x2)), X86_AND_(a[0], x7)));

	x12 = X86_AND_(a[2], x12);									// last use of x14 -->reuse it
	x10 = X86_ANDN(x11, x12);									// previous last use of x10 -->reuse it
	x6  = X86_XOR_(x10, X86_OR(a[1], x3));					// previous last use of x6 -->reuse it
	x3  = X86_OR(X86_ANDN(x1, x10), x3);					// last use of x3 -->reuse it

	out[0] = X86_XOR_(out[0], X86_XOR_(x6, X86_NOT_(X86_ANDN(a[0], X86_XOR_(X86_OR(a[2], x8), X86_ANDN(x3, a[1]))))));
	out[2] = X86_XOR_(out[2], X86_XOR_(X86_XOR_(X86_ANDN(x7, x9), x6), X86_NOT_(X86_OR(a[0], X86_XOR_(X86_ANDN(X86_XOR_(x4, x12), x5), X86_ANDN(a[1], X86_XOR_(X86_OR(x3, x11), a[4])))))));
}
PRIVATE void s2_x86f(X86_WORD* a, X86_WORD* out)
{
	X86_WORD x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;

	x1 = X86_XOR_(a[0], a[5]);
	x2 = X86_XOR_(x1, a[4]);
	x3 = X86_AND_(a[5], a[4]);
	x4 = X86_ANDN(a[0], x3);
	x5 = X86_ANDN(a[1], x4);
	x6 = X86_XOR_(x2, x5);
	x1 = X86_ANDN(X86_OR(x3, x5), x1);						// last use of x1 -->reuse it
	x5 = X86_XOR_(x6, X86_OR(a[2], x1));					// previous last use of x5 -->reuse it
	x7 = X86_ANDN(a[4], x4);
	x8 = X86_OR(x7, a[1]);
	x9 = X86_XOR_(x5, X86_NOT_(X86_AND_(a[3], x8)));
	out[0] = X86_XOR_(out[0], x9);

	x10 = X86_ANDN(a[5], x4);
	x7  = X86_AND_(a[1], X86_XOR_(x6, x7));					// last use of x7 -->reuse it
	x11 = X86_XOR_(a[4], a[1]);
	x1  = X86_ANDN(x11, x1);									// last use of x1 -->reuse it
	x6  = X86_XOR_(X86_OR(x6, a[0]), a[1]);					// last use of x6 -->reuse it
	x12 = X86_XOR_(x1, X86_ANDN(a[2], x6));
	out[2] = X86_XOR_(out[2], X86_XOR_(X86_XOR_(X86_XOR_(x2, X86_ANDN(X86_XOR_(x4, x9), a[1])), X86_AND_(a[2], X86_XOR_(x10, x7))), X86_OR(a[3], x12)));

	x1 = X86_XOR_(X86_OR(x10, x1), x5);						// last use of x1 -->reuse it
	x6 = X86_OR(x6, x7);										// last use of x6 -->reuse it
	out[3] = X86_XOR_(out[3], X86_XOR_(X86_XOR_(x1, X86_AND_(a[2], x6)), X86_NOT_(X86_OR(a[3], X86_ANDN(x8, X86_AND_(x11, x6))))));

	x2 = X86_XOR_(a[1], x2);									// last use of x2 -->reuse it
	out[1] = X86_XOR_(out[1], X86_XOR_(X86_XOR_(x2, X86_ANDN(a[2], X86_XOR_(X86_ANDN(x2, x1), x12))), X86_NOT_(X86_ANDN(a[3], X86_XOR_(X86_OR(x3, x7), X86_AND_(a[2], x3))))));
}
PRIVATE void s3_x86f(X86_WORD* a, X86_WORD* out)
{
	X86_WORD x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13;

	x1 = X86_XOR_(X86_XOR_(a[1], a[2]), a[5]);
	x2 = X86_AND_(a[1], x1);
	x3 = X86_OR(a[4], x2);
	x4 = X86_XOR_(x1, x3);
	x5 = X86_XOR_(a[2], x2);
	x6 = X86_ANDN(x5, a[4]);
	x7 = X86_ANDN(a[5], x2);
	x8 = X86_XOR_(x7, a[4]);
	x9 = X86_XOR_(X86_XOR_(x4, X86_OR(a[0], x6)), X86_OR(a[3], X86_XOR_(a[4], X86_AND_(a[0], x8))));
	out[3] = X86_XOR_(out[3], x9);

	x10 = X86_AND_(a[2], a[5]);
	x2  = X86_OR(x10, x2);								// last use of x2 -->reuse it
	x11 = X86_XOR_(x2, a[4]);
	x12 = X86_ANDN(x1, x6);
	x13 = X86_OR(a[1], x6);
	x8  = X86_XOR_(X86_OR(x8, x12), x2);				// last use of x8 -->reuse it
	out[2] = X86_XOR_(out[2], X86_XOR_(X86_XOR_(x11, X86_OR(a[0], X86_XOR_(x12, x10))), X86_NOT_(X86_ANDN(a[3], X86_XOR_(X86_XOR_(x13, x3), X86_OR(a[0], x8))))));

	x1 = X86_XOR_(X86_XOR_(X86_XOR_(X86_AND_(a[2], a[4]), x1), X86_OR(a[0], X86_ANDN(x6, a[2]))), X86_AND_(a[3], X86_XOR_(X86_OR(x7, x8), X86_AND_(a[0], X86_ANDN(X86_XOR_(a[5], x2), x4)))));// last use of x1 -->reuse it
	out[1] = X86_XOR_(out[1], x1);

	x5 = X86_ANDN(X86_XOR_(X86_AND_(a[5], x9), x5), a[0]);	// last use of x5 -->reuse it
	out[0] = X86_XOR_(out[0], X86_XOR_(X86_XOR_(X86_XOR_(X86_OR(a[1], x12), x11), x5), X86_NOT_(X86_AND_(a[3], X86_XOR_(x5, X86_OR(a[0], X86_ANDN(x1, x13)))))));
}
PRIVATE void s4_x86f(X86_WORD* a, X86_WORD* out)
{
	X86_WORD x1, x2, x3, x4, x5, x6, x7;

	x1 = X86_AND_(a[4], X86_OR(a[0], a[2]));
	x2 = X86_XOR_(a[0], x1);
	x3 = X86_OR(X86_ANDN(a[2], a[0]), x2);
	x4 = X86_AND_(a[1], x3);
	x5 = X86_XOR_(a[4], x4);
	x6 = X86_XOR_(X86_XOR_(x2, X86_OR(a[1], a[2])), X86_AND_(a[3], x5));
	x1 = X86_XOR_(a[2], x1);													// last use of x1 -->reuse it
	x2 = X86_OR(x1, x2);													// last use of x2 -->reuse it
	x7 = X86_ANDN(X86_XOR_(a[2], a[4]), a[1]);
	x1 = X86_XOR_(X86_XOR_(x3, X86_ANDN(a[1], x1)), X86_OR(a[3], X86_XOR_(x2, x7)));// last use of x1 -->reuse it
	x3 = X86_XOR_(x6, X86_OR(a[5], x1));									// previous last use of x3 -->reuse it
	out[0] = X86_XOR_(out[0], x3);

	x1 = X86_AND_(a[5], x1);													// last use of x1 -->reuse it
	out[1] = X86_XOR_(out[1], X86_XOR_(x1, X86_NOT_(x6)));

	x2 = X86_XOR_(X86_XOR_(X86_AND_(a[1], x5), x2), X86_ANDN(a[3], X86_XOR_(X86_XOR_(a[2], x4), x7)));// last use of x2 -->reuse it
	x4 = X86_XOR_(x6, x2);													// previous last use of x4 -->reuse it
	x3 = X86_XOR_(X86_XOR_(x3, X86_ANDN(a[1], x4)), X86_ANDN(x4, a[3]));	// last use of x3 -->reuse it
	x2 = X86_XOR_(x2, X86_NOT_(X86_OR(a[5], x3)));						// last use of x2 -->reuse it

	out[2] = X86_XOR_(out[2], x2);
	out[3] = X86_XOR_(out[3], X86_XOR_(X86_XOR_(x1, x3), x2));
}
PRIVATE void s5_x86f(X86_WORD* a, X86_WORD* out)
{
	X86_WORD x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13;

	x1 = X86_ANDN(a[2], a[3]);																
	x2 = X86_XOR_(x1, a[0]);																
	x6 = X86_XOR_(a[3], a[0]);																
	x1 = X86_OR(x6, x1);										/* last use of x1 -->reuse it*/		
	x7 = X86_ANDN(x1, a[5]);																
	x8 = X86_XOR_(a[2], x7);																
	x9 = X86_XOR_(X86_AND_(a[2], x1), a[3]);														
	x3 = X86_ANDN(a[0], a[2]);																
	x4 = X86_OR(a[5], x3);																
	x5 = X86_XOR_(x2, x4);																
	x10 = X86_OR(a[5], X86_XOR_(a[3], x3));														
	x3  = X86_XOR_(X86_ANDN(x9, x3), x10);					/* last use of x3 -->reuse it*/		
	x11 = X86_XOR_(x9, X86_OR(a[4], x3));														
	x12 = X86_XOR_(X86_XOR_(x5, X86_OR(a[4], x8)), X86_ANDN(x11, a[1]));										
	out[3] = X86_XOR_(out[3], x12);																

	x13 = X86_XOR_(a[0], x8);																
	x2 = X86_XOR_(X86_XOR_(X86_AND_(a[3], x4), x3), X86_ANDN(a[4], X86_AND_(x2, x13)));/* last use of x2 -->reuse it*/	
	x4 = X86_OR(a[3], x13);									/* previous last use of x4 -->reuse it*/	
	out[1] = X86_XOR_(out[1], X86_XOR_(x2, X86_ANDN(x4, a[1])));													

	x3 = X86_AND_(x3, x5);										/* last use of x3 -->reuse it*/		
	x1 = X86_ANDN(x1, x3);										/* last use of x1 -->reuse it*/		
	x5 = X86_XOR_(X86_ANDN(x7, a[3]), a[2]);						/* last use of x5 -->reuse it*/		
	x3 = X86_XOR_(x8, x3);										/* last use of x3 -->reuse it*/		
	out[2] = X86_XOR_(out[2], X86_XOR_(X86_XOR_(x1, X86_AND_(a[4], x5)), X86_NOT_(X86_OR(a[1], X86_XOR_(X86_OR(x9, x10), X86_OR(a[4], x3))))));

	x1 = X86_ANDN(x11, x1);									/* last use of x1 -->reuse it*/		
	out[0] = X86_XOR_(out[0], X86_XOR_(X86_XOR_(X86_XOR_(x1, x13), X86_ANDN(a[4], X86_XOR_(X86_OR(x2, x1), x6))), X86_OR(a[1], X86_XOR_(X86_XOR_(X86_AND_(x6, x3), x5), X86_AND_(a[4], X86_ANDN(x4, X86_XOR_(x12, x3)))))));
}
PRIVATE void s6_x86f(X86_WORD* a, X86_WORD* out)
{
	X86_WORD x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11;

	x3 = X86_AND_(a[0], a[5]);																
	x4 = X86_ANDN(x3, a[4]);																
	x5 = X86_ANDN(a[3], x4);																
	x1 = X86_XOR_(a[4], a[0]);																
	x2 = X86_XOR_(x1, a[5]);																
	x6 = X86_XOR_(x2, x5);																
	x7 = X86_XOR_(a[5], x3);																
	x8 = X86_XOR_(x7, X86_ANDN(X86_OR(x4, x7), a[3]));												
	x3 = X86_ANDN(X86_XOR_(x3, x6), x8);						/* last use of x3 -->reuse it*/			
	x4 = X86_OR(x4, x8);										/* previous last use of x4 -->reuse it*/	
	x9 = X86_XOR_(X86_XOR_(x6, X86_AND_(a[1], x8)), X86_NOT_(X86_ANDN(X86_XOR_(X86_ANDN(X86_OR(a[5], x6), a[4]), X86_ANDN(a[1], x4)), a[2])));
	out[0] = X86_XOR_(out[0], x9);																	

	x4 = X86_XOR_(X86_ANDN(x9, x1), x4);						/* last use of x4 -->reuse it*/			
	x6 = X86_XOR_(X86_ANDN(a[5], x4), x6);					/* last use of x6 -->reuse it*/
	x9 = X86_OR(a[4], a[5]);									/* previous last use of x9 -->reuse it*/	
	x10 = X86_ANDN(a[1], x6);																
	x11 = X86_XOR_(x4, x10);																

	out[3] = X86_XOR_(out[3], X86_XOR_(x11, X86_NOT_(X86_ANDN(a[2], X86_XOR_(X86_ANDN(x9, x1), X86_ANDN(a[1], x10))))));

	x1 = X86_ANDN(a[4], X86_XOR_(a[5], x11));						/* previous last use of x1 -->reuse it*/	

	out[2] = X86_XOR_(out[2], X86_XOR_(X86_XOR_(x3, X86_ANDN(a[1], x1)), X86_NOT_(X86_OR(a[2], X86_ANDN(x4, a[4])))));						
	out[1] = X86_XOR_(out[1], X86_XOR_(X86_XOR_(X86_OR(x1, x2), X86_OR(a[1], X86_ANDN(a[3], X86_AND_(a[4], x7)))), X86_NOT_(X86_ANDN(a[2], X86_XOR_(X86_XOR_(X86_OR(x6, x1), x5), X86_AND_(a[1], X86_XOR_(X86_AND_(x9, x3), x2)))))));
}
PRIVATE void s7_x86f(X86_WORD* a, X86_WORD* out)
{
	X86_WORD x1, x2, x3, x4, x5, x6, x7, x8, x9;

	x1 = X86_XOR_(X86_AND_(a[1], a[3]), a[4]);														
	x2 = X86_AND_(a[3], x1);																
	x3 = X86_XOR_(x2, a[1]);																
	x4 = X86_ANDN(a[2], x3);																
	x1 = X86_XOR_(x1, x4);												/* last use of x1 -->reuse it*/		
	x4 = X86_XOR_(a[2], x4);												/* last use of x4 -->reuse it*/		
	x5 = X86_XOR_(x1, X86_ANDN(a[5], x4));														
	x1 = X86_XOR_(x2, x1);												/* last use of x1 -->reuse it*/		
	x6 = X86_XOR_(x5, X86_AND_(a[0], X86_XOR_(X86_XOR_(X86_OR(X86_OR(a[1], a[3]), a[4]), X86_OR(a[2], X86_ANDN(a[4], a[1]))), X86_OR(a[5], x1))));
	out[0] = X86_XOR_(out[0], x6);																	

	x3 = X86_XOR_(a[3], x3);												/* last use of x3 -->reuse it*/		
	x9 = X86_XOR_(x3, X86_OR(a[2], x2));														
	x2 = X86_XOR_(x9, X86_ANDN(a[5], X86_AND_(X86_XOR_(a[2], x2), a[1])));/* last use of x2 -->reuse it*/		
	x7 = X86_ANDN(a[3], a[2]);																
	x8 = X86_AND_(a[5], X86_ANDN(a[1], x7));														
	out[1] = X86_XOR_(out[1], X86_XOR_(X86_XOR_(x5, x8), X86_NOT_(X86_OR(a[0], x2))));											

	x4 = X86_XOR_(x4, x2);												/* last use of x4 -->reuse it*/		
	out[2] = X86_XOR_(out[2], X86_XOR_(X86_XOR_(x4, X86_ANDN(X86_XOR_(X86_OR(a[1], x3), x6), a[5])), X86_ANDN(X86_OR(X86_ANDN(x9, a[2]), x2), a[0])));

	x1 = X86_AND_(a[5], X86_ANDN(x3, X86_XOR_(a[1], x1)));				/* last use of x1 -->reuse it*/		
	out[3] = X86_XOR_(out[3], X86_XOR_(X86_XOR_(X86_XOR_(X86_OR(a[4], x7), x4), x1), X86_OR(a[0], X86_XOR_(X86_AND_(a[2], x8), x1))));
}
PRIVATE void s8_x86f(X86_WORD* a, X86_WORD* out)
{
	X86_WORD x1, x2, x3, x4, x5, x6, x7, x8, x9, x10;

	x1 = X86_XOR_(a[2], a[0]);																	
	x2 = X86_ANDN(a[0], a[2]);																	
	x3 = X86_XOR_(x2, a[3]);																	
	x4 = X86_XOR_(x1, X86_OR(a[4], x3));
	x5 = X86_ANDN(x4, a[0]);																	
	x6 = X86_XOR_(x5, a[2]);																	
	x7 = X86_XOR_(a[3], X86_ANDN(x6, a[4]));
	x8 = X86_XOR_(x4, X86_ANDN(a[1], x7));
	x9 = X86_XOR_(X86_XOR_(X86_OR(x5, a[3]), x1), a[4]);														
	x6 = X86_XOR_(X86_ANDN(x3, x9), x6);								/* last use of x6 -->reuse it*/			
	x4 = X86_OR(x4, a[4]);												/* last use of x4 -->reuse it*/			
	out[0] = X86_XOR_(out[0], X86_XOR_(x8, X86_NOT_(X86_OR(a[5], X86_XOR_(x9, X86_ANDN(a[1], x6))))));

	x3 = X86_XOR_(x4, x3);												/* last use of x3 -->reuse it*/			
	x10 = X86_ANDN(x8, a[3]);																	
	x4 = X86_XOR_(X86_XOR_(x3, X86_ANDN(a[1], x10)), X86_ANDN(X86_XOR_(X86_AND_(a[0], x4), X86_AND_(a[1], X86_XOR_(X86_AND_(a[4], x2), x10))), a[5]));/* last use of x4 -->reuse it*/
	out[2] = X86_XOR_(out[2], x4);																		

	x2 = X86_ANDN(x2, x9);												/* last use of x2 -->reuse it*/			
	out[1] = X86_XOR_(out[1], X86_XOR_(X86_XOR_(X86_OR(x7, X86_ANDN(a[2], x6)), X86_OR(a[1], x5)), X86_NOT_(X86_OR(a[5], X86_XOR_(x2, X86_ANDN(a[1], X86_OR(x3, x4)))))));
	out[3] = X86_XOR_(out[3], X86_XOR_(x8, X86_NOT_(X86_AND_(a[5], X86_XOR_(X86_OR(X86_ANDN(x1, a[4]), a[3]), X86_ANDN(X86_XOR_(X86_XOR_(a[2], a[4]), x2), a[1]))))));
}

#define s1_x86( a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)		\
	a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6;	\
	s1_x86f(a, out1)
#define s2_x86( a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)		\
	a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6;	\
	s2_x86f(a, out1)
#define s3_x86( a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)		\
	a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6;	\
	s3_x86f(a, out1)
#define s4_x86( a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)		\
	a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6;	\
	s4_x86f(a, out1)
#define s5_x86( a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)		\
	a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6;	\
	s5_x86f(a, out1)
#define s6_x86( a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)		\
	a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6;	\
	s6_x86f(a, out1)
#define s7_x86( a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)		\
	a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6;	\
	s7_x86f(a, out1)
#define s8_x86( a1, a2, a3, a4, a5, a6, out1, out2, out3, out4)		\
	a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6;	\
	s8_x86f(a, out1)

#define X86_MASK_1(elem)	(X86_AND_(elem, (0x01010101U)))
#define X86_MASK_2(elem)	(X86_AND_(elem, (0x02020202U)))
#define X86_MASK_3(elem)	(X86_AND_(elem, (0x04040404U)))
#define X86_MASK_4(elem)	(X86_AND_(elem, (0x08080808U)))
#define X86_MASK_5(elem)	(X86_AND_(elem, (0x10101010U)))
#define X86_MASK_6(elem)	(X86_AND_(elem, (0x20202020U)))
#define X86_MASK_7(elem)	(X86_AND_(elem, (0x40404040U)))
#define X86_MASK_8(elem)	(X86_AND_(elem, (0x80808080U)))

#define X86_SL(elem,shift)	((elem)<<(shift))
#define X86_SR(elem,shift)	((elem)>>(shift))

PRIVATE void calculate_hash_x86(X86_WORD* c, unsigned int* hash_values, unsigned int i_shift)
{
	// I try to vectorize the code to obtain the hashes needed for the table
	// Look a the code commented in x86 version: this is the 'normal' version
	// Here i calculate hashes 8 at a time. This result in a dramatic better performance
	X86_WORD hash_tmp[8];
	unsigned int i;

	//0,1,2
	hash_tmp[0] = X86_OR(X86_OR(		  X86_MASK_1(c[0])	   ,  X86_SL(X86_MASK_1(c[1]), 1)),  X86_SL(X86_MASK_1(c[2]), 2));
	hash_tmp[1] = X86_OR(X86_OR(X86_SR(X86_MASK_2(c[0]), 1),		  X86_MASK_2(c[1]))	,  X86_SL(X86_MASK_2(c[2]), 1));
	hash_tmp[2] = X86_OR(X86_OR(X86_SR(X86_MASK_3(c[0]), 2),  X86_SR(X86_MASK_3(c[1]), 1)),		   X86_MASK_3(c[2]));
	hash_tmp[3] = X86_OR(X86_OR(X86_SR(X86_MASK_4(c[0]), 3),  X86_SR(X86_MASK_4(c[1]), 2)),  X86_SR(X86_MASK_4(c[2]), 1));
	hash_tmp[4] = X86_OR(X86_OR(X86_SR(X86_MASK_5(c[0]), 4),  X86_SR(X86_MASK_5(c[1]), 3)),  X86_SR(X86_MASK_5(c[2]), 2));
	hash_tmp[5] = X86_OR(X86_OR(X86_SR(X86_MASK_6(c[0]), 5),  X86_SR(X86_MASK_6(c[1]), 4)),  X86_SR(X86_MASK_6(c[2]), 3));
	hash_tmp[6] = X86_OR(X86_OR(X86_SR(X86_MASK_7(c[0]), 6),  X86_SR(X86_MASK_7(c[1]), 5)),  X86_SR(X86_MASK_7(c[2]), 4));
	hash_tmp[7] = X86_OR(X86_OR(X86_SR(X86_MASK_8(c[0]), 7),  X86_SR(X86_MASK_8(c[1]), 6)),  X86_SR(X86_MASK_8(c[2]), 5));
	//3, 4
	hash_tmp[0] = X86_OR(hash_tmp[0], X86_OR(X86_SL(X86_MASK_1(c[3]), 3),  X86_SL(X86_MASK_1(c[4]), 4)));
	hash_tmp[1] = X86_OR(hash_tmp[1], X86_OR(X86_SL(X86_MASK_2(c[3]), 2),  X86_SL(X86_MASK_2(c[4]), 3)));
	hash_tmp[2] = X86_OR(hash_tmp[2], X86_OR(X86_SL(X86_MASK_3(c[3]), 1),  X86_SL(X86_MASK_3(c[4]), 2)));
	hash_tmp[3] = X86_OR(hash_tmp[3], X86_OR(		   X86_MASK_4(c[3])	,  X86_SL(X86_MASK_4(c[4]), 1)));
	hash_tmp[4] = X86_OR(hash_tmp[4], X86_OR(X86_SR(X86_MASK_5(c[3]), 1),		   X86_MASK_5(c[4])));
	hash_tmp[5] = X86_OR(hash_tmp[5], X86_OR(X86_SR(X86_MASK_6(c[3]), 2),  X86_SR(X86_MASK_6(c[4]), 1)));
	hash_tmp[6] = X86_OR(hash_tmp[6], X86_OR(X86_SR(X86_MASK_7(c[3]), 3),  X86_SR(X86_MASK_7(c[4]), 2)));
	hash_tmp[7] = X86_OR(hash_tmp[7], X86_OR(X86_SR(X86_MASK_8(c[3]), 4),  X86_SR(X86_MASK_8(c[4]), 3)));
	//5,6,7
	hash_tmp[0] = X86_OR(hash_tmp[0], X86_OR(X86_OR(X86_SL(X86_MASK_1(c[5]), 5),  X86_SL(X86_MASK_1(c[6]), 6)), X86_SL(X86_MASK_1(c[7]), 7)));
	hash_tmp[1] = X86_OR(hash_tmp[1], X86_OR(X86_OR(X86_SL(X86_MASK_2(c[5]), 4),  X86_SL(X86_MASK_2(c[6]), 5)), X86_SL(X86_MASK_2(c[7]), 6)));
	hash_tmp[2] = X86_OR(hash_tmp[2], X86_OR(X86_OR(X86_SL(X86_MASK_3(c[5]), 3),  X86_SL(X86_MASK_3(c[6]), 4)), X86_SL(X86_MASK_3(c[7]), 5)));
	hash_tmp[3] = X86_OR(hash_tmp[3], X86_OR(X86_OR(X86_SL(X86_MASK_4(c[5]), 2),  X86_SL(X86_MASK_4(c[6]), 3)), X86_SL(X86_MASK_4(c[7]), 4)));
	hash_tmp[4] = X86_OR(hash_tmp[4], X86_OR(X86_OR(X86_SL(X86_MASK_5(c[5]), 1),  X86_SL(X86_MASK_5(c[6]), 2)), X86_SL(X86_MASK_5(c[7]), 3)));
	hash_tmp[5] = X86_OR(hash_tmp[5], X86_OR(X86_OR(		   X86_MASK_6(c[5])	,  X86_SL(X86_MASK_6(c[6]), 1)), X86_SL(X86_MASK_6(c[7]), 2)));
	hash_tmp[6] = X86_OR(hash_tmp[6], X86_OR(X86_OR(X86_SR(X86_MASK_7(c[5]), 1),		   X86_MASK_7(c[6]))	 , X86_SL(X86_MASK_7(c[7]), 1)));
	hash_tmp[7] = X86_OR(hash_tmp[7], X86_OR(X86_OR(X86_SR(X86_MASK_8(c[5]), 2),  X86_SR(X86_MASK_8(c[6]), 1)),		   X86_MASK_8(c[7])));
	
	if(i_shift)
		for(i = 0; i < X86_BIT_LENGHT; i+=8)
		{
			hash_values[i+0] |= ((hash_tmp[0]) & 0xFF) << i_shift; hash_tmp[0] = (hash_tmp[0] >> 8);
			hash_values[i+1] |= ((hash_tmp[1]) & 0xFF) << i_shift; hash_tmp[1] = (hash_tmp[1] >> 8);
			hash_values[i+2] |= ((hash_tmp[2]) & 0xFF) << i_shift; hash_tmp[2] = (hash_tmp[2] >> 8);
			hash_values[i+3] |= ((hash_tmp[3]) & 0xFF) << i_shift; hash_tmp[3] = (hash_tmp[3] >> 8);
			hash_values[i+4] |= ((hash_tmp[4]) & 0xFF) << i_shift; hash_tmp[4] = (hash_tmp[4] >> 8);
			hash_values[i+5] |= ((hash_tmp[5]) & 0xFF) << i_shift; hash_tmp[5] = (hash_tmp[5] >> 8);
			hash_values[i+6] |= ((hash_tmp[6]) & 0xFF) << i_shift; hash_tmp[6] = (hash_tmp[6] >> 8);
			hash_values[i+7] |= ((hash_tmp[7]) & 0xFF) << i_shift; hash_tmp[7] = (hash_tmp[7] >> 8);
		}
	else
		for(i = 0; i < X86_BIT_LENGHT; i+=8)
		{
			hash_values[i+0] = ((hash_tmp[0]) & 0xFF); hash_tmp[0] = (hash_tmp[0]>> 8);
			hash_values[i+1] = ((hash_tmp[1]) & 0xFF); hash_tmp[1] = (hash_tmp[1]>> 8);
			hash_values[i+2] = ((hash_tmp[2]) & 0xFF); hash_tmp[2] = (hash_tmp[2]>> 8);
			hash_values[i+3] = ((hash_tmp[3]) & 0xFF); hash_tmp[3] = (hash_tmp[3]>> 8);
			hash_values[i+4] = ((hash_tmp[4]) & 0xFF); hash_tmp[4] = (hash_tmp[4]>> 8);
			hash_values[i+5] = ((hash_tmp[5]) & 0xFF); hash_tmp[5] = (hash_tmp[5]>> 8);
			hash_values[i+6] = ((hash_tmp[6]) & 0xFF); hash_tmp[6] = (hash_tmp[6]>> 8);
			hash_values[i+7] = ((hash_tmp[7]) & 0xFF); hash_tmp[7] = (hash_tmp[7]>> 8);
		}
}
/*
* Bitslice implementation of DES.
*
* given the key bits k[0] .. k[55]
* encrypt to the ciphertext bits c[0] .. c[63]
*/
PRIVATE void lm_eval_x86(const X86_WORD* k)
{
	X86_WORD c[64];	// Crypt
	X86_WORD a[6];	// Params

	c[0]  = X86_ZERO;
	c[1]  = X86_ALL_ONES;
	c[2]  = X86_ALL_ONES;
	c[3]  = X86_ALL_ONES;
	c[4]  = X86_ZERO;
	c[5]  = X86_ZERO;
	c[6]  = X86_ZERO;
	c[7]  = X86_ALL_ONES;
	c[8]  = X86_ZERO;
	c[9]  = X86_ZERO;
	c[10] = X86_ALL_ONES;
	c[11] = X86_ALL_ONES;
	c[12] = X86_ZERO;
	c[13] = X86_ZERO;
	c[14] = X86_ZERO;
	c[15] = X86_ZERO;
	c[16] = X86_ALL_ONES;
	c[17] = X86_ALL_ONES;
	c[18] = X86_ALL_ONES;
	c[19] = X86_ZERO;
	c[20] = X86_ALL_ONES;
	c[21] = X86_ALL_ONES;
	c[22] = X86_ZERO;
	c[23] = X86_ZERO;
	c[24] = X86_ALL_ONES;
	c[25] = X86_ZERO;
	c[26] = X86_ZERO;
	c[27] = X86_ALL_ONES;
	c[28] = X86_ZERO;
	c[29] = X86_ALL_ONES;
	c[30] = X86_ZERO;
	c[31] = X86_ZERO;
	c[32] = X86_ALL_ONES;
	c[33] = X86_ZERO;
	c[34] = X86_ZERO;
	c[35] = X86_ALL_ONES;
	c[36] = X86_ALL_ONES;
	c[37] = X86_ZERO;
	c[38] = X86_ZERO;
	c[39] = X86_ZERO;
	c[40] = X86_ALL_ONES;
	c[41] = X86_ZERO;
	c[42] = X86_ALL_ONES;
	c[43] = X86_ZERO;
	c[44] = X86_ZERO;
	c[45] = X86_ZERO;
	c[46] = X86_ALL_ONES;
	c[47] = X86_ZERO;
	c[48] = X86_ZERO;
	c[49] = X86_ZERO;
	c[50] = X86_ZERO;
	c[51] = X86_ZERO;
	c[52] = X86_ZERO;
	c[53] = X86_ZERO;
	c[54] = X86_ALL_ONES;
	c[55] = X86_ZERO;
	c[56] = X86_ALL_ONES;
	c[57] = X86_ZERO;
	c[58] = X86_ZERO;
	c[59] = X86_ZERO;
	c[60] = X86_ZERO;
	c[61] = X86_ALL_ONES;
	c[62] = X86_ZERO;
	c[63] = X86_ZERO;

	//1
	s1_x86 (X86_XOR_(c[56], k[47]), X86_XOR_(c[47], k[11]), X86_XOR_(c[38], k[26]), X86_XOR_(c[51], k[3] ), X86_XOR_(c[52], k[13]), X86_XOR_(c[60], k[41]), &c[0] , &c[1] , &c[2] , &c[3]);
	s2_x86 (X86_XOR_(c[52], k[27]), X86_XOR_(c[60], k[6] ), X86_XOR_(c[43], k[54]), X86_XOR_(c[59], k[48]), X86_XOR_(c[48], k[39]), X86_XOR_(c[32], k[19]), &c[4] , &c[5] , &c[6] , &c[7]);
	s3_x86 (X86_XOR_(c[48], k[53]), X86_XOR_(c[32], k[25]), X86_XOR_(c[46], k[33]), X86_XOR_(c[54], k[34]), X86_XOR_(c[57], k[17]), X86_XOR_(c[36], k[5]) , &c[8] , &c[9] , &c[10], &c[11]);
	s4_x86 (X86_XOR_(c[57], k[4] ), X86_XOR_(c[36], k[55]), X86_XOR_(c[49], k[24]), X86_XOR_(c[62], k[32]), X86_XOR_(c[41], k[40]), X86_XOR_(c[33], k[20]), &c[12], &c[13], &c[14], &c[15]);
	s5_x86 (X86_XOR_(c[41], k[36]), X86_XOR_(c[33], k[31]), X86_XOR_(c[39], k[21]), X86_XOR_(c[55], k[8] ), X86_XOR_(c[45], k[23]), X86_XOR_(c[63], k[52]), &c[16], &c[17], &c[18], &c[19]);
	s6_x86 (X86_XOR_(c[45], k[14]), X86_XOR_(c[63], k[29]), X86_XOR_(c[58], k[51]), X86_XOR_(c[34], k[9] ), X86_XOR_(c[40], k[35]), X86_XOR_(c[50], k[30]), &c[20], &c[21], &c[22], &c[23]);
	s7_x86 (X86_XOR_(c[40], k[2] ), X86_XOR_(c[50], k[37]), X86_XOR_(c[44], k[22]), X86_XOR_(c[61], k[0] ), X86_XOR_(c[37], k[42]), X86_XOR_(c[53], k[38]), &c[24], &c[25], &c[26], &c[27] );
	s8_x86 (X86_XOR_(c[37], k[16]), X86_XOR_(c[53], k[43]), X86_XOR_(c[42], k[44]), X86_XOR_(c[35], k[1] ), X86_XOR_(c[56], k[7]) , X86_XOR_(c[47], k[28]), &c[28], &c[29], &c[30], &c[31]);
	//2
	s1_x86 (X86_XOR_(c[24], k[54]), X86_XOR_(c[15], k[18]), X86_XOR_(c[6] , k[33]), X86_XOR_(c[19], k[10]), X86_XOR_(c[20], k[20]), X86_XOR_(c[28], k[48]), &c[32], &c[33], &c[34], &c[35]);
	s2_x86 (X86_XOR_(c[20], k[34]), X86_XOR_(c[28], k[13]), X86_XOR_(c[11], k[4]) , X86_XOR_(c[27], k[55]), X86_XOR_(c[16], k[46]), X86_XOR_(c[0] , k[26]), &c[36], &c[37], &c[38], &c[39]);
	s3_x86 (X86_XOR_(c[16], k[3]) , X86_XOR_(c[0] , k[32]), X86_XOR_(c[14], k[40]), X86_XOR_(c[22], k[41]), X86_XOR_(c[25], k[24]), X86_XOR_(c[4] , k[12]), &c[40], &c[41], &c[42], &c[43]);
	s4_x86 (X86_XOR_(c[25], k[11]), X86_XOR_(c[4] , k[5]) , X86_XOR_(c[17], k[6]) , X86_XOR_(c[30], k[39]), X86_XOR_(c[9] , k[47]), X86_XOR_(c[1] , k[27]), &c[44], &c[45], &c[46], &c[47]);
	s5_x86 (X86_XOR_(c[9] , k[43]), X86_XOR_(c[1] , k[38]), X86_XOR_(c[7] , k[28]), X86_XOR_(c[23], k[15]), X86_XOR_(c[13], k[30]), X86_XOR_(c[31], k[0]) , &c[48], &c[49], &c[50], &c[51]);
	s6_x86 (X86_XOR_(c[13], k[21]), X86_XOR_(c[31], k[36]), X86_XOR_(c[26], k[31]), X86_XOR_(c[2] , k[16]), X86_XOR_(c[8] , k[42]), X86_XOR_(c[18], k[37]), &c[52], &c[53], &c[54], &c[55]);
	s7_x86 (X86_XOR_(c[8] , k[9]) , X86_XOR_(c[18], k[44]), X86_XOR_(c[12], k[29]), X86_XOR_(c[29], k[7]) , X86_XOR_(c[5] , k[49]), X86_XOR_(c[21], k[45]), &c[56], &c[57], &c[58], &c[59] );
	s8_x86 (X86_XOR_(c[5] , k[23]), X86_XOR_(c[21], k[50]), X86_XOR_(c[10], k[51]), X86_XOR_(c[3] , k[8]) , X86_XOR_(c[24], k[14]), X86_XOR_(c[15], k[35]), &c[60], &c[61], &c[62], &c[63]);
	//3
	s1_x86 (X86_XOR_(c[56], k[11]), X86_XOR_(c[47], k[32]), X86_XOR_(c[38], k[47]), X86_XOR_(c[51], k[24]), X86_XOR_(c[52], k[34]), X86_XOR_(c[60], k[5]) , &c[0] , &c[1] , &c[2] , &c[3] );
	s2_x86 (X86_XOR_(c[52], k[48]), X86_XOR_(c[60], k[27]), X86_XOR_(c[43], k[18]), X86_XOR_(c[59], k[12]), X86_XOR_(c[48], k[3]) , X86_XOR_(c[32], k[40]), &c[4] , &c[5] , &c[6] , &c[7] );
	s3_x86 (X86_XOR_(c[48], k[17]), X86_XOR_(c[32], k[46]), X86_XOR_(c[46], k[54]), X86_XOR_(c[54], k[55]), X86_XOR_(c[57], k[13]), X86_XOR_(c[36], k[26]), &c[8] , &c[9] , &c[10], &c[11]);
	s4_x86 (X86_XOR_(c[57], k[25]), X86_XOR_(c[36], k[19]), X86_XOR_(c[49], k[20]), X86_XOR_(c[62], k[53]), X86_XOR_(c[41], k[4]) , X86_XOR_(c[33], k[41]), &c[12], &c[13], &c[14], &c[15]);
	s5_x86 (X86_XOR_(c[41], k[2]) , X86_XOR_(c[33], k[52]), X86_XOR_(c[39], k[42]), X86_XOR_(c[55], k[29]), X86_XOR_(c[45], k[44]), X86_XOR_(c[63], k[14]), &c[16], &c[17], &c[18], &c[19]);
	s6_x86 (X86_XOR_(c[45], k[35]), X86_XOR_(c[63], k[50]), X86_XOR_(c[58], k[45]), X86_XOR_(c[34], k[30]), X86_XOR_(c[40], k[1]) , X86_XOR_(c[50], k[51]), &c[20], &c[21], &c[22], &c[23]);
	s7_x86 (X86_XOR_(c[40], k[23]), X86_XOR_(c[50], k[31]), X86_XOR_(c[44], k[43]), X86_XOR_(c[61], k[21]), X86_XOR_(c[37], k[8]) , X86_XOR_(c[53], k[0]) , &c[24], &c[25], &c[26], &c[27]);
	s8_x86 (X86_XOR_(c[37], k[37]), X86_XOR_(c[53], k[9]) , X86_XOR_(c[42], k[38]), X86_XOR_(c[35], k[22]), X86_XOR_(c[56], k[28]), X86_XOR_(c[47], k[49]), &c[28], &c[29], &c[30], &c[31]);
	//4
	s1_x86 (X86_XOR_(c[24], k[25]), X86_XOR_(c[15], k[46]), X86_XOR_(c[6] , k[4]) , X86_XOR_(c[19], k[13]), X86_XOR_(c[20], k[48]), X86_XOR_(c[28], k[19]), &c[32], &c[33], &c[34], &c[35]);
	s2_x86 (X86_XOR_(c[20], k[5]) , X86_XOR_(c[28], k[41]), X86_XOR_(c[11], k[32]), X86_XOR_(c[27], k[26]), X86_XOR_(c[16], k[17]), X86_XOR_(c[0] , k[54]), &c[36], &c[37], &c[38], &c[39]);
	s3_x86 (X86_XOR_(c[16], k[6]) , X86_XOR_(c[0] , k[3]) , X86_XOR_(c[14], k[11]), X86_XOR_(c[22], k[12]), X86_XOR_(c[25], k[27]), X86_XOR_(c[4] , k[40]), &c[40], &c[41], &c[42], &c[43]);
	s4_x86 (X86_XOR_(c[25], k[39]), X86_XOR_(c[4] , k[33]), X86_XOR_(c[17], k[34]), X86_XOR_(c[30], k[10]), X86_XOR_(c[9] , k[18]), X86_XOR_(c[1] , k[55]), &c[44], &c[45], &c[46], &c[47]);
	s5_x86 (X86_XOR_(c[9] , k[16]), X86_XOR_(c[1] , k[7]) , X86_XOR_(c[7] , k[1]) , X86_XOR_(c[23], k[43]), X86_XOR_(c[13], k[31]), X86_XOR_(c[31], k[28]), &c[48], &c[49], &c[50], &c[51]);
	s6_x86 (X86_XOR_(c[13], k[49]), X86_XOR_(c[31], k[9]) , X86_XOR_(c[26], k[0]) , X86_XOR_(c[2] , k[44]), X86_XOR_(c[8] , k[15]), X86_XOR_(c[18], k[38]), &c[52], &c[53], &c[54], &c[55]);
	s7_x86 (X86_XOR_(c[8] , k[37]), X86_XOR_(c[18], k[45]), X86_XOR_(c[12], k[2]) , X86_XOR_(c[29], k[35]), X86_XOR_(c[5] , k[22]), X86_XOR_(c[21], k[14]), &c[56], &c[57], &c[58], &c[59]);
	s8_x86 (X86_XOR_(c[5] , k[51]), X86_XOR_(c[21], k[23]), X86_XOR_(c[10], k[52]), X86_XOR_(c[3] , k[36]), X86_XOR_(c[24], k[42]), X86_XOR_(c[15], k[8]) , &c[60], &c[61], &c[62], &c[63]);
	//5
	s1_x86 (X86_XOR_(c[56], k[39]), X86_XOR_(c[47], k[3]) , X86_XOR_(c[38], k[18]), X86_XOR_(c[51], k[27]), X86_XOR_(c[52], k[5]) , X86_XOR_(c[60], k[33]), &c[0] , &c[1] , &c[2] , &c[3] );
	s2_x86 (X86_XOR_(c[52], k[19]), X86_XOR_(c[60], k[55]), X86_XOR_(c[43], k[46]), X86_XOR_(c[59], k[40]), X86_XOR_(c[48], k[6]) , X86_XOR_(c[32], k[11]), &c[4] , &c[5] , &c[6] , &c[7] );
	s3_x86 (X86_XOR_(c[48], k[20]), X86_XOR_(c[32], k[17]), X86_XOR_(c[46], k[25]), X86_XOR_(c[54], k[26]), X86_XOR_(c[57], k[41]), X86_XOR_(c[36], k[54]), &c[8] , &c[9] , &c[10], &c[11]);
	s4_x86 (X86_XOR_(c[57], k[53]), X86_XOR_(c[36], k[47]), X86_XOR_(c[49], k[48]), X86_XOR_(c[62], k[24]), X86_XOR_(c[41], k[32]), X86_XOR_(c[33], k[12]), &c[12], &c[13], &c[14], &c[15]);
	s5_x86 (X86_XOR_(c[41], k[30]), X86_XOR_(c[33], k[21]), X86_XOR_(c[39], k[15]), X86_XOR_(c[55], k[2]) , X86_XOR_(c[45], k[45]), X86_XOR_(c[63], k[42]), &c[16], &c[17], &c[18], &c[19]);
	s6_x86 (X86_XOR_(c[45], k[8]) , X86_XOR_(c[63], k[23]), X86_XOR_(c[58], k[14]), X86_XOR_(c[34], k[31]), X86_XOR_(c[40], k[29]), X86_XOR_(c[50], k[52]), &c[20], &c[21], &c[22], &c[23]);
	s7_x86 (X86_XOR_(c[40], k[51]), X86_XOR_(c[50], k[0]) , X86_XOR_(c[44], k[16]), X86_XOR_(c[61], k[49]), X86_XOR_(c[37], k[36]), X86_XOR_(c[53], k[28]), &c[24], &c[25], &c[26], &c[27]);
	s8_x86 (X86_XOR_(c[37], k[38]), X86_XOR_(c[53], k[37]), X86_XOR_(c[42], k[7]) , X86_XOR_(c[35], k[50]), X86_XOR_(c[56], k[1]) , X86_XOR_(c[47], k[22]), &c[28], &c[29], &c[30], &c[31]);
	//6
	s1_x86 (X86_XOR_(c[24], k[53]), X86_XOR_(c[15], k[17]), X86_XOR_(c[6] , k[32]), X86_XOR_(c[19], k[41]), X86_XOR_(c[20], k[19]), X86_XOR_(c[28], k[47]), &c[32], &c[33], &c[34], &c[35]);
	s2_x86 (X86_XOR_(c[20], k[33]), X86_XOR_(c[28], k[12]), X86_XOR_(c[11], k[3]) , X86_XOR_(c[27], k[54]), X86_XOR_(c[16], k[20]), X86_XOR_(c[0] , k[25]), &c[36], &c[37], &c[38], &c[39]);
	s3_x86 (X86_XOR_(c[16], k[34]), X86_XOR_(c[0] , k[6]) , X86_XOR_(c[14], k[39]), X86_XOR_(c[22], k[40]), X86_XOR_(c[25], k[55]), X86_XOR_(c[4] , k[11]), &c[40], &c[41], &c[42], &c[43]);
	s4_x86 (X86_XOR_(c[25], k[10]), X86_XOR_(c[4] , k[4]) , X86_XOR_(c[17], k[5]) , X86_XOR_(c[30], k[13]), X86_XOR_(c[9] , k[46]), X86_XOR_(c[1] , k[26]), &c[44], &c[45], &c[46], &c[47]);
	s5_x86 (X86_XOR_(c[9] , k[44]), X86_XOR_(c[1] , k[35]), X86_XOR_(c[7] , k[29]), X86_XOR_(c[23], k[16]), X86_XOR_(c[13], k[0]) , X86_XOR_(c[31], k[1]) , &c[48], &c[49], &c[50], &c[51]);
	s6_x86 (X86_XOR_(c[13], k[22]), X86_XOR_(c[31], k[37]), X86_XOR_(c[26], k[28]), X86_XOR_(c[2] , k[45]), X86_XOR_(c[8] , k[43]), X86_XOR_(c[18], k[7]) , &c[52], &c[53], &c[54], &c[55]);
	s7_x86 (X86_XOR_(c[8] , k[38]), X86_XOR_(c[18], k[14]), X86_XOR_(c[12], k[30]), X86_XOR_(c[29], k[8]) , X86_XOR_(c[5] , k[50]), X86_XOR_(c[21], k[42]), &c[56], &c[57], &c[58], &c[59]);
	s8_x86 (X86_XOR_(c[5] , k[52]), X86_XOR_(c[21], k[51]), X86_XOR_(c[10], k[21]), X86_XOR_(c[3] , k[9]) , X86_XOR_(c[24], k[15]), X86_XOR_(c[15], k[36]), &c[60], &c[61], &c[62], &c[63]);
	//7
	s1_x86 (X86_XOR_(c[56], k[10]), X86_XOR_(c[47], k[6]) , X86_XOR_(c[38], k[46]), X86_XOR_(c[51], k[55]), X86_XOR_(c[52], k[33]), X86_XOR_(c[60], k[4]) , &c[0] , &c[1] , &c[2] , &c[3] );
	s2_x86 (X86_XOR_(c[52], k[47]), X86_XOR_(c[60], k[26]), X86_XOR_(c[43], k[17]), X86_XOR_(c[59], k[11]), X86_XOR_(c[48], k[34]), X86_XOR_(c[32], k[39]), &c[4] , &c[5] , &c[6] , &c[7] );
	s3_x86 (X86_XOR_(c[48], k[48]), X86_XOR_(c[32], k[20]), X86_XOR_(c[46], k[53]), X86_XOR_(c[54], k[54]), X86_XOR_(c[57], k[12]), X86_XOR_(c[36], k[25]), &c[8] , &c[9] , &c[10], &c[11]);
	s4_x86 (X86_XOR_(c[57], k[24]), X86_XOR_(c[36], k[18]), X86_XOR_(c[49], k[19]), X86_XOR_(c[62], k[27]), X86_XOR_(c[41], k[3]) , X86_XOR_(c[33], k[40]), &c[12], &c[13], &c[14], &c[15]);
	s5_x86 (X86_XOR_(c[41], k[31]), X86_XOR_(c[33], k[49]), X86_XOR_(c[39], k[43]), X86_XOR_(c[55], k[30]), X86_XOR_(c[45], k[14]), X86_XOR_(c[63], k[15]), &c[16], &c[17], &c[18], &c[19]);
	s6_x86 (X86_XOR_(c[45], k[36]), X86_XOR_(c[63], k[51]), X86_XOR_(c[58], k[42]), X86_XOR_(c[34], k[0]) , X86_XOR_(c[40], k[2]) , X86_XOR_(c[50], k[21]), &c[20], &c[21], &c[22], &c[23]);
	s7_x86 (X86_XOR_(c[40], k[52]), X86_XOR_(c[50], k[28]), X86_XOR_(c[44], k[44]), X86_XOR_(c[61], k[22]), X86_XOR_(c[37], k[9]) , X86_XOR_(c[53], k[1]) , &c[24], &c[25], &c[26], &c[27]);
	s8_x86 (X86_XOR_(c[37], k[7]) , X86_XOR_(c[53], k[38]), X86_XOR_(c[42], k[35]), X86_XOR_(c[35], k[23]), X86_XOR_(c[56], k[29]), X86_XOR_(c[47], k[50]), &c[28], &c[29], &c[30], &c[31]);
	//8
	s1_x86 (X86_XOR_(c[24], k[24]), X86_XOR_(c[15], k[20]), X86_XOR_(c[6] , k[3]) , X86_XOR_(c[19], k[12]), X86_XOR_(c[20], k[47]), X86_XOR_(c[28], k[18]), &c[32], &c[33], &c[34], &c[35]);
	s2_x86 (X86_XOR_(c[20], k[4]) , X86_XOR_(c[28], k[40]), X86_XOR_(c[11], k[6]) , X86_XOR_(c[27], k[25]), X86_XOR_(c[16], k[48]), X86_XOR_(c[0] , k[53]), &c[36], &c[37], &c[38], &c[39]);
	s3_x86 (X86_XOR_(c[16], k[5]) , X86_XOR_(c[0] , k[34]), X86_XOR_(c[14], k[10]), X86_XOR_(c[22], k[11]), X86_XOR_(c[25], k[26]), X86_XOR_(c[4] , k[39]), &c[40], &c[41], &c[42], &c[43]);
	s4_x86 (X86_XOR_(c[25], k[13]), X86_XOR_(c[4] , k[32]), X86_XOR_(c[17], k[33]), X86_XOR_(c[30], k[41]), X86_XOR_(c[9] , k[17]), X86_XOR_(c[1] , k[54]), &c[44], &c[45], &c[46], &c[47]);
	s5_x86 (X86_XOR_(c[9] , k[45]), X86_XOR_(c[1] , k[8]) , X86_XOR_(c[7] , k[2]) , X86_XOR_(c[23], k[44]), X86_XOR_(c[13], k[28]), X86_XOR_(c[31], k[29]), &c[48], &c[49], &c[50], &c[51]);
	s6_x86 (X86_XOR_(c[13], k[50]), X86_XOR_(c[31], k[38]), X86_XOR_(c[26], k[1]) , X86_XOR_(c[2] , k[14]), X86_XOR_(c[8] , k[16]), X86_XOR_(c[18], k[35]), &c[52], &c[53], &c[54], &c[55]);
	s7_x86 (X86_XOR_(c[8] , k[7]) , X86_XOR_(c[18], k[42]), X86_XOR_(c[12], k[31]), X86_XOR_(c[29], k[36]), X86_XOR_(c[5] , k[23]), X86_XOR_(c[21], k[15]), &c[56], &c[57], &c[58], &c[59]);
	s8_x86 (X86_XOR_(c[5] , k[21]), X86_XOR_(c[21], k[52]), X86_XOR_(c[10], k[49]), X86_XOR_(c[3] , k[37]), X86_XOR_(c[24], k[43]), X86_XOR_(c[15], k[9]) , &c[60], &c[61], &c[62], &c[63]);
	//9
	s1_x86 (X86_XOR_(c[56], k[6]) , X86_XOR_(c[47], k[27]), X86_XOR_(c[38], k[10]), X86_XOR_(c[51], k[19]), X86_XOR_(c[52], k[54]), X86_XOR_(c[60], k[25]), &c[0] , &c[1] , &c[2] , &c[3] );
	s2_x86 (X86_XOR_(c[52], k[11]), X86_XOR_(c[60], k[47]), X86_XOR_(c[43], k[13]), X86_XOR_(c[59], k[32]), X86_XOR_(c[48], k[55]), X86_XOR_(c[32], k[3]) , &c[4] , &c[5] , &c[6] , &c[7] );
	s3_x86 (X86_XOR_(c[48], k[12]), X86_XOR_(c[32], k[41]), X86_XOR_(c[46], k[17]), X86_XOR_(c[54], k[18]), X86_XOR_(c[57], k[33]), X86_XOR_(c[36], k[46]), &c[8] , &c[9] , &c[10], &c[11]);
	s4_x86 (X86_XOR_(c[57], k[20]), X86_XOR_(c[36], k[39]), X86_XOR_(c[49], k[40]), X86_XOR_(c[62], k[48]), X86_XOR_(c[41], k[24]), X86_XOR_(c[33], k[4]) , &c[12], &c[13], &c[14], &c[15]);
	s5_x86 (X86_XOR_(c[41], k[52]), X86_XOR_(c[33], k[15]), X86_XOR_(c[39], k[9]) , X86_XOR_(c[55], k[51]), X86_XOR_(c[45], k[35]), X86_XOR_(c[63], k[36]), &c[16], &c[17], &c[18], &c[19]);
	s6_x86 (X86_XOR_(c[45], k[2]) , X86_XOR_(c[63], k[45]), X86_XOR_(c[58], k[8]) , X86_XOR_(c[34], k[21]), X86_XOR_(c[40], k[23]), X86_XOR_(c[50], k[42]), &c[20], &c[21], &c[22], &c[23]);
	s7_x86 (X86_XOR_(c[40], k[14]), X86_XOR_(c[50], k[49]), X86_XOR_(c[44], k[38]), X86_XOR_(c[61], k[43]), X86_XOR_(c[37], k[30]), X86_XOR_(c[53], k[22]), &c[24], &c[25], &c[26], &c[27]);
	s8_x86 (X86_XOR_(c[37], k[28]), X86_XOR_(c[53], k[0]) , X86_XOR_(c[42], k[1]) , X86_XOR_(c[35], k[44]), X86_XOR_(c[56], k[50]), X86_XOR_(c[47], k[16]), &c[28], &c[29], &c[30], &c[31]);
	//10
	s1_x86 (X86_XOR_(c[24], k[20]), X86_XOR_(c[15], k[41]), X86_XOR_(c[6] , k[24]), X86_XOR_(c[19], k[33]), X86_XOR_(c[20], k[11]), X86_XOR_(c[28], k[39]), &c[32], &c[33], &c[34], &c[35]);
	s2_x86 (X86_XOR_(c[20], k[25]), X86_XOR_(c[28], k[4]) , X86_XOR_(c[11], k[27]), X86_XOR_(c[27], k[46]), X86_XOR_(c[16], k[12]), X86_XOR_(c[0] , k[17]), &c[36], &c[37], &c[38], &c[39]);
	s3_x86 (X86_XOR_(c[16], k[26]), X86_XOR_(c[0] , k[55]), X86_XOR_(c[14], k[6]) , X86_XOR_(c[22], k[32]), X86_XOR_(c[25], k[47]), X86_XOR_(c[4] , k[3]) , &c[40], &c[41], &c[42], &c[43]);
	s4_x86 (X86_XOR_(c[25], k[34]), X86_XOR_(c[4] , k[53]), X86_XOR_(c[17], k[54]), X86_XOR_(c[30], k[5]) , X86_XOR_(c[9] , k[13]), X86_XOR_(c[1] , k[18]), &c[44], &c[45], &c[46], &c[47]);
	s5_x86 (X86_XOR_(c[9] , k[7]) , X86_XOR_(c[1] , k[29]), X86_XOR_(c[7] , k[23]), X86_XOR_(c[23], k[38]), X86_XOR_(c[13], k[49]), X86_XOR_(c[31], k[50]), &c[48], &c[49], &c[50], &c[51]);
	s6_x86 (X86_XOR_(c[13], k[16]), X86_XOR_(c[31], k[0]) , X86_XOR_(c[26], k[22]), X86_XOR_(c[2] , k[35]), X86_XOR_(c[8] , k[37]), X86_XOR_(c[18], k[1]) , &c[52], &c[53], &c[54], &c[55]);
	s7_x86 (X86_XOR_(c[8] , k[28]), X86_XOR_(c[18], k[8]) , X86_XOR_(c[12], k[52]), X86_XOR_(c[29], k[2]) , X86_XOR_(c[5] , k[44]), X86_XOR_(c[21], k[36]), &c[56], &c[57], &c[58], &c[59]);
	s8_x86 (X86_XOR_(c[5] , k[42]), X86_XOR_(c[21], k[14]), X86_XOR_(c[10], k[15]), X86_XOR_(c[3] , k[31]), X86_XOR_(c[24], k[9]) , X86_XOR_(c[15], k[30]), &c[60], &c[61], &c[62], &c[63]);
	//11
	s1_x86 (X86_XOR_(c[56], k[34]), X86_XOR_(c[47], k[55]), X86_XOR_(c[38], k[13]), X86_XOR_(c[51], k[47]), X86_XOR_(c[52], k[25]), X86_XOR_(c[60], k[53]), &c[0] , &c[1] , &c[2] , &c[3] );
	s2_x86 (X86_XOR_(c[52], k[39]), X86_XOR_(c[60], k[18]), X86_XOR_(c[43], k[41]), X86_XOR_(c[59], k[3]) , X86_XOR_(c[48], k[26]), X86_XOR_(c[32], k[6]) , &c[4] , &c[5] , &c[6] , &c[7] );
	s3_x86 (X86_XOR_(c[48], k[40]), X86_XOR_(c[32], k[12]), X86_XOR_(c[46], k[20]), X86_XOR_(c[54], k[46]), X86_XOR_(c[57], k[4]) , X86_XOR_(c[36], k[17]), &c[8] , &c[9] , &c[10], &c[11]);
	s4_x86 (X86_XOR_(c[57], k[48]), X86_XOR_(c[36], k[10]), X86_XOR_(c[49], k[11]), X86_XOR_(c[62], k[19]), X86_XOR_(c[41], k[27]), X86_XOR_(c[33], k[32]), &c[12], &c[13], &c[14], &c[15]);
	s5_x86 (X86_XOR_(c[41], k[21]), X86_XOR_(c[33], k[43]), X86_XOR_(c[39], k[37]), X86_XOR_(c[55], k[52]), X86_XOR_(c[45], k[8]) , X86_XOR_(c[63], k[9]) , &c[16], &c[17], &c[18], &c[19]);
	s6_x86 (X86_XOR_(c[45], k[30]), X86_XOR_(c[63], k[14]), X86_XOR_(c[58], k[36]), X86_XOR_(c[34], k[49]), X86_XOR_(c[40], k[51]), X86_XOR_(c[50], k[15]), &c[20], &c[21], &c[22], &c[23]);
	s7_x86 (X86_XOR_(c[40], k[42]), X86_XOR_(c[50], k[22]), X86_XOR_(c[44], k[7]) , X86_XOR_(c[61], k[16]), X86_XOR_(c[37], k[31]), X86_XOR_(c[53], k[50]), &c[24], &c[25], &c[26], &c[27]);
	s8_x86 (X86_XOR_(c[37], k[1]) , X86_XOR_(c[53], k[28]), X86_XOR_(c[42], k[29]), X86_XOR_(c[35], k[45]), X86_XOR_(c[56], k[23]), X86_XOR_(c[47], k[44]), &c[28], &c[29], &c[30], &c[31]);
	//12
	s1_x86 (X86_XOR_(c[24], k[48]), X86_XOR_(c[15], k[12]), X86_XOR_(c[6] , k[27]), X86_XOR_(c[19], k[4]) , X86_XOR_(c[20], k[39]), X86_XOR_(c[28], k[10]), &c[32], &c[33], &c[34], &c[35]);
	s2_x86 (X86_XOR_(c[20], k[53]), X86_XOR_(c[28], k[32]), X86_XOR_(c[11], k[55]), X86_XOR_(c[27], k[17]), X86_XOR_(c[16], k[40]), X86_XOR_(c[0] , k[20]), &c[36], &c[37], &c[38], &c[39]);
	s3_x86 (X86_XOR_(c[16], k[54]), X86_XOR_(c[0] , k[26]), X86_XOR_(c[14], k[34]), X86_XOR_(c[22], k[3]) , X86_XOR_(c[25], k[18]), X86_XOR_(c[4] , k[6]) , &c[40], &c[41], &c[42], &c[43]);
	s4_x86 (X86_XOR_(c[25], k[5]) , X86_XOR_(c[4] , k[24]), X86_XOR_(c[17], k[25]), X86_XOR_(c[30], k[33]), X86_XOR_(c[9] , k[41]), X86_XOR_(c[1] , k[46]), &c[44], &c[45], &c[46], &c[47]);
	s5_x86 (X86_XOR_(c[9] , k[35]), X86_XOR_(c[1] , k[2]) , X86_XOR_(c[7] , k[51]), X86_XOR_(c[23], k[7]) , X86_XOR_(c[13], k[22]), X86_XOR_(c[31], k[23]), &c[48], &c[49], &c[50], &c[51]);
	s6_x86 (X86_XOR_(c[13], k[44]), X86_XOR_(c[31], k[28]), X86_XOR_(c[26], k[50]), X86_XOR_(c[2] , k[8]) , X86_XOR_(c[8] , k[38]), X86_XOR_(c[18], k[29]), &c[52], &c[53], &c[54], &c[55]);
	s7_x86 (X86_XOR_(c[8] , k[1]) , X86_XOR_(c[18], k[36]), X86_XOR_(c[12], k[21]), X86_XOR_(c[29], k[30]), X86_XOR_(c[5] , k[45]), X86_XOR_(c[21], k[9]) , &c[56], &c[57], &c[58], &c[59]);
	s8_x86 (X86_XOR_(c[5] , k[15]), X86_XOR_(c[21], k[42]), X86_XOR_(c[10], k[43]), X86_XOR_(c[3] , k[0]) , X86_XOR_(c[24], k[37]), X86_XOR_(c[15], k[31]), &c[60], &c[61], &c[62], &c[63]);
	//13
	s1_x86 (X86_XOR_(c[56], k[5]) , X86_XOR_(c[47], k[26]), X86_XOR_(c[38], k[41]), X86_XOR_(c[51], k[18]), X86_XOR_(c[52], k[53]), X86_XOR_(c[60], k[24]), &c[0] , &c[1] , &c[2] , &c[3]);
	s2_x86 (X86_XOR_(c[52], k[10]), X86_XOR_(c[60], k[46]), X86_XOR_(c[43], k[12]), X86_XOR_(c[59], k[6]) , X86_XOR_(c[48], k[54]), X86_XOR_(c[32], k[34]), &c[4] , &c[5] , &c[6] , &c[7]);
	s3_x86 (X86_XOR_(c[48], k[11]), X86_XOR_(c[32], k[40]), X86_XOR_(c[46], k[48]), X86_XOR_(c[54], k[17]), X86_XOR_(c[57], k[32]), X86_XOR_(c[36], k[20]), &c[8] , &c[9] , &c[10], &c[11]);
	s4_x86 (X86_XOR_(c[57], k[19]), X86_XOR_(c[36], k[13]), X86_XOR_(c[49], k[39]), X86_XOR_(c[62], k[47]), X86_XOR_(c[41], k[55]), X86_XOR_(c[33], k[3]) , &c[12], &c[13], &c[14], &c[15]);
	s5_x86 (X86_XOR_(c[41], k[49]), X86_XOR_(c[33], k[16]), X86_XOR_(c[39], k[38]), X86_XOR_(c[55], k[21]), X86_XOR_(c[45], k[36]), X86_XOR_(c[63], k[37]), &c[16], &c[17], &c[18], &c[19]);
	s6_x86 (X86_XOR_(c[45], k[31]), X86_XOR_(c[63], k[42]), X86_XOR_(c[58], k[9]) , X86_XOR_(c[34], k[22]), X86_XOR_(c[40], k[52]), X86_XOR_(c[50], k[43]), &c[20], &c[21], &c[22], &c[23]);
	s7_x86 (X86_XOR_(c[40], k[15]), X86_XOR_(c[50], k[50]), X86_XOR_(c[44], k[35]), X86_XOR_(c[61], k[44]), X86_XOR_(c[37], k[0]) , X86_XOR_(c[53], k[23]), &c[24], &c[25], &c[26], &c[27]);
	s8_x86 (X86_XOR_(c[37], k[29]), X86_XOR_(c[53], k[1]) , X86_XOR_(c[42], k[2]) , X86_XOR_(c[35], k[14]), X86_XOR_(c[56], k[51]), X86_XOR_(c[47], k[45]), &c[28], &c[29], &c[30], &c[31]);
	//14
	s1_x86 (X86_XOR_(c[24], k[19]), X86_XOR_(c[15], k[40]), X86_XOR_(c[6] , k[55]), X86_XOR_(c[19], k[32]), X86_XOR_(c[20], k[10]), X86_XOR_(c[28], k[13]), &c[32], &c[33], &c[34], &c[35]);
	s2_x86 (X86_XOR_(c[20], k[24]), X86_XOR_(c[28], k[3]) , X86_XOR_(c[11], k[26]), X86_XOR_(c[27], k[20]), X86_XOR_(c[16], k[11]), X86_XOR_(c[0] , k[48]), &c[36], &c[37], &c[38], &c[39]);
	s3_x86 (X86_XOR_(c[16], k[25]), X86_XOR_(c[0] , k[54]), X86_XOR_(c[14], k[5]) , X86_XOR_(c[22], k[6]) , X86_XOR_(c[25], k[46]), X86_XOR_(c[4] , k[34]), &c[40], &c[41], &c[42], &c[43]);
	s4_x86 (X86_XOR_(c[25], k[33]), X86_XOR_(c[4] , k[27]), X86_XOR_(c[17], k[53]), X86_XOR_(c[30], k[4]) , X86_XOR_(c[9] , k[12]), X86_XOR_(c[1] , k[17]), &c[44], &c[45], &c[46], &c[47]);
	s5_x86 (X86_XOR_(c[9] , k[8]) , X86_XOR_(c[1] , k[30]), X86_XOR_(c[7] , k[52]), X86_XOR_(c[23], k[35]), X86_XOR_(c[13], k[50]), X86_XOR_(c[31], k[51]), &c[48], &c[49], &c[50], &c[51]);
	s6_x86 (X86_XOR_(c[13], k[45]), X86_XOR_(c[31], k[1]) , X86_XOR_(c[26], k[23]), X86_XOR_(c[2] , k[36]), X86_XOR_(c[8] , k[7]) , X86_XOR_(c[18], k[2]) , &c[52], &c[53], &c[54], &c[55]);
	s7_x86 (X86_XOR_(c[8] , k[29]), X86_XOR_(c[18], k[9]) , X86_XOR_(c[12], k[49]), X86_XOR_(c[29], k[31]), X86_XOR_(c[5] , k[14]), X86_XOR_(c[21], k[37]), &c[56], &c[57], &c[58], &c[59]);
	s8_x86 (X86_XOR_(c[5] , k[43]), X86_XOR_(c[21], k[15]), X86_XOR_(c[10], k[16]), X86_XOR_(c[3] , k[28]), X86_XOR_(c[24], k[38]), X86_XOR_(c[15], k[0]) , &c[60], &c[61], &c[62], &c[63]);
	//15
	s1_x86 (X86_XOR_(c[56], k[33]), X86_XOR_(c[47], k[54]), X86_XOR_(c[38], k[12]), X86_XOR_(c[51], k[46]), X86_XOR_(c[52], k[24]), X86_XOR_(c[60], k[27]), &c[0] , &c[1] , &c[2] , &c[3] );
	s2_x86 (X86_XOR_(c[52], k[13]), X86_XOR_(c[60], k[17]), X86_XOR_(c[43], k[40]), X86_XOR_(c[59], k[34]), X86_XOR_(c[48], k[25]), X86_XOR_(c[32], k[5]) , &c[4] , &c[5] , &c[6] , &c[7] );

	{
		unsigned int hash_values[X86_BIT_LENGHT];
		unsigned int i, j;
		int calculated_16_round = FALSE;
		int calculated_2_byte = size_table > 0xFF;
		int calculated_3_byte = size_table > 0xFFFF;
		int calculated_4_byte = size_table > 0xFFFFFF;

		calculate_hash_x86(c, hash_values, 0);

		if(calculated_2_byte)
		{
			s3_x86 (X86_XOR_(c[48], k[39]), X86_XOR_(c[32], k[11]), X86_XOR_(c[46], k[19]), X86_XOR_(c[54], k[20]), X86_XOR_(c[57], k[3]) , X86_XOR_(c[36], k[48]), &c[8] , &c[9] , &c[10], &c[11]);
			s4_x86 (X86_XOR_(c[57], k[47]), X86_XOR_(c[36], k[41]), X86_XOR_(c[49], k[10]), X86_XOR_(c[62], k[18]), X86_XOR_(c[41], k[26]), X86_XOR_(c[33], k[6]) , &c[12], &c[13], &c[14], &c[15]);
			calculate_hash_x86(c+8, hash_values, 8);
		}

		if(calculated_3_byte)
		{
			s5_x86 (X86_XOR_(c[41], k[22]), X86_XOR_(c[33], k[44]), X86_XOR_(c[39], k[7]) , X86_XOR_(c[55], k[49]), X86_XOR_(c[45], k[9]) , X86_XOR_(c[63], k[38]), &c[16], &c[17], &c[18], &c[19]);
			s6_x86 (X86_XOR_(c[45], k[0]) , X86_XOR_(c[63], k[15]), X86_XOR_(c[58], k[37]), X86_XOR_(c[34], k[50]), X86_XOR_(c[40], k[21]), X86_XOR_(c[50], k[16]), &c[20], &c[21], &c[22], &c[23]);
			calculate_hash_x86(c+16, hash_values, 16);
		}

		if(calculated_4_byte)
		{
			s7_x86 (X86_XOR_(c[40], k[43]), X86_XOR_(c[50], k[23]), X86_XOR_(c[44], k[8]) , X86_XOR_(c[61], k[45]), X86_XOR_(c[37], k[28]), X86_XOR_(c[53], k[51]), &c[24], &c[25], &c[26], &c[27]);
			s8_x86 (X86_XOR_(c[37], k[2]) , X86_XOR_(c[53], k[29]), X86_XOR_(c[42], k[30]), X86_XOR_(c[35], k[42]), X86_XOR_(c[56], k[52]), X86_XOR_(c[47], k[14]), &c[28], &c[29], &c[30], &c[31]);
			calculate_hash_x86(c+24, hash_values, 24);
		}

		for(j = 0; j < X86_BIT_LENGHT; j++)
		{
			unsigned int index = table[hash_values[j] & size_table];
			// Partial match
			while(index != NO_ELEM)
			{
				unsigned char* bin = ((unsigned char*)binary_values) + (index << 3);

				// If calculated in hash_values and not compared-->compare
				if(size_table < 0xFF && (hash_values[j] & 0xFF) != bin[0])
					goto next_iteration;
				i = __max(8, first_bit_size_table);

				if(!calculated_2_byte)
				{
					calculated_2_byte = TRUE;
					s3_x86 (X86_XOR_(c[48], k[39]), X86_XOR_(c[32], k[11]), X86_XOR_(c[46], k[19]), X86_XOR_(c[54], k[20]), X86_XOR_(c[57], k[3]) , X86_XOR_(c[36], k[48]), &c[8] , &c[9] , &c[10], &c[11]);
					s4_x86 (X86_XOR_(c[57], k[47]), X86_XOR_(c[36], k[41]), X86_XOR_(c[49], k[10]), X86_XOR_(c[62], k[18]), X86_XOR_(c[41], k[26]), X86_XOR_(c[33], k[6]) , &c[12], &c[13], &c[14], &c[15]);
				}
	
				if(size_table > 0xFF)// If calculated in hash_values...
				{
					if(i < 16 && ((hash_values[j]>>8) & 0xFF) != bin[1])//...and not compared-->compare
						goto next_iteration;
					i = __max(i, 16);
				}
				else// compare bit to bit
					for(; i < 16; i++)
						if( (( c[i] >> j) & 1) != ((bin[1] >> (i & 7)) & 1) )
							goto next_iteration;

				if(!calculated_3_byte)
				{
					calculated_3_byte = TRUE;
					s5_x86 (X86_XOR_(c[41], k[22]), X86_XOR_(c[33], k[44]), X86_XOR_(c[39], k[7]) , X86_XOR_(c[55], k[49]), X86_XOR_(c[45], k[9]) , X86_XOR_(c[63], k[38]), &c[16], &c[17], &c[18], &c[19]);
					s6_x86 (X86_XOR_(c[45], k[0]) , X86_XOR_(c[63], k[15]), X86_XOR_(c[58], k[37]), X86_XOR_(c[34], k[50]), X86_XOR_(c[40], k[21]), X86_XOR_(c[50], k[16]), &c[20], &c[21], &c[22], &c[23]);
				}

				if(size_table > 0xFFFF)// If calculated in hash_values...
				{
					if(i < 24 && ((hash_values[j]>>16) & 0xFF) != bin[2])//...and not compared-->compare
						goto next_iteration;
					i = __max(i, 24);
				}
				else// compare bit to bit
					for(; i < 24; i++)
						if( (( c[i] >> j) & 1) != ((bin[2] >> (i & 7)) & 1) )
							goto next_iteration;

				if(!calculated_4_byte)
				{
					calculated_4_byte = TRUE;
					s7_x86 (X86_XOR_(c[40], k[43]), X86_XOR_(c[50], k[23]), X86_XOR_(c[44], k[8]) , X86_XOR_(c[61], k[45]), X86_XOR_(c[37], k[28]), X86_XOR_(c[53], k[51]), &c[24], &c[25], &c[26], &c[27]);
					s8_x86 (X86_XOR_(c[37], k[2]) , X86_XOR_(c[53], k[29]), X86_XOR_(c[42], k[30]), X86_XOR_(c[35], k[42]), X86_XOR_(c[56], k[52]), X86_XOR_(c[47], k[14]), &c[28], &c[29], &c[30], &c[31]);
				}

				for(; i < 32; i++)// If distinct bits
					if( (( c[i] >> j) & 1) != ((bin[3] >> (i & 7)) & 1) )
						goto next_iteration;

				if(!calculated_16_round)
				{
					calculated_16_round = TRUE;
					// 16
					s1_x86 (X86_XOR_(c[24], k[40]), X86_XOR_(c[15], k[4]) , X86_XOR_(c[6] , k[19]), X86_XOR_(c[19], k[53]), X86_XOR_(c[20], k[6]) , X86_XOR_(c[28], k[34]), &c[32], &c[33], &c[34], &c[35]);
					s2_x86 (X86_XOR_(c[20], k[20]), X86_XOR_(c[28], k[24]), X86_XOR_(c[11], k[47]), X86_XOR_(c[27], k[41]), X86_XOR_(c[16], k[32]), X86_XOR_(c[0] , k[12]), &c[36], &c[37], &c[38], &c[39]);
					s3_x86 (X86_XOR_(c[16], k[46]), X86_XOR_(c[0] , k[18]), X86_XOR_(c[14], k[26]), X86_XOR_(c[22], k[27]), X86_XOR_(c[25], k[10]), X86_XOR_(c[4] , k[55]), &c[40], &c[41], &c[42], &c[43]);
					s4_x86 (X86_XOR_(c[25], k[54]), X86_XOR_(c[4] , k[48]), X86_XOR_(c[17], k[17]), X86_XOR_(c[30], k[25]), X86_XOR_(c[9] , k[33]), X86_XOR_(c[1] , k[13]), &c[44], &c[45], &c[46], &c[47]);
					s5_x86 (X86_XOR_(c[9] , k[29]), X86_XOR_(c[1] , k[51]), X86_XOR_(c[7] , k[14]), X86_XOR_(c[23], k[1]) , X86_XOR_(c[13], k[16]), X86_XOR_(c[31], k[45]), &c[48], &c[49], &c[50], &c[51]);
					s6_x86 (X86_XOR_(c[13], k[7]) , X86_XOR_(c[31], k[22]), X86_XOR_(c[26], k[44]), X86_XOR_(c[2] , k[2]) , X86_XOR_(c[8] , k[28]), X86_XOR_(c[18], k[23]), &c[52], &c[53], &c[54], &c[55]);
					s7_x86 (X86_XOR_(c[8] , k[50]), X86_XOR_(c[18], k[30]), X86_XOR_(c[12], k[15]), X86_XOR_(c[29], k[52]), X86_XOR_(c[5] , k[35]), X86_XOR_(c[21], k[31]), &c[56], &c[57], &c[58], &c[59]);
					s8_x86 (X86_XOR_(c[5] , k[9]) , X86_XOR_(c[21], k[36]), X86_XOR_(c[10], k[37]), X86_XOR_(c[3] , k[49]), X86_XOR_(c[24], k[0]) , X86_XOR_(c[15], k[21]), &c[60], &c[61], &c[62], &c[63]);
				}

				for(; i < 64; i++)// If distinct bits
					if( (( c[i] >> j) & 1) != ((bin[i >> 3] >> (i & 7)) & 1) )
						goto next_iteration;

				// Total match
				{
					unsigned char key[8];
					memset(key, 0, sizeof(key));

					for (i = 0; i < 56; i++)
					{
						if((k[55 - i]>>j) & 1)
							key[i/8] |= (128 >> (i % 8));	
					}

					password_was_found(index, key);
				}
next_iteration:
				index = same_hash_next[index];
			}
		}
	}
}
PRIVATE void convert_key_to_input_x86(unsigned char* key_iter, unsigned char* old_key_iter, X86_WORD* lm_buffer_key)
{
	X86_WORD _mask;
	unsigned int diff;

	//for(i = 0; i < BIT_LENGHT; i++, _mask <<= 1)
	//{
	//	for (j = 0; j < 56; j++)
	//		if ( (key_iter[j/8] & (128 >> (j % 8))) != 0)
	//			lm_buffer_key[55 - j] |= _mask;
	//}

	for(_mask = 1; _mask ; _mask <<= 1)
	{
		//0
		X86_WORD* _buffer_key_tmp = lm_buffer_key + 48;
		diff = *key_iter ^ *old_key_iter;
		*old_key_iter = *key_iter;
		while(diff)
		{
			uint32_t _first_bit_index = first_bit[diff];
			_buffer_key_tmp[_first_bit_index] ^= _mask;

			diff >>= _first_bit_index + 1;
			_buffer_key_tmp += _first_bit_index + 1;
		}

		key_iter++;
		old_key_iter++;
		//1
		diff = *key_iter ^ *old_key_iter;
		*old_key_iter = *key_iter;
		_buffer_key_tmp = lm_buffer_key + 40;
		while(diff)
		{
			uint32_t _first_bit_index = first_bit[diff];
			_buffer_key_tmp[_first_bit_index] ^= _mask;

			diff >>= _first_bit_index + 1;
			_buffer_key_tmp += _first_bit_index + 1;
		}

		key_iter++;
		old_key_iter++;
		//2
		if(key_iter != old_key_iter)
		{
			diff = *key_iter ^ *old_key_iter;
			*old_key_iter = *key_iter;
			_buffer_key_tmp = lm_buffer_key + 32;
			while(diff)
			{
				uint32_t _first_bit_index = first_bit[diff];
				_buffer_key_tmp[_first_bit_index] ^= _mask;

				diff >>= _first_bit_index + 1;
				_buffer_key_tmp += _first_bit_index + 1;
			}
		}

		key_iter++;
		old_key_iter++;
		//3
		if(key_iter != old_key_iter)
		{
			diff = *key_iter ^ *old_key_iter;
			*old_key_iter = *key_iter;
			_buffer_key_tmp = lm_buffer_key + 24;
			while(diff)
			{
				uint32_t _first_bit_index = first_bit[diff];
				_buffer_key_tmp[_first_bit_index] ^= _mask;

				diff >>= _first_bit_index + 1;
				_buffer_key_tmp += _first_bit_index + 1;
			}
		}

		key_iter++;
		old_key_iter++;
		//4
		if(key_iter != old_key_iter)
		{
			diff = *key_iter ^ *old_key_iter;
			*old_key_iter = *key_iter;
			_buffer_key_tmp = lm_buffer_key + 16;
			while(diff)
			{
				uint32_t _first_bit_index = first_bit[diff];
				_buffer_key_tmp[_first_bit_index] ^= _mask;

				diff >>= _first_bit_index + 1;
				_buffer_key_tmp += _first_bit_index + 1;
			}
		}

		key_iter++;
		old_key_iter++;
		//5
		if(key_iter != old_key_iter)
		{
			diff = *key_iter ^ *old_key_iter;
			*old_key_iter = *key_iter;
			_buffer_key_tmp = lm_buffer_key + 8;
			while(diff)
			{
				uint32_t _first_bit_index = first_bit[diff];
				_buffer_key_tmp[_first_bit_index] ^= _mask;

				diff >>= _first_bit_index + 1;
				_buffer_key_tmp += _first_bit_index + 1;
			}
		}

		key_iter++;
		old_key_iter++;
		//6
		if(key_iter != old_key_iter)
		{
			diff = *key_iter ^ *old_key_iter;
			*old_key_iter = *key_iter;
			_buffer_key_tmp = lm_buffer_key + 0;
			while(diff)
			{
				uint32_t _first_bit_index = first_bit[diff];
				_buffer_key_tmp[_first_bit_index] ^= _mask;

				diff >>= _first_bit_index + 1;
				_buffer_key_tmp += _first_bit_index + 1;
			}
		}

		key_iter+=2;
		old_key_iter+=2;
	}
}
PRIVATE void crypt_utf8_lm_protocol_x86(CryptParam* param)
{
	X86_WORD* lm_buffer_key = (X86_WORD*)calloc(56, sizeof(X86_WORD));

	unsigned char* keys		 = (unsigned char*)calloc(8*X86_BIT_LENGHT, sizeof(unsigned char));
	unsigned char* old_keys  = (unsigned char*)calloc(8*X86_BIT_LENGHT, sizeof(unsigned char));

	while(continue_attack && param->gen(keys, X86_BIT_LENGHT, param->thread_id))
	{
		convert_key_to_input_x86(keys, old_keys, lm_buffer_key);

		// Encrypt
		lm_eval_x86(lm_buffer_key);
		report_keys_processed(X86_BIT_LENGHT);
	}

	free(keys);
	free(old_keys);
	free(lm_buffer_key);

	finish_thread();
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// V128 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "arch_simd.h"
#define MAX_REPEAT 8
#define REPEAT		for(repeat=0;repeat<MAX_REPEAT;repeat++,c++,k++)
#define END_REPEAT	c=first_c;k=first_k;

#define V128_MASK_1(elem)	(V128_AND(elem, V128_CONST(0x01010101U)))
#define V128_MASK_2(elem)	(V128_AND(elem, V128_CONST(0x02020202U)))
#define V128_MASK_3(elem)	(V128_AND(elem, V128_CONST(0x04040404U)))
#define V128_MASK_4(elem)	(V128_AND(elem, V128_CONST(0x08080808U)))
#define V128_MASK_5(elem)	(V128_AND(elem, V128_CONST(0x10101010U)))
#define V128_MASK_6(elem)	(V128_AND(elem, V128_CONST(0x20202020U)))
#define V128_MASK_7(elem)	(V128_AND(elem, V128_CONST(0x40404040U)))
#define V128_MASK_8(elem)	(V128_AND(elem, V128_CONST(0x80808080U)))

typedef void calculate_hash_func(V128_WORD* c, unsigned int* hash_values, unsigned int i_shift);
typedef void calculate_lm_indexs_func(unsigned int* hash_values, unsigned int* indexs);
typedef void lm_eval_kernel_func(void* lm_buffer_key, void* lm_buffer_crypt, void* tmp_stor);
PRIVATE void lm_eval_final(V128_WORD* first_k, V128_WORD* first_c, V128_WORD* a, calculate_hash_func* calculate_hash, calculate_lm_indexs_func* calculate_lm_indexs);

PRIVATE void calculate_hash_v128(V128_WORD* c, unsigned int* hash_values, unsigned int i_shift)
{
	// I try to vectorize the code to obtain the hashes needed for the table
	// Look a the code commented in x86 version: this is the 'normal' version
	// Here i calculate hashes 8 at a time. This result in a dramatic better performance
	V128_WORD hash_tmp[8];
	unsigned int i;

	//0,1,2
	hash_tmp[0] = V128_OR(V128_OR(		  V128_MASK_1(c[0])	   ,  V128_SL(V128_MASK_1(c[1*MAX_REPEAT]), 1)),  V128_SL(V128_MASK_1(c[2*MAX_REPEAT]), 2));
	hash_tmp[1] = V128_OR(V128_OR(V128_SR(V128_MASK_2(c[0]), 1),		  V128_MASK_2(c[1*MAX_REPEAT]))	,	  V128_SL(V128_MASK_2(c[2*MAX_REPEAT]), 1));
	hash_tmp[2] = V128_OR(V128_OR(V128_SR(V128_MASK_3(c[0]), 2),  V128_SR(V128_MASK_3(c[1*MAX_REPEAT]), 1)),		  V128_MASK_3(c[2*MAX_REPEAT]));
	hash_tmp[3] = V128_OR(V128_OR(V128_SR(V128_MASK_4(c[0]), 3),  V128_SR(V128_MASK_4(c[1*MAX_REPEAT]), 2)),  V128_SR(V128_MASK_4(c[2*MAX_REPEAT]), 1));
	hash_tmp[4] = V128_OR(V128_OR(V128_SR(V128_MASK_5(c[0]), 4),  V128_SR(V128_MASK_5(c[1*MAX_REPEAT]), 3)),  V128_SR(V128_MASK_5(c[2*MAX_REPEAT]), 2));
	hash_tmp[5] = V128_OR(V128_OR(V128_SR(V128_MASK_6(c[0]), 5),  V128_SR(V128_MASK_6(c[1*MAX_REPEAT]), 4)),  V128_SR(V128_MASK_6(c[2*MAX_REPEAT]), 3));
	hash_tmp[6] = V128_OR(V128_OR(V128_SR(V128_MASK_7(c[0]), 6),  V128_SR(V128_MASK_7(c[1*MAX_REPEAT]), 5)),  V128_SR(V128_MASK_7(c[2*MAX_REPEAT]), 4));
	hash_tmp[7] = V128_OR(V128_OR(V128_SR(V128_MASK_8(c[0]), 7),  V128_SR(V128_MASK_8(c[1*MAX_REPEAT]), 6)),  V128_SR(V128_MASK_8(c[2*MAX_REPEAT]), 5));
	//3, 4
	hash_tmp[0] = V128_OR(hash_tmp[0], V128_OR(V128_SL(V128_MASK_1(c[3*MAX_REPEAT]), 3),  V128_SL(V128_MASK_1(c[4*MAX_REPEAT]), 4)));
	hash_tmp[1] = V128_OR(hash_tmp[1], V128_OR(V128_SL(V128_MASK_2(c[3*MAX_REPEAT]), 2),  V128_SL(V128_MASK_2(c[4*MAX_REPEAT]), 3)));
	hash_tmp[2] = V128_OR(hash_tmp[2], V128_OR(V128_SL(V128_MASK_3(c[3*MAX_REPEAT]), 1),  V128_SL(V128_MASK_3(c[4*MAX_REPEAT]), 2)));
	hash_tmp[3] = V128_OR(hash_tmp[3], V128_OR(		   V128_MASK_4(c[3*MAX_REPEAT]),	  V128_SL(V128_MASK_4(c[4*MAX_REPEAT]), 1)));
	hash_tmp[4] = V128_OR(hash_tmp[4], V128_OR(V128_SR(V128_MASK_5(c[3*MAX_REPEAT]), 1),		  V128_MASK_5(c[4*MAX_REPEAT])));
	hash_tmp[5] = V128_OR(hash_tmp[5], V128_OR(V128_SR(V128_MASK_6(c[3*MAX_REPEAT]), 2),  V128_SR(V128_MASK_6(c[4*MAX_REPEAT]), 1)));
	hash_tmp[6] = V128_OR(hash_tmp[6], V128_OR(V128_SR(V128_MASK_7(c[3*MAX_REPEAT]), 3),  V128_SR(V128_MASK_7(c[4*MAX_REPEAT]), 2)));
	hash_tmp[7] = V128_OR(hash_tmp[7], V128_OR(V128_SR(V128_MASK_8(c[3*MAX_REPEAT]), 4),  V128_SR(V128_MASK_8(c[4*MAX_REPEAT]), 3)));
	//5,6,7
	hash_tmp[0] = V128_OR(hash_tmp[0], V128_OR(V128_OR(V128_SL(V128_MASK_1(c[5*MAX_REPEAT]), 5),  V128_SL(V128_MASK_1(c[6*MAX_REPEAT]), 6)), V128_SL(V128_MASK_1(c[7*MAX_REPEAT]), 7)));
	hash_tmp[1] = V128_OR(hash_tmp[1], V128_OR(V128_OR(V128_SL(V128_MASK_2(c[5*MAX_REPEAT]), 4),  V128_SL(V128_MASK_2(c[6*MAX_REPEAT]), 5)), V128_SL(V128_MASK_2(c[7*MAX_REPEAT]), 6)));
	hash_tmp[2] = V128_OR(hash_tmp[2], V128_OR(V128_OR(V128_SL(V128_MASK_3(c[5*MAX_REPEAT]), 3),  V128_SL(V128_MASK_3(c[6*MAX_REPEAT]), 4)), V128_SL(V128_MASK_3(c[7*MAX_REPEAT]), 5)));
	hash_tmp[3] = V128_OR(hash_tmp[3], V128_OR(V128_OR(V128_SL(V128_MASK_4(c[5*MAX_REPEAT]), 2),  V128_SL(V128_MASK_4(c[6*MAX_REPEAT]), 3)), V128_SL(V128_MASK_4(c[7*MAX_REPEAT]), 4)));
	hash_tmp[4] = V128_OR(hash_tmp[4], V128_OR(V128_OR(V128_SL(V128_MASK_5(c[5*MAX_REPEAT]), 1),  V128_SL(V128_MASK_5(c[6*MAX_REPEAT]), 2)), V128_SL(V128_MASK_5(c[7*MAX_REPEAT]), 3)));
	hash_tmp[5] = V128_OR(hash_tmp[5], V128_OR(V128_OR(		   V128_MASK_6(c[5*MAX_REPEAT]),	  V128_SL(V128_MASK_6(c[6*MAX_REPEAT]), 1)), V128_SL(V128_MASK_6(c[7*MAX_REPEAT]), 2)));
	hash_tmp[6] = V128_OR(hash_tmp[6], V128_OR(V128_OR(V128_SR(V128_MASK_7(c[5*MAX_REPEAT]), 1),		  V128_MASK_7(c[6*MAX_REPEAT])),	 V128_SL(V128_MASK_7(c[7*MAX_REPEAT]), 1)));
	hash_tmp[7] = V128_OR(hash_tmp[7], V128_OR(V128_OR(V128_SR(V128_MASK_8(c[5*MAX_REPEAT]), 2),  V128_SR(V128_MASK_8(c[6*MAX_REPEAT]), 1)),		 V128_MASK_8(c[7*MAX_REPEAT])));

	i_shift *= 8;
	if(i_shift)
		for(i = 0; i < V128_BIT_LENGHT/8; i++)
		{
			hash_values[i*8+0] |= ((unsigned int)((unsigned char*)(&hash_tmp[0]))[i]) << i_shift;
			hash_values[i*8+1] |= ((unsigned int)((unsigned char*)(&hash_tmp[1]))[i]) << i_shift;
			hash_values[i*8+2] |= ((unsigned int)((unsigned char*)(&hash_tmp[2]))[i]) << i_shift;
			hash_values[i*8+3] |= ((unsigned int)((unsigned char*)(&hash_tmp[3]))[i]) << i_shift;
			hash_values[i*8+4] |= ((unsigned int)((unsigned char*)(&hash_tmp[4]))[i]) << i_shift;
			hash_values[i*8+5] |= ((unsigned int)((unsigned char*)(&hash_tmp[5]))[i]) << i_shift;
			hash_values[i*8+6] |= ((unsigned int)((unsigned char*)(&hash_tmp[6]))[i]) << i_shift;
			hash_values[i*8+7] |= ((unsigned int)((unsigned char*)(&hash_tmp[7]))[i]) << i_shift;
		}
	else
		for(i = 0; i < V128_BIT_LENGHT/8; i++)
		{
			hash_values[i*8+0] = ((unsigned char*)(&hash_tmp[0]))[i];
			hash_values[i*8+1] = ((unsigned char*)(&hash_tmp[1]))[i];
			hash_values[i*8+2] = ((unsigned char*)(&hash_tmp[2]))[i];
			hash_values[i*8+3] = ((unsigned char*)(&hash_tmp[3]))[i];
			hash_values[i*8+4] = ((unsigned char*)(&hash_tmp[4]))[i];
			hash_values[i*8+5] = ((unsigned char*)(&hash_tmp[5]))[i];
			hash_values[i*8+6] = ((unsigned char*)(&hash_tmp[6]))[i];
			hash_values[i*8+7] = ((unsigned char*)(&hash_tmp[7]))[i];
		}
}
//PRIVATE void convert_key_to_input_v128(unsigned char* key_iter, unsigned char* old_key_iter, V128_WORD lm_buffer_key1[56])
//{
//	V128_INIT_MASK(_mask);
//	unsigned int diff;
//
//	for(unsigned int i = 0; i < V128_BIT_LENGHT; i++)
//	{
//		//0
//		V128_WORD* _buffer_key_tmp1 = lm_buffer_key1 + 48 * MAX_REPEAT;
//		diff = *key_iter ^ *old_key_iter;
//		*old_key_iter = *key_iter;
//		while(diff)
//		{
//			uint32_t _first_bit_index = first_bit[diff];
//			_buffer_key_tmp1[_first_bit_index*MAX_REPEAT] = V128_XOR(_buffer_key_tmp1[_first_bit_index*MAX_REPEAT], _mask);
//
//			diff >>= _first_bit_index + 1;
//			_buffer_key_tmp1 += (_first_bit_index + 1)*MAX_REPEAT;
//		}
//
//		key_iter++;
//		old_key_iter++;
//		//1
//		diff = *key_iter ^ *old_key_iter;
//		*old_key_iter = *key_iter;
//		_buffer_key_tmp1 = lm_buffer_key1 + 40*MAX_REPEAT;
//		while(diff)
//		{
//			uint32_t _first_bit_index = first_bit[diff];
//			_buffer_key_tmp1[_first_bit_index*MAX_REPEAT] = V128_XOR(_buffer_key_tmp1[_first_bit_index*MAX_REPEAT], _mask);
//
//			diff >>= _first_bit_index + 1;
//			_buffer_key_tmp1 += (_first_bit_index + 1)*MAX_REPEAT;
//		}
//
//		key_iter++;
//		old_key_iter++;
//		//2
//		if(key_iter != old_key_iter)
//		{
//			diff = *key_iter ^ *old_key_iter;
//			*old_key_iter = *key_iter;
//			_buffer_key_tmp1 = lm_buffer_key1 + 32*MAX_REPEAT;
//			while(diff)
//			{
//				uint32_t _first_bit_index = first_bit[diff];
//				_buffer_key_tmp1[_first_bit_index*MAX_REPEAT] = V128_XOR(_buffer_key_tmp1[_first_bit_index*MAX_REPEAT], _mask);
//
//				diff >>= _first_bit_index + 1;
//				_buffer_key_tmp1 += (_first_bit_index + 1)*MAX_REPEAT;
//			}
//		}
//
//		key_iter++;
//		old_key_iter++;
//		//3
//		if(key_iter != old_key_iter)
//		{
//			diff = *key_iter ^ *old_key_iter;
//			*old_key_iter = *key_iter;
//			_buffer_key_tmp1 = lm_buffer_key1 + 24*MAX_REPEAT;
//			while(diff)
//			{
//				uint32_t _first_bit_index = first_bit[diff];
//				_buffer_key_tmp1[_first_bit_index*MAX_REPEAT] = V128_XOR(_buffer_key_tmp1[_first_bit_index*MAX_REPEAT], _mask);
//
//				diff >>= _first_bit_index + 1;
//				_buffer_key_tmp1 += (_first_bit_index + 1)*MAX_REPEAT;
//			}
//		}
//
//		key_iter++;
//		old_key_iter++;
//		//4
//		if(key_iter != old_key_iter)
//		{
//			diff = *key_iter ^ *old_key_iter;
//			*old_key_iter = *key_iter;
//			_buffer_key_tmp1 = lm_buffer_key1 + 16*MAX_REPEAT;
//			while(diff)
//			{
//				uint32_t _first_bit_index = first_bit[diff];
//				_buffer_key_tmp1[_first_bit_index*MAX_REPEAT] = V128_XOR(_buffer_key_tmp1[_first_bit_index*MAX_REPEAT], _mask);
//
//				diff >>= _first_bit_index + 1;
//				_buffer_key_tmp1 += (_first_bit_index + 1)*MAX_REPEAT;
//			}
//		}
//
//		key_iter++;
//		old_key_iter++;
//		//5
//		if(key_iter != old_key_iter)
//		{
//			diff = *key_iter ^ *old_key_iter;
//			*old_key_iter = *key_iter;
//			_buffer_key_tmp1 = lm_buffer_key1 + 8*MAX_REPEAT;
//			while(diff)
//			{
//				uint32_t _first_bit_index = first_bit[diff];
//				_buffer_key_tmp1[_first_bit_index*MAX_REPEAT] = V128_XOR(_buffer_key_tmp1[_first_bit_index*MAX_REPEAT], _mask);
//
//				diff >>= _first_bit_index + 1;
//				_buffer_key_tmp1 += (_first_bit_index + 1)*MAX_REPEAT;
//			}
//		}
//
//		key_iter++;
//		old_key_iter++;
//		//6
//		if(key_iter != old_key_iter)
//		{
//			diff = *key_iter ^ *old_key_iter;
//			*old_key_iter = *key_iter;
//			_buffer_key_tmp1 = lm_buffer_key1 + 0*MAX_REPEAT;
//			while(diff)
//			{
//				uint32_t _first_bit_index = first_bit[diff];
//				_buffer_key_tmp1[_first_bit_index*MAX_REPEAT] = V128_XOR(_buffer_key_tmp1[_first_bit_index*MAX_REPEAT], _mask);
//
//				diff >>= _first_bit_index + 1;
//				_buffer_key_tmp1 += (_first_bit_index + 1)*MAX_REPEAT;
//			}
//		}
//
//		key_iter+=2;
//		old_key_iter+=2;
//
//		V128_NEXT_MASK(_mask);
//	}
//}
PRIVATE void convert_key_to_input_v128(uint32_t* keys_ptr, V128_WORD* transpose_buffer, V128_WORD* lm_buffer_key)
{
	// Copy keys to buffer
	for (uint32_t i = 0; i < V128_BIT_LENGHT / 4; i++)
		for (uint32_t v_index = 0; v_index < 4; v_index++)
		{
			uint32_t idx = (v_index * 32 + i) * 2;
			((uint32_t*)(transpose_buffer     ))[i*(sizeof(V128_WORD) / 4) + v_index] = keys_ptr[idx + 0];
			((uint32_t*)(transpose_buffer + 32))[i*(sizeof(V128_WORD) / 4) + v_index] = keys_ptr[idx + 1];
		}

	// Transpose
	for (uint32_t j = 0; j < 2; j++)
	{
		V128_WORD* transpose_buffer_key_ptr = transpose_buffer + j * 32;
		// Transpose 32x32 bit matrix
#ifndef ANDROID
		V128_WORD m = V128_CONST(0x0000ffff);
		for (uint32_t i = 16; i != 0; i >>= 1, m = V128_XOR(m, V128_SL(m, i)))
			for (uint32_t k = 0; k < 32; k = (k + i + 1) & ~i)
			{
				V128_WORD tmp = V128_AND(V128_XOR(transpose_buffer_key_ptr[k + i], V128_SR(transpose_buffer_key_ptr[k], i)), m);
				transpose_buffer_key_ptr[k + i] = V128_XOR(transpose_buffer_key_ptr[k + i], tmp);
				transpose_buffer_key_ptr[k] = V128_XOR(transpose_buffer_key_ptr[k], V128_SL(tmp, i));
			}
#else// Unroll the outer cycle because Neon don't permit variable shifts
		for (uint32_t k = 0; k < 32; k = (k + 17) & 0xffffffef)
		{
			V128_WORD tmp = V128_AND(V128_XOR(transpose_buffer_key_ptr[k + 16], V128_SR(transpose_buffer_key_ptr[k], 16)), V128_CONST(0xffff));
			transpose_buffer_key_ptr[k + 16] = V128_XOR(transpose_buffer_key_ptr[k + 16], tmp);
			transpose_buffer_key_ptr[k] = V128_XOR(transpose_buffer_key_ptr[k], V128_SL(tmp, 16));
		}
		for (uint32_t k = 0; k < 32; k = (k + 9) & 0xfffffff7)
		{
			V128_WORD tmp = V128_AND(V128_XOR(transpose_buffer_key_ptr[k + 8], V128_SR(transpose_buffer_key_ptr[k], 8)), V128_CONST(0xff00ff));
			transpose_buffer_key_ptr[k + 8] = V128_XOR(transpose_buffer_key_ptr[k + 8], tmp);
			transpose_buffer_key_ptr[k] = V128_XOR(transpose_buffer_key_ptr[k], V128_SL(tmp, 8));
		}
		for (uint32_t k = 0; k < 32; k = (k + 5) & 0xfffffffb)
		{
			V128_WORD tmp = V128_AND(V128_XOR(transpose_buffer_key_ptr[k + 4], V128_SR(transpose_buffer_key_ptr[k], 4)), V128_CONST(0xf0f0f0f));
			transpose_buffer_key_ptr[k + 4] = V128_XOR(transpose_buffer_key_ptr[k + 4], tmp);
			transpose_buffer_key_ptr[k] = V128_XOR(transpose_buffer_key_ptr[k], V128_SL(tmp, 4));
		}
		for (uint32_t k = 0; k < 32; k = (k + 3) & 0xfffffffd)
		{
			V128_WORD tmp = V128_AND(V128_XOR(transpose_buffer_key_ptr[k + 2], V128_SR(transpose_buffer_key_ptr[k], 2)), V128_CONST(0x33333333));
			transpose_buffer_key_ptr[k + 2] = V128_XOR(transpose_buffer_key_ptr[k + 2], tmp);
			transpose_buffer_key_ptr[k] = V128_XOR(transpose_buffer_key_ptr[k], V128_SL(tmp, 2));
		}
		for (uint32_t k = 0; k < 32; k = (k + 2) & 0xfffffffe)
		{
			V128_WORD tmp = V128_AND(V128_XOR(transpose_buffer_key_ptr[k + 1], V128_SR(transpose_buffer_key_ptr[k], 1)), V128_CONST(0x55555555));
			transpose_buffer_key_ptr[k + 1] = V128_XOR(transpose_buffer_key_ptr[k + 1], tmp);
			transpose_buffer_key_ptr[k] = V128_XOR(transpose_buffer_key_ptr[k], V128_SL(tmp, 1));
		}
#endif
	}
	// Copy again
	for (uint32_t i = 0; i < 56; i++)
		lm_buffer_key[i*MAX_REPEAT] = transpose_buffer[55 - (i / 8 * 8) - (7 - (i & 7))];
}

PRIVATE void crypt_lm_body(CryptParam* param, lm_eval_kernel_func* lm_eval_kernel, calculate_hash_func* calculate_hash, calculate_lm_indexs_func* calculate_lm_indexs, int is_utf8)
{
	V128_WORD* lm_buffer_key	= (V128_WORD*)_aligned_malloc(56 * sizeof(V128_WORD)*MAX_REPEAT, 32);
	V128_WORD* lm_buffer_crypt	= (V128_WORD*)_aligned_malloc(64 * sizeof(V128_WORD)*MAX_REPEAT, 32);
	V128_WORD* tmp_stor			= (V128_WORD*)_aligned_malloc(8 * sizeof(V128_WORD), 32);

	unsigned char* keys = (unsigned char*)lm_buffer_key;
	if (is_utf8)
		keys = (unsigned char*)calloc(8 * V128_BIT_LENGHT*MAX_REPEAT, sizeof(unsigned char));

	memset(lm_buffer_key, 0, 56 * sizeof(V128_WORD)*MAX_REPEAT);

	while (continue_attack && param->gen(keys, V128_BIT_LENGHT*MAX_REPEAT, param->thread_id))
	{
		if (is_utf8)
			for (unsigned int i = 0; i < MAX_REPEAT; i++)
				convert_key_to_input_v128((uint32_t*)(keys + V128_BIT_LENGHT * 8 * i), lm_buffer_crypt, lm_buffer_key + i);

		// Encrypt
		lm_eval_kernel(lm_buffer_key, lm_buffer_crypt, tmp_stor);
		lm_eval_final(lm_buffer_key, lm_buffer_crypt, tmp_stor, calculate_hash, calculate_lm_indexs);

		report_keys_processed(V128_BIT_LENGHT*MAX_REPEAT);
	}

	if (is_utf8)
		free(keys);

	_aligned_free(lm_buffer_key);
	_aligned_free(lm_buffer_crypt);
	_aligned_free(tmp_stor);

	finish_thread();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Neon Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM
void s1_sse2(V128_WORD a0, V128_WORD a1, V128_WORD a2, V128_WORD a3, V128_WORD a4, V128_WORD a5, V128_WORD* out)
{
	V128_WORD q9 = vdupq_n_u32(0xffffffff);
	V128_WORD q0, q1, q2, q3, q4, q5, q6, q7, q8;

	q0 = veorq_u32(a4, q9);
	q2 = vorrq_u32(a2, a5);
	q0 = vandq_u32(a0, q0);
	q3 = veorq_u32(a0, a2);
	q1 = veorq_u32(a3, q0);
	q4 = vandq_u32(q2, q3);
	q6 = veorq_u32(q1, q9);
	q8 = veorq_u32(a3, q4);
	q7 = veorq_u32(a4, a5);
	q6 = vandq_u32(q8, q6);
	a2 = veorq_u32(a2, q9);
	q5 = veorq_u32(a2, q7);
	q4 = vorrq_u32(a5, q4);
	q5 = vandq_u32(q1, q5);
	q0 = vorrq_u32(a2, q0);
	q4 = veorq_u32(q5, q4);
	a5 = vorrq_u32(a0, a5);
	q5 = veorq_u32(q6, q9);
	a2 = vorrq_u32(q4, a5);
	q5 = vandq_u32(q4, q5);
	q8 = veorq_u32(q8, q9);
	a5 = veorq_u32(a5, q9);
	q8 = vandq_u32(a4, q8);
	a5 = vandq_u32(a3, a5);
	q3 = veorq_u32(q3, q9);
	a3 = veorq_u32(a2, q8);
	a5 = veorq_u32(q8, a5);
	q3 = vandq_u32(q7, q3);
	q4 = vandq_u32(q2, q4);
	a5 = vorrq_u32(a5, q3);
	q3 = veorq_u32(q1, a2);
	a2 = veorq_u32(q2, a2);
	q0 = vandq_u32(q3, q0);
	a2 = vorrq_u32(a5, a2);
	q3 = veorq_u32(q0, q9);
	q0 = veorq_u32(q7, q0);
	q4 = veorq_u32(q3, q4);
	q0 = vorrq_u32(q8, q0);
	a4 = vorrq_u32(a4, q1);
	q3 = veorq_u32(a1, q9);
	q0 = veorq_u32(q2, q0);
	q3 = vandq_u32(a3, q3);
	a0 = veorq_u32(a0, q0);
	q3 = veorq_u32(q3, q4);
	q6 = vorrq_u32(q6, a1);
	q4 = veorq_u32(q4, a0);

	out[2*MAX_REPEAT] = veorq_u32(out[2*MAX_REPEAT], q3);
	//{reg_out2, op_xor, reg_x3, reg_out2, reg_x0},//x3
	q6 = veorq_u32(q6, q4);
	q2 = veorq_u32(a0, a2);
	q4 = vorrq_u32(q7, q4);
	a0 = vandq_u32(q5, a0);
	q4 = veorq_u32(q2, q4);

	out[0*MAX_REPEAT] = veorq_u32(out[0*MAX_REPEAT], q6);
	//{reg_out0, op_xor, reg_x6, reg_out0, reg_x0},
	q2 = veorq_u32(q2, q9);
	q6 = vorrq_u32(q5, a1);
	q2 = vandq_u32(a4, q2);
	q4 = veorq_u32(q6, q4);
	a0 = veorq_u32(q2, a0);

	out[1*MAX_REPEAT] = veorq_u32(out[1*MAX_REPEAT], q4);
	//{reg_out1, op_xor, reg_x4, reg_out1, reg_x0},//x4
	a1 = vorrq_u32(a0, a1);
	a1 = veorq_u32(a1, a5);

	out[3*MAX_REPEAT] = veorq_u32(out[3*MAX_REPEAT], a1);
	//{reg_out3, op_xor, reg_a1, reg_out3, reg_x0}//a1
}
void s2_sse2(V128_WORD a0, V128_WORD a1, V128_WORD a2, V128_WORD a3, V128_WORD a4, V128_WORD a5, V128_WORD* out)
{
	V128_WORD q9 = vdupq_n_u32(0xffffffff);
	V128_WORD q0, q1, q2, q3, q4, q5, q6, q7, q8;

	q0 = veorq_u32(a1, a4);
	q7 = veorq_u32(a0, q9);
	q1 = vorrq_u32(q7, a5);
	q1 = vandq_u32(a4, q1);
	q2 = vorrq_u32(a1, q1);
	q3 = veorq_u32(a5, q9);
	q3 = vandq_u32(q0, q3);
	q4 = vandq_u32(a0, q0);
	a4 = veorq_u32(a4, q4);
	q5 = veorq_u32(q3, q9);
	q5 = vandq_u32(a4, q5);
	q5 = vorrq_u32(q5, a3);
	q4 = vandq_u32(a2, a5);
	q1 = veorq_u32(q1, q3);
	q1 = vandq_u32(q2, q1);
	q3 = veorq_u32(q1, q9);
	q3 = vorrq_u32(q3, q4);
	q6 = vandq_u32(a2, q1);
	a0 = veorq_u32(q6, q7);
	a5 = veorq_u32(a5, q0);
	q7 = veorq_u32(a5, q9);
	q7 = vorrq_u32(q7, q4);
	a1 = vandq_u32(a1, q7);//q7
	q7 = veorq_u32(q7, q9);
	q7 = veorq_u32(a0, q7);
	q3 = vandq_u32(a3, q3);
	q3 = veorq_u32(q3, q7);
	a4 = veorq_u32(a4, a1);
	q6 = veorq_u32(q6, a1);//a1

	out[1*MAX_REPEAT] = veorq_u32(out[1*MAX_REPEAT], q3);
	//{out1, op_xor, q3, out1, a1
	a4 = veorq_u32(a4, q9);
	q3 = vandq_u32(a0, a4);
	a2 = veorq_u32(a2, a5);
	q3 = veorq_u32(q3, a2);
	a0 = veorq_u32(a3, q9);
	a0 = vandq_u32(q2, a0);
	a0 = veorq_u32(a0, q3);

	out[0*MAX_REPEAT] = veorq_u32(out[0*MAX_REPEAT], a0);
	//{out0, op_xor, a0, out0, a1//a0
	a2 = vorrq_u32(a2, q6);
	q2 = veorq_u32(q2, q7);
	q4 = vorrq_u32(q4, q2);
	q6 = veorq_u32(a2, q4);
	q1 = veorq_u32(q1, q7);//q8
	q1 = veorq_u32(q3, q1);
	q1 = vandq_u32(q4, q1);//q4
	a2 = vandq_u32(q0, a2);//q0
	a2 = veorq_u32(q1, a2);//q1
	q3 = vorrq_u32(a2, a3);
	q6 = veorq_u32(q3, q6);

	out[2*MAX_REPEAT] = veorq_u32(out[2*MAX_REPEAT], q6);
	//{out2, op_xor, q6, out2, a1
	a4 = vandq_u32(a2, a4);//a2
	a5 = vorrq_u32(a5, q2);//q2
	a4 = veorq_u32(a4, a5);//a5
	q5 = veorq_u32(q5, a4);//a4

	out[3*MAX_REPEAT] = veorq_u32(out[3*MAX_REPEAT], q5);
	//{out3, op_xor, q5, out3, a1}//a3
}
void s3_sse2(V128_WORD a0, V128_WORD a1, V128_WORD a2, V128_WORD a3, V128_WORD a4, V128_WORD a5, V128_WORD* out)
{
	V128_WORD q9 = vdupq_n_u32(0xffffffff);
	V128_WORD q0, q1, q2, q3, q4, q5, q6, q7, q8;

	q0 = veorq_u32(a1, q9);// repeted below
		q0 = vandq_u32(a0, q0);
		q1 = veorq_u32(a2, a5);
		q2 = vorrq_u32(q0, q1);
		q3 = veorq_u32(a3, a5);
		q4 = veorq_u32(a0, q9);
		q4 = vandq_u32(q3, q4);
		q5 = veorq_u32(q2, q4);
		q6 = veorq_u32(a1, q1);
		q7 = veorq_u32(a5, q9);
		q7 = vandq_u32(q6, q7);
		q2 = veorq_u32(q2, q7);
		q7 = veorq_u32(q5, q9);
		q7 = vorrq_u32(q7, q2);
		q1 = vandq_u32(q1, q3);
		q3 = vandq_u32(a5, q5);
		q3 = vorrq_u32(a3, q3);
		q3 = vandq_u32(a0, q3);
		q3 = veorq_u32(q6, q3);
		q8 = veorq_u32(a0, a3);
		q4 = vorrq_u32(q4, q8);
		q8 = veorq_u32(q2, q8);
		q8 = vorrq_u32(a2, q8);
		q1 = veorq_u32(q1, q9);
		q1 = vandq_u32(q8, q1);
		q8 = veorq_u32(q4, q9);
		q8 = vandq_u32(q3, q8);
		a5 = vandq_u32(a3, a5);
		a2 = vorrq_u32(a1, a2);
		a1 = veorq_u32(a1, q9);
		a1 = vandq_u32(a5, a1);
		a1 = veorq_u32(q8, a1);//q8
		q2 = vandq_u32(q2, a1);
		a5 = vorrq_u32(q6, a5);
		q2 = veorq_u32(q2, q9);
		a5 = vandq_u32(a5, q2);//q2
		q7 = vandq_u32(a4, q7);
		q2 = veorq_u32(a4, q9);
		q2 = vandq_u32(q5, q2);
		q2 = veorq_u32(q2, q3);
		a0 = veorq_u32(a0, a5);

		out[3*MAX_REPEAT] = veorq_u32(out[3*MAX_REPEAT], q2);
		//{out3, op_xor, q2, out3, a5
		q1 = vandq_u32(q1, a4);
		q1 = veorq_u32(q1, a0);

		out[1*MAX_REPEAT] = veorq_u32(out[1*MAX_REPEAT], q1);
		//{out1, op_xor, q1, out1, a5//q1
		q5 = veorq_u32(q5, q9);
		a2 = vorrq_u32(a2, q5);
		a2 = veorq_u32(q6, a2);//q6
		q4 = veorq_u32(q4, a2);
		q4 = veorq_u32(q7, q4);//q7---------

		out[0*MAX_REPEAT] = veorq_u32(out[0*MAX_REPEAT], q4);
		//{out0, op_xor, q4, out0, a5//q4
		a3 = vandq_u32(a3, q5);//q5
		a3 = veorq_u32(q3, a3);//q3
		a3 = vorrq_u32(a2, a3);//a2
		a0 = veorq_u32(q0, a0);//q0
		a3 = veorq_u32(a3, a0);//a0
		a4 = vorrq_u32(a1, a4);//q3
		a4 = veorq_u32(a4, a3);//a3

		out[2*MAX_REPEAT] = veorq_u32(out[2*MAX_REPEAT], a4);
		//{out2, op_xor, a4, out2, a5}//a4
}
void s4_sse2(V128_WORD a0, V128_WORD a1, V128_WORD a2, V128_WORD a3, V128_WORD a4, V128_WORD a5, V128_WORD* out)
{
	V128_WORD q9 = vdupq_n_u32(0xffffffff);
	V128_WORD q0, q1, q2, q3, q4, q5, q6, q7, q8;

	a0 = veorq_u32(a0, a2);//a0
		a2 = veorq_u32(a2, a4);//a2
		q1 = veorq_u32(a1, q9);
		q0 = veorq_u32(q1, a3);
		q1 = vandq_u32(a2, q1);
		q2 = veorq_u32(a3, q1);
		a3 = vorrq_u32(a1, a3);//a3
		a3 = veorq_u32(a4, a3);
		q1 = vorrq_u32(a4, q1);//a4
		a3 = veorq_u32(a3, q9);
		a3 = vandq_u32(a2, a3);
		q3 = vorrq_u32(a0, q2);
		a4 = veorq_u32(a3, q9);
		a4 = vandq_u32(q3, a4);
		a1 = veorq_u32(a1, a4);//a1
		q2 = vandq_u32(q2, a1);
		q3 = veorq_u32(a2, q9);//a2
		q3 = vorrq_u32(q3, q2);
		a0 = veorq_u32(a0, a1);
		q3 = vandq_u32(a0, q3);
		q3 = veorq_u32(a3, q3);//a3
		q1 = veorq_u32(a0, q1);//a0
		a0 = vandq_u32(q1, q0);
		a0 = veorq_u32(a4, a0);
		a3 = veorq_u32(q3, q9);
		a3 = vandq_u32(a5, a3);
		a3 = veorq_u32(a3, a0);

		out[0*MAX_REPEAT] = veorq_u32(out[0*MAX_REPEAT], a3);
		//{out0, op_xor, a3, out0, a2
		a0 = veorq_u32(a0, q9);
		a4 = vorrq_u32(a1, a5);
		a1 = vandq_u32(a1, a5);
		a5 = veorq_u32(a5, q9);
		a5 = vandq_u32(q3, a5);//a5
		a5 = veorq_u32(a5, a0);

		out[1*MAX_REPEAT] = veorq_u32(out[1*MAX_REPEAT], a5);
		//{out1, op_xor, a5, out1, a2//a5
		a0 = veorq_u32(q3, a0);//q3
		q0 = vandq_u32(a0, q0);//q6
		q0 = vorrq_u32(q2, q0);//q2
		q0 = veorq_u32(q1, q0);//q1
		a4 = veorq_u32(a4, q0);

		out[2*MAX_REPEAT] = veorq_u32(out[2*MAX_REPEAT], a4);
		//{out2, op_xor, a4, out2, a2
		q0 = veorq_u32(a1, q0);

		out[3*MAX_REPEAT] = veorq_u32(out[3*MAX_REPEAT], q0);
		//{out3, op_xor, q0, out3, a2}
}
void s5_sse2(V128_WORD a0, V128_WORD a1, V128_WORD a2, V128_WORD a3, V128_WORD a4, V128_WORD a5, V128_WORD* out)
{
	V128_WORD q9 = vdupq_n_u32(0xffffffff);
	V128_WORD q0, q1, q2, q3, q4, q5, q6, q7, q8;

	q0 = vorrq_u32(a0, a2);
	q1 = veorq_u32(a5, q9);
	q1 = vandq_u32(q0, q1);
	q2 = veorq_u32(a3, q9);
	q2 = vandq_u32(q1, q2);
	q1 = veorq_u32(a0, q1);
	q2 = veorq_u32(a2, q2);
	a2 = veorq_u32(a2, q1);//a2
	q4 = vorrq_u32(a3, a2);
	q5 = vandq_u32(a4, q2);
	a2 = vorrq_u32(a0, a2);
	q5 = veorq_u32(q5, a2);
	q5 = veorq_u32(a3, q5);
	a5 = veorq_u32(a5, q5);//a5
	q8 = vorrq_u32(q1, a5);
	q0 = veorq_u32(a0, q0);
	a0 = veorq_u32(a0, q9);
	a0 = vandq_u32(q8, a0);
	q3 = vandq_u32(a3, a2);
	q3 = veorq_u32(q1, q3);
	q7 = veorq_u32(q2, a0);
	q8 = vandq_u32(a4, q8);
	a4 = veorq_u32(a4, q4);
	a0 = veorq_u32(a0, a4);
	q3 = veorq_u32(q3, q8);
	a0 = vorrq_u32(q3, a0);
	a2 = vandq_u32(q2, a2);
	q6 = veorq_u32(q2, q9);
	q6 = vorrq_u32(q6, q8);
	a0 = vandq_u32(a0, q6);
	a5 = vandq_u32(a5, a0);
	q0 = veorq_u32(a0, q0);
	a0 = veorq_u32(a0, q9);
	a0 = vandq_u32(q4, a0);
	a5 = veorq_u32(a4, a5);
	a2 = vorrq_u32(a5, a2);
	a2 = veorq_u32(q8, a2);//q8
	a2 = vandq_u32(a2, a1);
	a2 = veorq_u32(a2, q3);//q3

	out[3*MAX_REPEAT] = veorq_u32(out[3*MAX_REPEAT], a2);
	//{out3, op_xor, a2, out3, q6//q6
	a3 = vandq_u32(a3, a5);//a3
	q0 = veorq_u32(q0, a3);
	a0 = vorrq_u32(a0, a1);
	a0 = veorq_u32(a0, q0);

	out[0*MAX_REPEAT] = veorq_u32(out[0*MAX_REPEAT], a0);
	//{out0, op_xor, a0, out0, q6
	q2 = veorq_u32(q4, q2);
	q0 = veorq_u32(q0, q9);
	q0 = vandq_u32(q2, q0);
	q1 = veorq_u32(q1, a5);
	q0 = veorq_u32(q0, q1);
	q4 = vandq_u32(q4, a1);//a1
	a1 = veorq_u32(a1, q9);
	q1 = veorq_u32(a4, q9);
	q7 = vorrq_u32(q1, q7);
	q7 = vandq_u32(a1, q7);
	q5 = veorq_u32(q7, q5);//q7

	out[2*MAX_REPEAT] = veorq_u32(out[2*MAX_REPEAT], q5);
	//{out2, op_xor, q5, out2, q6//q5
	q0 = veorq_u32(q4, q0);

	out[1*MAX_REPEAT] = veorq_u32(out[1*MAX_REPEAT], q0);
	//{out1, op_xor, q0, out1, q6}
}
void s6_sse2(V128_WORD a0, V128_WORD a1, V128_WORD a2, V128_WORD a3, V128_WORD a4, V128_WORD a5, V128_WORD* out)
{
	V128_WORD q9 = vdupq_n_u32(0xffffffff);
	V128_WORD q0, q1, q2, q3, q4, q5, q6, q7, q8;

	q0 = veorq_u32(a1, a4);
	q1 = vorrq_u32(a1, a5);
	q1 = vandq_u32(a0, q1);
	q0 = veorq_u32(q0, q1);
	q2 = veorq_u32(a5, q0);
	q3 = vandq_u32(a0, q2);
	q2 = veorq_u32(q2, q9);
	q2 = vandq_u32(a4, q2);
	q4 = veorq_u32(a1, q3);
	q3 = veorq_u32(a5, q3);
	q5 = veorq_u32(a0, a2);
	q6 = vorrq_u32(q4, q5);
	q4 = vorrq_u32(q2, q4);
	q5 = vorrq_u32(a1, q5);
	a1 = veorq_u32(a1, q6);
	q6 = veorq_u32(q0, q6);
	a1 = veorq_u32(a1, q9);
	q8 = vandq_u32(a5, a1);
	q8 = veorq_u32(a2, q8);
	a2 = vandq_u32(a2, q6);
	a5 = veorq_u32(a5, q9);
	a5 = vandq_u32(a2, a5);
	q7 = veorq_u32(a0, q8);
	a0 = vorrq_u32(a0, q6);
	a0 = vandq_u32(q4, a0);
	q4 = veorq_u32(a5, q4);
	a1 = veorq_u32(q5, a1);
	q5 = veorq_u32(q4, q5);
	a0 = veorq_u32(q8, a0);
	a5 = veorq_u32(a5, q9);
	a5 = vandq_u32(a0, a5);
	q0 = veorq_u32(q0, a0);
	q0 = veorq_u32(q0, q9);
	q0 = vandq_u32(a4, q0);
	q0 = veorq_u32(q0, a1);
	a1 = veorq_u32(a2, a1);
	a2 = veorq_u32(a2, q9);
	a2 = vandq_u32(a4, a2);//a4
	a2 = vorrq_u32(q8, a2);//q8
	q4 = vandq_u32(q4, a3);
	q4 = veorq_u32(q4, q6);//q6

	out[3*MAX_REPEAT] = veorq_u32(out[3*MAX_REPEAT], q4);
	//{out3, op_xor, q4, out3, a4//q4
	q2 = vorrq_u32(q2, a3);
	q2 = veorq_u32(q2, a5);//a5

	out[2*MAX_REPEAT] = veorq_u32(out[2*MAX_REPEAT], q2);
	//{out2, op_xor, q2, out2, a4//q2
	q1 = vorrq_u32(q1, a2);
	q1 = veorq_u32(q5, q1);//q5
	a3 = veorq_u32(a3, q9);
	q0 = vandq_u32(q0, a3);//q0
	q1 = veorq_u32(q0, q1);

	out[1*MAX_REPEAT] = veorq_u32(out[1*MAX_REPEAT], q1);
	//{out1, op_xor, q1, out1, a4//q1
	q3 = vandq_u32(q3, q7);
	q3 = veorq_u32(q3, a1);//a1
	a3 = vandq_u32(a2, a3);//a3
	q3 = veorq_u32(a3, q3);

	out[0*MAX_REPEAT] = veorq_u32(out[0*MAX_REPEAT], q3);
	//{out0, op_xor, q3, out0, a4}//q3
}
void s7_sse2(V128_WORD a0, V128_WORD a1, V128_WORD a2, V128_WORD a3, V128_WORD a4, V128_WORD a5, V128_WORD* out)
{
	V128_WORD q9 = vdupq_n_u32(0xffffffff);
	V128_WORD q0, q1, q2, q3, q4, q5, q6, q7, q8;

	q0 = veorq_u32(a3, a4);
	q1 = veorq_u32(a2, q0);
	q2 = vandq_u32(a5, q1);
	q3 = vandq_u32(a3, q0);
	q4 = veorq_u32(a1, q3);
	q5 = vandq_u32(q2, q4);
	q6 = vandq_u32(a5, q3);
	q6 = veorq_u32(a2, q6);
	q7 = vorrq_u32(q4, q6);
	q0 = veorq_u32(a5, q0);
	q7 = veorq_u32(q7, q0);
	q5 = veorq_u32(q5, q9);
	q5 = vandq_u32(a0, q5);
	q5 = veorq_u32(q5, q7);
	q3 = vorrq_u32(q3, q7);

	out[3*MAX_REPEAT] = veorq_u32(out[3*MAX_REPEAT], q5);
	//{out3, op_xor, q5, out3, q7
	q7 = veorq_u32(q1, q9);
	q7 = vandq_u32(a4, q7);
	q5 = vorrq_u32(q4, q7);
	q6 = veorq_u32(q2, q6);
	q5 = veorq_u32(q5, q6);
	q2 = veorq_u32(q2, q0);
	a3 = veorq_u32(a3, q9);
	a3 = vorrq_u32(a3, q2);
	a3 = vandq_u32(q4, a3);
	q6 = veorq_u32(a4, q6);
	a3 = veorq_u32(a3, q6);
	a2 = vandq_u32(a2, a3);
	q3 = vorrq_u32(q3, a2);
	q0 = veorq_u32(q0, q9);
	q0 = vandq_u32(q1, q0);//q1
	q0 = veorq_u32(q3, q0);//q3
	q2 = veorq_u32(a0, q9);
	q2 = vandq_u32(q0, q2);
	q2 = veorq_u32(q2, q5);

	out[0*MAX_REPEAT] = veorq_u32(out[0*MAX_REPEAT], q2);
	//{out0, op_xor, q2, out0, q1
	q4 = vorrq_u32(a3, q0);
	a5 = vandq_u32(a5, q4);//q4
	a1 = vandq_u32(a1, a5);
	q5 = veorq_u32(q5, q0);
	a1 = veorq_u32(a1, q5);
	a2 = vorrq_u32(a2, a1);
	a2 = veorq_u32(a5, a2);
	a4 = veorq_u32(a4, q5);//q5
	a2 = vorrq_u32(a2, a4);//a4
	q6 = vandq_u32(a2, a0);
	a3 = veorq_u32(q6, a3);//q6

	out[2*MAX_REPEAT] = veorq_u32(out[2*MAX_REPEAT], a3);
	//{out2, op_xor, a3, out2, q1//a3
	a2 = veorq_u32(a5, a2);//a5
	a2 = vorrq_u32(q7, a2);//q7
	q0 = veorq_u32(q0, q9);
	a2 = veorq_u32(a2, q0);//q0
	a0 = veorq_u32(a0, q9);
	a0 = vandq_u32(a2, a0);//a2
	a0 = veorq_u32(a0, a1);//a1

	out[1*MAX_REPEAT] = veorq_u32(out[1*MAX_REPEAT], a0);
	//{out1, op_xor, a0, out1, q1}//a0
}
void s8_sse2(V128_WORD a0, V128_WORD a1, V128_WORD a2, V128_WORD a3, V128_WORD a4, V128_WORD a5, V128_WORD* out)
{
	V128_WORD q9 = vdupq_n_u32(0xffffffff);
	V128_WORD q0, q1, q2, q3, q4, q5, q6, q7, q8;

	q6 = veorq_u32(a2, q9);
	q0 = vorrq_u32(q6, a1);
	q1 = vandq_u32(a4, q6);
	q1 = veorq_u32(a3, q1);
	q2 = vandq_u32(a0, q1);
	q1 = veorq_u32(q1, q9);
	q3 = vandq_u32(a1, q1);
	q4 = vorrq_u32(a0, q3);
	q5 = veorq_u32(q4, q9);
	q5 = vandq_u32(a2, q5);
	a2 = vandq_u32(a1, q6);//a2
	a2 = veorq_u32(a4, a2);
	q4 = vandq_u32(q4, a2);
	q1 = veorq_u32(q4, q1);
	q1 = veorq_u32(q1, q5);
	q6 = veorq_u32(q0, q9);
	q6 = veorq_u32(q6, q1);
	q0 = vandq_u32(q2, q0);
	q2 = vorrq_u32(q2, q4);
	q5 = vorrq_u32(q0, a5);
	q5 = veorq_u32(q5, q6);
	q6 = veorq_u32(a0, q6);
	q4 = vandq_u32(a4, q6);
	q6 = veorq_u32(a4, q6);//a4

	out[1*MAX_REPEAT] = veorq_u32(out[1*MAX_REPEAT], q5);
	//{out1, op_xor, q5, out1, a4//q5----------
	q1 = veorq_u32(a1, q1);
	q4 = veorq_u32(q4, q1);
	q3 = veorq_u32(q3, q4);
	q4 = veorq_u32(q2, q4);
	q4 = vorrq_u32(a1, q4);//a1
	q4 = veorq_u32(q4, q6);//q6
	q2 = vandq_u32(q2, a5);
	q2 = veorq_u32(q2, q4);

	out[2*MAX_REPEAT] = veorq_u32(out[2*MAX_REPEAT], q2);
	//{out2, op_xor, q2, out2, a4
	a2 = veorq_u32(a2, q3);//a2
	q1 = vorrq_u32(a3, q1);
	q1 = veorq_u32(a2, q1);
	a0 = veorq_u32(a0, q1);//a0
	q1 = veorq_u32(q0, q1);
	a0 = vandq_u32(a0, a5);
	a0 = veorq_u32(a0, q3);

	out[3*MAX_REPEAT] = veorq_u32(out[3*MAX_REPEAT], a0);
	//{out3, op_xor, a0, out3, a4
	a3 = veorq_u32(a3, q9);
	a3 = vandq_u32(a2, a3);//a3
	q4 = vandq_u32(q4, a3);//a3
	q4 = veorq_u32(q4, q1);
	q4 = vorrq_u32(q4, a5);//a5
	q4 = veorq_u32(q4, q3);

	out[0*MAX_REPEAT] = veorq_u32(out[0*MAX_REPEAT], q4);
	//{out0, op_xor, q4, out0, a4}
}

PRIVATE void calculate_lm_indexs_neon(unsigned int* hash_values, unsigned int* indexs)
{
	for(unsigned int j4 = 0; j4 < V128_BIT_LENGHT*MAX_REPEAT/4; j4++)
	{
		unsigned int val4 = 0;

		for (int i = 0; i < 4; i++)
		{
			unsigned int val = hash_values[j4*4+i] & size_bit_table;
			val4 += ((bit_table[val >> 5] >> (val & 31)) & 1) << (8*i);
		}

		indexs[j4] = val4;
	}
}

void lm_eval_neon_kernel(void* lm_buffer_key, void* lm_buffer_crypt, void* tmp_stor);
PRIVATE void crypt_utf8_lm_protocol_neon(CryptParam* param)
{
	crypt_lm_body(param, lm_eval_neon_kernel, calculate_hash_v128, calculate_lm_indexs_neon, TRUE);
}
PRIVATE void crypt_fast_lm_protocol_neon(CryptParam* param)
{
	crypt_lm_body(param, lm_eval_neon_kernel, calculate_hash_v128, calculate_lm_indexs_neon, FALSE);
}
#endif

#ifdef HS_X86
/*
 * Bitslice DES S-boxes for x86 with MMX/SSE2/AVX and for typical RISC
 * architectures.  These use AND, OR, XOR, NOT, and AND-NOT gates.
 *
 * Gate counts: 49 44 46 33 48 46 46 41
 * Average: 44.125
 *
 * These Boolean expressions corresponding to DES S-boxes have been generated
 * by Roman Rusakov <roman_rus at openwall.com> for use in Openwall's
 * John the Ripper password cracker: http://www.openwall.com/john/
 * Being mathematical formulas, they are not copyrighted and are free for reuse
 * by anyone.
 *
 * This file (a specific representation of the S-box expressions, surrounding
 * logic) is Copyright (c) 2011 by Solar Designer <solar at openwall.com>.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.  (This is a heavily cut-down "BSD license".)
 *
 * The effort has been sponsored by Rapid7: http://www.rapid7.com
 *
 * Optimized by Alain Espinosa - March 2012
 */
#define vand(res, a, b)  res=SSE2_AND(a,b)
#define vor(res, a, b)   res=SSE2_OR(a,b)
#define vxor(res, a, b)  res=SSE2_XOR(a,b)
#define vnot(res, a)     res=SSE2_NOT(a)
#define vandn(res, a, b) res=SSE2_ANDN(a,b)

/* s1-00484, 49 gates, 17 regs, 11 andn, 4/9/39/79/120 stalls, 74 biop */
/* Currently used for MMX/SSE2 and x86-64 SSE2 */
PRIVATE void s1_sse2f(SSE2_WORD* a, SSE2_WORD* out)
{
	SSE2_WORD x0, x1, x2, x3, x4, x5, x6, x7, x8, xa2, xa4, xa5;

	//mov
	vandn(x0, a[0], a[4]);
	//mov
	vor(x2, a[2], a[5]);
	//mov
	vxor(x3, a[0], a[2]);
	//mov
	vand(x4, x2, x3);
	//mov
	vxor(x7, a[4], a[5]);
	//mov
	vxor(x1, a[3], x0);
	//mov
	vxor(x5, a[3], x4);
	vor(x4, a[5], x4);
	vor(xa5, a[0], a[5]);//a[5]
	vandn(x0, a[2], x0);
	vxor(xa2, a[2], x7);//a[2]
	vandn(xa2, x1, xa2);
	vxor(x4, xa2, x4);//xa2
	//mov
	vor(x8, x4, xa5);
	vandn(xa5, a[3], xa5);//a[3]
	//mov
	vandn(x6, x5, x1);
	vandn(x5, a[4], x5);
	vor(xa4, a[4], x1);//a[4]
	vxor(xa5, x5, xa5);
	vandn(x3, x7, x3);
	vor(x3, xa5, x3);//xa5
	vxor(x1, x1, x8);
	vandn(x0, x1, x0);
	//mov
	vnot(x1, x0);
	vxor(x0, x7, x0);
	vor(x0, x5, x0);
	vxor(x5, x8, x5);
	vxor(x0, x2, x0);
	vxor(x8, x2, x8);
	vand(x2, x2, x4);
	vxor(x2, x1, x2);
	//mov
	vandn(x1, x5, a[1]);
	vxor(x1, x1, x2);
	vxor(out[2*MAX_REPEAT], out[2*MAX_REPEAT], x1);//x1
	vxor(x0, a[0], x0);//a[0]
	vxor(x2, x2, x0);
	vor(x8, x3, x8);
	vxor(x8, x0, x8);
	vor(x7, x7, x2);
	vxor(x7, x8, x7);
	vandn(x8, xa4, x8);
	//mov
	vandn(x5, x4, x6);//x4
	vand(x0, x5, x0);
	vxor(x0, x8, x0);//x8
	vor(x0, x0, a[1]);
	vor(x5, x5, a[1]);
	vor(x6, x6, a[1]);//a[1]
	vxor(x6, x6, x2);//x2
	vxor(out[0*MAX_REPEAT], out[0*MAX_REPEAT], x6);//x6
	vxor(x7, x5, x7);//x5
	vxor(out[1*MAX_REPEAT], out[1*MAX_REPEAT], x7);//x7
	vxor(x0, x0, x3);//x3
	vxor(out[3*MAX_REPEAT], out[3*MAX_REPEAT], x0);
}
/* s2-016277, 44 gates, 15 regs, 12 andn, 4/15/35/74/121 stalls, 65 biop */
/* Currently used for x86-64 SSE2 */
PRIVATE void s2_sse2f(SSE2_WORD* a, SSE2_WORD* out)
{
	SSE2_WORD x0, x1, x2, x3, x4, x5, x6, x7, xa0, xa1, xa2, xa5;

	//mov
	vxor(x0, a[1], a[4]);
	//mov
	vandn(x1, a[0], a[5]);
	vandn(x1, a[4], x1);
	//mov
	vandn(x3, x0, a[5]);
	//mov
	vand(x4, a[0], x0);
	vxor(x4, a[4], x4);
	//mov
	vandn(x5, x4, x3);
	vxor(x0, a[5], x0);
	vand(xa5, a[2], a[5]);//a[5]
	vnot(xa0, a[0]);//a[0]
	//mov
	vandn(x6, x0, xa5);
	//mov
	vandn(x2, a[1], x6);
	vor(xa1, a[1], x1);//a[1]
	vxor(x1, x1, x3);
	vand(x1, xa1, x1);
	//mov
	vandn(x7, x1, xa5);
	vand(x1, a[2], x1);
	vxor(xa2, a[2], x0);//a[2]
	vxor(xa0, x1, xa0);
	vxor(x6, xa0, x6);
	vandn(x7, a[3], x7);
	vxor(x7, x7, x6);
	vxor(out[1*MAX_REPEAT], out[1*MAX_REPEAT], x7);
	vxor(x4, x4, x2);
	vxor(x1, x1, x2);
	//mov
	vandn(x7, xa0, x4);//xa0
	vxor(x7, x7, xa2);
	//mov
	vandn(x2, xa1, a[3]);
	vxor(x2, x2, x7);
	vxor(out[0*MAX_REPEAT], out[0*MAX_REPEAT], x2);//x2
	vor(xa2, xa2, x1);
	vxor(xa1, xa1, x6);
	vor(xa5, xa5, xa1);
	vxor(xa2, xa2, xa5);
	vxor(x1, x7, x1);//x7
	vand(x1, xa5, x1);
	vxor(x1, a[4], x1);//a[4]
	vandn(x3, x1, x3);
	vxor(x3, x6, x3);//x6
	vandn(x4, x3, x4);
	vor(x3, x3, a[3]);
	vor(x5, x5, a[3]);//a[3]
	vxor(x3, x3, xa2);
	vxor(out[2*MAX_REPEAT], out[2*MAX_REPEAT], x3);
	vor(x0, x0, xa1);
	vxor(x0, x4, x0);
	vxor(x0, x5, x0);
	vxor(out[3*MAX_REPEAT], out[3*MAX_REPEAT], x0);
}
/* s3-000406, 46 gates, 15 regs, 12 andn, 3/7/19/50/89 stalls, 70 biop */
/* Currently used for MMX/SSE2 */
PRIVATE void s3_sse2f(SSE2_WORD* a, SSE2_WORD* out)
{
	SSE2_WORD x0, x1, x2, x3, x4, x5, x6, xa0, xa1, xa2, xa3, xa5;

	//mov
	vandn(x0, a[0], a[1]);
	//mov
	vxor(x1, a[2], a[5]);
	vor(x0, x0, x1);
	//mov
	vxor(x2, a[3], a[5]);
	//mov
	vandn(x3, x2, a[0]);
	vand(x2, x1, x2);
	vxor(x1, a[1], x1);
	//mov
	vandn(x5, x1, a[5]);
	vxor(x5, x0, x5);
	vxor(x0, x0, x3);
	//mov
	vand(x6, a[5], x0);
	vor(x6, a[3], x6);
	vand(x6, a[0], x6);
	vxor(x6, x1, x6);
	//mov
	vandn(x4, x0, a[4]);
	vxor(x4, x4, x6);
	vxor(out[3*MAX_REPEAT], out[3*MAX_REPEAT], x4);
	vand(xa5, a[3], a[5]);//a[5]
	vxor(xa3, a[0], a[3]);//a[3]
	vor(x3, x3, xa3);
	vxor(xa3, x5, xa3);
	vandn(x5, x0, x5);
	vor(xa3, a[2], xa3);
	vandn(x2, xa3, x2);//xa3
	//mov
	vandn(x4, xa5, a[1]);
	vor(xa5, x1, xa5);
	vxor(x1, x1, x3);
	vandn(x3, x6, x3);
	vxor(x3, x3, x4);
	vor(xa1, a[1], a[2]);//a[1]
	vandn(xa2, x3, a[2]);//a[2]
	vandn(xa2, xa5, xa2);//xa5
	vxor(xa2, a[0], xa2);
	vxor(xa0, a[0], x2);//a[0]
	vand(x2, x2, a[4]);
	vxor(x2, x2, xa2);//xa2
	vxor(out[1*MAX_REPEAT], out[1*MAX_REPEAT], x2);//x2
	//mov
	vandn(x4, x0, xa1);
	vnot(x1, x1);
	vxor(x4, x4, x1);
	vandn(x5, a[4], x5);
	vxor(x5, x5, x4);//x4
	vxor(out[0*MAX_REPEAT], out[0*MAX_REPEAT], x5);//x5
	vor(x1, x1, xa0);//xa0
	vxor(x1, x0, x1);//x0
	vxor(x1, x6, x1);//x6
	vxor(x1, xa1, x1);//xa1
	vor(x3, x3, a[4]);//a[4]
	vxor(x1, x3, x1);
	vxor(out[2*MAX_REPEAT], out[2*MAX_REPEAT], x1);
}
PRIVATE void s4_sse2f(SSE2_WORD* a, SSE2_WORD* out)
{
	SSE2_WORD x0, x1, x2, x3, x4, x5, x6, xa0, xa1, xa2, xa3, xa5;

	vxor(xa0, a[0], a[2]);//a[0]
	vxor(xa2, a[2], a[4]);//a[2]
	//mov
	vxor(x0, a[1], a[3]);
	//mov
	vandn(x1, xa2, a[1]);
	//mov
	vxor(x2, a[3], x1);
	vor(xa3, a[1], a[3]);//a[3]
	vxor(xa3, a[4], xa3);
	vor(x1, a[4], x1);//a[4]
	vandn(xa3, xa2, xa3);
	//mov
	vor(x3, xa0, x2);
	//mov
	vandn(x4, x3, xa3);
	vxor(xa1, a[1], x4);//a[1]
	vand(x2, x2, xa1);
	//mov
	vandn(x3, xa2, x2);//xa2
	vxor(xa0, xa0, xa1);
	vandn(x3, xa0, x3);
	vxor(x3, xa3, x3);//xa3
	vxor(x1, xa0, x1);//xa0
	//mov
	vandn(x6, x1, x0);
	vxor(x6, x4, x6);
	//mov
	vandn(x5, a[5], x3);
	vxor(x5, x5, x6);
	vxor(out[0*MAX_REPEAT], out[0*MAX_REPEAT], x5);
	vnot(x6, x6);
	//mov
	vor(x4, xa1, a[5]);
	vand(xa1, xa1, a[5]);
	vandn(xa5, x3, a[5]);//a[5]
	vxor(xa5, xa5, x6);
	vxor(out[1*MAX_REPEAT], out[1*MAX_REPEAT], xa5);//xa5
	vxor(x6, x3, x6);//x3
	vandn(x0, x6, x0);//x6
	vor(x0, x2, x0);//x2
	vxor(x0, x1, x0);//x1
	vxor(x4, x4, x0);
	vxor(out[2*MAX_REPEAT], out[2*MAX_REPEAT], x4);
	vxor(x0, xa1, x0);
	vxor(out[3*MAX_REPEAT], out[3*MAX_REPEAT], x0);
}
/* s5-04829, 48 gates, 15/16 regs, 9 andn, 4/24/65/113/163 stalls, 72 biop */
/* Currently used for x86-64 SSE2 */
PRIVATE void s5_sse2f(SSE2_WORD* a, SSE2_WORD* out)
{
	SSE2_WORD x0, x1, x2, x3, x4, x5, x6, x7, x8, xa0, xa1, xa2, xa3, xa4, xa5;

	//mov
	vor(x0, a[0], a[2]);
	//mov
	vandn(x1, x0, a[5]);
	//mov
	vandn(x2, x1, a[3]);
	vxor(x1, a[0], x1);
	vxor(x2, a[2], x2);
	vxor(xa2, a[2], x1);//a[2]
	//mov
	vor(x4, a[3], xa2);
	//mov
	vand(x5, a[4], x2);
	vor(xa2, a[0], xa2);
	vxor(x5, x5, xa2);
	vxor(x5, a[3], x5);
	vxor(xa5, a[5], x5);//a[5]
	//mov
	vor(x6, x1, xa5);
	vxor(x0, a[0], x0);
	vandn(xa0, x6, a[0]);//a[0]
	vand(x6, a[4], x6);
	//mov
	vand(x3, a[3], xa2);
	vxor(x3, x1, x3);
	vxor(x3, x3, x6);
	//mov
	vxor(x7, x2, xa0);
	vxor(xa4, a[4], x4);//a[4]
	vandn(x7, xa4, x7);
	vxor(xa0, xa0, xa4);
	vand(xa2, x2, xa2);
	//mov
	vandn(x8, x2, x6);
	vor(xa0, x3, xa0);
	vandn(x8, xa0, x8);//xa0
	vand(xa5, xa5, x8);
	vxor(x0, x8, x0);
	vandn(x8, x4, x8);
	vxor(xa5, xa4, xa5);//xa5
	vor(xa2, xa5, xa2);
	vxor(x6, x6, xa2);//xa2
	vand(x6, x6, a[1]);
	vxor(x6, x6, x3);//x3
	vxor(out[3*MAX_REPEAT], out[3*MAX_REPEAT], x6);//x6
	vand(xa3, a[3], xa5);//a[3]
	vxor(x0, x0, xa3);
	vor(x8, x8, a[1]);
	vxor(x8, x8, x0);
	vxor(out[0*MAX_REPEAT], out[0*MAX_REPEAT], x8);//x8
	vxor(x2, x4, x2);
	vandn(x0, x2, x0);
	vxor(x1, x1, xa5);
	vxor(x0, x0, x1);
	vand(x4, x4, a[1]);//a[1]
	vnot(xa1, a[1]);
	vandn(x7, xa1, x7);
	vxor(x5, x7, x5);//x7
	vxor(out[2*MAX_REPEAT], out[2*MAX_REPEAT], x5);//x5
	vxor(x0, x4, x0);
	vxor(out[1*MAX_REPEAT], out[1*MAX_REPEAT], x0);
}
/* s6-000007, 46 gates, 19 regs, 8 andn, 3/19/39/66/101 stalls, 69 biop */
/* Currently used for x86-64 SSE2 */
PRIVATE void s6_sse2f(SSE2_WORD* a, SSE2_WORD* out)
{
	SSE2_WORD x0, x1, x2, x3, x4, x5, x6, x7, x8, xa1, xa2, xa3, xa5;

	//mov
	vxor(x0, a[1], a[4]);
	//mov
	vor(x1, a[1], a[5]);
	vand(x1, a[0], x1);
	vxor(x0, x0, x1);
	//mov
	vxor(x2, a[5], x0);
	//mov
	vand(x3, a[0], x2);
	vandn(x2, a[4], x2);
	//mov
	vxor(x4, a[1], x3);
	vxor(x3, a[5], x3);
	//mov
	vxor(x5, a[0], a[2]);
	//mov
	vor(x6, x4, x5);
	vor(x4, x2, x4);
	vor(x5, a[1], x5);
	vxor(xa1, a[1], x6);//a[1]
	vxor(x6, x0, x6);
	vnot(xa1, xa1);
	//mov
	vand(x7, a[5], xa1);
	vxor(x7, a[2], x7);
	vand(xa2, a[2], x6);//a[2]
	vandn(xa5, xa2, a[5]);//a[5]
	//mov
	vxor(x8, xa5, x4);
	vxor(xa1, x5, xa1);
	vxor(x5, x8, x5);
	vand(x8, x8, a[3]);
	vxor(x8, x8, x6);
	vxor(out[3*MAX_REPEAT], out[3*MAX_REPEAT], x8);//x8
	vor(x6, a[0], x6);
	vand(x6, x4, x6);//x4
	vxor(x6, x7, x6);
	vandn(xa5, x6, xa5);
	vxor(x0, x0, x6);
	vandn(x0, a[4], x0);//a[4]
	vxor(x0, x0, xa1);
	vxor(xa1, xa2, xa1);
	vandn(xa2, a[4], xa2);
	vor(xa2, x7, xa2);
	vor(x2, x2, a[3]);
	vxor(x2, x2, xa5);//xa5
	vxor(out[2*MAX_REPEAT], out[2*MAX_REPEAT], x2);//x2
	vor(x1, x1, xa2);
	vxor(x1, x5, x1);//x5
	//mov
	vandn(x6, x0, a[3]);//x0
	vxor(x1, x6, x1);
	vxor(out[1*MAX_REPEAT], out[1*MAX_REPEAT], x1);//x1
	vxor(x7, a[0], x7);//a[0]
	vand(x3, x3, x7);
	vxor(x3, x3, xa1);//xa1
	vandn(xa3, xa2, a[3]);//a[3]
	vxor(x3, xa3, x3);
	vxor(out[0*MAX_REPEAT], out[0*MAX_REPEAT], x3);
}
/* s7-056945, 46 gates, 16 regs, 7 andn, 10/31/62/107/156 stalls, 67 biop */
/* Currently used for MMX/SSE2 */
PRIVATE void s7_sse2f(SSE2_WORD* a, SSE2_WORD* out)
{
	SSE2_WORD x0, x1, x2, x3, x4, x5, x6, x7, xa0, xa1, xa2;

	//mov
	vxor(x0, a[3], a[4]);
	//mov
	vxor(x1, a[2], x0);
	//mov
	vand(x2, a[5], x1);
	//mov
	vand(x3, a[3], x0);
	//mov
	vxor(x4, a[1], x3);
	//mov
	vand(x5, x2, x4);
	//mov
	vand(x6, a[5], x3);
	vxor(x6, a[2], x6);
	//mov
	vor(x7, x4, x6);
	vxor(x6, x2, x6);
	vxor(x0, a[5], x0);
	vxor(x2, x2, x0);
	vandn(x2, a[3], x2);//a[3]
	vxor(x7, x7, x0);
	vandn(x0, x1, x0);
	vandn(x1, a[4], x1);
	vandn(x5, a[0], x5);
	vxor(x5, x5, x7);
	vxor(out[3*MAX_REPEAT], out[3*MAX_REPEAT], x5);
	vandn(x2, x4, x2);
	vor(x4, x4, x1);
	vxor(x4, x4, x6);
	vxor(x6, a[4], x6);
	vxor(x2, x2, x6);
	vor(x3, x3, x7);//x7
	vand(xa2, a[2], x2);//a[2]
	vor(x3, x3, xa2);
	vxor(x0, x3, x0);//x3
	//mov
	vandn(x5, x0, a[0]);
	vxor(x5, x5, x4);
	vxor(out[0*MAX_REPEAT], out[0*MAX_REPEAT], x5);//x5
	vxor(x4, x4, x0);
	//mov
	vor(x6, x2, x0);
	vand(x6, a[5], x6);//a[5]
	vand(xa1, a[1], x6);//a[1]
	vxor(xa1, xa1, x4);
	vor(xa2, xa2, xa1);//xa2
	vxor(xa2, x6, xa2);
	vxor(x4, a[4], x4);//a[4]
	vor(x4, xa2, x4);//xa2
	vxor(x6, x6, x4);
	vand(x4, x4, a[0]);
	vxor(x2, x4, x2);//x4
	vxor(out[2*MAX_REPEAT], out[2*MAX_REPEAT], x2);//x2
	vor(x1, x1, x6);//x6
	vnot(x0, x0);
	vxor(x0, x1, x0);//x1
	vandn(xa0, x0, a[0]);//a[0], x0
	vxor(xa0, xa0, xa1);//xa1
	vxor(out[1*MAX_REPEAT], out[1*MAX_REPEAT], xa0);//xa0
}
/* s8-019374, 41 gates, 14 regs, 7 andn, 4/25/61/103/145 stalls, 59 biop */
/* Currently used for x86-64 SSE2 */
PRIVATE void s8_sse2f(SSE2_WORD* a, SSE2_WORD* out)
{
	SSE2_WORD x0, x1, x2, x3, x4, x5, x6, xa0, xa2, xa3;

	//mov
	vandn(x0, a[2], a[1]);
	//mov
	vandn(x1, a[4], a[2]);
	vxor(x1, a[3], x1);
	//mov
	vand(x2, a[0], x1);
	vnot(x1, x1);
	//mov
	vand(x3, a[1], x1);
	//mov
	vor(x4, a[0], x3);
	//mov
	vandn(x5, a[2], x4);
	vandn(xa2, a[1], a[2]);//a[2]
	vxor(xa2, a[4], xa2);
	vand(x4, x4, xa2);
	vxor(x1, x4, x1);
	vxor(x1, x1, x5);
	//mov
	vxor(x6, x0, x1);
	vandn(x0, x2, x0);
	vor(x2, x2, x4);
	//mov
	vor(x5, x0, a[5]);
	vxor(x5, x5, x6);
	vxor(out[1*MAX_REPEAT], out[1*MAX_REPEAT], x5);//x5
	vxor(x6, a[0], x6);
	//mov
	vand(x4, a[4], x6);
	vxor(x6, a[4], x6);//a[4]
	vxor(x1, a[1], x1);
	vxor(x4, x4, x1);
	vxor(x3, x3, x4);
	vxor(x4, x2, x4);
	vor(x4, a[1], x4);//a[1]
	vxor(x4, x4, x6);//x6
	vand(x2, x2, a[5]);
	vxor(x2, x2, x4);
	vxor(out[2*MAX_REPEAT], out[2*MAX_REPEAT], x2);
	vxor(xa2, xa2, x3);//xa2
	vor(x1, a[3], x1);
	vxor(x1, xa2, x1);
	vxor(xa0, a[0], x1);//a[0]
	vxor(x1, x0, x1);
	vand(xa0, xa0, a[5]);
	vxor(xa0, xa0, x3);
	vxor(out[3*MAX_REPEAT], out[3*MAX_REPEAT], xa0);
	vandn(xa3, xa2, a[3]);//a[3]
	vand(x4, x4, xa3);//xa3
	vxor(x4, x4, x1);
	vor(x4, x4, a[5]);//a[5]
	vxor(x4, x4, x3);
	vxor(out[0*MAX_REPEAT], out[0*MAX_REPEAT], x4);
}

#define s1_sse2(a1,a2,a3,a4,a5,a6,out1) a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6; s1_sse2f(a, out1)
#define s2_sse2(a1,a2,a3,a4,a5,a6,out1) a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6; s2_sse2f(a, out1)
#define s3_sse2(a1,a2,a3,a4,a5,a6,out1) a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6; s3_sse2f(a, out1)
#define s4_sse2(a1,a2,a3,a4,a5,a6,out1) a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6; s4_sse2f(a, out1)
#define s5_sse2(a1,a2,a3,a4,a5,a6,out1) a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6; s5_sse2f(a, out1)
#define s6_sse2(a1,a2,a3,a4,a5,a6,out1) a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6; s6_sse2f(a, out1)
#define s7_sse2(a1,a2,a3,a4,a5,a6,out1) a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6; s7_sse2f(a, out1)
#define s8_sse2(a1,a2,a3,a4,a5,a6,out1) a[0] = a1; a[1] = a2; a[2] = a3; a[3] = a4; a[4] = a5; a[5] = a6; s8_sse2f(a, out1)

#ifdef _M_X64
void lm_eval_sse2_kernel(SSE2_WORD* first_k, SSE2_WORD* first_c, SSE2_WORD* a);
void lm_eval_avx2_kernel(void* first_k, void* first_c, void* tmp);
void calculate_hash_avx(SSE2_WORD* c, unsigned int* hash_values, unsigned int i_shift);
void calculate_lm_indexs_avx(unsigned int* hash_values, unsigned int* indexs);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void crypt_utf8_lm_protocol_avx2(CryptParam* param)
{
	crypt_lm_body(param, lm_eval_avx2_kernel, calculate_hash_avx, calculate_lm_indexs_avx, TRUE);
}
PRIVATE void crypt_fast_lm_protocol_avx2(CryptParam* param)
{
	crypt_lm_body(param, lm_eval_avx2_kernel, calculate_hash_avx, calculate_lm_indexs_avx, FALSE);
}
#else
PRIVATE void lm_eval_sse2_kernel(SSE2_WORD* first_k, SSE2_WORD* first_c, SSE2_WORD* a)
{
	SSE2_WORD* c = first_c;
	SSE2_WORD* k = first_k;
	unsigned int repeat;

	for(repeat = 0; repeat < MAX_REPEAT; repeat++,c++)
	{
		c[0*MAX_REPEAT]  = SSE2_ZERO;
		c[1*MAX_REPEAT]  = SSE2_ALL_ONES;
		c[2*MAX_REPEAT]  = SSE2_ALL_ONES;
		c[3*MAX_REPEAT]  = SSE2_ALL_ONES;
		c[4*MAX_REPEAT]  = SSE2_ZERO;
		c[5*MAX_REPEAT]  = SSE2_ZERO;
		c[6*MAX_REPEAT]  = SSE2_ZERO;
		c[7*MAX_REPEAT]  = SSE2_ALL_ONES;
		c[8*MAX_REPEAT]  = SSE2_ZERO;
		c[9*MAX_REPEAT]  = SSE2_ZERO;
		c[10*MAX_REPEAT] = SSE2_ALL_ONES;
		c[11*MAX_REPEAT] = SSE2_ALL_ONES;
		c[12*MAX_REPEAT] = SSE2_ZERO;
		c[13*MAX_REPEAT] = SSE2_ZERO;
		c[14*MAX_REPEAT] = SSE2_ZERO;
		c[15*MAX_REPEAT] = SSE2_ZERO;
		c[16*MAX_REPEAT] = SSE2_ALL_ONES;
		c[17*MAX_REPEAT] = SSE2_ALL_ONES;
		c[18*MAX_REPEAT] = SSE2_ALL_ONES;
		c[19*MAX_REPEAT] = SSE2_ZERO;
		c[20*MAX_REPEAT] = SSE2_ALL_ONES;
		c[21*MAX_REPEAT] = SSE2_ALL_ONES;
		c[22*MAX_REPEAT] = SSE2_ZERO;
		c[23*MAX_REPEAT] = SSE2_ZERO;
		c[24*MAX_REPEAT] = SSE2_ALL_ONES;
		c[25*MAX_REPEAT] = SSE2_ZERO;
		c[26*MAX_REPEAT] = SSE2_ZERO;
		c[27*MAX_REPEAT] = SSE2_ALL_ONES;
		c[28*MAX_REPEAT] = SSE2_ZERO;
		c[29*MAX_REPEAT] = SSE2_ALL_ONES;
		c[30*MAX_REPEAT] = SSE2_ZERO;
		c[31*MAX_REPEAT] = SSE2_ZERO;
		c[32*MAX_REPEAT] = SSE2_ALL_ONES;
		c[33*MAX_REPEAT] = SSE2_ZERO;
		c[34*MAX_REPEAT] = SSE2_ZERO;
		c[35*MAX_REPEAT] = SSE2_ALL_ONES;
		c[36*MAX_REPEAT] = SSE2_ALL_ONES;
		c[37*MAX_REPEAT] = SSE2_ZERO;
		c[38*MAX_REPEAT] = SSE2_ZERO;
		c[39*MAX_REPEAT] = SSE2_ZERO;
		c[40*MAX_REPEAT] = SSE2_ALL_ONES;
		c[41*MAX_REPEAT] = SSE2_ZERO;
		c[42*MAX_REPEAT] = SSE2_ALL_ONES;
		c[43*MAX_REPEAT] = SSE2_ZERO;
		c[44*MAX_REPEAT] = SSE2_ZERO;
		c[45*MAX_REPEAT] = SSE2_ZERO;
		c[46*MAX_REPEAT] = SSE2_ALL_ONES;
		c[47*MAX_REPEAT] = SSE2_ZERO;
		c[48*MAX_REPEAT] = SSE2_ZERO;
		c[49*MAX_REPEAT] = SSE2_ZERO;
		c[50*MAX_REPEAT] = SSE2_ZERO;
		c[51*MAX_REPEAT] = SSE2_ZERO;
		c[52*MAX_REPEAT] = SSE2_ZERO;
		c[53*MAX_REPEAT] = SSE2_ZERO;
		c[54*MAX_REPEAT] = SSE2_ALL_ONES;
		c[55*MAX_REPEAT] = SSE2_ZERO;
		c[56*MAX_REPEAT] = SSE2_ALL_ONES;
		c[57*MAX_REPEAT] = SSE2_ZERO;
		c[58*MAX_REPEAT] = SSE2_ZERO;
		c[59*MAX_REPEAT] = SSE2_ZERO;
		c[60*MAX_REPEAT] = SSE2_ZERO;
		c[61*MAX_REPEAT] = SSE2_ALL_ONES;
		c[62*MAX_REPEAT] = SSE2_ZERO;
		c[63*MAX_REPEAT] = SSE2_ZERO;
	}
	c = first_c;

	//1
	REPEAT{
	s1_sse2 (SSE2_XOR(c[56*MAX_REPEAT], k[47*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[38*MAX_REPEAT], k[26*MAX_REPEAT]), SSE2_XOR(c[51*MAX_REPEAT], k[3*MAX_REPEAT] ), SSE2_XOR(c[52*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[41*MAX_REPEAT]), &c[0*MAX_REPEAT]);
	s2_sse2 (SSE2_XOR(c[52*MAX_REPEAT], k[27*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[6*MAX_REPEAT] ), SSE2_XOR(c[43*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[59*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[48*MAX_REPEAT], k[39*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[19*MAX_REPEAT]), &c[4*MAX_REPEAT] );
	s3_sse2 (SSE2_XOR(c[48*MAX_REPEAT], k[53*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[46*MAX_REPEAT], k[33*MAX_REPEAT]), SSE2_XOR(c[54*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[57*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[5*MAX_REPEAT]) , &c[8*MAX_REPEAT] );
	s4_sse2 (SSE2_XOR(c[57*MAX_REPEAT], k[4*MAX_REPEAT] ), SSE2_XOR(c[36*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[49*MAX_REPEAT], k[24*MAX_REPEAT]), SSE2_XOR(c[62*MAX_REPEAT], k[32*MAX_REPEAT]), SSE2_XOR(c[41*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[20*MAX_REPEAT]), &c[12*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[41*MAX_REPEAT], k[36*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[39*MAX_REPEAT], k[21*MAX_REPEAT]), SSE2_XOR(c[55*MAX_REPEAT], k[8*MAX_REPEAT] ), SSE2_XOR(c[45*MAX_REPEAT], k[23*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[52*MAX_REPEAT]), &c[16*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[45*MAX_REPEAT], k[14*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[29*MAX_REPEAT]), SSE2_XOR(c[58*MAX_REPEAT], k[51*MAX_REPEAT]), SSE2_XOR(c[34*MAX_REPEAT], k[9*MAX_REPEAT] ), SSE2_XOR(c[40*MAX_REPEAT], k[35*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[30*MAX_REPEAT]), &c[20*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[40*MAX_REPEAT], k[2*MAX_REPEAT] ), SSE2_XOR(c[50*MAX_REPEAT], k[37*MAX_REPEAT]), SSE2_XOR(c[44*MAX_REPEAT], k[22*MAX_REPEAT]), SSE2_XOR(c[61*MAX_REPEAT], k[0*MAX_REPEAT] ), SSE2_XOR(c[37*MAX_REPEAT], k[42*MAX_REPEAT]), SSE2_XOR(c[53*MAX_REPEAT], k[38*MAX_REPEAT]), &c[24*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[37*MAX_REPEAT], k[16*MAX_REPEAT]), SSE2_XOR(c[53*MAX_REPEAT], k[43*MAX_REPEAT]), SSE2_XOR(c[42*MAX_REPEAT], k[44*MAX_REPEAT]), SSE2_XOR(c[35*MAX_REPEAT], k[1*MAX_REPEAT] ), SSE2_XOR(c[56*MAX_REPEAT], k[7*MAX_REPEAT]) , SSE2_XOR(c[47*MAX_REPEAT], k[28*MAX_REPEAT]), &c[28*MAX_REPEAT]);
	//2
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[24*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[18*MAX_REPEAT]), SSE2_XOR(c[6*MAX_REPEAT] , k[33*MAX_REPEAT]), SSE2_XOR(c[19*MAX_REPEAT], k[10*MAX_REPEAT]), SSE2_XOR(c[20*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[48*MAX_REPEAT]), &c[32*MAX_REPEAT]);
	s2_sse2 (SSE2_XOR(c[20*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[11*MAX_REPEAT], k[4*MAX_REPEAT]) , SSE2_XOR(c[27*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[16*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[26*MAX_REPEAT]), &c[36*MAX_REPEAT]);
	s3_sse2 (SSE2_XOR(c[16*MAX_REPEAT], k[3*MAX_REPEAT]) , SSE2_XOR(c[0*MAX_REPEAT] , k[32*MAX_REPEAT]), SSE2_XOR(c[14*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[22*MAX_REPEAT], k[41*MAX_REPEAT]), SSE2_XOR(c[25*MAX_REPEAT], k[24*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[12*MAX_REPEAT]), &c[40*MAX_REPEAT]);
	s4_sse2 (SSE2_XOR(c[25*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[5*MAX_REPEAT]) , SSE2_XOR(c[17*MAX_REPEAT], k[6*MAX_REPEAT]) , SSE2_XOR(c[30*MAX_REPEAT], k[39*MAX_REPEAT]), SSE2_XOR(c[9*MAX_REPEAT] , k[47*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[27*MAX_REPEAT]), &c[44*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[9*MAX_REPEAT] , k[43*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[38*MAX_REPEAT]), SSE2_XOR(c[7*MAX_REPEAT] , k[28*MAX_REPEAT]), SSE2_XOR(c[23*MAX_REPEAT], k[15*MAX_REPEAT]), SSE2_XOR(c[13*MAX_REPEAT], k[30*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[0*MAX_REPEAT]) , &c[48*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[13*MAX_REPEAT], k[21*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[36*MAX_REPEAT]), SSE2_XOR(c[26*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[2*MAX_REPEAT] , k[16*MAX_REPEAT]), SSE2_XOR(c[8*MAX_REPEAT] , k[42*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[37*MAX_REPEAT]), &c[52*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[8*MAX_REPEAT] , k[9*MAX_REPEAT]) , SSE2_XOR(c[18*MAX_REPEAT], k[44*MAX_REPEAT]), SSE2_XOR(c[12*MAX_REPEAT], k[29*MAX_REPEAT]), SSE2_XOR(c[29*MAX_REPEAT], k[7*MAX_REPEAT]) , SSE2_XOR(c[5*MAX_REPEAT] , k[49*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[45*MAX_REPEAT]), &c[56*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[5*MAX_REPEAT] , k[23*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[50*MAX_REPEAT]), SSE2_XOR(c[10*MAX_REPEAT], k[51*MAX_REPEAT]), SSE2_XOR(c[3*MAX_REPEAT] , k[8*MAX_REPEAT]) , SSE2_XOR(c[24*MAX_REPEAT], k[14*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[35*MAX_REPEAT]), &c[60*MAX_REPEAT]);
	//3
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[56*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[32*MAX_REPEAT]), SSE2_XOR(c[38*MAX_REPEAT], k[47*MAX_REPEAT]), SSE2_XOR(c[51*MAX_REPEAT], k[24*MAX_REPEAT]), SSE2_XOR(c[52*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[5*MAX_REPEAT]) , &c[0*MAX_REPEAT] );
	s2_sse2 (SSE2_XOR(c[52*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[27*MAX_REPEAT]), SSE2_XOR(c[43*MAX_REPEAT], k[18*MAX_REPEAT]), SSE2_XOR(c[59*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[48*MAX_REPEAT], k[3*MAX_REPEAT]) , SSE2_XOR(c[32*MAX_REPEAT], k[40*MAX_REPEAT]), &c[4*MAX_REPEAT] );
	s3_sse2 (SSE2_XOR(c[48*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[46*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[54*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[57*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[26*MAX_REPEAT]), &c[8*MAX_REPEAT] );
	s4_sse2 (SSE2_XOR(c[57*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[19*MAX_REPEAT]), SSE2_XOR(c[49*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[62*MAX_REPEAT], k[53*MAX_REPEAT]), SSE2_XOR(c[41*MAX_REPEAT], k[4*MAX_REPEAT]) , SSE2_XOR(c[33*MAX_REPEAT], k[41*MAX_REPEAT]), &c[12*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[41*MAX_REPEAT], k[2*MAX_REPEAT]) , SSE2_XOR(c[33*MAX_REPEAT], k[52*MAX_REPEAT]), SSE2_XOR(c[39*MAX_REPEAT], k[42*MAX_REPEAT]), SSE2_XOR(c[55*MAX_REPEAT], k[29*MAX_REPEAT]), SSE2_XOR(c[45*MAX_REPEAT], k[44*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[14*MAX_REPEAT]), &c[16*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[45*MAX_REPEAT], k[35*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[50*MAX_REPEAT]), SSE2_XOR(c[58*MAX_REPEAT], k[45*MAX_REPEAT]), SSE2_XOR(c[34*MAX_REPEAT], k[30*MAX_REPEAT]), SSE2_XOR(c[40*MAX_REPEAT], k[1*MAX_REPEAT]) , SSE2_XOR(c[50*MAX_REPEAT], k[51*MAX_REPEAT]), &c[20*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[40*MAX_REPEAT], k[23*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[44*MAX_REPEAT], k[43*MAX_REPEAT]), SSE2_XOR(c[61*MAX_REPEAT], k[21*MAX_REPEAT]), SSE2_XOR(c[37*MAX_REPEAT], k[8*MAX_REPEAT]) , SSE2_XOR(c[53*MAX_REPEAT], k[0*MAX_REPEAT]) , &c[24*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[37*MAX_REPEAT], k[37*MAX_REPEAT]), SSE2_XOR(c[53*MAX_REPEAT], k[9*MAX_REPEAT]) , SSE2_XOR(c[42*MAX_REPEAT], k[38*MAX_REPEAT]), SSE2_XOR(c[35*MAX_REPEAT], k[22*MAX_REPEAT]), SSE2_XOR(c[56*MAX_REPEAT], k[28*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[49*MAX_REPEAT]), &c[28*MAX_REPEAT]);
	//4
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[24*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[6*MAX_REPEAT] , k[4*MAX_REPEAT]) , SSE2_XOR(c[19*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[20*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[19*MAX_REPEAT]), &c[32*MAX_REPEAT]);
	s2_sse2 (SSE2_XOR(c[20*MAX_REPEAT], k[5*MAX_REPEAT]) , SSE2_XOR(c[28*MAX_REPEAT], k[41*MAX_REPEAT]), SSE2_XOR(c[11*MAX_REPEAT], k[32*MAX_REPEAT]), SSE2_XOR(c[27*MAX_REPEAT], k[26*MAX_REPEAT]), SSE2_XOR(c[16*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[54*MAX_REPEAT]), &c[36*MAX_REPEAT]);
	s3_sse2 (SSE2_XOR(c[16*MAX_REPEAT], k[6*MAX_REPEAT]) , SSE2_XOR(c[0*MAX_REPEAT] , k[3*MAX_REPEAT]) , SSE2_XOR(c[14*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[22*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[25*MAX_REPEAT], k[27*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[40*MAX_REPEAT]), &c[40*MAX_REPEAT]);
	s4_sse2 (SSE2_XOR(c[25*MAX_REPEAT], k[39*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[33*MAX_REPEAT]), SSE2_XOR(c[17*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[30*MAX_REPEAT], k[10*MAX_REPEAT]), SSE2_XOR(c[9*MAX_REPEAT] , k[18*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[55*MAX_REPEAT]), &c[44*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[9*MAX_REPEAT] , k[16*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[7*MAX_REPEAT]) , SSE2_XOR(c[7*MAX_REPEAT] , k[1*MAX_REPEAT]) , SSE2_XOR(c[23*MAX_REPEAT], k[43*MAX_REPEAT]), SSE2_XOR(c[13*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[28*MAX_REPEAT]), &c[48*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[13*MAX_REPEAT], k[49*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[9*MAX_REPEAT]) , SSE2_XOR(c[26*MAX_REPEAT], k[0*MAX_REPEAT]) , SSE2_XOR(c[2*MAX_REPEAT] , k[44*MAX_REPEAT]), SSE2_XOR(c[8*MAX_REPEAT] , k[15*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[38*MAX_REPEAT]), &c[52*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[8*MAX_REPEAT] , k[37*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[45*MAX_REPEAT]), SSE2_XOR(c[12*MAX_REPEAT], k[2*MAX_REPEAT]) , SSE2_XOR(c[29*MAX_REPEAT], k[35*MAX_REPEAT]), SSE2_XOR(c[5*MAX_REPEAT] , k[22*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[14*MAX_REPEAT]), &c[56*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[5*MAX_REPEAT] , k[51*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[23*MAX_REPEAT]), SSE2_XOR(c[10*MAX_REPEAT], k[52*MAX_REPEAT]), SSE2_XOR(c[3*MAX_REPEAT] , k[36*MAX_REPEAT]), SSE2_XOR(c[24*MAX_REPEAT], k[42*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[8*MAX_REPEAT]) , &c[60*MAX_REPEAT]);
	//5
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[56*MAX_REPEAT], k[39*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[3*MAX_REPEAT]) , SSE2_XOR(c[38*MAX_REPEAT], k[18*MAX_REPEAT]), SSE2_XOR(c[51*MAX_REPEAT], k[27*MAX_REPEAT]), SSE2_XOR(c[52*MAX_REPEAT], k[5*MAX_REPEAT]) , SSE2_XOR(c[60*MAX_REPEAT], k[33*MAX_REPEAT]), &c[0*MAX_REPEAT] );
	s2_sse2 (SSE2_XOR(c[52*MAX_REPEAT], k[19*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[43*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[59*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[48*MAX_REPEAT], k[6*MAX_REPEAT]) , SSE2_XOR(c[32*MAX_REPEAT], k[11*MAX_REPEAT]), &c[4*MAX_REPEAT] );
	s3_sse2 (SSE2_XOR(c[48*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[46*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[54*MAX_REPEAT], k[26*MAX_REPEAT]), SSE2_XOR(c[57*MAX_REPEAT], k[41*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[54*MAX_REPEAT]), &c[8*MAX_REPEAT] );
	s4_sse2 (SSE2_XOR(c[57*MAX_REPEAT], k[53*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[47*MAX_REPEAT]), SSE2_XOR(c[49*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[62*MAX_REPEAT], k[24*MAX_REPEAT]), SSE2_XOR(c[41*MAX_REPEAT], k[32*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[12*MAX_REPEAT]), &c[12*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[41*MAX_REPEAT], k[30*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[21*MAX_REPEAT]), SSE2_XOR(c[39*MAX_REPEAT], k[15*MAX_REPEAT]), SSE2_XOR(c[55*MAX_REPEAT], k[2*MAX_REPEAT]) , SSE2_XOR(c[45*MAX_REPEAT], k[45*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[42*MAX_REPEAT]), &c[16*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[45*MAX_REPEAT], k[8*MAX_REPEAT]) , SSE2_XOR(c[63*MAX_REPEAT], k[23*MAX_REPEAT]), SSE2_XOR(c[58*MAX_REPEAT], k[14*MAX_REPEAT]), SSE2_XOR(c[34*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[40*MAX_REPEAT], k[29*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[52*MAX_REPEAT]), &c[20*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[40*MAX_REPEAT], k[51*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[0*MAX_REPEAT]) , SSE2_XOR(c[44*MAX_REPEAT], k[16*MAX_REPEAT]), SSE2_XOR(c[61*MAX_REPEAT], k[49*MAX_REPEAT]), SSE2_XOR(c[37*MAX_REPEAT], k[36*MAX_REPEAT]), SSE2_XOR(c[53*MAX_REPEAT], k[28*MAX_REPEAT]), &c[24*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[37*MAX_REPEAT], k[38*MAX_REPEAT]), SSE2_XOR(c[53*MAX_REPEAT], k[37*MAX_REPEAT]), SSE2_XOR(c[42*MAX_REPEAT], k[7*MAX_REPEAT]) , SSE2_XOR(c[35*MAX_REPEAT], k[50*MAX_REPEAT]), SSE2_XOR(c[56*MAX_REPEAT], k[1*MAX_REPEAT]) , SSE2_XOR(c[47*MAX_REPEAT], k[22*MAX_REPEAT]), &c[28*MAX_REPEAT]);
	//6
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[24*MAX_REPEAT], k[53*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[6*MAX_REPEAT] , k[32*MAX_REPEAT]), SSE2_XOR(c[19*MAX_REPEAT], k[41*MAX_REPEAT]), SSE2_XOR(c[20*MAX_REPEAT], k[19*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[47*MAX_REPEAT]), &c[32*MAX_REPEAT]);
	s2_sse2 (SSE2_XOR(c[20*MAX_REPEAT], k[33*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[11*MAX_REPEAT], k[3*MAX_REPEAT]) , SSE2_XOR(c[27*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[16*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[25*MAX_REPEAT]), &c[36*MAX_REPEAT]);
	s3_sse2 (SSE2_XOR(c[16*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[6*MAX_REPEAT]) , SSE2_XOR(c[14*MAX_REPEAT], k[39*MAX_REPEAT]), SSE2_XOR(c[22*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[25*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[11*MAX_REPEAT]), &c[40*MAX_REPEAT]);
	s4_sse2 (SSE2_XOR(c[25*MAX_REPEAT], k[10*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[4*MAX_REPEAT]) , SSE2_XOR(c[17*MAX_REPEAT], k[5*MAX_REPEAT]) , SSE2_XOR(c[30*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[9*MAX_REPEAT] , k[46*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[26*MAX_REPEAT]), &c[44*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[9*MAX_REPEAT] , k[44*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[35*MAX_REPEAT]), SSE2_XOR(c[7*MAX_REPEAT] , k[29*MAX_REPEAT]), SSE2_XOR(c[23*MAX_REPEAT], k[16*MAX_REPEAT]), SSE2_XOR(c[13*MAX_REPEAT], k[0*MAX_REPEAT]) , SSE2_XOR(c[31*MAX_REPEAT], k[1*MAX_REPEAT]) , &c[48*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[13*MAX_REPEAT], k[22*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[37*MAX_REPEAT]), SSE2_XOR(c[26*MAX_REPEAT], k[28*MAX_REPEAT]), SSE2_XOR(c[2*MAX_REPEAT] , k[45*MAX_REPEAT]), SSE2_XOR(c[8*MAX_REPEAT] , k[43*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[7*MAX_REPEAT]) , &c[52*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[8*MAX_REPEAT] , k[38*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[14*MAX_REPEAT]), SSE2_XOR(c[12*MAX_REPEAT], k[30*MAX_REPEAT]), SSE2_XOR(c[29*MAX_REPEAT], k[8*MAX_REPEAT]) , SSE2_XOR(c[5*MAX_REPEAT] , k[50*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[42*MAX_REPEAT]), &c[56*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[5*MAX_REPEAT] , k[52*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[51*MAX_REPEAT]), SSE2_XOR(c[10*MAX_REPEAT], k[21*MAX_REPEAT]), SSE2_XOR(c[3*MAX_REPEAT] , k[9*MAX_REPEAT]) , SSE2_XOR(c[24*MAX_REPEAT], k[15*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[36*MAX_REPEAT]), &c[60*MAX_REPEAT]);
	//7
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[56*MAX_REPEAT], k[10*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[6*MAX_REPEAT]) , SSE2_XOR(c[38*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[51*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[52*MAX_REPEAT], k[33*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[4*MAX_REPEAT]) , &c[0*MAX_REPEAT] );
	s2_sse2 (SSE2_XOR(c[52*MAX_REPEAT], k[47*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[26*MAX_REPEAT]), SSE2_XOR(c[43*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[59*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[48*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[39*MAX_REPEAT]), &c[4*MAX_REPEAT] );
	s3_sse2 (SSE2_XOR(c[48*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[46*MAX_REPEAT], k[53*MAX_REPEAT]), SSE2_XOR(c[54*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[57*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[25*MAX_REPEAT]), &c[8*MAX_REPEAT] );
	s4_sse2 (SSE2_XOR(c[57*MAX_REPEAT], k[24*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[18*MAX_REPEAT]), SSE2_XOR(c[49*MAX_REPEAT], k[19*MAX_REPEAT]), SSE2_XOR(c[62*MAX_REPEAT], k[27*MAX_REPEAT]), SSE2_XOR(c[41*MAX_REPEAT], k[3*MAX_REPEAT]) , SSE2_XOR(c[33*MAX_REPEAT], k[40*MAX_REPEAT]), &c[12*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[41*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[49*MAX_REPEAT]), SSE2_XOR(c[39*MAX_REPEAT], k[43*MAX_REPEAT]), SSE2_XOR(c[55*MAX_REPEAT], k[30*MAX_REPEAT]), SSE2_XOR(c[45*MAX_REPEAT], k[14*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[15*MAX_REPEAT]), &c[16*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[45*MAX_REPEAT], k[36*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[51*MAX_REPEAT]), SSE2_XOR(c[58*MAX_REPEAT], k[42*MAX_REPEAT]), SSE2_XOR(c[34*MAX_REPEAT], k[0*MAX_REPEAT]) , SSE2_XOR(c[40*MAX_REPEAT], k[2*MAX_REPEAT]) , SSE2_XOR(c[50*MAX_REPEAT], k[21*MAX_REPEAT]), &c[20*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[40*MAX_REPEAT], k[52*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[28*MAX_REPEAT]), SSE2_XOR(c[44*MAX_REPEAT], k[44*MAX_REPEAT]), SSE2_XOR(c[61*MAX_REPEAT], k[22*MAX_REPEAT]), SSE2_XOR(c[37*MAX_REPEAT], k[9*MAX_REPEAT]) , SSE2_XOR(c[53*MAX_REPEAT], k[1*MAX_REPEAT]) , &c[24*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[37*MAX_REPEAT], k[7*MAX_REPEAT]) , SSE2_XOR(c[53*MAX_REPEAT], k[38*MAX_REPEAT]), SSE2_XOR(c[42*MAX_REPEAT], k[35*MAX_REPEAT]), SSE2_XOR(c[35*MAX_REPEAT], k[23*MAX_REPEAT]), SSE2_XOR(c[56*MAX_REPEAT], k[29*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[50*MAX_REPEAT]), &c[28*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	//8
	s1_sse2 (SSE2_XOR(c[24*MAX_REPEAT], k[24*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[6*MAX_REPEAT] , k[3*MAX_REPEAT]) , SSE2_XOR(c[19*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[20*MAX_REPEAT], k[47*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[18*MAX_REPEAT]), &c[32*MAX_REPEAT]);
	s2_sse2 (SSE2_XOR(c[20*MAX_REPEAT], k[4*MAX_REPEAT]) , SSE2_XOR(c[28*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[11*MAX_REPEAT], k[6*MAX_REPEAT]) , SSE2_XOR(c[27*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[16*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[53*MAX_REPEAT]), &c[36*MAX_REPEAT]);
	s3_sse2 (SSE2_XOR(c[16*MAX_REPEAT], k[5*MAX_REPEAT]) , SSE2_XOR(c[0*MAX_REPEAT] , k[34*MAX_REPEAT]), SSE2_XOR(c[14*MAX_REPEAT], k[10*MAX_REPEAT]), SSE2_XOR(c[22*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[25*MAX_REPEAT], k[26*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[39*MAX_REPEAT]), &c[40*MAX_REPEAT]);
	s4_sse2 (SSE2_XOR(c[25*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[32*MAX_REPEAT]), SSE2_XOR(c[17*MAX_REPEAT], k[33*MAX_REPEAT]), SSE2_XOR(c[30*MAX_REPEAT], k[41*MAX_REPEAT]), SSE2_XOR(c[9*MAX_REPEAT] , k[17*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[54*MAX_REPEAT]), &c[44*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[9*MAX_REPEAT] , k[45*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[8*MAX_REPEAT]) , SSE2_XOR(c[7*MAX_REPEAT] , k[2*MAX_REPEAT]) , SSE2_XOR(c[23*MAX_REPEAT], k[44*MAX_REPEAT]), SSE2_XOR(c[13*MAX_REPEAT], k[28*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[29*MAX_REPEAT]), &c[48*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[13*MAX_REPEAT], k[50*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[38*MAX_REPEAT]), SSE2_XOR(c[26*MAX_REPEAT], k[1*MAX_REPEAT]) , SSE2_XOR(c[2*MAX_REPEAT] , k[14*MAX_REPEAT]), SSE2_XOR(c[8*MAX_REPEAT] , k[16*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[35*MAX_REPEAT]), &c[52*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[8*MAX_REPEAT] , k[7*MAX_REPEAT]) , SSE2_XOR(c[18*MAX_REPEAT], k[42*MAX_REPEAT]), SSE2_XOR(c[12*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[29*MAX_REPEAT], k[36*MAX_REPEAT]), SSE2_XOR(c[5*MAX_REPEAT] , k[23*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[15*MAX_REPEAT]), &c[56*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[5*MAX_REPEAT] , k[21*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[52*MAX_REPEAT]), SSE2_XOR(c[10*MAX_REPEAT], k[49*MAX_REPEAT]), SSE2_XOR(c[3*MAX_REPEAT] , k[37*MAX_REPEAT]), SSE2_XOR(c[24*MAX_REPEAT], k[43*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[9*MAX_REPEAT]) , &c[60*MAX_REPEAT]);
	//9
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[56*MAX_REPEAT], k[6*MAX_REPEAT]) , SSE2_XOR(c[47*MAX_REPEAT], k[27*MAX_REPEAT]), SSE2_XOR(c[38*MAX_REPEAT], k[10*MAX_REPEAT]), SSE2_XOR(c[51*MAX_REPEAT], k[19*MAX_REPEAT]), SSE2_XOR(c[52*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[25*MAX_REPEAT]), &c[0*MAX_REPEAT] );
	s2_sse2 (SSE2_XOR(c[52*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[47*MAX_REPEAT]), SSE2_XOR(c[43*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[59*MAX_REPEAT], k[32*MAX_REPEAT]), SSE2_XOR(c[48*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[3*MAX_REPEAT]) , &c[4*MAX_REPEAT] );
	s3_sse2 (SSE2_XOR(c[48*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[41*MAX_REPEAT]), SSE2_XOR(c[46*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[54*MAX_REPEAT], k[18*MAX_REPEAT]), SSE2_XOR(c[57*MAX_REPEAT], k[33*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[46*MAX_REPEAT]), &c[8*MAX_REPEAT] );
	s4_sse2 (SSE2_XOR(c[57*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[39*MAX_REPEAT]), SSE2_XOR(c[49*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[62*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[41*MAX_REPEAT], k[24*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[4*MAX_REPEAT]) , &c[12*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[41*MAX_REPEAT], k[52*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[15*MAX_REPEAT]), SSE2_XOR(c[39*MAX_REPEAT], k[9*MAX_REPEAT]) , SSE2_XOR(c[55*MAX_REPEAT], k[51*MAX_REPEAT]), SSE2_XOR(c[45*MAX_REPEAT], k[35*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[36*MAX_REPEAT]), &c[16*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[45*MAX_REPEAT], k[2*MAX_REPEAT]) , SSE2_XOR(c[63*MAX_REPEAT], k[45*MAX_REPEAT]), SSE2_XOR(c[58*MAX_REPEAT], k[8*MAX_REPEAT]) , SSE2_XOR(c[34*MAX_REPEAT], k[21*MAX_REPEAT]), SSE2_XOR(c[40*MAX_REPEAT], k[23*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[42*MAX_REPEAT]), &c[20*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[40*MAX_REPEAT], k[14*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[49*MAX_REPEAT]), SSE2_XOR(c[44*MAX_REPEAT], k[38*MAX_REPEAT]), SSE2_XOR(c[61*MAX_REPEAT], k[43*MAX_REPEAT]), SSE2_XOR(c[37*MAX_REPEAT], k[30*MAX_REPEAT]), SSE2_XOR(c[53*MAX_REPEAT], k[22*MAX_REPEAT]), &c[24*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[37*MAX_REPEAT], k[28*MAX_REPEAT]), SSE2_XOR(c[53*MAX_REPEAT], k[0*MAX_REPEAT]) , SSE2_XOR(c[42*MAX_REPEAT], k[1*MAX_REPEAT]) , SSE2_XOR(c[35*MAX_REPEAT], k[44*MAX_REPEAT]), SSE2_XOR(c[56*MAX_REPEAT], k[50*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[16*MAX_REPEAT]), &c[28*MAX_REPEAT]);
	//10
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[24*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[41*MAX_REPEAT]), SSE2_XOR(c[6*MAX_REPEAT] , k[24*MAX_REPEAT]), SSE2_XOR(c[19*MAX_REPEAT], k[33*MAX_REPEAT]), SSE2_XOR(c[20*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[39*MAX_REPEAT]), &c[32*MAX_REPEAT]);
	s2_sse2 (SSE2_XOR(c[20*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[4*MAX_REPEAT]) , SSE2_XOR(c[11*MAX_REPEAT], k[27*MAX_REPEAT]), SSE2_XOR(c[27*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[16*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[17*MAX_REPEAT]), &c[36*MAX_REPEAT]);
	s3_sse2 (SSE2_XOR(c[16*MAX_REPEAT], k[26*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[55*MAX_REPEAT]), SSE2_XOR(c[14*MAX_REPEAT], k[6*MAX_REPEAT]) , SSE2_XOR(c[22*MAX_REPEAT], k[32*MAX_REPEAT]), SSE2_XOR(c[25*MAX_REPEAT], k[47*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[3*MAX_REPEAT]) , &c[40*MAX_REPEAT]);
	s4_sse2 (SSE2_XOR(c[25*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[53*MAX_REPEAT]), SSE2_XOR(c[17*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[30*MAX_REPEAT], k[5*MAX_REPEAT]) , SSE2_XOR(c[9*MAX_REPEAT] , k[13*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[18*MAX_REPEAT]), &c[44*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[9*MAX_REPEAT] , k[7*MAX_REPEAT]) , SSE2_XOR(c[1*MAX_REPEAT] , k[29*MAX_REPEAT]), SSE2_XOR(c[7*MAX_REPEAT] , k[23*MAX_REPEAT]), SSE2_XOR(c[23*MAX_REPEAT], k[38*MAX_REPEAT]), SSE2_XOR(c[13*MAX_REPEAT], k[49*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[50*MAX_REPEAT]), &c[48*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[13*MAX_REPEAT], k[16*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[0*MAX_REPEAT]) , SSE2_XOR(c[26*MAX_REPEAT], k[22*MAX_REPEAT]), SSE2_XOR(c[2*MAX_REPEAT] , k[35*MAX_REPEAT]), SSE2_XOR(c[8*MAX_REPEAT] , k[37*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[1*MAX_REPEAT]) , &c[52*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[8*MAX_REPEAT] , k[28*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[8*MAX_REPEAT]) , SSE2_XOR(c[12*MAX_REPEAT], k[52*MAX_REPEAT]), SSE2_XOR(c[29*MAX_REPEAT], k[2*MAX_REPEAT]) , SSE2_XOR(c[5*MAX_REPEAT] , k[44*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[36*MAX_REPEAT]), &c[56*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[5*MAX_REPEAT] , k[42*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[14*MAX_REPEAT]), SSE2_XOR(c[10*MAX_REPEAT], k[15*MAX_REPEAT]), SSE2_XOR(c[3*MAX_REPEAT] , k[31*MAX_REPEAT]), SSE2_XOR(c[24*MAX_REPEAT], k[9*MAX_REPEAT]) , SSE2_XOR(c[15*MAX_REPEAT], k[30*MAX_REPEAT]), &c[60*MAX_REPEAT]);
	//11
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[56*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[38*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[51*MAX_REPEAT], k[47*MAX_REPEAT]), SSE2_XOR(c[52*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[53*MAX_REPEAT]), &c[0*MAX_REPEAT] );
	s2_sse2 (SSE2_XOR(c[52*MAX_REPEAT], k[39*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[18*MAX_REPEAT]), SSE2_XOR(c[43*MAX_REPEAT], k[41*MAX_REPEAT]), SSE2_XOR(c[59*MAX_REPEAT], k[3*MAX_REPEAT]) , SSE2_XOR(c[48*MAX_REPEAT], k[26*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[6*MAX_REPEAT]) , &c[4*MAX_REPEAT] );
	s3_sse2 (SSE2_XOR(c[48*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[46*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[54*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[57*MAX_REPEAT], k[4*MAX_REPEAT]) , SSE2_XOR(c[36*MAX_REPEAT], k[17*MAX_REPEAT]), &c[8*MAX_REPEAT] );
	s4_sse2 (SSE2_XOR(c[57*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[10*MAX_REPEAT]), SSE2_XOR(c[49*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[62*MAX_REPEAT], k[19*MAX_REPEAT]), SSE2_XOR(c[41*MAX_REPEAT], k[27*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[32*MAX_REPEAT]), &c[12*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[41*MAX_REPEAT], k[21*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[43*MAX_REPEAT]), SSE2_XOR(c[39*MAX_REPEAT], k[37*MAX_REPEAT]), SSE2_XOR(c[55*MAX_REPEAT], k[52*MAX_REPEAT]), SSE2_XOR(c[45*MAX_REPEAT], k[8*MAX_REPEAT]) , SSE2_XOR(c[63*MAX_REPEAT], k[9*MAX_REPEAT]) , &c[16*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[45*MAX_REPEAT], k[30*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[14*MAX_REPEAT]), SSE2_XOR(c[58*MAX_REPEAT], k[36*MAX_REPEAT]), SSE2_XOR(c[34*MAX_REPEAT], k[49*MAX_REPEAT]), SSE2_XOR(c[40*MAX_REPEAT], k[51*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[15*MAX_REPEAT]), &c[20*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[40*MAX_REPEAT], k[42*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[22*MAX_REPEAT]), SSE2_XOR(c[44*MAX_REPEAT], k[7*MAX_REPEAT]) , SSE2_XOR(c[61*MAX_REPEAT], k[16*MAX_REPEAT]), SSE2_XOR(c[37*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[53*MAX_REPEAT], k[50*MAX_REPEAT]), &c[24*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[37*MAX_REPEAT], k[1*MAX_REPEAT]) , SSE2_XOR(c[53*MAX_REPEAT], k[28*MAX_REPEAT]), SSE2_XOR(c[42*MAX_REPEAT], k[29*MAX_REPEAT]), SSE2_XOR(c[35*MAX_REPEAT], k[45*MAX_REPEAT]), SSE2_XOR(c[56*MAX_REPEAT], k[23*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[44*MAX_REPEAT]), &c[28*MAX_REPEAT]);
	//12
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[24*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[6*MAX_REPEAT] , k[27*MAX_REPEAT]), SSE2_XOR(c[19*MAX_REPEAT], k[4*MAX_REPEAT]) , SSE2_XOR(c[20*MAX_REPEAT], k[39*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[10*MAX_REPEAT]), &c[32*MAX_REPEAT]);
	s2_sse2 (SSE2_XOR(c[20*MAX_REPEAT], k[53*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[32*MAX_REPEAT]), SSE2_XOR(c[11*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[27*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[16*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[20*MAX_REPEAT]), &c[36*MAX_REPEAT]);
	s3_sse2 (SSE2_XOR(c[16*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[26*MAX_REPEAT]), SSE2_XOR(c[14*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[22*MAX_REPEAT], k[3*MAX_REPEAT]) , SSE2_XOR(c[25*MAX_REPEAT], k[18*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[6*MAX_REPEAT]) , &c[40*MAX_REPEAT]);
	s4_sse2 (SSE2_XOR(c[25*MAX_REPEAT], k[5*MAX_REPEAT]) , SSE2_XOR(c[4*MAX_REPEAT] , k[24*MAX_REPEAT]), SSE2_XOR(c[17*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[30*MAX_REPEAT], k[33*MAX_REPEAT]), SSE2_XOR(c[9*MAX_REPEAT] , k[41*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[46*MAX_REPEAT]), &c[44*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[9*MAX_REPEAT] , k[35*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[2*MAX_REPEAT]) , SSE2_XOR(c[7*MAX_REPEAT] , k[51*MAX_REPEAT]), SSE2_XOR(c[23*MAX_REPEAT], k[7*MAX_REPEAT]) , SSE2_XOR(c[13*MAX_REPEAT], k[22*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[23*MAX_REPEAT]), &c[48*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[13*MAX_REPEAT], k[44*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[28*MAX_REPEAT]), SSE2_XOR(c[26*MAX_REPEAT], k[50*MAX_REPEAT]), SSE2_XOR(c[2*MAX_REPEAT] , k[8*MAX_REPEAT]) , SSE2_XOR(c[8*MAX_REPEAT] , k[38*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[29*MAX_REPEAT]), &c[52*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[8*MAX_REPEAT] , k[1*MAX_REPEAT]) , SSE2_XOR(c[18*MAX_REPEAT], k[36*MAX_REPEAT]), SSE2_XOR(c[12*MAX_REPEAT], k[21*MAX_REPEAT]), SSE2_XOR(c[29*MAX_REPEAT], k[30*MAX_REPEAT]), SSE2_XOR(c[5*MAX_REPEAT] , k[45*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[9*MAX_REPEAT]) , &c[56*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[5*MAX_REPEAT] , k[15*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[42*MAX_REPEAT]), SSE2_XOR(c[10*MAX_REPEAT], k[43*MAX_REPEAT]), SSE2_XOR(c[3*MAX_REPEAT] , k[0*MAX_REPEAT]) , SSE2_XOR(c[24*MAX_REPEAT], k[37*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[31*MAX_REPEAT]), &c[60*MAX_REPEAT]);
	//13
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[56*MAX_REPEAT], k[5*MAX_REPEAT]) , SSE2_XOR(c[47*MAX_REPEAT], k[26*MAX_REPEAT]), SSE2_XOR(c[38*MAX_REPEAT], k[41*MAX_REPEAT]), SSE2_XOR(c[51*MAX_REPEAT], k[18*MAX_REPEAT]), SSE2_XOR(c[52*MAX_REPEAT], k[53*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[24*MAX_REPEAT]), &c[0*MAX_REPEAT] );
	s2_sse2 (SSE2_XOR(c[52*MAX_REPEAT], k[10*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[43*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[59*MAX_REPEAT], k[6*MAX_REPEAT]) , SSE2_XOR(c[48*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[34*MAX_REPEAT]), &c[4*MAX_REPEAT] );
	s3_sse2 (SSE2_XOR(c[48*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[46*MAX_REPEAT], k[48*MAX_REPEAT]), SSE2_XOR(c[54*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[57*MAX_REPEAT], k[32*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[20*MAX_REPEAT]), &c[8*MAX_REPEAT] );
	s4_sse2 (SSE2_XOR(c[57*MAX_REPEAT], k[19*MAX_REPEAT]), SSE2_XOR(c[36*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[49*MAX_REPEAT], k[39*MAX_REPEAT]), SSE2_XOR(c[62*MAX_REPEAT], k[47*MAX_REPEAT]), SSE2_XOR(c[41*MAX_REPEAT], k[55*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[3*MAX_REPEAT]) , &c[12*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[41*MAX_REPEAT], k[49*MAX_REPEAT]), SSE2_XOR(c[33*MAX_REPEAT], k[16*MAX_REPEAT]), SSE2_XOR(c[39*MAX_REPEAT], k[38*MAX_REPEAT]), SSE2_XOR(c[55*MAX_REPEAT], k[21*MAX_REPEAT]), SSE2_XOR(c[45*MAX_REPEAT], k[36*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[37*MAX_REPEAT]), &c[16*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[45*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[63*MAX_REPEAT], k[42*MAX_REPEAT]), SSE2_XOR(c[58*MAX_REPEAT], k[9*MAX_REPEAT]) , SSE2_XOR(c[34*MAX_REPEAT], k[22*MAX_REPEAT]), SSE2_XOR(c[40*MAX_REPEAT], k[52*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[43*MAX_REPEAT]), &c[20*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[40*MAX_REPEAT], k[15*MAX_REPEAT]), SSE2_XOR(c[50*MAX_REPEAT], k[50*MAX_REPEAT]), SSE2_XOR(c[44*MAX_REPEAT], k[35*MAX_REPEAT]), SSE2_XOR(c[61*MAX_REPEAT], k[44*MAX_REPEAT]), SSE2_XOR(c[37*MAX_REPEAT], k[0*MAX_REPEAT]) , SSE2_XOR(c[53*MAX_REPEAT], k[23*MAX_REPEAT]), &c[24*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[37*MAX_REPEAT], k[29*MAX_REPEAT]), SSE2_XOR(c[53*MAX_REPEAT], k[1*MAX_REPEAT]) , SSE2_XOR(c[42*MAX_REPEAT], k[2*MAX_REPEAT]) , SSE2_XOR(c[35*MAX_REPEAT], k[14*MAX_REPEAT]), SSE2_XOR(c[56*MAX_REPEAT], k[51*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[45*MAX_REPEAT]), &c[28*MAX_REPEAT]);
	//14
	}END_REPEAT;REPEAT{
	s1_sse2 (SSE2_XOR(c[24*MAX_REPEAT], k[19*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[6*MAX_REPEAT] , k[55*MAX_REPEAT]), SSE2_XOR(c[19*MAX_REPEAT], k[32*MAX_REPEAT]), SSE2_XOR(c[20*MAX_REPEAT], k[10*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[13*MAX_REPEAT]), &c[32*MAX_REPEAT]);
	s2_sse2 (SSE2_XOR(c[20*MAX_REPEAT], k[24*MAX_REPEAT]), SSE2_XOR(c[28*MAX_REPEAT], k[3*MAX_REPEAT]) , SSE2_XOR(c[11*MAX_REPEAT], k[26*MAX_REPEAT]), SSE2_XOR(c[27*MAX_REPEAT], k[20*MAX_REPEAT]), SSE2_XOR(c[16*MAX_REPEAT], k[11*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[48*MAX_REPEAT]), &c[36*MAX_REPEAT]);
	s3_sse2 (SSE2_XOR(c[16*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[0*MAX_REPEAT] , k[54*MAX_REPEAT]), SSE2_XOR(c[14*MAX_REPEAT], k[5*MAX_REPEAT]) , SSE2_XOR(c[22*MAX_REPEAT], k[6*MAX_REPEAT]) , SSE2_XOR(c[25*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[34*MAX_REPEAT]), &c[40*MAX_REPEAT]);
	s4_sse2 (SSE2_XOR(c[25*MAX_REPEAT], k[33*MAX_REPEAT]), SSE2_XOR(c[4*MAX_REPEAT] , k[27*MAX_REPEAT]), SSE2_XOR(c[17*MAX_REPEAT], k[53*MAX_REPEAT]), SSE2_XOR(c[30*MAX_REPEAT], k[4*MAX_REPEAT]) , SSE2_XOR(c[9*MAX_REPEAT] , k[12*MAX_REPEAT]), SSE2_XOR(c[1*MAX_REPEAT] , k[17*MAX_REPEAT]), &c[44*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	s5_sse2 (SSE2_XOR(c[9*MAX_REPEAT] , k[8*MAX_REPEAT]) , SSE2_XOR(c[1*MAX_REPEAT] , k[30*MAX_REPEAT]), SSE2_XOR(c[7*MAX_REPEAT] , k[52*MAX_REPEAT]), SSE2_XOR(c[23*MAX_REPEAT], k[35*MAX_REPEAT]), SSE2_XOR(c[13*MAX_REPEAT], k[50*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[51*MAX_REPEAT]), &c[48*MAX_REPEAT]);
	s6_sse2 (SSE2_XOR(c[13*MAX_REPEAT], k[45*MAX_REPEAT]), SSE2_XOR(c[31*MAX_REPEAT], k[1*MAX_REPEAT]) , SSE2_XOR(c[26*MAX_REPEAT], k[23*MAX_REPEAT]), SSE2_XOR(c[2*MAX_REPEAT] , k[36*MAX_REPEAT]), SSE2_XOR(c[8*MAX_REPEAT] , k[7*MAX_REPEAT]) , SSE2_XOR(c[18*MAX_REPEAT], k[2*MAX_REPEAT]) , &c[52*MAX_REPEAT]);
	s7_sse2 (SSE2_XOR(c[8*MAX_REPEAT] , k[29*MAX_REPEAT]), SSE2_XOR(c[18*MAX_REPEAT], k[9*MAX_REPEAT]) , SSE2_XOR(c[12*MAX_REPEAT], k[49*MAX_REPEAT]), SSE2_XOR(c[29*MAX_REPEAT], k[31*MAX_REPEAT]), SSE2_XOR(c[5*MAX_REPEAT] , k[14*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[37*MAX_REPEAT]), &c[56*MAX_REPEAT]);
	s8_sse2 (SSE2_XOR(c[5*MAX_REPEAT] , k[43*MAX_REPEAT]), SSE2_XOR(c[21*MAX_REPEAT], k[15*MAX_REPEAT]), SSE2_XOR(c[10*MAX_REPEAT], k[16*MAX_REPEAT]), SSE2_XOR(c[3*MAX_REPEAT] , k[28*MAX_REPEAT]), SSE2_XOR(c[24*MAX_REPEAT], k[38*MAX_REPEAT]), SSE2_XOR(c[15*MAX_REPEAT], k[0*MAX_REPEAT]) , &c[60*MAX_REPEAT]);
	}END_REPEAT;REPEAT{
	//15
	s1_sse2 (SSE2_XOR(c[56*MAX_REPEAT], k[33*MAX_REPEAT]), SSE2_XOR(c[47*MAX_REPEAT], k[54*MAX_REPEAT]), SSE2_XOR(c[38*MAX_REPEAT], k[12*MAX_REPEAT]), SSE2_XOR(c[51*MAX_REPEAT], k[46*MAX_REPEAT]), SSE2_XOR(c[52*MAX_REPEAT], k[24*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[27*MAX_REPEAT]), &c[0*MAX_REPEAT] );
	s2_sse2 (SSE2_XOR(c[52*MAX_REPEAT], k[13*MAX_REPEAT]), SSE2_XOR(c[60*MAX_REPEAT], k[17*MAX_REPEAT]), SSE2_XOR(c[43*MAX_REPEAT], k[40*MAX_REPEAT]), SSE2_XOR(c[59*MAX_REPEAT], k[34*MAX_REPEAT]), SSE2_XOR(c[48*MAX_REPEAT], k[25*MAX_REPEAT]), SSE2_XOR(c[32*MAX_REPEAT], k[5*MAX_REPEAT]) , &c[4*MAX_REPEAT] );
	}END_REPEAT;
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void calculate_lm_indexs_see2(unsigned int* hash_values, unsigned int* indexs);

PRIVATE void crypt_utf8_lm_protocol_sse2(CryptParam* param)
{
#ifdef _M_X64
	if (current_cpu.capabilites[CPU_CAP_AVX2])
		crypt_lm_body(param, lm_eval_avx2_kernel, calculate_hash_avx, calculate_lm_indexs_avx, TRUE);
	else
#endif
		crypt_lm_body(param, lm_eval_sse2_kernel, calculate_hash_v128, calculate_lm_indexs_see2, TRUE);
}
PRIVATE void crypt_fast_lm_protocol_sse2(CryptParam* param)
{
	crypt_lm_body(param, lm_eval_sse2_kernel, calculate_hash_v128, calculate_lm_indexs_see2, FALSE);
}
#endif

PRIVATE void lm_eval_final(V128_WORD* first_k, V128_WORD* first_c, V128_WORD* a, calculate_hash_func* calculate_hash, calculate_lm_indexs_func* calculate_lm_indexs)
{
	V128_WORD* c = first_c;
	V128_WORD* k = first_k;
	unsigned int repeat;

	HS_ALIGN(16) unsigned int hash_values[V128_BIT_LENGHT*MAX_REPEAT];
	HS_ALIGN(16) unsigned int indexs[V128_BIT_LENGHT*MAX_REPEAT / 4];
	unsigned int i, j4;
	int calculated_16_round = FALSE;
	int calculated_2_byte = size_bit_table > 0xFF;
	int calculated_3_byte = size_bit_table > 0xFFFF;
	int calculated_4_byte = size_bit_table > 0xFFFFFF;

	for (repeat = 0; repeat < MAX_REPEAT; repeat++, c++)
		calculate_hash(c, hash_values + V128_BIT_LENGHT*repeat, 0);
	c = first_c;

	if (calculated_2_byte)
	{
		REPEAT{
			s3_sse2(V128_XOR(c[48 * MAX_REPEAT], k[39 * MAX_REPEAT]), V128_XOR(c[32 * MAX_REPEAT], k[11 * MAX_REPEAT]), V128_XOR(c[46 * MAX_REPEAT], k[19 * MAX_REPEAT]), V128_XOR(c[54 * MAX_REPEAT], k[20 * MAX_REPEAT]), V128_XOR(c[57 * MAX_REPEAT], k[3 * MAX_REPEAT]), V128_XOR(c[36 * MAX_REPEAT], k[48 * MAX_REPEAT]), &c[8 * MAX_REPEAT]);
			s4_sse2(V128_XOR(c[57 * MAX_REPEAT], k[47 * MAX_REPEAT]), V128_XOR(c[36 * MAX_REPEAT], k[41 * MAX_REPEAT]), V128_XOR(c[49 * MAX_REPEAT], k[10 * MAX_REPEAT]), V128_XOR(c[62 * MAX_REPEAT], k[18 * MAX_REPEAT]), V128_XOR(c[41 * MAX_REPEAT], k[26 * MAX_REPEAT]), V128_XOR(c[33 * MAX_REPEAT], k[6 * MAX_REPEAT]), &c[12 * MAX_REPEAT]);
			calculate_hash(c + 8 * MAX_REPEAT, hash_values + V128_BIT_LENGHT*repeat, 1);
		}END_REPEAT;
	}

	if (calculated_3_byte)
	{
		REPEAT{
			s5_sse2(V128_XOR(c[41 * MAX_REPEAT], k[22 * MAX_REPEAT]), V128_XOR(c[33 * MAX_REPEAT], k[44 * MAX_REPEAT]), V128_XOR(c[39 * MAX_REPEAT], k[7  * MAX_REPEAT]), V128_XOR(c[55 * MAX_REPEAT], k[49 * MAX_REPEAT]), V128_XOR(c[45 * MAX_REPEAT], k[9 * MAX_REPEAT]), V128_XOR(c[63 * MAX_REPEAT], k[38 * MAX_REPEAT]), &c[16 * MAX_REPEAT]);
			s6_sse2(V128_XOR(c[45 * MAX_REPEAT], k[0  * MAX_REPEAT]), V128_XOR(c[63 * MAX_REPEAT], k[15 * MAX_REPEAT]), V128_XOR(c[58 * MAX_REPEAT], k[37 * MAX_REPEAT]), V128_XOR(c[34 * MAX_REPEAT], k[50 * MAX_REPEAT]), V128_XOR(c[40 * MAX_REPEAT], k[21 * MAX_REPEAT]), V128_XOR(c[50 * MAX_REPEAT], k[16 * MAX_REPEAT]), &c[20 * MAX_REPEAT]);
			calculate_hash(c + 16 * MAX_REPEAT, hash_values + V128_BIT_LENGHT*repeat, 2);
		}END_REPEAT;
	}

	if (calculated_4_byte)
	{
		REPEAT{
			s7_sse2(V128_XOR(c[40 * MAX_REPEAT], k[43 * MAX_REPEAT]), V128_XOR(c[50 * MAX_REPEAT], k[23 * MAX_REPEAT]), V128_XOR(c[44 * MAX_REPEAT], k[8  * MAX_REPEAT]), V128_XOR(c[61 * MAX_REPEAT], k[45 * MAX_REPEAT]), V128_XOR(c[37 * MAX_REPEAT], k[28 * MAX_REPEAT]), V128_XOR(c[53 * MAX_REPEAT], k[51 * MAX_REPEAT]), &c[24 * MAX_REPEAT]);
			s8_sse2(V128_XOR(c[37 * MAX_REPEAT], k[2  * MAX_REPEAT]), V128_XOR(c[53 * MAX_REPEAT], k[29 * MAX_REPEAT]), V128_XOR(c[42 * MAX_REPEAT], k[30 * MAX_REPEAT]), V128_XOR(c[35 * MAX_REPEAT], k[42 * MAX_REPEAT]), V128_XOR(c[56 * MAX_REPEAT], k[52 * MAX_REPEAT]), V128_XOR(c[47 * MAX_REPEAT], k[14 * MAX_REPEAT]), &c[28 * MAX_REPEAT]);
			calculate_hash(c + 24 * MAX_REPEAT, hash_values + V128_BIT_LENGHT*repeat, 3);
		}END_REPEAT;
	}

	calculate_lm_indexs(hash_values, indexs);

	for (j4 = 0; j4 < V128_BIT_LENGHT*MAX_REPEAT / 4; j4++)
	{
		unsigned int indexs_j4 = indexs[j4];
		if (indexs_j4)// Check 4 bytes at a time
		{
			/*unsigned int end;
			_BitScanReverse(&end, indexs[j4]);
			_BitScanForward(&rest_j, indexs[j4]);
			end = end/8+1;
			rest_j /= 8;*/

			for (unsigned int rest_j = 0, mask = 0xff; rest_j < 4; rest_j++, mask <<= 8)
				if (indexs_j4 & mask)
				{
					unsigned int j = 4 * j4 + rest_j;
					unsigned int index = table[hash_values[j] & size_table];
					// Partial match
					while (index != NO_ELEM)
					{
						unsigned char* bin = ((unsigned char*)binary_values) + (index << 3);

						// If calculated in hash_values and not compared-->compare
						if (size_bit_table < 0xFF && (hash_values[j] & 0xFF) != bin[0])
							goto next_iteration;
						i = __max(8, first_bit_size_table);

						if (!calculated_2_byte)
						{
							calculated_2_byte = TRUE;
							REPEAT{
								s3_sse2(V128_XOR(c[48 * MAX_REPEAT], k[39 * MAX_REPEAT]), V128_XOR(c[32 * MAX_REPEAT], k[11 * MAX_REPEAT]), V128_XOR(c[46 * MAX_REPEAT], k[19 * MAX_REPEAT]), V128_XOR(c[54 * MAX_REPEAT], k[20 * MAX_REPEAT]), V128_XOR(c[57 * MAX_REPEAT], k[3 * MAX_REPEAT]), V128_XOR(c[36 * MAX_REPEAT], k[48 * MAX_REPEAT]), &c[8 * MAX_REPEAT]);
								s4_sse2(V128_XOR(c[57 * MAX_REPEAT], k[47 * MAX_REPEAT]), V128_XOR(c[36 * MAX_REPEAT], k[41 * MAX_REPEAT]), V128_XOR(c[49 * MAX_REPEAT], k[10 * MAX_REPEAT]), V128_XOR(c[62 * MAX_REPEAT], k[18 * MAX_REPEAT]), V128_XOR(c[41 * MAX_REPEAT], k[26 * MAX_REPEAT]), V128_XOR(c[33 * MAX_REPEAT], k[6 * MAX_REPEAT]), &c[12 * MAX_REPEAT]);
							}END_REPEAT;
						}

						if (size_bit_table > 0xFF)// If calculated in hash_values...
						{
							if (i < 16 && ((hash_values[j] >> 8) & 0xFF) != bin[1])//...and not compared-->compare
								goto next_iteration;
							i = __max(i, 16);
						}
						else// compare bit to bit
						{
							int j_index = (j / V128_BIT_LENGHT) * 4 + ((j >> 5) & 3);
							for (; i < 16; i++)
							{
								uint32_t val = ((uint32_t*)c)[i*MAX_REPEAT * 4 + j_index];

								if (((val >> (j & 31)) & 1) != ((bin[1] >> (i & 7)) & 1))
									goto next_iteration;
							}
						}

						if (!calculated_3_byte)
						{
							calculated_3_byte = TRUE;
							REPEAT{
								s5_sse2(V128_XOR(c[41 * MAX_REPEAT], k[22 * MAX_REPEAT]), V128_XOR(c[33 * MAX_REPEAT], k[44 * MAX_REPEAT]), V128_XOR(c[39 * MAX_REPEAT], k[7 * MAX_REPEAT]), V128_XOR(c[55 * MAX_REPEAT], k[49 * MAX_REPEAT]), V128_XOR(c[45 * MAX_REPEAT], k[9 * MAX_REPEAT]), V128_XOR(c[63 * MAX_REPEAT], k[38 * MAX_REPEAT]), &c[16 * MAX_REPEAT]);
								s6_sse2(V128_XOR(c[45 * MAX_REPEAT], k[0 * MAX_REPEAT]), V128_XOR(c[63 * MAX_REPEAT], k[15 * MAX_REPEAT]), V128_XOR(c[58 * MAX_REPEAT], k[37 * MAX_REPEAT]), V128_XOR(c[34 * MAX_REPEAT], k[50 * MAX_REPEAT]), V128_XOR(c[40 * MAX_REPEAT], k[21 * MAX_REPEAT]), V128_XOR(c[50 * MAX_REPEAT], k[16 * MAX_REPEAT]), &c[20 * MAX_REPEAT]);
							}END_REPEAT;
						}

						if (size_bit_table > 0xFFFF)// If calculated in hash_values...
						{
							if (i < 24 && ((hash_values[j] >> 16) & 0xFF) != bin[2])//...and not compared-->compare
								goto next_iteration;
							i = __max(i, 24);
						}
						else// compare bit to bit
						{
							int j_index = (j / V128_BIT_LENGHT) * 4 + ((j >> 5) & 3);
							for (; i < 24; i++)
							{
								uint32_t val = ((uint32_t*)c)[i*MAX_REPEAT * 4 + j_index];

								if (((val >> (j & 31)) & 1) != ((bin[2] >> (i & 7)) & 1))
									goto next_iteration;
							}
						}

						if (!calculated_4_byte)
						{
							calculated_4_byte = TRUE;
							REPEAT{
								s7_sse2(V128_XOR(c[40 * MAX_REPEAT], k[43 * MAX_REPEAT]), V128_XOR(c[50 * MAX_REPEAT], k[23 * MAX_REPEAT]), V128_XOR(c[44 * MAX_REPEAT], k[8 * MAX_REPEAT]), V128_XOR(c[61 * MAX_REPEAT], k[45 * MAX_REPEAT]), V128_XOR(c[37 * MAX_REPEAT], k[28 * MAX_REPEAT]), V128_XOR(c[53 * MAX_REPEAT], k[51 * MAX_REPEAT]), &c[24 * MAX_REPEAT]);
								s8_sse2(V128_XOR(c[37 * MAX_REPEAT], k[2 * MAX_REPEAT]), V128_XOR(c[53 * MAX_REPEAT], k[29 * MAX_REPEAT]), V128_XOR(c[42 * MAX_REPEAT], k[30 * MAX_REPEAT]), V128_XOR(c[35 * MAX_REPEAT], k[42 * MAX_REPEAT]), V128_XOR(c[56 * MAX_REPEAT], k[52 * MAX_REPEAT]), V128_XOR(c[47 * MAX_REPEAT], k[14 * MAX_REPEAT]), &c[28 * MAX_REPEAT]);
							}END_REPEAT;
						}

						{// compare bit to bit
							int j_index = (j / V128_BIT_LENGHT) * 4 + ((j >> 5) & 3);
							for (; i < 32; i++)
							{
								uint32_t val = ((uint32_t*)c)[i*MAX_REPEAT * 4 + j_index];

								if (((val >> (j & 31)) & 1) != ((bin[3] >> (i & 7)) & 1))
									goto next_iteration;
							}
						}

						if (!calculated_16_round)
						{
							calculated_16_round = TRUE;
							// 16
							REPEAT{
								s1_sse2(V128_XOR(c[24 * MAX_REPEAT], k[40 * MAX_REPEAT]), V128_XOR(c[15 * MAX_REPEAT], k[4 * MAX_REPEAT]), V128_XOR(c[6 * MAX_REPEAT], k[19 * MAX_REPEAT]), V128_XOR(c[19 * MAX_REPEAT], k[53 * MAX_REPEAT]), V128_XOR(c[20 * MAX_REPEAT], k[6 * MAX_REPEAT]), V128_XOR(c[28 * MAX_REPEAT], k[34 * MAX_REPEAT]), &c[32 * MAX_REPEAT]);
								s2_sse2(V128_XOR(c[20 * MAX_REPEAT], k[20 * MAX_REPEAT]), V128_XOR(c[28 * MAX_REPEAT], k[24 * MAX_REPEAT]), V128_XOR(c[11 * MAX_REPEAT], k[47 * MAX_REPEAT]), V128_XOR(c[27 * MAX_REPEAT], k[41 * MAX_REPEAT]), V128_XOR(c[16 * MAX_REPEAT], k[32 * MAX_REPEAT]), V128_XOR(c[0 * MAX_REPEAT], k[12 * MAX_REPEAT]), &c[36 * MAX_REPEAT]);
								s3_sse2(V128_XOR(c[16 * MAX_REPEAT], k[46 * MAX_REPEAT]), V128_XOR(c[0 * MAX_REPEAT], k[18 * MAX_REPEAT]), V128_XOR(c[14 * MAX_REPEAT], k[26 * MAX_REPEAT]), V128_XOR(c[22 * MAX_REPEAT], k[27 * MAX_REPEAT]), V128_XOR(c[25 * MAX_REPEAT], k[10 * MAX_REPEAT]), V128_XOR(c[4 * MAX_REPEAT], k[55 * MAX_REPEAT]), &c[40 * MAX_REPEAT]);
								s4_sse2(V128_XOR(c[25 * MAX_REPEAT], k[54 * MAX_REPEAT]), V128_XOR(c[4 * MAX_REPEAT], k[48 * MAX_REPEAT]), V128_XOR(c[17 * MAX_REPEAT], k[17 * MAX_REPEAT]), V128_XOR(c[30 * MAX_REPEAT], k[25 * MAX_REPEAT]), V128_XOR(c[9 * MAX_REPEAT], k[33 * MAX_REPEAT]), V128_XOR(c[1 * MAX_REPEAT], k[13 * MAX_REPEAT]), &c[44 * MAX_REPEAT]);
								s5_sse2(V128_XOR(c[9 * MAX_REPEAT], k[29 * MAX_REPEAT]), V128_XOR(c[1 * MAX_REPEAT], k[51 * MAX_REPEAT]), V128_XOR(c[7 * MAX_REPEAT], k[14 * MAX_REPEAT]), V128_XOR(c[23 * MAX_REPEAT], k[1 * MAX_REPEAT]), V128_XOR(c[13 * MAX_REPEAT], k[16 * MAX_REPEAT]), V128_XOR(c[31 * MAX_REPEAT], k[45 * MAX_REPEAT]), &c[48 * MAX_REPEAT]);
								s6_sse2(V128_XOR(c[13 * MAX_REPEAT], k[7 * MAX_REPEAT]), V128_XOR(c[31 * MAX_REPEAT], k[22 * MAX_REPEAT]), V128_XOR(c[26 * MAX_REPEAT], k[44 * MAX_REPEAT]), V128_XOR(c[2 * MAX_REPEAT], k[2 * MAX_REPEAT]), V128_XOR(c[8 * MAX_REPEAT], k[28 * MAX_REPEAT]), V128_XOR(c[18 * MAX_REPEAT], k[23 * MAX_REPEAT]), &c[52 * MAX_REPEAT]);
								s7_sse2(V128_XOR(c[8 * MAX_REPEAT], k[50 * MAX_REPEAT]), V128_XOR(c[18 * MAX_REPEAT], k[30 * MAX_REPEAT]), V128_XOR(c[12 * MAX_REPEAT], k[15 * MAX_REPEAT]), V128_XOR(c[29 * MAX_REPEAT], k[52 * MAX_REPEAT]), V128_XOR(c[5 * MAX_REPEAT], k[35 * MAX_REPEAT]), V128_XOR(c[21 * MAX_REPEAT], k[31 * MAX_REPEAT]), &c[56 * MAX_REPEAT]);
								s8_sse2(V128_XOR(c[5 * MAX_REPEAT], k[9 * MAX_REPEAT]), V128_XOR(c[21 * MAX_REPEAT], k[36 * MAX_REPEAT]), V128_XOR(c[10 * MAX_REPEAT], k[37 * MAX_REPEAT]), V128_XOR(c[3 * MAX_REPEAT], k[49 * MAX_REPEAT]), V128_XOR(c[24 * MAX_REPEAT], k[0 * MAX_REPEAT]), V128_XOR(c[15 * MAX_REPEAT], k[21 * MAX_REPEAT]), &c[60 * MAX_REPEAT]);
							}END_REPEAT;
						}

						{// compare bit to bit
							int j_index = (j / V128_BIT_LENGHT) * 4 + ((j >> 5) & 3);
							for (; i < 64; i++)
							{
								uint32_t val = ((uint32_t*)c)[i*MAX_REPEAT * 4 + j_index];

								if (((val >> (j & 31)) & 1) != ((bin[i >> 3] >> (i & 7)) & 1))
									goto next_iteration;
							}
						}

						// Total match
						{
							unsigned char key[8];
							memset(key, 0, sizeof(key));
							int j_index = (j / V128_BIT_LENGHT) * 4 + ((j >> 5) & 3);

							for (i = 0; i < 56; i++)
							{
								uint32_t lane = ((uint32_t*)k)[(55 - i)*MAX_REPEAT * 4 + j_index];

								if ((lane >> (j & 31)) & 1)
									key[i / 8] |= (128 >> (i % 8));
							}

							password_was_found(index, key);
						}
					next_iteration:
						index = same_hash_next[index];
					}
				}
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
#ifdef ANDROID
	#define LM_BEGIN_USE_HASHTABLE	TRUE
#else
	#define LM_BEGIN_USE_HASHTABLE	(num_passwords_loaded>50)
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// SBoxs definition to generate code
/////////////////////////////////////////////////////////////////////////////////////////////////////////
#define reg_a0 0
#define reg_a1 1
#define reg_a2 2
#define reg_a3 3
#define reg_a4 4
#define reg_a5 5
#define reg_x0 6
#define reg_x1 7
#define reg_x2 8
#define reg_x3 9
#define reg_x4 10
#define reg_x5 11
#define reg_x6 12
#define reg_x7 13
#define reg_x8 14
#define reg_x9 15
#define reg_out0 16
#define reg_out1 17
#define reg_out2 18
#define reg_out3 19

#define op_lop3			'3'
#define op_bs			'b'
#define op_xor			'^'
#define op_or			'|'
#define op_not			'~'
#define op_and			'&'
#define op_nop			'n'
#define op_load_param	'l'
#define op_store_shared	's'
#define op_load_shared	'c'

typedef struct LM_Instruction
{
	char reg_result;
	char operation;
	char operand1;
	char operand2;
	char operand3;
	uint8_t immLut;
}
LM_Instruction;

typedef struct LM_SBox
{
	int lenght;
	LM_Instruction* instructions;
}
LM_SBox;

// --------------------------------------------------------------------------------------------------
// Sboxs using standard instructions
// Gate counts: 62 55 59 43 59 56 56 49
// Average: 55.125
// --------------------------------------------------------------------------------------------------
/* s1-00484, 49 gates, 17 regs, 11 andn, 4/9/39/79/120 stalls, 74 biop */
// Now 62 reg_x 7
PRIVATE LM_Instruction s1_code_std[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0, op_not, reg_a4},
	{reg_x2, op_or, reg_a2, reg_a5},
	{reg_x0, op_and, reg_a0, reg_x0},
	{reg_x3, op_xor, reg_a0, reg_a2},
	{reg_x1, op_xor, reg_a3, reg_x0},
	{reg_x4, op_and, reg_x2, reg_x3},
	{reg_x6, op_not, reg_x1},
	{reg_a1, op_xor, reg_a3, reg_x4},
	{reg_x7, op_xor, reg_a4, reg_a5},
	{reg_x6, op_and, reg_a1, reg_x6},
	{reg_a2, op_not, reg_a2},
	{reg_x5, op_xor, reg_a2, reg_x7},
	{reg_x4, op_or, reg_a5, reg_x4},
	{reg_x5, op_and, reg_x1, reg_x5},
	{reg_x0, op_or, reg_a2, reg_x0},
	{reg_x4, op_xor, reg_x5, reg_x4},
	{reg_a5, op_or, reg_a0, reg_a5},
	{reg_x5, op_not, reg_x6},
	{reg_a2, op_or, reg_x4, reg_a5},
	{reg_x5, op_and, reg_x4, reg_x5},
	{reg_a1, op_not, reg_a1},
	{reg_a5, op_not, reg_a5},
	{reg_a1, op_and, reg_a4, reg_a1},
	{reg_a5, op_and, reg_a3, reg_a5},
	{reg_x3, op_not, reg_x3},
	{reg_a3, op_xor, reg_a2, reg_a1},
	{reg_a5, op_xor, reg_a1, reg_a5},
	{reg_x3, op_and, reg_x7, reg_x3},
	{reg_x4, op_and, reg_x2, reg_x4},
	{reg_a5, op_or, reg_a5, reg_x3},
	{reg_x3, op_xor, reg_x1, reg_a2},
	{reg_a2, op_xor, reg_x2, reg_a2},
	{reg_x0, op_and, reg_x3, reg_x0},
	{reg_a2, op_or, reg_a5, reg_a2},
	{reg_x3, op_not, reg_x0},
	{reg_x0, op_xor, reg_x7, reg_x0},
	{reg_x4, op_xor, reg_x3, reg_x4},
	{reg_x0, op_or, reg_a1, reg_x0},//reg_a1
	{reg_a4, op_or, reg_a4, reg_x1},//x1
	{reg_a1, op_load_param, reg_x1},
	{reg_x3, op_not, reg_a1},
	{reg_x0, op_xor, reg_x2, reg_x0},
	{reg_x3, op_and, reg_a3, reg_x3},//a3
	{reg_a0, op_xor, reg_a0, reg_x0},// x0
	{reg_x3, op_xor, reg_x3, reg_x4},
	{reg_x6, op_or, reg_x6, reg_a1},
	{reg_x4, op_xor, reg_x4, reg_a0},
	{reg_out2, op_xor, reg_x3, reg_out2, reg_x0},//x3
	{reg_x6, op_xor, reg_x6, reg_x4},
	{reg_x2, op_xor, reg_a0, reg_a2},
	{reg_x4, op_or, reg_x7, reg_x4},//x7
	{reg_a0, op_and, reg_x5, reg_a0},
	{reg_x4, op_xor, reg_x2, reg_x4},
	{reg_out0, op_xor, reg_x6, reg_out0, reg_x0},
	{reg_x2, op_not, reg_x2},
	{reg_x6, op_or, reg_x5, reg_a1},//reg_x5
	{reg_x2, op_and, reg_a4, reg_x2},//a4
	{reg_x4, op_xor, reg_x6, reg_x4},//x6
	{reg_a0, op_xor, reg_x2, reg_a0},//x2
	{reg_out1, op_xor, reg_x4, reg_out1, reg_x0},//x4
	{reg_a1, op_or, reg_a0, reg_a1},//a0
	{reg_a1, op_xor, reg_a1, reg_a5},//a5
	{reg_out3, op_xor, reg_a1, reg_out3, reg_x0}//a1
};
/* s2-016276, 44 gates, 15 regs, 11 andn, 1/9/24/59/104 stalls, 67 biop */
// Now 55 reg_x 7
PRIVATE LM_Instruction s2_code_std[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0, op_xor, reg_a1, reg_a4},
	{reg_x7, op_not, reg_a0},
	{reg_x1, op_or, reg_x7, reg_a5},
	{reg_x1, op_and, reg_a4, reg_x1},
	{reg_x2, op_or, reg_a1, reg_x1},
	{reg_x3, op_not, reg_a5},
	{reg_x3, op_and, reg_x0, reg_x3},
	{reg_x4, op_and, reg_a0, reg_x0},
	{reg_a4, op_xor, reg_a4, reg_x4},
	{reg_x5, op_not, reg_x3},
	{reg_x5, op_and, reg_a4, reg_x5},
	{reg_x5, op_or, reg_x5, reg_a3},
	{reg_x4, op_and, reg_a2, reg_a5},
	{reg_x1, op_xor, reg_x1, reg_x3},
	{reg_x1, op_and, reg_x2, reg_x1},
	{reg_x3, op_not, reg_x1},
	{reg_x3, op_or, reg_x3, reg_x4},
	{reg_x6, op_and, reg_a2, reg_x1},
	{reg_a0, op_xor, reg_x6, reg_x7},
	{reg_a5, op_xor, reg_a5, reg_x0},
	{reg_x7, op_not, reg_a5},
	{reg_x7, op_or, reg_x7, reg_x4},
	{reg_a1, op_and, reg_a1, reg_x7},//x7
	{reg_x7, op_not, reg_x7},
	{reg_x7, op_xor, reg_a0, reg_x7},
	{reg_x3, op_and, reg_a3, reg_x3},
	{reg_x3, op_xor, reg_x3, reg_x7},
	{reg_a4, op_xor, reg_a4, reg_a1},
	{reg_x6, op_xor, reg_x6, reg_a1},//a1
	{reg_out1, op_xor, reg_x3, reg_out1, reg_a1},
	{reg_a4, op_not, reg_a4},
	{reg_x3, op_and, reg_a0, reg_a4},
	{reg_a2, op_xor, reg_a2, reg_a5},
	{reg_x3, op_xor, reg_x3, reg_a2},
	{reg_a0, op_not, reg_a3},
	{reg_a0, op_and, reg_x2, reg_a0},
	{reg_a0, op_xor, reg_a0, reg_x3},
	{reg_out0, op_xor, reg_a0, reg_out0, reg_a1},//a0
	{reg_a2, op_or, reg_a2, reg_x6},
	{reg_x2, op_xor, reg_x2, reg_x7},
	{reg_x4, op_or, reg_x4, reg_x2},
	{reg_x6, op_xor, reg_a2, reg_x4},
	{reg_x1, op_xor, reg_x1, reg_x7},//x8
	{reg_x1, op_xor, reg_x3, reg_x1},
	{reg_x1, op_and, reg_x4, reg_x1},//x4
	{reg_a2, op_and, reg_x0, reg_a2},//x0
	{reg_a2, op_xor, reg_x1, reg_a2},//x1
	{reg_x3, op_or, reg_a2, reg_a3},
	{reg_x6, op_xor, reg_x3, reg_x6},
	{reg_out2, op_xor, reg_x6, reg_out2, reg_a1},
	{reg_a4, op_and, reg_a2, reg_a4},//a2
	{reg_a5, op_or, reg_a5, reg_x2},//x2
	{reg_a4, op_xor, reg_a4, reg_a5},//a5
	{reg_x5, op_xor, reg_x5, reg_a4},//a4
	{reg_out3, op_xor, reg_x5, reg_out3, reg_a1}//a3
};
/* s3-001117, 46 gates, 17 regs, 10 andn, 2/4/19/47/92 stalls, 69 biop */
// Now 59 reg_x 7
PRIVATE LM_Instruction s3_code_std[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0, op_not, reg_a1},// repeted below
	{reg_x0, op_and, reg_a0, reg_x0},
	{reg_x1, op_xor, reg_a2, reg_a5},
	{reg_x2, op_or, reg_x0, reg_x1},
	{reg_x3, op_xor, reg_a3, reg_a5},
	{reg_x4, op_not, reg_a0},
	{reg_x4, op_and, reg_x3, reg_x4},
	{reg_x5, op_xor, reg_x2, reg_x4},
	{reg_x6, op_xor, reg_a1, reg_x1},
	{reg_x7, op_not, reg_a5},
	{reg_x7, op_and, reg_x6, reg_x7},
	{reg_x2, op_xor, reg_x2, reg_x7},
	{reg_x7, op_not, reg_x5},
	{reg_x7, op_or, reg_x7, reg_x2},
	{reg_x1, op_and, reg_x1, reg_x3},
	{reg_x3, op_and, reg_a5, reg_x5},
	{reg_x3, op_or, reg_a3, reg_x3},
	{reg_x3, op_and, reg_a0, reg_x3},
	{reg_x3, op_xor, reg_x6, reg_x3},
	{reg_a4, op_xor, reg_a0, reg_a3},
	{reg_x4, op_or, reg_x4, reg_a4},
	{reg_a4, op_xor, reg_x2, reg_a4},
	{reg_a4, op_or, reg_a2, reg_a4},
	{reg_x1, op_not, reg_x1},
	{reg_x1, op_and, reg_a4, reg_x1},
	{reg_a4, op_not, reg_x4},
	{reg_a4, op_and, reg_x3, reg_a4},
	{reg_a5, op_and, reg_a3, reg_a5},
	{reg_a2, op_or, reg_a1, reg_a2},
	{reg_a1, op_not, reg_a1},
	{reg_a1, op_and, reg_a5, reg_a1},
	{reg_a1, op_xor, reg_a4, reg_a1},//reg_a4
	{reg_x2, op_and, reg_x2, reg_a1},
	{reg_a5, op_or, reg_x6, reg_a5},
	{reg_x2, op_not, reg_x2},
	{reg_a5, op_and, reg_a5, reg_x2},//x2
	{reg_a4, op_load_param, reg_x2},
	{reg_x7, op_and, reg_a4, reg_x7},
	{reg_x2, op_not, reg_a4},
	{reg_x2, op_and, reg_x5, reg_x2},
	{reg_x2, op_xor, reg_x2, reg_x3},
	{reg_a0, op_xor, reg_a0, reg_a5},
	{reg_out3, op_xor, reg_x2, reg_out3, reg_a5},
	{reg_x1, op_and, reg_x1, reg_a4},
	{reg_x1, op_xor, reg_x1, reg_a0},
	{reg_out1, op_xor, reg_x1, reg_out1, reg_a5},//x1
	{reg_x5, op_not, reg_x5},
	{reg_a2, op_or, reg_a2, reg_x5},
	{reg_a2, op_xor, reg_x6, reg_a2},//x6
	{reg_x4, op_xor, reg_x4, reg_a2},
	{reg_x4, op_xor, reg_x7, reg_x4},//x7---------
	{reg_out0, op_xor, reg_x4, reg_out0, reg_a5},//x4
	{reg_a3, op_and, reg_a3, reg_x5},//x5
	{reg_a3, op_xor, reg_x3, reg_a3},//reg_x3
	{reg_a3, op_or, reg_a2, reg_a3},//a2
	{reg_a0, op_xor, reg_x0, reg_a0},//x0
	{reg_a3, op_xor, reg_a3, reg_a0},//a0
	{reg_a4, op_or, reg_a1, reg_a4},//x3
	{reg_a4, op_xor, reg_a4, reg_a3},//a3
	{reg_out2, op_xor, reg_a4, reg_out2, reg_a5}//a4
};
/* s4, 33 gates, 11/12 regs, 9 andn, 2/21/53/86/119 stalls, 52 biop */
// Now 43 reg_x 3
PRIVATE LM_Instruction s4_code_std[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_a0, op_xor, reg_a0, reg_a2},//a0
	{reg_a2, op_xor, reg_a2, reg_a4},//a2
	{reg_x1, op_not, reg_a1},
	{reg_x0, op_xor, reg_x1, reg_a3},
	{reg_x1, op_and, reg_a2, reg_x1},
	{reg_x2, op_xor, reg_a3, reg_x1},
	{reg_a3, op_or, reg_a1, reg_a3},//a3
	{reg_a3, op_xor, reg_a4, reg_a3},
	{reg_x1, op_or, reg_a4, reg_x1},//a4
	{reg_a3, op_not, reg_a3},
	{reg_a3, op_and, reg_a2, reg_a3},
	{reg_x3, op_or, reg_a0, reg_x2},
	{reg_a4, op_not, reg_a3},
	{reg_a4, op_and, reg_x3, reg_a4},
	{reg_a1, op_xor, reg_a1, reg_a4},//a1
	{reg_x2, op_and, reg_x2, reg_a1},
	{reg_x3, op_not, reg_a2},//a2
	{reg_x3, op_or, reg_x3, reg_x2},
	{reg_a0, op_xor, reg_a0, reg_a1},
	{reg_x3, op_and, reg_a0, reg_x3},
	{reg_x3, op_xor, reg_a3, reg_x3},//a3
	{reg_x1, op_xor, reg_a0, reg_x1},//a0
	{reg_a0, op_and, reg_x1, reg_x0},
	{reg_a0, op_xor, reg_a4, reg_a0},
	{reg_a3, op_not, reg_x3},
	{reg_a3, op_and, reg_a5, reg_a3},
	{reg_a3, op_xor, reg_a3, reg_a0},
	{reg_out0, op_xor, reg_a3, reg_out0, reg_a2},
	{reg_a0, op_not, reg_a0},
	{reg_a4, op_or, reg_a1, reg_a5},
	{reg_a1, op_and, reg_a1, reg_a5},
	{reg_a5, op_not, reg_a5},
	{reg_a5, op_and, reg_x3, reg_a5},//a5
	{reg_a5, op_xor, reg_a5, reg_a0},
	{reg_out1, op_xor, reg_a5, reg_out1, reg_a2},//a5
	{reg_a0, op_xor, reg_x3, reg_a0},//x3
	{reg_x0, op_and, reg_a0, reg_x0},//x6
	{reg_x0, op_or, reg_x2, reg_x0},//x2
	{reg_x0, op_xor, reg_x1, reg_x0},//x1
	{reg_a4, op_xor, reg_a4, reg_x0},
	{reg_out2, op_xor, reg_a4, reg_out2, reg_a2},
	{reg_x0, op_xor, reg_a1, reg_x0},
	{reg_out3, op_xor, reg_x0, reg_out3, reg_a2}
};
/* s5-04829, 48 gates, 15/16 regs, 9 andn, 4/24/65/113/163 stalls, 72 biop */
// Now 59 reg_x 7
PRIVATE LM_Instruction s5_code_std[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0, op_or, reg_a0, reg_a2},
	{reg_x1, op_not, reg_a5},
	{reg_x1, op_and, reg_x0, reg_x1},
	{reg_x2, op_not, reg_a3},
	{reg_x2, op_and, reg_x1, reg_x2},
	{reg_x1, op_xor, reg_a0, reg_x1},
	{reg_x2, op_xor, reg_a2, reg_x2},
	{reg_a2, op_xor, reg_a2, reg_x1},//a2
	{reg_x4, op_or, reg_a3, reg_a2},
	{reg_x5, op_and, reg_a4, reg_x2},
	{reg_a2, op_or, reg_a0, reg_a2},
	{reg_x5, op_xor, reg_x5, reg_a2},
	{reg_x5, op_xor, reg_a3, reg_x5},
	{reg_a5, op_xor, reg_a5, reg_x5},//a5
	{reg_a1, op_or, reg_x1, reg_a5},
	{reg_x0, op_xor, reg_a0, reg_x0},
	{reg_a0, op_not, reg_a0},
	{reg_a0, op_and, reg_a1, reg_a0},
	{reg_x3, op_and, reg_a3, reg_a2},
	{reg_x3, op_xor, reg_x1, reg_x3},
	{reg_x7, op_xor, reg_x2, reg_a0},
	{reg_a1, op_and, reg_a4, reg_a1},
	{reg_a4, op_xor, reg_a4, reg_x4},
	{reg_a0, op_xor, reg_a0, reg_a4},
	{reg_x3, op_xor, reg_x3, reg_a1},
	{reg_a0, op_or, reg_x3, reg_a0},
	{reg_a2, op_and, reg_x2, reg_a2},
	{reg_x6, op_not, reg_x2},
	{reg_x6, op_or, reg_x6, reg_a1},
	{reg_a0, op_and, reg_a0, reg_x6},
	{reg_a5, op_and, reg_a5, reg_a0},
	{reg_x0, op_xor, reg_a0, reg_x0},
	{reg_a0, op_not, reg_a0},
	{reg_a0, op_and, reg_x4, reg_a0},
	{reg_a5, op_xor, reg_a4, reg_a5},
	{reg_a2, op_or, reg_a5, reg_a2},
	{reg_a2, op_xor, reg_a1, reg_a2},//reg_a1
	{reg_a1, op_load_param, reg_x6},
	{reg_a2, op_and, reg_a2, reg_a1},
	{reg_a2, op_xor, reg_a2, reg_x3},//x3
	{reg_out3, op_xor, reg_a2, reg_out3, reg_x6},//x6
	{reg_a3, op_and, reg_a3, reg_a5},//a3
	{reg_x0, op_xor, reg_x0, reg_a3},
	{reg_a0, op_or, reg_a0, reg_a1},
	{reg_a0, op_xor, reg_a0, reg_x0},
	{reg_out0, op_xor, reg_a0, reg_out0, reg_x6},
	{reg_x2, op_xor, reg_x4, reg_x2},
	{reg_x0, op_not, reg_x0},
	{reg_x0, op_and, reg_x2, reg_x0},
	{reg_x1, op_xor, reg_x1, reg_a5},
	{reg_x0, op_xor, reg_x0, reg_x1},
	{reg_x4, op_and, reg_x4, reg_a1},//a1
	{reg_a1, op_not, reg_a1},
	{reg_x1, op_not, reg_a4},
	{reg_x7, op_or, reg_x1, reg_x7},
	{reg_x7, op_and, reg_a1, reg_x7},
	{reg_x5, op_xor, reg_x7, reg_x5},//x7
	{reg_out2, op_xor, reg_x5, reg_out2, reg_x6},//x5
	{reg_x0, op_xor, reg_x4, reg_x0},
	{reg_out1, op_xor, reg_x0, reg_out1, reg_x6}
};
/* s6-000007, 46 gates, 19 regs, 8 andn, 3/19/39/66/101 stalls, 69 biop */
// Now 56 reg_x 7
PRIVATE LM_Instruction s6_code_std[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0, op_xor, reg_a1, reg_a4},
	{reg_x1, op_or, reg_a1, reg_a5},
	{reg_x1, op_and, reg_a0, reg_x1},
	{reg_x0, op_xor, reg_x0, reg_x1},
	{reg_x2, op_xor, reg_a5, reg_x0},
	{reg_x3, op_and, reg_a0, reg_x2},
	{reg_x2, op_not, reg_x2},
	{reg_x2, op_and, reg_a4, reg_x2},
	{reg_x4, op_xor, reg_a1, reg_x3},
	{reg_x3, op_xor, reg_a5, reg_x3},
	{reg_x5, op_xor, reg_a0, reg_a2},
	{reg_x6, op_or, reg_x4, reg_x5},
	{reg_x4, op_or, reg_x2, reg_x4},
	{reg_x5, op_or, reg_a1, reg_x5},
	{reg_a1, op_xor, reg_a1, reg_x6},
	{reg_x6, op_xor, reg_x0, reg_x6},
	{reg_a1, op_not, reg_a1},
	{reg_a3, op_and, reg_a5, reg_a1},
	{reg_a3, op_xor, reg_a2, reg_a3},
	{reg_a2, op_and, reg_a2, reg_x6},
	{reg_a5, op_not, reg_a5},
	{reg_a5, op_and, reg_a2, reg_a5},
	{reg_x7, op_xor, reg_a0, reg_a3},
	{reg_a0, op_or, reg_a0, reg_x6},
	{reg_a0, op_and, reg_x4, reg_a0},
	{reg_x4, op_xor, reg_a5, reg_x4},
	{reg_a1, op_xor, reg_x5, reg_a1},
	{reg_x5, op_xor, reg_x4, reg_x5},
	{reg_a0, op_xor, reg_a3, reg_a0},
	{reg_a5, op_not, reg_a5},
	{reg_a5, op_and, reg_a0, reg_a5},
	{reg_x0, op_xor, reg_x0, reg_a0},
	{reg_x0, op_not, reg_x0},
	{reg_x0, op_and, reg_a4, reg_x0},
	{reg_x0, op_xor, reg_x0, reg_a1},
	{reg_a1, op_xor, reg_a2, reg_a1},
	{reg_a2, op_not, reg_a2},
	{reg_a2, op_and, reg_a4, reg_a2},//a4
	{reg_a2, op_or, reg_a3, reg_a2},//reg_a3
	{reg_a3, op_load_param, reg_a4},
	{reg_x4, op_and, reg_x4, reg_a3},
	{reg_x4, op_xor, reg_x4, reg_x6},//x6
	{reg_out3, op_xor, reg_x4, reg_out3, reg_a4},//reg_x4
	{reg_x2, op_or, reg_x2, reg_a3},
	{reg_x2, op_xor, reg_x2, reg_a5},//a5
	{reg_out2, op_xor, reg_x2, reg_out2, reg_a4},//x2
	{reg_x1, op_or, reg_x1, reg_a2},
	{reg_x1, op_xor, reg_x5, reg_x1},//x5
	{reg_a3, op_not, reg_a3},
	{reg_x0, op_and, reg_x0, reg_a3},//x0
	{reg_x1, op_xor, reg_x0, reg_x1},
	{reg_out1, op_xor, reg_x1, reg_out1, reg_a4},//x1
	{reg_x3, op_and, reg_x3, reg_x7},
	{reg_x3, op_xor, reg_x3, reg_a1},//a1
	{reg_a3, op_and, reg_a2, reg_a3},//a3
	{reg_x3, op_xor, reg_a3, reg_x3},
	{reg_out0, op_xor, reg_x3, reg_out0, reg_a4}//x3
};
/* s7-056945, 46 gates, 16 regs, 7 andn, 10/31/62/107/156 stalls, 67 biop */
/* Currently used for MMX/SSE2 */
// Now 56 reg_x 7
PRIVATE LM_Instruction s7_code_std[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},
	
	{reg_x0, op_xor, reg_a3, reg_a4},
	{reg_x1, op_xor, reg_a2, reg_x0},
	{reg_x2, op_and, reg_a5, reg_x1},
	{reg_x3, op_and, reg_a3, reg_x0},
	{reg_x4, op_xor, reg_a1, reg_x3},
	{reg_x5, op_and, reg_x2, reg_x4},
	{reg_x6, op_and, reg_a5, reg_x3},
	{reg_x6, op_xor, reg_a2, reg_x6},
	{reg_x7, op_or, reg_x4, reg_x6},
	{reg_x0, op_xor, reg_a5, reg_x0},
	{reg_x7, op_xor, reg_x7, reg_x0},
	{reg_x5, op_not, reg_x5},
	{reg_x5, op_and, reg_a0, reg_x5},
	{reg_x5, op_xor, reg_x5, reg_x7},
	{reg_x3, op_or, reg_x3, reg_x7},
	{reg_out3, op_xor, reg_x5, reg_out3, reg_x7},
	{reg_x7, op_not, reg_x1},
	{reg_x7, op_and, reg_a4, reg_x7},
	{reg_x5, op_or, reg_x4, reg_x7},
	{reg_x6, op_xor, reg_x2, reg_x6},
	{reg_x5, op_xor, reg_x5, reg_x6},
	{reg_x2, op_xor, reg_x2, reg_x0},
	{reg_a3, op_not, reg_a3},
	{reg_a3, op_or, reg_a3, reg_x2},
	{reg_a3, op_and, reg_x4, reg_a3},
	{reg_x6, op_xor, reg_a4, reg_x6},
	{reg_a3, op_xor, reg_a3, reg_x6},
	{reg_a2, op_and, reg_a2, reg_a3},
	{reg_x3, op_or, reg_x3, reg_a2},
	{reg_x0, op_not, reg_x0},
	{reg_x0, op_and, reg_x1, reg_x0},//reg_x1
	{reg_x0, op_xor, reg_x3, reg_x0},//reg_x3
	{reg_x2, op_not, reg_a0},
	{reg_x2, op_and, reg_x0, reg_x2},
	{reg_x2, op_xor, reg_x2, reg_x5},
	{reg_out0, op_xor, reg_x2, reg_out0, reg_x1},
	{reg_x4, op_or, reg_a3, reg_x0},
	{reg_a5, op_and, reg_a5, reg_x4},//reg_x4
	{reg_a1, op_and, reg_a1, reg_a5},
	{reg_x5, op_xor, reg_x5, reg_x0},
	{reg_a1, op_xor, reg_a1, reg_x5},
	{reg_a2, op_or, reg_a2, reg_a1},
	{reg_a2, op_xor, reg_a5, reg_a2},
	{reg_a4, op_xor, reg_a4, reg_x5},//reg_x5
	{reg_a2, op_or, reg_a2, reg_a4},//reg_a4
	{reg_x6, op_and, reg_a2, reg_a0},
	{reg_a3, op_xor, reg_x6, reg_a3},//reg_x6
	{reg_out2, op_xor, reg_a3, reg_out2, reg_x1},//reg_a3
	{reg_a2, op_xor, reg_a5, reg_a2},//reg_a5
	{reg_a2, op_or, reg_x7, reg_a2},//reg_x7
	{reg_x0, op_not, reg_x0},
	{reg_a2, op_xor, reg_a2, reg_x0},//reg_x0
	{reg_a0, op_not, reg_a0},
	{reg_a0, op_and, reg_a2, reg_a0},//reg_a2
	{reg_a0, op_xor, reg_a0, reg_a1},//reg_a1
	{reg_out1, op_xor, reg_a0, reg_out1, reg_x1}//reg_a0
};
/* s8-019374, 41 gates, 14 regs, 7 andn, 4/25/61/103/145 stalls, 59 biop */
/* Currently used for x86-64 SSE2 */
// Now 49 reg_x 6
PRIVATE LM_Instruction s8_code_std[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x6, op_not, reg_a2},
	{reg_x0, op_or, reg_x6, reg_a1},
	{reg_x1, op_and, reg_a4, reg_x6},
	{reg_x1, op_xor, reg_a3, reg_x1},
	{reg_x2, op_and, reg_a0, reg_x1},
	{reg_x1, op_not, reg_x1},
	{reg_x3, op_and, reg_a1, reg_x1},
	{reg_x4, op_or, reg_a0, reg_x3},
	{reg_x5, op_not, reg_x4},
	{reg_x5, op_and, reg_a2, reg_x5},
	{reg_a2, op_and, reg_a1, reg_x6},//a2
	{reg_a2, op_xor, reg_a4, reg_a2},
	{reg_x4, op_and, reg_x4, reg_a2},
	{reg_x1, op_xor, reg_x4, reg_x1},
	{reg_x1, op_xor, reg_x1, reg_x5},
	{reg_x6, op_not, reg_x0},
	{reg_x6, op_xor, reg_x6, reg_x1},
	{reg_x0, op_and, reg_x2, reg_x0},
	{reg_x2, op_or, reg_x2, reg_x4},
	{reg_x5, op_or, reg_x0, reg_a5},
	{reg_x5, op_xor, reg_x5, reg_x6},
	{reg_x6, op_xor, reg_a0, reg_x6},
	{reg_x4, op_and, reg_a4, reg_x6},
	{reg_x6, op_xor, reg_a4, reg_x6},//a4
	{reg_out1, op_xor, reg_x5, reg_out1, reg_a4},//x5----------
	{reg_x1, op_xor, reg_a1, reg_x1},
	{reg_x4, op_xor, reg_x4, reg_x1},
	{reg_x3, op_xor, reg_x3, reg_x4},
	{reg_x4, op_xor, reg_x2, reg_x4},
	{reg_x4, op_or, reg_a1, reg_x4},//a1
	{reg_x4, op_xor, reg_x4, reg_x6},//x6
	{reg_x2, op_and, reg_x2, reg_a5},
	{reg_x2, op_xor, reg_x2, reg_x4},
	{reg_out2, op_xor, reg_x2, reg_out2, reg_a4},
	{reg_a2, op_xor, reg_a2, reg_x3},//a2
	{reg_x1, op_or, reg_a3, reg_x1},
	{reg_x1, op_xor, reg_a2, reg_x1},
	{reg_a0, op_xor, reg_a0, reg_x1},//a0
	{reg_x1, op_xor, reg_x0, reg_x1},
	{reg_a0, op_and, reg_a0, reg_a5},
	{reg_a0, op_xor, reg_a0, reg_x3},
	{reg_out3, op_xor, reg_a0, reg_out3, reg_a4},
	{reg_a3, op_not, reg_a3},
	{reg_a3, op_and, reg_a2, reg_a3},//a3
	{reg_x4, op_and, reg_x4, reg_a3},//a3
	{reg_x4, op_xor, reg_x4, reg_x1},
	{reg_x4, op_or, reg_x4, reg_a5},//a5
	{reg_x4, op_xor, reg_x4, reg_x3},
	{reg_out0, op_xor, reg_x4, reg_out0, reg_a4}
};


// --------------------------------------------------------------------------------------------------
// Sboxs using bitselect
// Gate counts: 39 37 37 30 39 38 38 36
// Average: 36.75
// --------------------------------------------------------------------------------------------------
/* s1-000011, 36 gates, 16 regs, 10/37/74/111/148 stall cycles */
// Now 39 reg_x 8
PRIVATE LM_Instruction s1_code_bs[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},

	{reg_x0,	op_bs,	reg_a2, reg_a1,reg_a4},
	{reg_x1,	op_xor,	reg_a1, reg_a2},
	{reg_x2,	op_or,	reg_a0, reg_a3},
	{reg_x3,	op_xor,	reg_x1, reg_x2},
	{reg_x4,	op_bs,	reg_x1, reg_x3,reg_a4},
	{reg_x5,	op_bs,	reg_a4, reg_x0,reg_x3},
	{reg_x6,	op_xor,	reg_a3, reg_x5},
	{reg_a0,	op_xor,	reg_x6, reg_a0},
	{reg_x7,	op_bs,	reg_x6, reg_a0,reg_a4},
	{reg_x8,	op_bs,	reg_a0, reg_x2,reg_x0},
	{reg_x8,	op_xor,	reg_x4, reg_x8},
	{reg_x2,	op_bs,	reg_x2, reg_a0,reg_x8},
	{reg_a5,	op_bs,	reg_x0, reg_x3,reg_a0},
	{reg_x6,	op_bs,	reg_x3, reg_x6,reg_x2},
	{reg_x2,	op_bs,	reg_x2, reg_x8,reg_x7},
	{reg_x2,	op_xor,	reg_x0, reg_x2},
	{reg_a4,	op_bs,	reg_a4, reg_a5,reg_x2},
	{reg_x0,	op_bs,	reg_a3, reg_x0,reg_x2},
	{reg_x6,	op_xor,	reg_a4, reg_x6},
	{reg_a5,	op_bs,	reg_a0, reg_a5,reg_a2},
	{reg_x0,	op_bs,	reg_x6, reg_a5,reg_x0},
	{reg_a1,	op_bs,	reg_a5, reg_a1,reg_x3},
	{reg_x0,	op_not,	reg_x0},
	{reg_a5, op_load_param, reg_x3},
	{reg_x6,	op_bs,	reg_x0, reg_x6,reg_a5},
	{reg_out0,	op_xor,	reg_x6, reg_out0, reg_x3},//////
	{reg_a4,	op_bs,	reg_x0, reg_a2,reg_a4},
	{reg_a3,	op_bs,	reg_a4, reg_a3,reg_a1},
	{reg_x4,	op_bs,	reg_x7, reg_x4,reg_a3},
	{reg_a1,	op_bs,	reg_a1, reg_a0,reg_x5},
	{reg_x4,	op_xor,	reg_a1, reg_x4},
	{reg_x4,	op_bs,	reg_x4, reg_x2,reg_a5},
	{reg_x2,	op_xor,	reg_a3, reg_x2},
	{reg_x6,	op_bs,	reg_x2, reg_a0,reg_a5},
	{reg_out1,	op_xor,	reg_x6, reg_out1, reg_x3},
	{reg_out3,	op_xor,	reg_x4, reg_out3, reg_x3},
	{reg_a0,	op_xor,	reg_x2, reg_a0},
	{reg_a0,	op_bs,	reg_a2, reg_a0,reg_a3},
	{reg_a0,	op_bs,	reg_a0, reg_x1,reg_a1},
	{reg_a0,	op_bs,	reg_a0, reg_x8,reg_a5},
	{reg_out2,	op_xor,	reg_a0, reg_out2, reg_x3}
};
/* s2-000012, 33 gates, 17 regs, 5/17/51/86/121 stall cycles */
// Now 37 reg_x 9
PRIVATE LM_Instruction s2_code_bs[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0,	op_bs, reg_a0, reg_a2, reg_a5},
	{reg_x1,	op_bs, reg_a5, reg_x0, reg_a4},
	{reg_x2,	op_bs, reg_a2, reg_a3, reg_x1},
	{reg_x2,	op_xor, reg_a0, reg_x2},
	{reg_x3,	op_xor, reg_a4, reg_a5},
	{reg_x4,	op_xor, reg_x2, reg_x3},
	{reg_x5,	op_bs, reg_a3, reg_x2, reg_a5},
	{reg_x6,	op_not, reg_x5},
	{reg_x0,	op_xor, reg_x0, reg_x6},
	{reg_x7,	op_xor, reg_x3, reg_x0},
	{reg_x7,	op_bs, reg_x7, reg_x4, reg_a1},
	{reg_out1,	op_xor, reg_x7, reg_out1, reg_x8},
	{reg_x8,	op_xor, reg_a3, reg_x1},
	{reg_x7,	op_bs, reg_x2, reg_a5, reg_x3},
	{reg_x2,	op_bs, reg_x2, reg_x4, reg_x0},
	{reg_x4,	op_bs, reg_x4, reg_x0, reg_a0},
	{reg_x9,	op_bs, reg_x0, reg_x8, reg_x7},//--x9
	{reg_x0,	op_bs, reg_x0, reg_x8, reg_a4},
	{reg_x8,	op_xor, reg_a2, reg_x8},
	{reg_x0,	op_bs, reg_x0, reg_x8, reg_a0},//a0,reg_x8
	{reg_a3,	op_bs, reg_a3, reg_x0, reg_a4},
	{reg_x6,	op_xor, reg_x6, reg_x2},
	{reg_x6,	op_xor, reg_a3, reg_x6},
	{reg_a0,	op_bs, reg_x6, reg_x0, reg_a1},
	{reg_out0,	op_xor, reg_a0, reg_out0, reg_x8},//reg_a0//////
	{reg_x3,	op_bs, reg_x0, reg_x6, reg_x3},
	{reg_x3,	op_bs, reg_x3, reg_x4, reg_x7},
	{reg_x2,	op_bs, reg_x2, reg_x6, reg_x0},//reg_x6,reg_x0
	{reg_a2,	op_bs, reg_x4, reg_a2, reg_x1},//reg_x1
	{reg_a4,	op_bs, reg_x2, reg_a2, reg_a4},//reg_x2
	{reg_a4,	op_bs, reg_x9, reg_a4, reg_a1},//reg_x9
	{reg_out3,	op_xor, reg_a4, reg_out3, reg_x8},//reg_a4
	{reg_x4,	op_bs, reg_x4, reg_a3, reg_a5},//reg_a3,reg_a5
	{reg_x4,	op_bs, reg_x5, reg_x3, reg_x4},//reg_x5
	{reg_x4,	op_xor, reg_a2, reg_x4},//reg_a2
	{reg_x4,	op_bs, reg_x3, reg_x4, reg_a1},//reg_a1,reg_x3
	{reg_out2,	op_xor, reg_x4, reg_out2, reg_x8}//reg_x4
};
// Now 37 reg_x 8
PRIVATE LM_Instruction s3_code_bs[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0,	op_bs,	reg_a3,reg_a2,reg_a4},
	{reg_x1,	op_xor, reg_a5,reg_x0},
	{reg_x4,	op_xor, reg_a1,reg_x1},
	{reg_x2,	op_bs,	reg_a2,reg_a5,reg_x4},
	{reg_x6,	op_bs,	reg_a4,reg_a2,reg_x1},
	{reg_x7,	op_bs,	reg_a4,reg_x1,reg_a1},
	{reg_x8,	op_bs,	reg_x6,reg_a3,reg_x7},
	{reg_x2,	op_xor, reg_x8,reg_x2},
	{reg_x5,	op_bs,	reg_x4,reg_x7,reg_a3},
	{reg_a2,	op_bs,	reg_x5,reg_x2,reg_a2},
	{reg_x8,	op_bs,	reg_a1,reg_x1,reg_x8},
	{reg_a1,	op_bs,	reg_a2,reg_a1,reg_a4},
	{reg_a2,	op_not, reg_a2},
	{reg_x3,	op_xor, reg_x6,reg_x2},
	{reg_x6,	op_xor, reg_a2,reg_x6},
	{reg_a2,	op_bs,	reg_x2,reg_a2,reg_a0},
	{reg_out1,	op_xor, reg_a2,reg_out1, reg_x9},
	{reg_x3,	op_bs,	reg_x3,reg_x8,reg_a1},
	{reg_x5,	op_bs,	reg_x6,reg_x5,reg_x4},
	{reg_x8,	op_xor, reg_x5,reg_x8},
	{reg_x0,	op_and, reg_x7,reg_x0},
	{reg_a4,	op_bs,	reg_a4,reg_a5,reg_x6},
	{reg_a2,	op_xor, reg_a1,reg_x8},
	{reg_x8,	op_bs,	reg_x6,reg_x8,reg_x2},//x6
	{reg_x7,	op_bs,	reg_a1,reg_x7,reg_a3},
	{reg_x8,	op_bs,	reg_x8,reg_x7,reg_a4},//x7
	{reg_x8,	op_bs,	reg_x8,reg_a2,reg_a0},//reg_a2
	{reg_out0,	op_xor, reg_x8,reg_out0, reg_x9},//x8
	{reg_x1,	op_bs,	reg_x5,reg_a1,reg_x1},
	{reg_a4,	op_bs,	reg_x1,reg_a4,reg_x0},//x1
	{reg_a4,	op_bs,	reg_x4,reg_a4,reg_a0},//x4
	{reg_out3,	op_xor, reg_a4,reg_out3, reg_x9},
	{reg_a1,	op_bs,	reg_x2,reg_a1,reg_x3},//x2
	{reg_a3,	op_bs,	reg_x5,reg_x0,reg_a3},//x0, x5
	{reg_a1,	op_xor, reg_a3,reg_a1},
	{reg_a0,	op_bs,	reg_a1,reg_x3,reg_a0},//a1
	{reg_out2,	op_xor, reg_a0,reg_out2, reg_x9}//a0
};
// Now 30 reg_x 6
PRIVATE LM_Instruction s4_code_bs[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0,	op_bs,	reg_a4,reg_a2,reg_a0},
	{reg_x6,	op_bs,	reg_x0,reg_a0,reg_a3},
	{reg_x5,	op_xor, reg_a2,reg_x6},
	{reg_x5,	op_bs,	reg_a0,reg_x5,reg_a1},
	{reg_x4,	op_bs,	reg_a2,reg_a4,reg_a0},
	{reg_x3,	op_xor, reg_a3,reg_x4},
	{reg_x2,	op_bs,	reg_x3,reg_a2,reg_a4},
	{reg_x5,	op_xor, reg_x2,reg_x5},
	{reg_a2,	op_not, reg_x5},
	{reg_x6,	op_bs,	reg_a3,reg_a1,reg_x6},
	{reg_a0,	op_xor, reg_x0,reg_a0},
	{reg_a4,	op_bs,	reg_a2,reg_x6,reg_a0},
	{reg_a4,	op_xor, reg_x4,reg_a4},
	{reg_x7,	op_not, reg_a4},
	{reg_a0,	op_bs,	reg_a0,reg_x7,reg_a3},
	{reg_x1,	op_bs,	reg_x2,reg_x3,reg_x4},
	{reg_x0,	op_bs,	reg_a2,reg_x1,reg_a1},
	{reg_a0,	op_xor, reg_x0,reg_a0},
	{reg_x5,	op_bs,	reg_a0,reg_x5,reg_a5},
	{reg_out2,	op_xor, reg_x5,reg_out2, reg_x0},
	{reg_a2,	op_bs,	reg_a2,reg_a0,reg_a5},
	{reg_out3,	op_xor, reg_a2,reg_out3, reg_x0},
	{reg_a0,	op_bs,	reg_a0,reg_x1,reg_a3},
	{reg_x2,	op_bs,	reg_x7,reg_x2,reg_a1},
	{reg_a1,	op_bs,	reg_x2,reg_a1,reg_x6},
	{reg_a0,	op_xor, reg_a1,reg_a0},
	{reg_x7,	op_bs,	reg_x7,reg_a0,reg_a5},
	{reg_out0,	op_xor, reg_x7,reg_out0, reg_x0},
	{reg_a0,	op_bs,	reg_a0,reg_a4,reg_a5},
	{reg_out1,	op_xor, reg_a0,reg_out1, reg_x0}
};
// Now 39 reg_x 8
PRIVATE LM_Instruction s5_code_bs[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_a3,	op_bs,	reg_a0,reg_a2,reg_a4},
	{reg_x1,	op_not, reg_a3},
	{reg_x2,	op_bs,	reg_x1,reg_a0,reg_a2},
	{reg_x2,	op_xor, reg_a1,reg_x2},
	{reg_x3,	op_xor, reg_a4,reg_a5},
	{reg_x4,	op_xor, reg_x2,reg_x3},
	{reg_a2,	op_bs,	reg_a2,reg_x1,reg_a1},
	{reg_x5,	op_bs,	reg_a1,reg_x4,reg_x2},
	{reg_x6,	op_bs,	reg_a5,reg_a3,reg_x5},
	{reg_x7,	op_bs,	reg_x6,reg_a4,reg_a0},
	{reg_x8,	op_xor, reg_a2,reg_x7},//--x8
	{reg_x0,	op_bs,	reg_x3,reg_x8,reg_x2},//--x9
	{reg_x1,	op_bs,	reg_x1,reg_x6,reg_x0},
	{reg_x0,	op_bs,	reg_a5,reg_a0,reg_x0},
	{reg_x5,	op_bs,	reg_x5,reg_a5,reg_x0},
	{reg_x0,	op_bs,	reg_x2,reg_x4,reg_x0},
	
	{reg_a0,	op_bs,	reg_x5,reg_a3,reg_a0},
	{reg_a3, op_load_param, reg_x6},
	{reg_x6,	op_xor, reg_x8,reg_x5},
	{reg_x8,	op_bs,	reg_x6,reg_x8,reg_a3},
	{reg_out2,	op_xor, reg_x8,reg_out2, reg_x9},//x8
	{reg_x8,	op_xor, reg_x1,reg_a0},//--x8
	{reg_x1,	op_bs,	reg_x2,reg_x6,reg_x1},//x6
	{reg_x6,	op_bs,	reg_x8,reg_x4,reg_a3},
	{reg_out1,	op_xor, reg_x6,reg_out1, reg_x9},
	{reg_x6,	op_bs,	reg_x8,reg_a0,reg_a5},
	{reg_x7,	op_bs,	reg_x6,reg_x7,reg_a1},
	{reg_a1,	op_bs,	reg_a2,reg_a1,reg_x4},
	{reg_a4,	op_bs,	reg_a4,reg_x8,reg_x4},//x4
	{reg_x8,	op_bs,	reg_x7,reg_a1,reg_x8},
	{reg_a2,	op_bs,	reg_a2,reg_x1,reg_a5},//a5
	{reg_x1,	op_bs,	reg_a4,reg_x1,reg_x7},
	{reg_a2,	op_bs,	reg_a2,reg_x0,reg_x6},//x6, x2, reg_x0
	{reg_a2,	op_bs,	reg_a2,reg_x1,reg_a3},//x1
	{reg_out0,	op_xor, reg_a2,reg_out0, reg_x9},//a2
	{reg_a1,	op_bs,	reg_x5,reg_x7,reg_a1},//x5, x7
	{reg_a0,	op_bs,	reg_a0,reg_x3,reg_a4},//x3, a4
	{reg_a0,	op_xor, reg_a1,reg_a0},//a1
	{reg_a0,	op_bs,	reg_x8,reg_a0,reg_a3},//x8, a3
	{reg_out3,	op_xor, reg_a0,reg_out3, reg_x9}//a0
};
// Now 38 reg_x 6
PRIVATE LM_Instruction s6_code_bs[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0,	op_bs,	reg_a0,reg_a3,reg_a4},
	{reg_x0,	op_xor, reg_a1,reg_x0},
	{reg_x1,	op_bs,	reg_x0,reg_a3,reg_a2},
	{reg_x1,	op_xor, reg_a0,reg_x1},
	{reg_x2,	op_xor, reg_a4,reg_x1},
	{reg_x3,	op_not, reg_x2},
	{reg_x4,	op_bs,	reg_x1,reg_x2,reg_a3},
	{reg_x5,	op_bs,	reg_a2,reg_a3,reg_x4},
	{reg_x0,	op_xor, reg_x5,reg_x0},
	{reg_x6,	op_xor, reg_x2,reg_x0},
	{reg_x1,	op_bs,	reg_a3,reg_x1,reg_x4},
	{reg_x5,	op_xor, reg_a2,reg_x1},
	{reg_a2,	op_bs,	reg_a2,reg_a3,reg_x6},
	{reg_x7,	op_bs,	reg_x5,reg_a2,reg_x0},
	{reg_a0,	op_bs,	reg_x6,reg_x5,reg_a0},
	{reg_x1,	op_bs,	reg_x1,reg_x4,reg_x0},
	{reg_x1,	op_bs,	reg_a0,reg_x1,reg_a2},
	{reg_x6,	op_bs,	reg_x6,reg_x1,reg_a5},
	{reg_out3,	op_xor, reg_x6,reg_out3, reg_x4},
	{reg_x4,	op_bs,	reg_x3,reg_a2,reg_x0},
	{reg_a4,	op_bs,	reg_a4,reg_x5,reg_x7},
	{reg_x4,	op_bs,	reg_x4,reg_x2,reg_a4},
	{reg_x6,	op_bs,	reg_x3,reg_x4,reg_a5},
	{reg_out0,	op_xor, reg_x6,reg_out0,reg_x5},
	{reg_a0,	op_bs,	reg_a0,reg_a2,reg_a1},
	{reg_x4,	op_xor, reg_a0,reg_x4},
	{reg_a3,	op_bs,	reg_a4,reg_a3,reg_x2},
	{reg_a3,	op_bs,	reg_x4,reg_a3,reg_x0},
	{reg_x3,	op_bs,	reg_a1,reg_x3,reg_x4},
	{reg_a0,	op_bs,	reg_a0,reg_x3,reg_a3},
	{reg_x6,	op_xor, reg_a1,reg_a0},
	{reg_x6,	op_bs,	reg_x7,reg_x6,reg_a5},
	{reg_out2,	op_xor, reg_x6,reg_out2,reg_x5},
	{reg_a1,	op_bs,	reg_a1,reg_x4,reg_x7},
	{reg_a0,	op_bs,	reg_a0,reg_a1,reg_x1},
	{reg_a0,	op_not, reg_a0},
	{reg_a0,	op_bs,	reg_a3,reg_a0,reg_a5},
	{reg_out1,	op_xor, reg_a0,reg_out1,reg_x5}
};
// Now 38 reg_x 6
PRIVATE LM_Instruction s7_code_bs[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0,	op_bs,	reg_a1,reg_a5,reg_a2},
	{reg_x0,	op_xor, reg_a3,reg_x0},
	{reg_x1,	op_bs,	reg_a2,reg_a4,reg_a1},
	{reg_x2,	op_bs,	reg_a5,reg_a1,reg_a3},
	{reg_x1,	op_bs,	reg_x1,reg_x2,reg_a4},
	{reg_x3,	op_xor, reg_x0,reg_x1},
	{reg_x4,	op_xor, reg_a4,reg_a5},
	{reg_x5,	op_xor, reg_a1,reg_a2},
	{reg_a2,	op_bs,	reg_a2,reg_x1,reg_a3},
	{reg_x6,	op_bs,	reg_x5,reg_a2,reg_x0},
	{reg_x6,	op_xor, reg_x4,reg_x6},
	{reg_x1,	op_bs,	reg_x6,reg_x3,reg_a0},
	{reg_out0,	op_xor, reg_x1,reg_out0, reg_x7},
	{reg_x7,	op_xor, reg_a1,reg_x6},
	{reg_x1,	op_bs,	reg_x7,reg_a4,reg_x5},
	{reg_x6,	op_bs,	reg_x6,reg_x1,reg_a5},
	{reg_x1,	op_bs,	reg_x0,reg_x7,reg_a5},
	{reg_x4,	op_bs,	reg_x1,reg_x5,reg_x4},
	{reg_x2,	op_xor, reg_x4,reg_x2},
	{reg_a1,	op_bs,	reg_x0,reg_x2,reg_a1},
	{reg_a4,	op_not, reg_a4},
	{reg_a4,	op_bs,	reg_a4,reg_x7,reg_a2},
	{reg_x1,	op_xor, reg_a1,reg_a4},
	{reg_x5,	op_xor, reg_x1,reg_x5},
	{reg_a1,	op_bs,	reg_x6,reg_x5,reg_a1},
	{reg_x6,	op_bs,	reg_x1,reg_x6,reg_a0},
	{reg_out1,	op_xor, reg_x6,reg_out1, reg_x4},
	{reg_a1,	op_bs,	reg_a1,reg_x3,reg_a4},
	{reg_a1,	op_bs,	reg_a1,reg_x2,reg_a0},
	{reg_out2,	op_xor, reg_a1,reg_out2, reg_x4},
	{reg_x0,	op_bs,	reg_x7,reg_x5,reg_x0},
	{reg_x5,	op_xor, reg_x7,reg_x5},
	{reg_a3,	op_bs,	reg_x0,reg_x5,reg_a3},
	{reg_a2,	op_bs,	reg_a2,reg_x0,reg_x1},
	{reg_a2,	op_bs,	reg_a3,reg_a2,reg_a5},
	{reg_a2,	op_not, reg_a2},
	{reg_a0,	op_bs,	reg_a3,reg_a2,reg_a0},
	{reg_out3,	op_xor, reg_a0,reg_out3, reg_x4}
};
// Now 36 reg_x 6
PRIVATE LM_Instruction s8_code_bs[] = {
	{reg_a0, op_load_param, reg_x0},
	{reg_a1, op_load_param, reg_x0},
	{reg_a2, op_load_param, reg_x0},
	{reg_a3, op_load_param, reg_x0},
	{reg_a4, op_load_param, reg_x0},
	{reg_a5, op_load_param, reg_x0},

	{reg_x0,	op_bs,	reg_a2,reg_a3,reg_a4},
	{reg_x1,	op_bs,	reg_a4,reg_a0,reg_a2},
	{reg_x1,	op_xor, reg_a3,reg_x1},
	{reg_x6,	op_bs,	reg_a1,reg_a4,reg_a0},
	{reg_x0,	op_bs,	reg_x1,reg_x0,reg_x6},
	{reg_x5,	op_xor, reg_a1,reg_x0},
	{reg_a3,	op_bs,	reg_x1,reg_a3,reg_a2},
	{reg_x6,	op_bs,	reg_a4,reg_a3,reg_a1},
	{reg_x4,	op_bs,	reg_a0,reg_x5,reg_x6},
	{reg_a2,	op_bs,	reg_a2,reg_a4,reg_a1},
	{reg_x3,	op_xor, reg_x4,reg_a2},
	{reg_x1,	op_bs,	reg_x5,reg_a4,reg_x1},
	{reg_a3,	op_bs,	reg_x1,reg_a0,reg_a3},
	{reg_x2,	op_xor, reg_x3,reg_a3},
	{reg_a4,	op_bs,	reg_a2,reg_x2,reg_a4},
	{reg_x1,	op_bs,	reg_x2,reg_x3,reg_a5},
	{reg_out2,	op_xor, reg_x1,reg_out2, reg_x8},
	{reg_x6,	op_xor, reg_a4,reg_x6},
	{reg_x1,	op_xor, reg_x5,reg_x6},
	{reg_x2,	op_not, reg_x1},
	{reg_a4,	op_bs,	reg_x0,reg_a1,reg_a4},
	{reg_x7,	op_bs,	reg_x2,reg_a4,reg_a3},
	{reg_x6,	op_xor, reg_x7,reg_x6},
	{reg_x5,	op_bs,	reg_x6,reg_x5,reg_a5},
	{reg_out1,	op_xor, reg_x5,reg_out1, reg_x8},
	{reg_a2,	op_bs,	reg_x4,reg_a2,reg_a4},
	{reg_a2,	op_bs,	reg_x0,reg_a2,reg_x3},
	{reg_a2,	op_xor, reg_x2,reg_a2},
	{reg_a2,	op_bs,	reg_x2,reg_a2,reg_a5},
	{reg_out3,	op_xor, reg_a2,reg_out3, reg_x8},
	{reg_a1,	op_bs,	reg_x0,reg_a1,reg_x3},
	{reg_a0,	op_or,	reg_a3,reg_a0},
	{reg_a0,	op_xor, reg_a1,reg_a0},
	{reg_a0,	op_xor, reg_x7,reg_a0},
	{reg_a0,	op_bs,	reg_a0,reg_x1,reg_a5},
	{reg_out0,	op_xor, reg_a0,reg_out0, reg_x8}
};
// --------------------------------------------------------------------------------------------------
// Sboxs using lop3
// Gate counts: 29 28 29 22 29 28 28 27
// Average: 27.5
// --------------------------------------------------------------------------------------------------
PRIVATE LM_Instruction s1_code_lop3[] = {
	{ reg_a0, op_load_param, reg_x0 },
	{ reg_a1, op_load_param, reg_x0 },
	{ reg_a2, op_load_param, reg_x0 },
	{ reg_a3, op_load_param, reg_x0 },
	{ reg_a4, op_load_param, reg_x0 },
	{ reg_a5, op_load_param, reg_x0 },

	{ reg_x0, op_lop3, reg_a0, reg_a3, reg_a5, 0xC1},
	{ reg_x1, op_lop3, reg_a2, reg_a5, reg_x0, 0x9E},
	{ reg_x2, op_lop3, reg_a0, reg_a2, reg_a5, 0xD6},
	{ reg_x3, op_lop3, reg_a3, reg_x0, reg_x2, 0x56},
	{ reg_x4, op_lop3, reg_a1, reg_x1, reg_x3, 0x6C},
	{ reg_x5, op_lop3, reg_a5, reg_x0, reg_x2, 0x7B},
	{ reg_x5, op_lop3, reg_a1, reg_x3, reg_x5, 0xD6},//x5
	{ reg_x7, op_lop3, reg_a4, reg_x4, reg_x5, 0x6A},
	{ reg_out2, op_xor, reg_x7, reg_out2, reg_x9},

	{ reg_x6, op_lop3, reg_a0, reg_a1, reg_a3, 0x7A},
	{ reg_x3, op_lop3, reg_a1, reg_a5, reg_x3, 0xC9},//x3
	{ reg_x7, op_lop3, reg_x4, reg_x6, reg_x3, 0x72},
	{ reg_x8, op_lop3, reg_a2, reg_a5, reg_x6, 0x29},
	{ reg_x9, op_lop3, reg_a1, reg_x4, reg_x8, 0x95},
	{ reg_a3, op_lop3, reg_a4, reg_x7, reg_x9, 0xC6},
	{ reg_out1, op_xor, reg_a3, reg_out1/*, reg_x10*/},// TODO: last var is needed if c_out is in local memory

	{ reg_x7, op_lop3, reg_a0, reg_a1, reg_x7, 0xD2},//x7
	{ reg_x6, op_lop3, reg_x4, reg_x6, reg_x3, 0x90},//x6
	{ reg_a3, op_lop3, reg_x8, reg_x7, reg_x6, 0x76},
	{ reg_x7, op_lop3, reg_a2, reg_x0, reg_x7, 0x80},//x7
	{ reg_x5, op_lop3, reg_x5, reg_x9, reg_x7, 0xA6},//x5,x9
	{ reg_x5, op_lop3, reg_a4, reg_a3, reg_x5, 0xA6},
	{ reg_x0, op_lop3, reg_a0, reg_x0, reg_x4, 0x21},//x0,x4
	{ reg_x0, op_lop3, reg_x1, reg_x6, reg_x0, 0x6A},//x1, x6
	{ reg_x4, op_lop3, reg_a0, reg_a5, reg_x3, 0x70},//x3
	{ reg_x4, op_lop3, reg_x2, reg_x8, reg_x4, 0x97},//x2,x8
	{ reg_x0, op_lop3, reg_a4, reg_x0, reg_x4, 0x6C},

	{ reg_out0, op_xor, reg_x0, reg_out0, reg_x9 },
	{ reg_out3, op_xor, reg_x5, reg_out3, reg_x9 }
};

PRIVATE LM_Instruction s2_code_lop3[] = {
	{ reg_a0, op_load_param, reg_x0 },
	{ reg_a1, op_load_param, reg_x0 },
	{ reg_a2, op_load_param, reg_x0 },
	{ reg_a3, op_load_param, reg_x0 },
	{ reg_a4, op_load_param, reg_x0 },
	{ reg_a5, op_load_param, reg_x0 },

	{ reg_x0, op_lop3, reg_a0, reg_a1, reg_a5, 0x97},
	{ reg_x1, op_lop3, reg_a4, reg_a5, reg_x0, 0x67},
	{ reg_x2, op_lop3, reg_a0, reg_a4, reg_a5, 0x76},
	{ reg_x3, op_lop3, reg_a1, reg_x1, reg_x2, 0x69},
	{ reg_x4, op_lop3, reg_a2, reg_x1, reg_x3, 0x6A},
	{ reg_x5, op_lop3, reg_a1, reg_a2, reg_a4, 0x65},
	{ reg_x0, op_lop3, reg_a2, reg_x0, reg_x2, 0x8D},//x0, x2
	{ reg_x2, op_lop3, reg_a0, reg_x5, reg_x0, 0xCA},
	{ reg_x7, op_lop3, reg_a3, reg_x4, reg_x2, 0xC6},
	{ reg_out2, op_xor, reg_x7, reg_out2, reg_x9 },

	{ reg_x6, op_lop3, reg_a1, reg_a4, reg_a5, 0x14},
	{ reg_x7, op_lop3, reg_a4, reg_x0, reg_x6, 0xB5},
	{ reg_x8, op_lop3, reg_a2, reg_a5, reg_x1, 0x1C},
	{ reg_x8, op_lop3, reg_a0, reg_x5, reg_x8, 0x96},//x5
	{ reg_x7, op_lop3, reg_a3, reg_x7, reg_x8, 0x6A},//x7
	{ reg_out1, op_xor, reg_x7, reg_out1, reg_x9 },

	{ reg_x5, op_lop3, reg_a0, reg_a1, reg_x3, 0xDE},//x3
	{ reg_x7, op_lop3, reg_a0, reg_a2, reg_x0, 0x90},
	{ reg_x3, op_lop3, reg_x4, reg_x8, reg_x5, 0x79},//x4
	{ reg_x4, op_lop3, reg_a4, reg_x7, reg_x3, 0x29},//x7, x3
	{ reg_x5, op_lop3, reg_a3, reg_x5, reg_x4, 0xA6},//x5, x4
	{ reg_x0, op_lop3, reg_a0, reg_a0, reg_x0, 0x4A},//x0
	{ reg_x6, op_lop3, reg_a1, reg_x6, reg_x8, 0xEF},//x6, x8
	{ reg_x0, op_lop3, reg_x2, reg_x0, reg_x6, 0x8D},//x2, x0
	{ reg_x1, op_lop3, reg_a1, reg_a4, reg_x1, 0x2B},//x1
	{ reg_x0, op_lop3, reg_a3, reg_x0, reg_x1, 0x6C},

	{ reg_out0, op_xor, reg_x5, reg_out0, reg_x9 },
	{ reg_out3, op_xor, reg_x0, reg_out3, reg_x9 }
};

PRIVATE LM_Instruction s3_code_lop3[] = {
	{ reg_a0, op_load_param, reg_x0 },
	{ reg_a1, op_load_param, reg_x0 },
	{ reg_a2, op_load_param, reg_x0 },
	{ reg_a3, op_load_param, reg_x0 },
	{ reg_a4, op_load_param, reg_x0 },
	{ reg_a5, op_load_param, reg_x0 },

	{ reg_x0, op_lop3, reg_a0, reg_a2, reg_a3, 0xC9},
	{ reg_x1, op_lop3, reg_a2, reg_a4, reg_a5, 0x4B},
	{ reg_x2, op_lop3, reg_a0, reg_x0, reg_x1, 0x4D},
	{ reg_x1, op_lop3, reg_a0, reg_a3, reg_x1, 0x69},//x1
	{ reg_x3, op_lop3, reg_a2, reg_a4, reg_x0, 0xD6},
	{ reg_x4, op_lop3, reg_a5, reg_x1, reg_x3, 0x9C},
	{ reg_x2, op_lop3, reg_a1, reg_x2, reg_x4, 0xA6},//x2
	{ reg_out0, op_xor, reg_x2, reg_out0, reg_x9 },

	{ reg_x2, op_lop3, reg_a0, reg_a3, reg_a5, 0x49},
	{ reg_x5, op_lop3, reg_a0, reg_a4, reg_x0, 0x9B},
	{ reg_x6, op_xor, reg_x2, reg_x5},//{ reg_x6, op_lop3, reg_a0, reg_x2, reg_x5, 0x66},
	
	{ reg_x7, op_lop3, reg_a0, reg_a2, reg_a5, 0x6F},
	{ reg_x8, op_lop3, reg_a3, reg_x6, reg_x7, 0xEB},
	{ reg_x8, op_lop3, reg_a1, reg_x6, reg_x8, 0x6C},//x6, x8
	{ reg_out3, op_xor, reg_x8, reg_out3, reg_x9 },

	{ reg_x6, op_lop3, reg_a0, reg_a2, reg_a3, 0x98},
	{ reg_x8, op_lop3, reg_x4, reg_x2, reg_x7, 0x1D},//x4, x2
	{ reg_x6, op_lop3, reg_a5, reg_x6, reg_x8, 0x9A},//x6
	{ reg_x4, op_lop3, reg_a0, reg_a3, reg_x3, 0xB2},//x3
	{ reg_x2, op_lop3, reg_a4, reg_x0, reg_x1, 0x3D},//x0
	{ reg_x2, op_lop3, reg_a5, reg_x4, reg_x2, 0xA6},//x4
	{ reg_x2, op_lop3, reg_a1, reg_x6, reg_x2, 0xA6},
	{ reg_x0, op_lop3, reg_a0, reg_a2, reg_a5, 0xC6},
	{ reg_x1, op_lop3, reg_x1, reg_x7, reg_x0, 0xDB},//x1, x7
	{ reg_x5, op_lop3, reg_a4, reg_x5, reg_x8, 0xB9},//x5, x8
	{ reg_x6, op_lop3, reg_x6, reg_x0, reg_x5, 0x9B},//x6
	{ reg_x6, op_lop3, reg_a1, reg_x1, reg_x6, 0xA6},

	{ reg_out1, op_xor, reg_x6, reg_out1, reg_x9 },
	{ reg_out2, op_xor, reg_x2, reg_out2, reg_x9 }
};

PRIVATE LM_Instruction s4_code_lop3[] = {
	{ reg_a0, op_load_param, reg_x0 },
	{ reg_a1, op_load_param, reg_x0 },
	{ reg_a2, op_load_param, reg_x0 },
	{ reg_a3, op_load_param, reg_x0 },
	{ reg_a4, op_load_param, reg_x0 },
	{ reg_a5, op_load_param, reg_x0 },

	{ reg_x0, op_lop3, reg_a0, reg_a2, reg_a3, 0x72},
	{ reg_x1, op_lop3, reg_a2, reg_a4, reg_x0, 0xAD},
	{ reg_x2, op_lop3, reg_a0, reg_a2, reg_a3, 0x59},
	{ reg_x3, op_lop3, reg_a2, reg_a4, reg_x2, 0xE7},
	{ reg_x1, op_lop3, reg_a1, reg_x1, reg_x3, 0xC6},//x1
	{ reg_x4, op_lop3, reg_a0, reg_a1, reg_a4, 0x69},
	{ reg_x0, op_lop3, reg_a1, reg_a3, reg_x0, 0x18},//x0
	{ reg_x0, op_lop3, reg_x3, reg_x4, reg_x0, 0x63},
	{ reg_x8, op_lop3, reg_a5, reg_x1, reg_x0, 0x6A},
	{ reg_x5, op_lop3, reg_a0, reg_a1, reg_a2, 0x12},
	{ reg_x6, op_lop3, reg_a0, reg_a4, reg_x3, 0x28},
	{ reg_x7, op_lop3, reg_x1, reg_x5, reg_x6, 0x1E},
	{ reg_x4, op_lop3, reg_a0, reg_x4, reg_x5, 0x14},//x4, x5
	{ reg_x5, op_lop3, reg_x2, reg_x3, reg_x0, 0x78},//x2, x3
	{ reg_x5, op_lop3, reg_x6, reg_x4, reg_x5, 0xD6},//x6, x4
	{ reg_x2, op_lop3, reg_a5, reg_x7, reg_x5, 0x6A},
	{ reg_x3, op_lop3, reg_a5, reg_x7, reg_x5, 0xA9},//x7
	{ reg_x0, op_lop3, reg_a5, reg_x1, reg_x0, 0x56},//x1, x0

	{ reg_out0, op_xor, reg_x3, reg_out0, reg_x9 },
	{ reg_out1, op_xor, reg_x2, reg_out1, reg_x9 },
	{ reg_out2, op_xor, reg_x0, reg_out2, reg_x9 },
	{ reg_out3, op_xor, reg_x8, reg_out3, reg_x9 }
};

PRIVATE LM_Instruction s5_code_lop3[] = {
	{ reg_a0, op_load_param, reg_x0 },
	{ reg_a1, op_load_param, reg_x0 },
	{ reg_a2, op_load_param, reg_x0 },
	{ reg_a3, op_load_param, reg_x0 },
	{ reg_a4, op_load_param, reg_x0 },
	{ reg_a5, op_load_param, reg_x0 },

	{ reg_x0, op_lop3, reg_a0, reg_a2, reg_a5, 0xAB},
	{ reg_x1, op_lop3, reg_a0, reg_a4, reg_a5, 0xB9},
	{ reg_x2, op_lop3, reg_a1, reg_x0, reg_x1, 0xE8},
	{ reg_x3, op_lop3, reg_a0, reg_a2, reg_x1, 0x34},
	{ reg_x4, op_lop3, reg_a0, reg_a4, reg_x2, 0xCE},
	{ reg_x5, op_lop3, reg_a1, reg_x3, reg_x4, 0x29},
	{ reg_x2, op_lop3, reg_a3, reg_x2, reg_x5, 0xA6},//x2
	{ reg_out2, op_xor, reg_x2, reg_out2, reg_x9 },

	{ reg_x2, op_lop3, reg_a0, reg_a2, reg_a4, 0x49},
	{ reg_x6, op_lop3, reg_a1, reg_a5, reg_x2, 0x96},
	{ reg_x7, op_lop3, reg_a0, reg_a1, reg_a2, 0xCA},
	{ reg_x0, op_lop3, reg_a2, reg_x0, reg_x6, 0x7E},//x0
	{ reg_x7, op_lop3, reg_x1, reg_x7, reg_x0, 0x96},//x7
	{ reg_x7, op_lop3, reg_a3, reg_x6, reg_x7, 0xCA},
	{ reg_out1, op_xor, reg_x7, reg_out1, reg_x9 },

	{ reg_x7, op_lop3, reg_a0, reg_a1, reg_x1, 0xE5},
	{ reg_x3, op_lop3, reg_x3, reg_x4, reg_x6, 0x97},//x3
	{ reg_x7, op_lop3, reg_x2, reg_x7, reg_x3, 0x47},//x7
	{ reg_x8, op_lop3, reg_a2, reg_x1, reg_x2, 0x3B},
	{ reg_x3, op_lop3, reg_x6, reg_x3, reg_x8, 0xD9},//x3
	{ reg_x7, op_lop3, reg_a3, reg_x7, reg_x3, 0xCA},//x7
	{ reg_x1, op_lop3, reg_a0, reg_a2, reg_x1, 0xB1},//x1
	{ reg_x2, op_lop3, reg_x4, reg_x2, reg_x6, 0x47},//x2, x6
	{ reg_x0, op_lop3, reg_x0, reg_x1, reg_x2, 0x6E},//x0
	{ reg_x3, op_lop3, reg_a1, reg_x4, reg_x3, 0x94},//x4, x3
	{ reg_x5, op_lop3, reg_a0, reg_x5, reg_x3, 0xD9},//x5
	{ reg_x0, op_lop3, reg_a3, reg_x0, reg_x5, 0xC6},

	{ reg_out0, op_xor, reg_x7, reg_out0, reg_x9 },
	{ reg_out3, op_xor, reg_x0, reg_out3, reg_x9 }
};

PRIVATE LM_Instruction s6_code_lop3[] = {
	{ reg_a0, op_load_param, reg_x0 },
	{ reg_a1, op_load_param, reg_x0 },
	{ reg_a2, op_load_param, reg_x0 },
	{ reg_a3, op_load_param, reg_x0 },
	{ reg_a4, op_load_param, reg_x0 },
	{ reg_a5, op_load_param, reg_x0 },

	{ reg_x0, op_lop3, reg_a0, reg_a2, reg_a4, 0xB2},
	{ reg_x1, op_xor, reg_a1, reg_x0},//{ reg_x1, op_lop3, reg_a0, reg_a1, reg_x0, 0x66},

	{ reg_x2, op_lop3, reg_a0, reg_a0, reg_a4, 0xA9},
	{ reg_x3, op_lop3, reg_a2, reg_x1, reg_x2, 0xA9},
	{ reg_x4, op_lop3, reg_a3, reg_x1, reg_x3, 0xC6},
	{ reg_x5, op_lop3, reg_a4, reg_x1, reg_x3, 0xAD},
	{ reg_x6, op_lop3, reg_a0, reg_a3, reg_x5, 0xE4},
	{ reg_x8, op_lop3, reg_a5, reg_x4, reg_x6, 0x6C},
	{ reg_x2, op_lop3, reg_a1, reg_x2, reg_x4, 0x20},//x2
	{ reg_x7, op_lop3, reg_a2, reg_a3, reg_a4, 0x69},
	{ reg_x5, op_lop3, reg_x5, reg_x2, reg_x7, 0x9E},//x5
	{ reg_x7, op_lop3, reg_a0, reg_a1, reg_x7, 0x49},//x7
	{ reg_x7, op_lop3, reg_a4, reg_x0, reg_x7, 0x93},//x0
	{ reg_x0, op_lop3, reg_a5, reg_x5, reg_x7, 0x6C},
	{ reg_out2, op_xor, reg_x0, reg_out2, reg_x9 },
							   
	{ reg_x0, op_lop3, reg_a3, reg_x4, reg_x2, 0xA4},//x4
	{ reg_x0, op_lop3, reg_a4, reg_x5, reg_x0, 0x76},
	{ reg_x4, op_lop3, reg_a2, reg_a3, reg_a4, 0xCD},
	{ reg_x4, op_lop3, reg_x3, reg_x0, reg_x4, 0x86},
	{ reg_x0, op_lop3, reg_a5, reg_x0, reg_x4, 0xA6},//x0
	{ reg_out0, op_xor, reg_x0, reg_out0, reg_x9 },
							   
	{ reg_x0, op_lop3, reg_a1, reg_x8, reg_x7, 0x2D},//x7
	{ reg_x0, op_lop3, reg_x2, reg_x5, reg_x0, 0x26},//x2, x5
	{ reg_x1, op_lop3, reg_a2, reg_x1, reg_x6, 0x6B},//x1, x6
	{ reg_x1, op_lop3, reg_x3, reg_x0, reg_x1, 0xA2},//x3
	{ reg_x0, op_lop3, reg_a5, reg_x0, reg_x1, 0xCA},
	
	{ reg_out1, op_xor, reg_x0, reg_out1, reg_x9 },
	{ reg_out3, op_xor, reg_x8, reg_out3, reg_x9 }
};

PRIVATE LM_Instruction s7_code_lop3[] = {
	{ reg_a0, op_load_param, reg_x0 },
	{ reg_a1, op_load_param, reg_x0 },
	{ reg_a2, op_load_param, reg_x0 },
	{ reg_a3, op_load_param, reg_x0 },
	{ reg_a4, op_load_param, reg_x0 },
	{ reg_a5, op_load_param, reg_x0 },

	{ reg_x0, op_lop3, reg_a0, reg_a1, reg_a3, 0x0B},
	{ reg_x1, op_lop3, reg_a0, reg_a3, reg_a4, 0x27},
	{ reg_x2, op_lop3, reg_a2, reg_x0, reg_x1, 0x9E},
	{ reg_x3, op_lop3, reg_a0, reg_a2, reg_a4, 0xA6},
	{ reg_x4, op_lop3, reg_a1, reg_x2, reg_x3, 0x6B},
	{ reg_x5, op_lop3, reg_a3, reg_x0, reg_x4, 0xA9},
	{ reg_x7, op_lop3, reg_a5, reg_x2, reg_x5, 0x6A},
	{ reg_out0, op_xor, reg_x7, reg_out0, reg_x9 },

	{ reg_x6, op_lop3, reg_a0, reg_a1, reg_a2, 0x63},
	{ reg_x7, op_lop3, reg_a1, reg_x1, reg_x3, 0xE7},
	{ reg_x8, op_lop3, reg_a3, reg_x6, reg_x7, 0x93},
	{ reg_x4, op_lop3, reg_a1, reg_x4, reg_x7, 0x5D},//x4, x7
	{ reg_x4, op_lop3, reg_a3, reg_x3, reg_x4, 0x6E},
	{ reg_x7, op_lop3, reg_a5, reg_x8, reg_x4, 0xC6},//x8
	{ reg_out2, op_xor, reg_x7, reg_out2, reg_x9 },

	{ reg_x7, op_lop3, reg_a2, reg_a3, reg_x3, 0x6D},//x3
	{ reg_x7, op_lop3, reg_a2, reg_x6, reg_x7, 0xA6},//x6
	{ reg_x3, op_lop3, reg_a0, reg_a1, reg_a4, 0x23},
	{ reg_x6, op_lop3, reg_x5, reg_x7, reg_x3, 0x72},//x5
	{ reg_x8, op_lop3, reg_a5, reg_x7, reg_x6, 0xAC},
	{ reg_x5, op_lop3, reg_a0, reg_a2, reg_a3, 0x21},
	{ reg_x1, op_lop3, reg_x1, reg_x4, reg_x6, 0xA4},//x1, x4
	{ reg_x1, op_lop3, reg_x3, reg_x5, reg_x1, 0x96},//x3, x5
	{ reg_x4, op_lop3, reg_x0, reg_x7, reg_x1, 0x3E},//x0, x7
	{ reg_x4, op_lop3, reg_x2, reg_x6, reg_x4, 0x6B},//x2, x6
	{ reg_x1, op_lop3, reg_a5, reg_x1, reg_x4, 0xC6},
	
	{ reg_out1, op_xor, reg_x1, reg_out1, reg_x9 },
	{ reg_out3, op_xor, reg_x8, reg_out3, reg_x9 }
};

PRIVATE LM_Instruction s8_code_lop3[] = {
	{ reg_a0, op_load_param, reg_x0 },
	{ reg_a1, op_load_param, reg_x0 },
	{ reg_a2, op_load_param, reg_x0 },
	{ reg_a3, op_load_param, reg_x0 },
	{ reg_a4, op_load_param, reg_x0 },
	{ reg_a5, op_load_param, reg_x0 },

	{ reg_x0, op_lop3, reg_a0, reg_a1, reg_a4, 0x9D},
	{ reg_x1, op_lop3, reg_a0, reg_a0, reg_a1, 0x83},
	{ reg_x2, op_lop3, reg_a0, reg_a1, reg_a4, 0x5B},
	{ reg_x3, op_lop3, reg_a2, reg_x1, reg_x2, 0x85},
	{ reg_x0, op_lop3, reg_a3, reg_x0, reg_x3, 0xA6},//x0
	{ reg_x4, op_lop3, reg_a1, reg_a4, reg_x0, 0xF9},
	{ reg_x5, op_lop3, reg_a3, reg_a4, reg_x3, 0x0E},
	{ reg_x5, op_lop3, reg_x1, reg_x4, reg_x5, 0x61},
	{ reg_x5, op_lop3, reg_a5, reg_x0, reg_x5, 0x6C},
	{ reg_out3, op_xor, reg_x5, reg_out3, reg_x9 },

	{ reg_x5, op_lop3, reg_a0, reg_a1, reg_a2, 0xDF},
	{ reg_x6, op_lop3, reg_a1, reg_a4, reg_x0, 0xD4},
	{ reg_x6, op_lop3, reg_a3, reg_x5, reg_x6, 0x69},// x5
	{ reg_x5, op_lop3, reg_a0, reg_x3, reg_x6, 0x6F},// x3
	{ reg_x3, op_lop3, reg_a2, reg_x1, reg_x5, 0xB9},
	{ reg_x3, op_lop3, reg_a5, reg_x6, reg_x3, 0xC6},
	{ reg_out1, op_xor, reg_x3, reg_out1, reg_x9 },

	{ reg_x3, op_lop3, reg_a1, reg_x2, reg_x6, 0x5C},
	{ reg_x3, op_lop3, reg_a0, reg_x0, reg_x3, 0x71},
	{ reg_x1, op_lop3, reg_a3, reg_x1, reg_x2, 0xB9},//x1, x2
	{ reg_x2, op_lop3, reg_x4, reg_x6, reg_x1, 0x69},// x6
	{ reg_x3, op_lop3, reg_a5, reg_x3, reg_x2, 0x6A},// x3
	{ reg_x2, op_lop3, reg_a0, reg_a3, reg_x1, 0xE2},// x1
	{ reg_x2, op_lop3, reg_x4, reg_x5, reg_x2, 0x9C},//x5
	{ reg_x2, op_lop3, reg_a5, reg_x0, reg_x2, 0x39},

	{ reg_out0, op_xor, reg_x2, reg_out0, reg_x9 },
	{ reg_out2, op_xor, reg_x3, reg_out2, reg_x9 }
};


PRIVATE LM_SBox sboxs_std[]={
	{LENGHT(s1_code_std), s1_code_std}, {LENGHT(s2_code_std), s2_code_std}, {LENGHT(s3_code_std), s3_code_std}, {LENGHT(s4_code_std), s4_code_std},
	{LENGHT(s5_code_std), s5_code_std}, {LENGHT(s6_code_std), s6_code_std}, {LENGHT(s7_code_std), s7_code_std}, {LENGHT(s8_code_std), s8_code_std}
};
PRIVATE LM_SBox sboxs_bs[]={
	{LENGHT(s1_code_bs), s1_code_bs}, {LENGHT(s2_code_bs), s2_code_bs}, {LENGHT(s3_code_bs), s3_code_bs}, {LENGHT(s4_code_bs), s4_code_bs},
	{LENGHT(s5_code_bs), s5_code_bs}, {LENGHT(s6_code_bs), s6_code_bs}, {LENGHT(s7_code_bs), s7_code_bs}, {LENGHT(s8_code_bs), s8_code_bs}
};
PRIVATE LM_SBox sboxs_lop3[] = {
	{ LENGHT(s1_code_lop3), s1_code_lop3 }, { LENGHT(s2_code_lop3), s2_code_lop3 }, { LENGHT(s3_code_lop3), s3_code_lop3 }, { LENGHT(s4_code_lop3), s4_code_lop3 },
	{ LENGHT(s5_code_lop3), s5_code_lop3 }, { LENGHT(s6_code_lop3), s6_code_lop3 }, { LENGHT(s7_code_lop3), s7_code_lop3 }, { LENGHT(s8_code_lop3), s8_code_lop3 }
};
// Read only once
//2 3 6 7 10 11 12 14 17 19 22 23 26 27 29 30
//34 35 38 39 42 43 44 46 49 51 54 55 58 59 61 62 
PRIVATE int c0[] = {56,52,48,57,41,45,40,37, 24,20,16,25,9,13,8,5};
PRIVATE int c1[] = {47,60,32,36,33,63,50,53, 15,28,0,4,1,31,18,21};
PRIVATE int c2[] = {38,43,46,49,39,58,44,42, 6,11,14,17,7,26,12,10};
PRIVATE int c3[] = {51,59,54,62,55,34,61,35, 19,27,22,30,23,2,29,3};
PRIVATE int c4[] = {52,48,57,41,45,40,37,56, 20,16,25,9,13,8,5,24};
PRIVATE int c5[] = {60,32,36,33,63,50,53,47, 28,0,4,1,31,18,21,15};

PRIVATE unsigned char ks[] = {
16, 43, 44, 1, 7, 28,
27, 6, 54, 48, 39, 19,
53, 25, 33, 34, 17, 5,
4, 55, 24, 32, 40, 20,
36, 31, 21, 8, 23, 52,
14, 29, 51, 9, 35, 30,
2, 37, 22, 0, 42, 38,
47, 11, 26, 3, 13, 41,

23, 50, 51, 8, 14, 35,
34, 13, 4, 55, 46, 26,
3, 32, 40, 41, 24, 12,
11, 5, 6, 39, 47, 27,
43, 38, 28, 15, 30, 0,
21, 36, 31, 16, 42, 37,
9, 44, 29, 7, 49, 45,
54, 18, 33, 10, 20, 48,

37, 9, 38, 22, 28, 49,
48, 27, 18, 12, 3, 40,
17, 46, 54, 55, 13, 26,
25, 19, 20, 53, 4, 41,
2, 52, 42, 29, 44, 14,
35, 50, 45, 30, 1, 51,
23, 31, 43, 21, 8, 0,
11, 32, 47, 24, 34, 5,

51, 23, 52, 36, 42, 8,
5, 41, 32, 26, 17, 54,
6, 3, 11, 12, 27, 40,
39, 33, 34, 10, 18, 55,
16, 7, 1, 43, 31, 28,
49, 9, 0, 44, 15, 38,
37, 45, 2, 35, 22, 14,
25, 46, 4, 13, 48, 19,

38, 37, 7, 50, 1, 22,
19, 55, 46, 40, 6, 11,
20, 17, 25, 26, 41, 54,
53, 47, 48, 24, 32, 12,
30, 21, 15, 2, 45, 42,
8, 23, 14, 31, 29, 52,
51, 0, 16, 49, 36, 28,
39, 3, 18, 27, 5, 33,

52, 51, 21, 9, 15, 36,
33, 12, 3, 54, 20, 25,
34, 6, 39, 40, 55, 11,
10, 4, 5, 13, 46, 26,
44, 35, 29, 16, 0, 1,
22, 37, 28, 45, 43, 7,
38, 14, 30, 8, 50, 42,
53, 17, 32, 41, 19, 47,

7, 38, 35, 23, 29, 50,
47, 26, 17, 11, 34, 39,
48, 20, 53, 54, 12, 25,
24, 18, 19, 27, 3, 40,
31, 49, 43, 30, 14, 15,
36, 51, 42, 0, 2, 21,
52, 28, 44, 22, 9, 1,
10, 6, 46, 55, 33, 4,

21, 52, 49, 37, 43, 9,
4, 40, 6, 25, 48, 53,
5, 34, 10, 11, 26, 39,
13, 32, 33, 41, 17, 54,
45, 8, 2, 44, 28, 29,
50, 38, 1, 14, 16, 35,
7, 42, 31, 36, 23, 15,
24, 20, 3, 12, 47, 18,

28, 0, 1, 44, 50, 16,
11, 47, 13, 32, 55, 3,
12, 41, 17, 18, 33, 46,
20, 39, 40, 48, 24, 4,
52, 15, 9, 51, 35, 36,
2, 45, 8, 21, 23, 42,
14, 49, 38, 43, 30, 22,
6, 27, 10, 19, 54, 25,

42, 14, 15, 31, 9, 30,
25, 4, 27, 46, 12, 17,
26, 55, 6, 32, 47, 3,
34, 53, 54, 5, 13, 18,
7, 29, 23, 38, 49, 50,
16, 0, 22, 35, 37, 1,
28, 8, 52, 2, 44, 36,
20, 41, 24, 33, 11, 39,

1, 28, 29, 45, 23, 44,
39, 18, 41, 3, 26, 6,
40, 12, 20, 46, 4, 17,
48, 10, 11, 19, 27, 32,
21, 43, 37, 52, 8, 9,
30, 14, 36, 49, 51, 15,
42, 22, 7, 16, 31, 50,
34, 55, 13, 47, 25, 53,

15, 42, 43, 0, 37, 31,
53, 32, 55, 17, 40, 20,
54, 26, 34, 3, 18, 6,
5, 24, 25, 33, 41, 46,
35, 2, 51, 7, 22, 23,
44, 28, 50, 8, 38, 29,
1, 36, 21, 30, 45, 9,
48, 12, 27, 4, 39, 10,

29, 1, 2, 14, 51, 45,
10, 46, 12, 6, 54, 34,
11, 40, 48, 17, 32, 20,
19, 13, 39, 47, 55, 3,
49, 16, 38, 21, 36, 37,
31, 42, 9, 22, 52, 43,
15, 50, 35, 44, 0, 23,
5, 26, 41, 18, 53, 24,

43, 15, 16, 28, 38, 0,
24, 3, 26, 20, 11, 48,
25, 54, 5, 6, 46, 34,
33, 27, 53, 4, 12, 17,
8, 30, 52, 35, 50, 51,
45, 1, 23, 36, 7, 2,
29, 9, 49, 31, 14, 37,
19, 40, 55, 32, 10, 13,

2, 29, 30, 42, 52, 14,
13, 17, 40, 34, 25, 5,
39, 11, 19, 20, 3, 48,
47, 41, 10, 18, 26, 6,
22, 44, 7, 49, 9, 38,
0, 15, 37, 50, 21, 16,
43, 23, 8, 45, 28, 51,
33, 54, 12, 46, 24, 27,

9, 36, 37, 49, 0, 21,
20, 24, 47, 41, 32, 12,
46, 18, 26, 27, 10, 55,
54, 48, 17, 25, 33, 13,
29, 51, 14, 1, 16, 45,
7, 22, 44, 2, 28, 23,
50, 30, 15, 52, 35, 31,
40, 4, 19, 53, 6, 34};

// Know values to optimize code and reduce register pressure
#define VALUE_KNOW_0		0
#define VALUE_KNOW_ALL_1	1
#define VALUE_UNKNOW		2
// Values of memory space
#define MEMORY_REGISTER		0
#define MEMORY_SHARED		1

#include <math.h>
PRIVATE unsigned int lm_get_bit_table_mask(unsigned int num_passwords_loaded, cl_ulong l1_size, cl_ulong l2_size)
{
	int i;
	unsigned int result = 1;
	int num_bytes_bit_table;

	// Generate result with all bits less than
	// first bit in num_elem in 1
	while(result < num_passwords_loaded)
		result = (result << 1) + 1;

	// 3 bits more into account
	for(i = 0; i < 4; i++)
		result = (result << 1) + 1;

	if(l1_size==0 || l2_size==0)
		return result;

	// Calculate size
	num_bytes_bit_table = sizeof(unsigned int) * (result/32+1);

	// Large
	if(num_bytes_bit_table >= 2*l2_size)
		return (result << 4) + 15;

	// Bit_table is at limit of L2 cache
	if(num_bytes_bit_table >= l2_size/2)
		return result;

	num_bytes_bit_table = (int)log((double)l2_size/num_bytes_bit_table/8);
	if(num_bytes_bit_table >  1) num_bytes_bit_table++;
	if(num_bytes_bit_table >= 8) num_bytes_bit_table--;

	for(i = 0; i < num_bytes_bit_table; i++)
		result = (result << 1) + 1;

	return result;
}

PRIVATE void insert_instruction(LM_Instruction* sbox, unsigned int* lenght, unsigned int pos_to_insert, char operation, char reg_result, char reg_op1)
{
	memmove(sbox+pos_to_insert+1, sbox+pos_to_insert, sizeof(LM_Instruction)*(lenght[0]-pos_to_insert));
	sbox[pos_to_insert].operation = operation;
	sbox[pos_to_insert].reg_result = reg_result;
	sbox[pos_to_insert].operand1 = reg_op1;
	lenght[0] = lenght[0] + 1;
}
PRIVATE void change_sbox_code(LM_Instruction* sbox, unsigned int* lenght, char reg_out, int c_value_index, unsigned char* c_values, unsigned char* c_memory_space)
{
	int i;

	// Find assignment instruction
	for (i = 0; i < (int)lenght[0]; i++)
	{
		if(sbox[i].operation != op_nop && sbox[i].reg_result == reg_out)
			break;
	}

	if(c_values[c_value_index] == VALUE_UNKNOW && c_memory_space[c_value_index] != MEMORY_REGISTER)
	{
		insert_instruction(sbox, lenght, i+1, op_store_shared, reg_out, sbox[i].operand3);
		sbox[i].reg_result = sbox[i].operand2 = sbox[i].operand3;
		insert_instruction(sbox, lenght, i, op_load_shared, reg_out, sbox[i].operand3);
	}

	if(c_values[c_value_index] == VALUE_KNOW_ALL_1)
	{
		sbox[i].operation = op_not;

		if (c_memory_space[c_value_index] == MEMORY_SHARED)
		{
			sbox[i].reg_result = sbox[i].operand3;
			insert_instruction(sbox, lenght, i+1, op_store_shared, reg_out, sbox[i].operand3);
		}
	}

	if(c_values[c_value_index] == VALUE_KNOW_0)
	{
		char reg1 = sbox[i].operand1;
		sbox[i].operation = op_nop;

		for(; i >= 0; i--)
			if(sbox[i].operation != op_nop && sbox[i].reg_result == reg1)
			{
				if (c_memory_space[c_value_index] == MEMORY_SHARED)
					insert_instruction(sbox, lenght, i+1, op_store_shared, reg_out, sbox[i].reg_result);
				else
					sbox[i].reg_result = reg_out;
				break;
			}
	}
}
PRIVATE void gen_load_param_new(char* source, int count_step, int* c_num, int k_num, int reg_a, int reg_tmp, char l_regs[20][12], cl_bool is_ptx, cl_uint key_lenght, cl_uchar* c_memory_space, cl_uchar* cs_mapped, cl_uchar* posible_last_load, cl_uchar* use_only_kmask1, cl_uint workgroup)
{
	if(is_ptx)
	{
		// Load the key_index
		sprintf(source+strlen(source),	"ld.const.u8 %s,[kptr+%iU];\n", l_regs[reg_a], k_num);

		if(posible_last_load[k_num])
			// Check if is a normal or a last
			sprintf(source+strlen(source),	"setp.lt.u32 pred0,%s,16;\n"
											"@pred0 bra.uni last_handle%i;\n", l_regs[reg_a], k_num);

		if(use_only_kmask1[k_num])
			sprintf(source+strlen(source),	"and.b32 %s,%s,31;\n"
											"bfe.u32 %s,kmask1,%s,1;\n"
											"set.ne.u32.u32 %s,%s,0;\n" , l_regs[reg_a], l_regs[reg_a]
																		, l_regs[reg_a], l_regs[reg_a]
																		, l_regs[reg_a], l_regs[reg_a]);
		else
		{
			// Handle normal load key
			sprintf(source+strlen(source),	"mov.b32 %s,kmask0;\n"
											"setp.gt.u32 pred0,%s,31;\n"
											"@pred0 mov.b32 %s,kmask1;\n"
											"@pred0 and.b32 %s,%s,31;\n", l_regs[reg_tmp]
																		, l_regs[reg_a]
																		, l_regs[reg_tmp]
																		, l_regs[reg_a], l_regs[reg_a]);
		
			sprintf(source+strlen(source),	"bfe.u32 %s,%s,%s,1;\n"
											"set.ne.u32.u32 %s,%s,0;\n", l_regs[reg_a], l_regs[reg_tmp], l_regs[reg_a], l_regs[reg_a], l_regs[reg_a]);
		}
		if(posible_last_load[k_num])
			// Handle last load key
			sprintf(source+strlen(source),	"bra.uni bxor%i;\n"
											"last_handle%i: mad.%s.u32 ptr1,%s,%uU,ptr0;\n"
											"ld.const.u32 %s,[ptr1];\n"
											"bxor%i:", k_num, k_num, (PTR_SIZE_IN_BITS==64)?"wide":"lo", l_regs[reg_a], num_char_in_charset*num_char_in_charset/32*4, l_regs[reg_a], k_num);
		
		// Load c and XOR
		if(c_memory_space[c_num[count_step]] == MEMORY_REGISTER)
			sprintf(source+strlen(source),	"xor.b32 %s,c%i,%s;\n", l_regs[reg_a], c_num[count_step], l_regs[reg_a]);
		else if (c_memory_space[c_num[count_step]] == MEMORY_SHARED)// MEMORY_SHARED	
			sprintf(source+strlen(source),	"ld.shared.b32 %s,[cs_ptr+%uU];\n"
											"xor.b32 %s,%s,%s;\n", l_regs[reg_tmp], cs_mapped[c_num[count_step]]*workgroup*4, l_regs[reg_a], l_regs[reg_tmp], l_regs[reg_a]);
	}
	else
	{
		// Load the key_index
		sprintf(source+strlen(source),	"%s=kptr%u[i+%iU];", l_regs[reg_a], key_lenght, k_num);

		if(posible_last_load[k_num])
			// Check if is a normal or a last
			sprintf(source+strlen(source), "if(%s>=16){", l_regs[reg_a]);

		if(use_only_kmask1[k_num])
			sprintf(source+strlen(source), "%s=((kmask1>>(%s&31))&1)?0xffffffff:0;", l_regs[reg_a], l_regs[reg_a]);
		else
		{
			// Handle normal load key
			sprintf(source+strlen(source),	"if(%s>31){"
												"%s=kmask1>>(%s&31);"
											"}else{"
												"%s=kmask0>>%s;}", l_regs[reg_a], l_regs[reg_a], l_regs[reg_a], l_regs[reg_a], l_regs[reg_a]);
		
			sprintf(source+strlen(source),	"%s=(%s&1)?0xffffffff:0;", l_regs[reg_a], l_regs[reg_a]);
		}
		if(posible_last_load[k_num])
			// Handle last load key
			sprintf(source+strlen(source),	"}else{"
												"%s=last[%s*%uU+(kmask0&0xffff)];"
											"}", l_regs[reg_a], l_regs[reg_a], num_char_in_charset*num_char_in_charset/32);
		
		// Load c and XOR
		if(c_memory_space[c_num[count_step]] == MEMORY_REGISTER)
			sprintf(source+strlen(source), "%s=c%i^%s;", l_regs[reg_a], c_num[count_step], l_regs[reg_a]);
		else if (c_memory_space[c_num[count_step]] == MEMORY_SHARED)// MEMORY_SHARED	
			sprintf(source+strlen(source), "%s=%s^cs[get_local_id(0)+%uU];", l_regs[reg_a], l_regs[reg_a], cs_mapped[c_num[count_step]]*workgroup);
	}
}
PRIVATE void gen_load_param_old(char* source, int count_step, int* c_num, int k_num, int reg_a, int reg_tmp, char l_regs[20][12], cl_bool is_ptx, char r_regs[20][12], cl_uchar* c_values, cl_uchar* k_index_mask, cl_uint key_lenght, cl_uchar* c_memory_space, cl_uchar* cs_mapped, int* k_mapped_to_last, cl_uint workgroup)
{
	if (is_ptx)
	{
		if (c_values[c_num[count_step]] == VALUE_UNKNOW)
		{
			if (k_index_mask[k_num] > VALUE_KNOW_ALL_1)
			{
				if (k_index_mask[k_num] > VALUE_UNKNOW)// Load kmask
					sprintf(source + strlen(source), "and.b32 %s,kmask%i,%i;\n"
													 "set.ne.u32.u32 %s,%s,0;\n", l_regs[reg_a], k_index_mask[k_num] / 32, 1 << (k_index_mask[k_num] % 32)
																				, l_regs[reg_a], l_regs[reg_a]);
				else// Load last
					sprintf(source + strlen(source), "ld.const.u32 %s,[ptr0+%u];\n", l_regs[reg_a], (k_mapped_to_last[k_num & 7] + num_char_in_charset*num_char_in_charset / 32 * (8 - key_lenght - k_num / 8)) * 4);

				if (c_memory_space[c_num[count_step]] == MEMORY_SHARED)
					sprintf(source + strlen(source), "ld.shared.b32 %s,[cs_ptr+%uU];\n"
													 "xor.b32 %s,%s,%s;\n", l_regs[reg_tmp], cs_mapped[c_num[count_step]] * workgroup * 4
																		  , l_regs[reg_a], l_regs[reg_tmp], l_regs[reg_a]);
				else if (c_memory_space[c_num[count_step]] == MEMORY_REGISTER)
					sprintf(source + strlen(source), "xor.b32 %s,c%i,%s;\n", l_regs[reg_a], c_num[count_step], l_regs[reg_a]);
			}
			else if (k_index_mask[k_num] == VALUE_KNOW_0)
			{
				if (c_memory_space[c_num[count_step]] == MEMORY_SHARED)
					sprintf(source + strlen(source), "ld.shared.b32 %s,[cs_ptr+%uU];\n", l_regs[reg_a], cs_mapped[c_num[count_step]] * workgroup * 4);
				else if (c_memory_space[c_num[count_step]] == MEMORY_REGISTER)
					sprintf(source + strlen(source), "mov.u32 %s,c%i;\n", l_regs[reg_a], c_num[count_step]);
			}
			else
			{
				if (c_memory_space[c_num[count_step]] == MEMORY_SHARED)
					sprintf(source + strlen(source), "ld.shared.b32 %s,[cs_ptr+%uU];\n"
													 "not.b32 %s,%s;\n", l_regs[reg_a], cs_mapped[c_num[count_step]] * workgroup * 4
																	   , l_regs[reg_a], l_regs[reg_a]);
				else if (c_memory_space[c_num[count_step]] == MEMORY_REGISTER)
					sprintf(source + strlen(source), "not.b32 %s,c%i;\n", l_regs[reg_a], c_num[count_step]);
			}
		}
		else
		{
			// error
			count_step++;
		}
	}
	else
	{
		if (c_values[c_num[count_step]] == VALUE_UNKNOW)
		{
			if (k_index_mask[k_num] > VALUE_KNOW_ALL_1)
			{
				if (k_index_mask[k_num] > VALUE_UNKNOW)
				{
					if (c_memory_space[c_num[count_step]] == MEMORY_SHARED)
						sprintf(source + strlen(source), "%s=(kmask%i&%uU)?0xffffffff:0;"
						"%s=cs[get_local_id(0)+%uU]^%s;", l_regs[reg_a], k_index_mask[k_num] / 32, 1 << (k_index_mask[k_num] % 32)
						, l_regs[reg_a], cs_mapped[c_num[count_step]] * workgroup, l_regs[reg_a]);
					else if (c_memory_space[c_num[count_step]] == MEMORY_REGISTER)
						sprintf(source + strlen(source), "%s=(kmask%i&%uU)?0xffffffff:0;"
						"%s=c%i^%s;", l_regs[reg_a], k_index_mask[k_num] / 32, 1 << (k_index_mask[k_num] % 32)
						, l_regs[reg_a], c_num[count_step], l_regs[reg_a]);
				}
				else
				{
					if (c_memory_space[c_num[count_step]] == MEMORY_SHARED)
						sprintf(source + strlen(source), "%s=cs[get_local_id(0)+%uU]^last[(kmask0&0xffff)+%uU];", l_regs[reg_a], cs_mapped[c_num[count_step]] * workgroup, k_mapped_to_last[k_num & 7] + num_char_in_charset*num_char_in_charset / 32 * (8 - key_lenght - k_num / 8));
					else if (c_memory_space[c_num[count_step]] == MEMORY_REGISTER)
						sprintf(source + strlen(source), "%s=c%i^last[(kmask0&0xffff)+%uU];", l_regs[reg_a], c_num[count_step], k_mapped_to_last[k_num & 7] + num_char_in_charset*num_char_in_charset / 32 * (8 - key_lenght - k_num / 8));
				}
			}
			else if (k_index_mask[k_num] == VALUE_KNOW_0)
			{
				if (c_memory_space[c_num[count_step]] == MEMORY_SHARED)
					sprintf(source + strlen(source), "%s=cs[get_local_id(0)+%uU];", l_regs[reg_a], cs_mapped[c_num[count_step]] * workgroup);
				else
					sprintf(r_regs[reg_a], "c%i", c_num[count_step]);
			}
			else
			{
				if (c_memory_space[c_num[count_step]] == MEMORY_SHARED)
					sprintf(source + strlen(source), "%s=~cs[get_local_id(0)+%uU];", l_regs[reg_a], cs_mapped[c_num[count_step]] * workgroup);
				else
					sprintf(source + strlen(source), "%s=~c%i;", l_regs[reg_a], c_num[count_step]);
			}
		}
		if (c_values[c_num[count_step]] == VALUE_KNOW_ALL_1)
		{
			if (k_index_mask[k_num] > VALUE_KNOW_ALL_1)
			{
				if (k_index_mask[k_num] > VALUE_UNKNOW)
					sprintf(source + strlen(source), "%s=(kmask%i&%uU)?0:0xffffffff;", l_regs[reg_a], k_index_mask[k_num] / 32, 1 << (k_index_mask[k_num] % 32));
				else
					sprintf(source + strlen(source), "%s=~last[(kmask0&0xffff)+%uU];", l_regs[reg_a], k_mapped_to_last[k_num & 7] + num_char_in_charset*num_char_in_charset / 32 * (8 - key_lenght - k_num / 8));
			}
			else if (k_index_mask[k_num] == VALUE_KNOW_0)
				strcpy(r_regs[reg_a], "0xffffffff");
			else
				strcpy(r_regs[reg_a], "0U");
		}
		if (c_values[c_num[count_step]] == VALUE_KNOW_0)
		{
			if (k_index_mask[k_num] > VALUE_KNOW_ALL_1)
			{
				if (k_index_mask[k_num] > VALUE_UNKNOW)
					sprintf(source + strlen(source), "%s=(kmask%i&%uU)?0xffffffff:0;", l_regs[reg_a], k_index_mask[k_num] / 32, 1 << (k_index_mask[k_num] % 32));
				else
					sprintf(source + strlen(source), "%s=last[(kmask0&0xffff)+%uU];", l_regs[reg_a], k_mapped_to_last[k_num & 7] + num_char_in_charset*num_char_in_charset / 32 * (8 - key_lenght - k_num / 8));
			}
			else if (k_index_mask[k_num] == VALUE_KNOW_0)
				strcpy(r_regs[reg_a], "0U");
			else
				strcpy(r_regs[reg_a], "0xffffffff");
		}
	}
}
PRIVATE int map2k(char reg_a, int k0, int k1, int k2, int k3, int k4, int k5)
{
	if(reg_a == reg_a0) return k0;
	if(reg_a == reg_a1) return k1;
	if(reg_a == reg_a2) return k2;
	if(reg_a == reg_a3) return k3;
	if(reg_a == reg_a4) return k4;
	if(reg_a == reg_a5) return k5;

	return -1;
}
PRIVATE int* map2c(char reg_a)
{
	if(reg_a == reg_a0) return c0;
	if(reg_a == reg_a1) return c1;
	if(reg_a == reg_a2) return c2;
	if(reg_a == reg_a3) return c3;
	if(reg_a == reg_a4) return c4;
	if(reg_a == reg_a5) return c5;

	return NULL;
}
PRIVATE void generate_copy_if_needed(char* source, LM_Instruction* sbox, cl_uint length, cl_uint pos, char reg_result, char reg_operand, cl_bool is_ptx, char l_regs[20][12], char r_regs[20][12])
{
	unsigned int pos_operand_change, pos_result_last_use, i;
	int need_to_copy = FALSE;

	if(reg_result == reg_operand) return;

	if(reg_result == reg_out0 || reg_result == reg_out1 || reg_result == reg_out2 || reg_result == reg_out3)
		need_to_copy = TRUE;
	else if(strcmp(r_regs[reg_operand], "0U") && strcmp(r_regs[reg_operand], "0xffffffff"))
	{
		// Find the position where the operand change value
		for (pos_operand_change = pos+1; pos_operand_change < length; pos_operand_change++)
			if(sbox[pos_operand_change].operation != op_nop && sbox[pos_operand_change].reg_result == reg_operand)
				break;

		// Find the position of last use of reg_result
		pos_result_last_use = pos;
		for (i = pos+1; i < length; i++)
			if(sbox[i].operation != op_nop)
			{
				if(sbox[i].operand1 == reg_result || (sbox[i].operation != op_not && sbox[i].operand2 == reg_result) || (sbox[i].operation == op_bs && sbox[i].operand3 == reg_result))
					pos_result_last_use = i;
				if(sbox[i].reg_result == reg_result)
					break;
			}

		need_to_copy = pos_result_last_use > pos_operand_change;
	}

	// Generate copy if needed
	if(need_to_copy)
	{
		sprintf(source+strlen(source), is_ptx ? "mov.b32 %s,%s;\n" : "%s=%s;", l_regs[reg_result], r_regs[reg_operand]);
		strcpy(r_regs[reg_result], l_regs[reg_result]);// Now override r_values
	}
	else if(strcmp(r_regs[reg_operand], "0U") && strcmp(r_regs[reg_operand], "0xffffffff"))// Perform a change in the sbox
		for (i = pos+1; i <= pos_result_last_use; i++)
		{
			if(sbox[i].operand1 == reg_result) sbox[i].operand1 = reg_operand;
			if(sbox[i].operand2 == reg_result) sbox[i].operand2 = reg_operand;
			if(sbox[i].operand3 == reg_result) sbox[i].operand3 = reg_operand;
		}
	else
		strcpy(r_regs[reg_result], r_regs[reg_operand]);
}
PRIVATE void step(char* source, int count_step, int k0, int k1, int k2, int k3, int k4, int k5, cl_uchar* c_values, GPUDevice* gpu, cl_uchar* k_index_mask, cl_uint key_lenght, int use_generic_load, cl_uchar* c_memory_space, cl_uchar* cs_mapped, int* k_mapped_to_last, cl_uchar* posible_last_load, cl_uchar* use_only_kmask1)
{
	unsigned int i;
	char l_regs[20][12];
	char r_regs[20][12];
	LM_Instruction sbox[80];

	// Select the optimized sboxs
	LM_SBox* sboxs_ptr = (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? sboxs_bs : sboxs_std;
	if ((gpu->flags & GPU_FLAG_SUPPORT_PTX) && (gpu->flags & GPU_FLAG_NVIDIA_LOP3))
		sboxs_ptr = sboxs_lop3;

	unsigned int lenght = sboxs_ptr[count_step & 7].lenght;
	memcpy(sbox, sboxs_ptr[count_step & 7].instructions, sizeof(LM_Instruction)*lenght);

	// Params and temporal names
	sprintf(l_regs[reg_a0], "a0"); sprintf(r_regs[reg_a0], "a0");
	sprintf(l_regs[reg_a1], "a1"); sprintf(r_regs[reg_a1], "a1");
	sprintf(l_regs[reg_a2], "a2"); sprintf(r_regs[reg_a2], "a2");
	sprintf(l_regs[reg_a3], "a3"); sprintf(r_regs[reg_a3], "a3");
	sprintf(l_regs[reg_a4], "a4"); sprintf(r_regs[reg_a4], "a4");
	sprintf(l_regs[reg_a5], "a5"); sprintf(r_regs[reg_a5], "a5");
	sprintf(l_regs[reg_x0], "x0"); sprintf(r_regs[reg_x0], "x0");
	sprintf(l_regs[reg_x1], "x1"); sprintf(r_regs[reg_x1], "x1");
	sprintf(l_regs[reg_x2], "x2"); sprintf(r_regs[reg_x2], "x2");
	sprintf(l_regs[reg_x3], "x3"); sprintf(r_regs[reg_x3], "x3");
	sprintf(l_regs[reg_x4], "x4"); sprintf(r_regs[reg_x4], "x4");
	sprintf(l_regs[reg_x5], "x5"); sprintf(r_regs[reg_x5], "x5");
	sprintf(l_regs[reg_x6], "x6"); sprintf(r_regs[reg_x6], "x6");
	sprintf(l_regs[reg_x7], "x7"); sprintf(r_regs[reg_x7], "x7");
	sprintf(l_regs[reg_x8], "x8"); sprintf(r_regs[reg_x8], "x8");
	sprintf(l_regs[reg_x9], "x9"); sprintf(r_regs[reg_x9], "x9");

	sprintf(l_regs[reg_out0], "c%i", count_step*4+0);  sprintf(r_regs[reg_out0], "c%i", count_step*4);
	sprintf(l_regs[reg_out1], "c%i", count_step*4+1);  sprintf(r_regs[reg_out1], "c%i", count_step*4+1);
	sprintf(l_regs[reg_out2], "c%i", count_step*4+2);  sprintf(r_regs[reg_out2], "c%i", count_step*4+2);
	sprintf(l_regs[reg_out3], "c%i", count_step*4+3);  sprintf(r_regs[reg_out3], "c%i", count_step*4+3);

	// Out values
	change_sbox_code(sbox, &lenght, reg_out0, count_step*4+0, c_values, c_memory_space);
	change_sbox_code(sbox, &lenght, reg_out1, count_step*4+1, c_values, c_memory_space);
	change_sbox_code(sbox, &lenght, reg_out2, count_step*4+2, c_values, c_memory_space);
	change_sbox_code(sbox, &lenght, reg_out3, count_step*4+3, c_values, c_memory_space);

	// Generate instructions
	for(i = 0; i < lenght; i++)
	{
		int reg_result = sbox[i].reg_result;
		int reg_op1 = sbox[i].operand1;
		int reg_op2 = sbox[i].operand2;

		switch (sbox[i].operation)
		{
		case op_load_param:// Load parameter a
			if(use_generic_load)
				gen_load_param_new(source, count_step, map2c(reg_result), map2k(reg_result, k0, k1, k2, k3, k4, k5), reg_result, reg_op1, l_regs, gpu->flags & GPU_FLAG_SUPPORT_PTX, key_lenght, c_memory_space, cs_mapped, posible_last_load, use_only_kmask1, (cl_uint)gpu->lm_work_group_size);
			else
				gen_load_param_old(source, count_step, map2c(reg_result), map2k(reg_result, k0, k1, k2, k3, k4, k5), reg_result, reg_op1, l_regs, gpu->flags & GPU_FLAG_SUPPORT_PTX, r_regs, c_values, k_index_mask, key_lenght, c_memory_space, cs_mapped, k_mapped_to_last, (cl_uint)gpu->lm_work_group_size);
			break;

		// Support c in memory (local or shared)
		case op_load_shared:
		{
			cl_uint c_index = atoi(l_regs[reg_result] + 1);
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				sprintf(source + strlen(source), "ld.shared.b32 %s,[cs_ptr+%uU];\n", l_regs[reg_op1], cs_mapped[c_index] * gpu->lm_work_group_size * 4);
			else
			{
				if (c_memory_space[c_index] == MEMORY_SHARED)
					sprintf(source + strlen(source), "%s=cs[get_local_id(0)+%uU];", l_regs[reg_op1], cs_mapped[c_index] * gpu->lm_work_group_size);
			}

			strcpy(r_regs[reg_op1], l_regs[reg_op1]);// Now override r_values
		}
			break;
		case op_store_shared:
		{
			cl_uint c_index = atoi(l_regs[reg_result] + 1);
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				sprintf(source + strlen(source), "st.shared.b32 [cs_ptr+%uU],%s;\n", cs_mapped[c_index] * gpu->lm_work_group_size * 4, l_regs[reg_op1]);
			else
			{
				if (c_memory_space[c_index] == MEMORY_SHARED)
					sprintf(source + strlen(source), "cs[get_local_id(0)+%uU]=%s;", cs_mapped[c_index] * gpu->lm_work_group_size, l_regs[reg_op1]);
			}
		}
			break;

		case op_bs:// Bitselect
			// Handle constants
			if(		!strcmp(r_regs[sbox[i].operand3], "0U"		  )) generate_copy_if_needed(source, sbox, lenght, i, reg_result, reg_op1, FALSE, l_regs, r_regs);
			else if(!strcmp(r_regs[sbox[i].operand3], "0xffffffff")) generate_copy_if_needed(source, sbox, lenght, i, reg_result, reg_op2, FALSE, l_regs, r_regs);
			else// Normal execution
			{
				sprintf(source+strlen(source), "%s=bs(%s,%s,%s);", l_regs[reg_result], r_regs[reg_op1], r_regs[reg_op2], r_regs[sbox[i].operand3]);
				strcpy(r_regs[reg_result], l_regs[reg_result]);// Now override r_values
			}
			break;

		case op_lop3:// Nvidia Arbitrary logical operation on 3 inputs
			sprintf(source + strlen(source), "lop3.b32 %s,%s,%s,%s,%i;\n", l_regs[reg_result], r_regs[reg_op1], r_regs[reg_op2], r_regs[sbox[i].operand3], (int)sbox[i].immLut);
			strcpy(r_regs[reg_result], l_regs[reg_result]);// Now override r_values
			break;

		case op_not:// Not
			OP_NOT_CASE:
			// Handle constants
			if(		!strcmp(r_regs[reg_op1], "0U"			))	strcpy(r_regs[reg_result], "0xffffffff");
			else if(!strcmp(r_regs[reg_op1], "0xffffffff"	))	strcpy(r_regs[reg_result], "0U");
			else// Normal execution
			{
				sprintf(source + strlen(source), (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? "not.b32 %s,%s;\n" : "%s=~%s;", l_regs[reg_result], r_regs[reg_op1]);
				strcpy(r_regs[reg_result], l_regs[reg_result]);// Now override r_values
			}
			break;

		case op_and:// And
			// Handle constants
			if(!strcmp(r_regs[reg_op1], "0U") || !strcmp(r_regs[reg_op2], "0U"))
				strcpy(r_regs[reg_result], "0U");
			else if(!strcmp(r_regs[reg_op1], "0xffffffff") || !strcmp(r_regs[reg_op2], "0xffffffff"))
				generate_copy_if_needed(source, sbox, lenght, i, reg_result, !strcmp(r_regs[reg_op2], "0xffffffff") ? reg_op1 : reg_op2, gpu->flags & GPU_FLAG_SUPPORT_PTX, l_regs, r_regs);
			else// Normal execution
			{
				sprintf(source + strlen(source), (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? "and.b32 %s,%s,%s;\n" : "%s=%s&%s;", l_regs[reg_result], r_regs[reg_op1], r_regs[reg_op2]);
				strcpy(r_regs[reg_result], l_regs[reg_result]);// Now override r_values
			}
			break;

		case op_or:// Or
			// Handle constants
			if(!strcmp(r_regs[reg_op1], "0U") || !strcmp(r_regs[reg_op2], "0U"))
				generate_copy_if_needed(source, sbox, lenght, i, reg_result, !strcmp(r_regs[reg_op2], "0U") ? reg_op1 : reg_op2, gpu->flags & GPU_FLAG_SUPPORT_PTX, l_regs, r_regs);
			else if(!strcmp(r_regs[reg_op1], "0xffffffff") || !strcmp(r_regs[reg_op2], "0xffffffff"))
				strcpy(r_regs[reg_result], "0xffffffff");
			else// Normal execution
			{
				sprintf(source + strlen(source), (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? "or.b32 %s,%s,%s;\n" : "%s=%s|%s;", l_regs[reg_result], r_regs[reg_op1], r_regs[reg_op2]);
				strcpy(r_regs[reg_result], l_regs[reg_result]);// Now override r_values
			}
			break;

		case op_xor:// Xor
			// Handle constants
			if(!strcmp(r_regs[reg_op1], "0U") || !strcmp(r_regs[reg_op2], "0U"))
				generate_copy_if_needed(source, sbox, lenght, i, reg_result, !strcmp(r_regs[reg_op2], "0U") ? reg_op1 : reg_op2, gpu->flags & GPU_FLAG_SUPPORT_PTX, l_regs, r_regs);
			else if(!strcmp(r_regs[reg_op1], "0xffffffff") || !strcmp(r_regs[reg_op2], "0xffffffff"))
			{
				if(!strcmp(r_regs[reg_op1], "0xffffffff"))	reg_op1 = reg_op2;

				goto OP_NOT_CASE;
			}
			else// Normal execution
			{
				sprintf(source + strlen(source), (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? "xor.b32 %s,%s,%s;\n" : "%s=%s^%s;", l_regs[reg_result], r_regs[reg_op1], r_regs[reg_op2]);
				strcpy(r_regs[reg_result], l_regs[reg_result]);// Now override r_values
			}
			break;

			default: break;
		}
	}

	c_values[count_step*4] = c_values[count_step*4+1] = c_values[count_step*4+2] = c_values[count_step*4+3] = VALUE_UNKNOW;
}
PRIVATE void gen_kernel_with_lenght(cl_uint key_lenght, char* source, cl_uchar* k_values_char, GPUDevice* gpu, int* k_mapped_to_last, cl_uint lm_size_bit_table)
{
	unsigned int i, k;
	unsigned char c_values[64];
	unsigned char c_memory_space[64];// Use register or shared memory for cs
	unsigned char cs_mapped[64];// Mapped the c index to shared memory index
	// Here we get the index of the mask keys
	unsigned char k_index_mask[56];

	// Use in generic load
	PRIVATE unsigned char posible_last_load[96];
	PRIVATE unsigned char use_only_kmask1[96];

	// Initialize c_memory_space
	memset(c_memory_space, MEMORY_REGISTER, sizeof(c_memory_space));
	if (gpu->major_cc < 3 && (gpu->flags & GPU_FLAG_SUPPORT_PTX) && (gpu->flags & GPU_FLAG_LM_USE_SHARED_MEMORY))
	{
		// This 8 cs are readied twice
		c_memory_space[63] = MEMORY_SHARED;
		c_memory_space[60] = MEMORY_SHARED;
		c_memory_space[57] = MEMORY_SHARED;
		c_memory_space[56] = MEMORY_SHARED;
											  
		c_memory_space[53] = MEMORY_SHARED;
		c_memory_space[52] = MEMORY_SHARED;
		c_memory_space[50] = MEMORY_SHARED;
		c_memory_space[48] = MEMORY_SHARED;
		// From here down cs are read only once
		c_memory_space[34] = MEMORY_SHARED;
		c_memory_space[35] = MEMORY_SHARED;
		c_memory_space[38] = MEMORY_SHARED;
		c_memory_space[39] = MEMORY_SHARED;

		c_memory_space[42] = MEMORY_SHARED;
		c_memory_space[43] = MEMORY_SHARED;
		c_memory_space[44] = MEMORY_SHARED;
		c_memory_space[46] = MEMORY_SHARED;
	}

	//2 3 6 7 10 11 12 14 17 19 22 23 26 27 29 30
	//34 35 38 39 42 43 44 46 49 51 54 55 58 59 61 62
	if (gpu->flags & GPU_FLAG_LM_USE_SHARED_MEMORY)
	{
#ifdef ANDROID
		// From here down cs are read only once
		/*c_memory_space[34] = MEMORY_SHARED;
		c_memory_space[35] = MEMORY_SHARED;
		c_memory_space[38] = MEMORY_SHARED;
		c_memory_space[39] = MEMORY_SHARED;*/
										  
		c_memory_space[42] = MEMORY_SHARED;
		c_memory_space[43] = MEMORY_SHARED;
		c_memory_space[44] = MEMORY_SHARED;
		c_memory_space[46] = MEMORY_SHARED;
#endif									  
		c_memory_space[49] = MEMORY_SHARED;
		c_memory_space[51] = MEMORY_SHARED;
		c_memory_space[54] = MEMORY_SHARED;
		c_memory_space[55] = MEMORY_SHARED;
										  
		c_memory_space[58] = MEMORY_SHARED;
		c_memory_space[59] = MEMORY_SHARED;
		c_memory_space[61] = MEMORY_SHARED;
		c_memory_space[62] = MEMORY_SHARED;
	}

	// Put the pattern in an easy way to interpret
	memset(k_index_mask, VALUE_KNOW_0, sizeof(k_index_mask));
	for(i = 0; i < key_lenght-2; i++)
		for(k = 0; k < 8; k++)
			if(k_values_char[k] == VALUE_UNKNOW)
				k_index_mask[55-i*8-7+k] = 63 - ( i*8 + 7 - k);
			else
				k_index_mask[55-i*8-7+k] = k_values_char[k];

	for(i = key_lenght-2; i < key_lenght; i++)
		for(k = 0; k < 8; k++)
			k_index_mask[55-i*8-7+k] = k_values_char[k];

	// Generate keys index in steps
	if (!(gpu->flags & GPU_FLAG_HAD_LM_UNROll))
	{
		memset(posible_last_load, FALSE, sizeof(posible_last_load));
		memset(use_only_kmask1, TRUE, sizeof(use_only_kmask1));
		sprintf(source, (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? ".const .b8 kptr%u[]={" : "__constant uchar kptr%u[]={", key_lenght);
		for(i = 0; i < sizeof(ks); i++)
		{
			int k_index = ks[i];
			if(k_index_mask[k_index] == VALUE_KNOW_0)
			{
				// Find one bit with 0
				int k_0 = 0;
				for (; k_0 < 8; k_0++)
					if(k_values_char[k_0] == VALUE_KNOW_0)
						break;

				// Use the 1th character (always in use)
				if(k_0 < 8)
					k_index = 63 - (7 - k_0);
				else
				{
					k_index = 23;
					use_only_kmask1[i%96] = FALSE;
				}
			}
			else if(k_index_mask[k_index] > VALUE_UNKNOW)
			{
				k_index = 55 - k_index;
				k_index = 63 - k_index;

				if(k_index < 32)
					use_only_kmask1[i%96] = FALSE;
			}
			else if(k_index_mask[k_index] == VALUE_KNOW_ALL_1)
			{
				// Find one bit with all 1
				int k_all_1 = 0;
				for (; k_all_1 < 8; k_all_1++)
					if(k_values_char[k_all_1] == VALUE_KNOW_ALL_1)
						break;

				// Use the 1th character (always in use)
				k_index = 63 - (7 - k_all_1);
			}
			else// Use of last
			{
				int index = (55 - k_index)/8;
				k =  k_index&7;

				// Convert to a 16 value
				k_index = k_mapped_to_last[k]/(num_char_in_charset*num_char_in_charset/32);
				if(index == key_lenght-1)
					k_index++;

				posible_last_load[i%96] = TRUE;
			}
			sprintf(source+strlen(source), "%s%iU", i ? "," : "", k_index);
		}
		strcat(source, "};\n");
	}

	// Kernel definitions
	if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
		sprintf(source+strlen(source), "\n.visible .entry lm_crypt%u(.param .u32 current_key, .param .u32 last_key_index, .param .u%i .ptr.global output", key_lenght, PTR_SIZE_IN_BITS);
	else
	{
		if (gpu->flags & GPU_FLAG_LM_REQUIRE_WORKGROUP)
			sprintf(source + strlen(source), "\n__attribute__((reqd_work_group_size(%i, 1, 1))) ", gpu->lm_work_group_size);
		else
			strcat(source, "\n");
		sprintf(source + strlen(source), "__kernel void lm_crypt%u(uint current_key, uint last_key_index, __global uint* restrict output", key_lenght);
	}

	if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
	{
		if(LM_BEGIN_USE_HASHTABLE)
			sprintf(source+strlen(source), ", .param .u%i .ptr.global table, .param .u%i .ptr.global binary_values, .param .u%i .ptr.global same_hash_next, .param .u%i .ptr.global bit_table", PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS);
		sprintf(source+strlen(source), ") .reqntid %i\n{\n"
			".reg .b32 a<6>;\n"
			".reg .b32 x<%i>;\n"
			".reg .b32 kmask0;\n"
			".reg .b32 kmask1;\n", (int)gpu->lm_work_group_size, (gpu->flags & GPU_FLAG_NVIDIA_LOP3) ? 10 : 8);// Use lop3 instruction to reduce gate counts
	}
	else
	{
		if(LM_BEGIN_USE_HASHTABLE)
			strcat(source, ", const __global uint* restrict table, const __global uchar* restrict binary_values, const __global uint* restrict same_hash_next, const __global uint* restrict bit_table");
		sprintf(source+strlen(source), "){"
			"uint a0,a1,a2,a3,a4,a5, x0,x1,x2,x3,x4,x5,x6,x7%s;"
			"uint kmask0,kmask1;", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? ",x8,x9" : "");
	}

	// Predicates and Pointers
	if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
		sprintf(source+strlen(source),	".reg .pred pred0;\n"
										".reg .u%u kptr;\n"
										".reg .u%i ptr<2>;\n"
										"mov.u%i ptr0,charset;\n", PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS);

	// Declare variables c
	{// Use of shared (opencl local) memory
		int num_shared_c = 0;
		for(i = 0; i < 64; i++)
			if(c_memory_space[i] == MEMORY_SHARED)
			{
				cs_mapped[i] = num_shared_c;
				num_shared_c++;
			}

		for (i = 0; i < 64; i++)
			if (c_memory_space[i] == MEMORY_REGISTER)
				cs_mapped[i] = i;

		if ((gpu->flags & GPU_FLAG_SUPPORT_PTX) && num_shared_c)
			sprintf(source+strlen(source),	".shared .align 4 .b8 cs[%i];\n"
											".reg .b%i cs_ptr;\n"
											"cvt.u%i.u16 cs_ptr,%%tid.x;\n"
											"shl.b%i cs_ptr,cs_ptr,2;\n"
											"mov.u%i ptr1,cs;\n"
											"add.u%i cs_ptr,cs_ptr,ptr1;\n", gpu->lm_work_group_size*num_shared_c * 4, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS);
		else if(num_shared_c)
			sprintf(source+strlen(source), "local uint cs[%i];", gpu->lm_work_group_size*num_shared_c);
	}
	// Declare other c as using register
	for(i = 0; i < 64; i++)
		if(c_memory_space[i] == MEMORY_REGISTER)
			sprintf(source + strlen(source), (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? ".reg .b32 c%u;\n" : "uint c%u;", i);

	// Begin to found the key based on the index
	strcat(source, (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? "ld.param.u32 a1,[current_key];\n"
										"mov.u32 a3,%tid.x;\n"
										"mov.u32 a4,%ctaid.x;\n"
										"mov.u32 a5,%ntid.x;\n"
										"add.u32 a1,a1,a3;\n"
										"mad.lo.u32 a1,a4,a5,a1;\n"
										:
										"a1=current_key+get_global_id(0);");

	{
		DivisionParams div_param = get_div_params(num_char_in_charset);

		strcat(source, (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? "mov.u32 kmask0,0;\n"
											"mov.u32 kmask1,0;\n"
											:
											"kmask0=0;kmask1=0;");

		// Fill key with characters
		for(i = 0; i < key_lenght-2; i++)
		{
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
			{
				// Divide by num_char_in_charset
				if(div_param.sum_one) sprintf(source+strlen(source), "add.u32 a2,a1,1;\n");
				if(div_param.magic) sprintf(source+strlen(source), "mul.hi.u32 a2,a%i,%uU;\n", div_param.sum_one+1, div_param.magic);

				sprintf(source+strlen(source), "shr.u32 a2,a%i,%i;\n"
											   "mul.lo.u32 a3,a2,%uU;\n"
											   "sub.u32 a3,a1,a3;\n"
											   "cvt.u%i.u32 ptr1,a3;\n"
											   "add.u%i ptr1,ptr1,ptr0;\n"
											   "ld.const.u8 a0,[ptr1];\n"
											   "mov.u32 a1,a2;\n", (div_param.sum_one||div_param.magic) ? 2 : 1, (int)div_param.shift, num_char_in_charset, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS);
				// Copy the selected character
				sprintf(source+strlen(source),	"shl.b32 a3,a0,%uU;\n"
												"or.b32 kmask%i,kmask%i,a3;\n", 24-(i&3)*8
																			, 1-i/4, 1-i/4);
			}
			else
				sprintf(source+strlen(source), "kmask%i|=charset[a1%%%uu]<<%uU;a1/=%uu;", 1-i/4, num_char_in_charset, 24-(i&3)*8, num_char_in_charset);
		}
	}

	// Last 2 characters
	strcat(source, (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? "ld.param.u32 a0,[last_key_index];\n"
									   "mad.lo.u32 a1,4,a1,a0;\n"
									   "shl.b32 a1,a1,2;\n"
									   "or.b32 kmask0,kmask0,a1;\n"
									   : 
									   "kmask0|=last_key_index+4*a1;");

	// Initialize know values of c
	memset(c_values, VALUE_KNOW_0, sizeof(c_values));
	c_values[1]  = VALUE_KNOW_ALL_1;
	c_values[2]  = VALUE_KNOW_ALL_1;
	c_values[3]  = VALUE_KNOW_ALL_1;
	c_values[7]  = VALUE_KNOW_ALL_1;
	c_values[10] = VALUE_KNOW_ALL_1;
	c_values[11] = VALUE_KNOW_ALL_1;
	c_values[16] = VALUE_KNOW_ALL_1;
	c_values[17] = VALUE_KNOW_ALL_1;
	c_values[18] = VALUE_KNOW_ALL_1;
	c_values[20] = VALUE_KNOW_ALL_1;
	c_values[21] = VALUE_KNOW_ALL_1;
	c_values[24] = VALUE_KNOW_ALL_1;
	c_values[27] = VALUE_KNOW_ALL_1;
	c_values[29] = VALUE_KNOW_ALL_1;
	c_values[32] = VALUE_KNOW_ALL_1;
	c_values[35] = VALUE_KNOW_ALL_1;
	c_values[36] = VALUE_KNOW_ALL_1;
	c_values[40] = VALUE_KNOW_ALL_1;
	c_values[42] = VALUE_KNOW_ALL_1;
	c_values[46] = VALUE_KNOW_ALL_1;
	c_values[54] = VALUE_KNOW_ALL_1;
	c_values[56] = VALUE_KNOW_ALL_1;
	c_values[61] = VALUE_KNOW_ALL_1;

	if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
	{
		for (i = 0; i < 64; i++)
		{
			if(c_memory_space[i] == MEMORY_REGISTER)
				sprintf(source+strlen(source), "mov.u32 c%i,%s;\n", i, c_values[i]==VALUE_KNOW_0 ? "0" : "0xffffffff");
			else if (c_memory_space[i] == MEMORY_SHARED)//MEMORY_SHARED
				sprintf(source+strlen(source), "st.shared.u32 [cs_ptr+%uU],%s;\n", cs_mapped[i]*gpu->lm_work_group_size*4, c_values[i] == VALUE_KNOW_0 ? "0" : "0xffffffff");
		}
		memset(c_values, VALUE_UNKNOW, sizeof(c_values));
	}
	else //if(!gpu->LM_UNROll)
	{
		for (i = 0; i < 64; i++)
		{
			if (c_memory_space[i] == MEMORY_REGISTER)
				sprintf(source + strlen(source), "c%i=%s;", i, c_values[i] == VALUE_KNOW_0 ? "0" : "0xffffffff");
			else  if (c_memory_space[i] == MEMORY_SHARED)
				sprintf(source + strlen(source), "cs[get_local_id(0)+%uU]=%s;", cs_mapped[i] * gpu->lm_work_group_size, c_values[i] == VALUE_KNOW_0 ? "0" : "0xffffffff");
		}
		memset(c_values, VALUE_UNKNOW, sizeof(c_values));
	}

	// Begin generation of code
	if (!(gpu->flags & GPU_FLAG_HAD_LM_UNROll))
	{
		if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
			sprintf(source+strlen(source),	".reg .b32 i;\n"
											"mov.b32 i,0;\n"
											"mov.u%i kptr,kptr%u;\n"

											"mov.u%i ptr0,last;\n"
											"cvt.u%i.u16 ptr1,kmask0;\n"
											"add.u%i ptr0,ptr1,ptr0;\n"

											"beginsbox:", PTR_SIZE_IN_BITS, key_lenght, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS);
		else 
			sprintf(source+strlen(source),	"for(uint i=0;i<768;i+=96){");
		// 1
		step(source, 7,  0 , 1 , 2 , 3 , 4 , 5 , c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 1,  6 , 7 , 8 , 9 , 10, 11, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 2,  12, 13, 14, 15, 16, 17, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 3,  18, 19, 20, 21, 22, 23, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 4,  24, 25, 26, 27, 28, 29, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 5,  30, 31, 32, 33, 34, 35, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 6,  36, 37, 38, 39, 40, 41, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 0,  42, 43, 44, 45, 46, 47, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		//2
		step(source, 15, 48, 49, 50, 51, 52, 53, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 9,  54, 55, 56, 57, 58, 59, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 10, 60, 61, 62, 63, 64, 65, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 11, 66, 67, 68, 69, 70, 71, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 12, 72, 73, 74, 75, 76, 77, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 13, 78, 79, 80, 81, 82, 83, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 14, 84, 85, 86, 87, 88, 89, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		step(source, 8,  90, 91, 92, 93, 94, 95, c_values, gpu, k_index_mask, key_lenght, TRUE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);

		if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
			sprintf(source+strlen(source),	"add.u32 i,i,96;\n"
											"add.u%i kptr,kptr,96;\n"
											"setp.lt.u32 pred0,i,768U;\n"//8*96
											"@pred0 bra.uni beginsbox;\n", PTR_SIZE_IN_BITS);
		else
			sprintf(source+strlen(source), "}\n");
	}
	else
	{
		if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
			sprintf(source + strlen(source), "mov.u%i ptr0,last;\n"
											 "cvt.u%i.u16 ptr1,kmask0;\n"
											 "add.u%i ptr0,ptr1,ptr0;\n", PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS);

		for(i = 0; i < 8; i++)
		{
			unsigned char* kptr = ks+96*i;

			// 1
			step(source, 7,  kptr[0 ], kptr[1 ], kptr[2 ], kptr[3 ], kptr[4 ], kptr[5] , c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 1,  kptr[6 ], kptr[7 ], kptr[8 ], kptr[9 ], kptr[10], kptr[11], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 2,  kptr[12], kptr[13], kptr[14], kptr[15], kptr[16], kptr[17], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 3,  kptr[18], kptr[19], kptr[20], kptr[21], kptr[22], kptr[23], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 4,  kptr[24], kptr[25], kptr[26], kptr[27], kptr[28], kptr[29], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 5,  kptr[30], kptr[31], kptr[32], kptr[33], kptr[34], kptr[35], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 6,  kptr[36], kptr[37], kptr[38], kptr[39], kptr[40], kptr[41], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 0,  kptr[42], kptr[43], kptr[44], kptr[45], kptr[46], kptr[47], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			//2
			step(source, 15, kptr[48], kptr[49], kptr[50], kptr[51], kptr[52], kptr[53], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 9,  kptr[54], kptr[55], kptr[56], kptr[57], kptr[58], kptr[59], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 10, kptr[60], kptr[61], kptr[62], kptr[63], kptr[64], kptr[65], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 11, kptr[66], kptr[67], kptr[68], kptr[69], kptr[70], kptr[71], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 12, kptr[72], kptr[73], kptr[74], kptr[75], kptr[76], kptr[77], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 13, kptr[78], kptr[79], kptr[80], kptr[81], kptr[82], kptr[83], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 14, kptr[84], kptr[85], kptr[86], kptr[87], kptr[88], kptr[89], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
			step(source, 8,  kptr[90], kptr[91], kptr[92], kptr[93], kptr[94], kptr[95], c_values, gpu, k_index_mask, key_lenght, FALSE, c_memory_space, cs_mapped, k_mapped_to_last, posible_last_load, use_only_kmask1);
		}
	}

	if(!LM_BEGIN_USE_HASHTABLE)
	{
		if (!(gpu->flags & GPU_FLAG_SUPPORT_PTX))
			strcat(source, "uint result,j;");
		else
			sprintf(source+strlen(source),	"ld.param.u%i kptr,[output];\n"
											"cvta.to.global.u%i kptr,kptr;\n", PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS);

		for(k = 0; k < num_passwords_loaded; k++)
		{
			strcat(source, (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? "mov.u32 x0,0;\n" : "result=0;");
			// TODO: Generate better code that reuse intermediate results
			for(i = 0; i < 64; i++)
			{
				cl_uint bin_val = ((((cl_uchar*)binary_values)[k*8+i/8] >> (i&7)) & 1);

				if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				{
					if(c_memory_space[i] == MEMORY_SHARED)
						sprintf(source+strlen(source), bin_val ? "ld.shared.b32 x1,[cs_ptr+%uU];\n"
																 "not.b32 x1,x1;\n"
																 "or.b32 x0,x0,x1;\n"
																 :
																 "ld.shared.b32 x1,[cs_ptr+%uU];\n"
																 "or.b32 x0,x0,x1;\n", cs_mapped[i] * gpu->lm_work_group_size * 4);// x0 is result
					else
						sprintf(source+strlen(source), bin_val ? "not.b32 x1,c%i;\n"
																 "or.b32 x0,x0,x1;\n"
																 :
																 "or.b32 x0,x0,c%i;\n", i);// x0 is result
					if(i >= 8 && i%4 == 0 && i <= 24)
						sprintf(source+strlen(source),	"setp.eq.b32 pred0,x0,0xffffffff;\n"
														"@pred0 bra branchtarget%u;\n", k);// x1 is j
				}
				else
				{
					if(c_memory_space[i] == MEMORY_SHARED)
						sprintf(source + strlen(source), "result|=%scs[get_local_id(0)+%uU];\n", bin_val ? "~" : "", cs_mapped[i] * gpu->lm_work_group_size);
					else// Registers
						sprintf(source+strlen(source), "result|=%sc%i;", bin_val?"~":"", i);
				}
			}

			// Total match
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)// Search for the index of the key founded
				sprintf(source+strlen(source),
								"setp.eq.u32 pred0,x0,0xffffffff;\n"
								"@pred0 bra branchtarget%u;\n"
								"not.b32 x1,x0;\n"
								"clz.b32 x1,x1;\n"
								"sub.u32 x1,31,x1;\n", k);// x1 is j
			else
				strcat(source, "if(result!=0xffffffff){"
									"j=31-clz(~result);");
			// Notify that thread found a password
			if(num_passwords_loaded==1)
				strcat(source, (gpu->flags & GPU_FLAG_SUPPORT_PTX) ?
							"st.global.cs.u32 [kptr],1;\n"
							"st.global.cs.u32 [kptr+4],0;\n"
							"mov.b32 a0,kmask1;\n"
							"and.b32 a1,kmask0,0xffff0000;\n"
							:
							"output[0]=1;"
							"output[1]=0;"
							"a0=kmask1,a1=kmask0&0xffff0000;");
			else
			{
				if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
					sprintf(source+strlen(source),
							"atom.global.add.u32 a0,[kptr],1;\n"
							"mad.%s.u32 ptr1,a0,12,kptr;\n"
							"st.global.cs.u32 [ptr1+4],%uU;\n"
							"mov.b32 a0,kmask1;\n"
							"and.b32 a1,kmask0,0xffff0000;\n", (PTR_SIZE_IN_BITS==64)?"wide":"lo", k);// a0 is key0; a1 is key1
				else
					sprintf(source+strlen(source),
							"uint found=atomic_inc(output)*3;"
							"output[found+1]=%uu;"
							"a0=kmask1,a1=kmask0&0xffff0000;", k);
			}

		// Get last part of key
		for(i = 0; i < 8; i++)
			if(k_values_char[i] == VALUE_UNKNOW)
			{
				if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				{
					sprintf(source+strlen(source),	"ld.const.u32 a2,[ptr0+%iU];\n"
													"bfe.u32 a2,a2,x1,1;\n"
													"bfi.b32 a%i,a2,a%i,%i,1;\n", k_mapped_to_last[i]*4
																			  , (key_lenght-2)/4, (key_lenght-2)/4, (3 - (key_lenght-2) & 3)*8+i);

					sprintf(source+strlen(source),	"ld.const.u32 a2,[ptr0+%iU];\n"
													"bfe.u32 a2,a2,x1,1;\n"
													"bfi.b32 a%i,a2,a%i,%i,1;\n", k_mapped_to_last[i]*4+num_char_in_charset*num_char_in_charset/32*4, (key_lenght-1)/4, (key_lenght-1)/4, (3 - (key_lenght-1) & 3)*8+i);
				}
				else
				{
					sprintf(source+strlen(source), "a%i|=((last[(kmask0&0xffff)+%uU]>>j)&1)<<%i;", (key_lenght-2)/4, k_mapped_to_last[i], (3 - (key_lenght-2) & 3)*8+i);
					sprintf(source+strlen(source), "a%i|=((last[(kmask0&0xffff)+%uU]>>j)&1)<<%i;", (key_lenght-1)/4, k_mapped_to_last[i]+num_char_in_charset*num_char_in_charset/32, (3 - (key_lenght-1) & 3)*8+i);
				}
			}
			else if(k_values_char[i] == VALUE_KNOW_ALL_1)
			{
				if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				{
					sprintf(source+strlen(source), "or.b32 a%i,a%i,%i;\n", (key_lenght-2)/4, (key_lenght-2)/4, 1 << ((3 - (key_lenght-2) & 3)*8+i));
					sprintf(source+strlen(source), "or.b32 a%i,a%i,%i;\n", (key_lenght-1)/4, (key_lenght-1)/4, 1 << ((3 - (key_lenght-1) & 3)*8+i));
				}
				else
				{
					sprintf(source+strlen(source), "a%i|=%i;", (key_lenght-2)/4, 1 << ((3 - (key_lenght-2) & 3)*8+i));
					sprintf(source+strlen(source), "a%i|=%i;", (key_lenght-1)/4, 1 << ((3 - (key_lenght-1) & 3)*8+i));
				}
			}
			
			// Store the result
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				sprintf(source+strlen(source),	"st.global.cs.u32 [%s+8],a0;\n"
												"st.global.cs.u32 [%s+12],a1;\n"
												"branchtarget%u:", (num_passwords_loaded==1)?"kptr":"ptr1"
																 , (num_passwords_loaded==1)?"kptr":"ptr1", k);
			else
				sprintf(source+strlen(source),	"output[%s2]=a0;"
												"output[%s3]=a1;}", num_passwords_loaded==1?"":"found+", num_passwords_loaded==1?"":"found+");
		}
	}
	else
	{
		// How to use the cache depending on the number of hash loaded
		char cache_bit_table[4];
		char cache_other[4];
		cl_uint m = 0x0000ffff, k, j;
		int bits_to_check;
		cl_uint first_bit_lm_size_bit_table;

		_BitScanReverse(&first_bit_lm_size_bit_table, lm_size_bit_table);
		bits_to_check = __min(first_bit_lm_size_bit_table+1, first_bit_size_table)+1;

		if(lm_size_bit_table/8192 > gpu->l2_cache_size)
		{
			strcpy(cache_bit_table, "cg");
			strcpy(cache_other, "cg");
		}
		else
		{
			strcpy(cache_bit_table, "ca");
			strcpy(cache_other, (size_table*4/1024 > 4*gpu->l1_cache_size) ? "cg" : "ca");
		}

		// Transpose 32x32 bit matrix
		for (i = 16; i != 0; i >>= 1, m ^= m << i)
			for(k = 0; k < 32; k = (k+i+1) & ~i)
				if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
					sprintf(source+strlen(source),	"shr.b32 x0,c%u,%uU;\n"
													"xor.b32 x0,x0,c%u;\n"
													"and.b32 x0,x0,%uU;\n"
													"xor.b32 c%u,c%u,x0;\n"
													"shl.b32 x0,x0,%uU;\n"
													"xor.b32 c%u,c%u,x0;\n", k, i, k+i, m, k+i, k+i, i, k, k);
				else
				{
					sprintf(source+strlen(source),"x0=(c%u^(c%u>>%uU))&%uU;"
													"c%u^=x0;"
													"c%u^=x0<<%uU;" , k+i, k, i, m
																	, k+i
																	, k, i);
				}

		if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
			sprintf(source+strlen(source),  "ld.param.u%i kptr,[bit_table];\n"
											"cvta.to.global.u%i kptr,kptr;\n", PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS);
		else
			sprintf(source+strlen(source),	"uint hash_value;");
		// Check match
		for(j = 0; j < 32; j++)
		{
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				sprintf(source+strlen(source), "and.b32 x0,c%u,%uU;\n", j, lm_size_bit_table);//x0 is hash_value
			else
			{
				if (c_memory_space[j] == MEMORY_REGISTER)
					sprintf(source + strlen(source), "hash_value=c%u&%uU;", j, lm_size_bit_table);
				if (c_memory_space[j] == MEMORY_SHARED)
					sprintf(source + strlen(source), "hash_value=cs[get_local_id(0)+%u]&%uU;\n", cs_mapped[j]*gpu->lm_work_group_size, lm_size_bit_table);
			}
			// TODO: Take into account that SIZE_TABLE can be greater than SIZE_BIT_TABLE
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				sprintf(source+strlen(source),	"shr.b32 x2,x0,5;\n"// x2 is hash_value_index
												"and.b32 x3,x0,31;\n"// x3 is hash_value_shift

												"mad.%s.u32 ptr1,x2,4,kptr;\n"
												"ld.global.%s.u32 x2,[ptr1];\n"
												"bfe.u32 x2,x2,x3,1;\n"

												"setp.eq.b32 pred0,x2,0;\n"
												"@pred0 bra endfortable%u;\n"

												"ld.param.u%i ptr0,[table];\n"
												"cvta.to.global.u%i ptr0,ptr0;\n"
												"and.b32 x2,x0,%uU;\n"
												"mul.%s.u32 ptr1,x2,4;\n"
												"add.u%i ptr1,ptr1,ptr0;\n"
												"ld.global.%s.u32 x2,[ptr1];\n"
							"beginfortable%u:	setp.eq.b32 pred0,x2,0xffffffff;\n"
												"@pred0 bra endfortable%u;\n", (PTR_SIZE_IN_BITS==64)?"wide":"lo", cache_bit_table, j, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, size_table, (PTR_SIZE_IN_BITS==64)? "wide":"lo", PTR_SIZE_IN_BITS, cache_other, j, j);// x2 is index
			else
				sprintf(source+strlen(source),	"if((bit_table[hash_value>>5]>>(hash_value&31))&1)"
													"for(uint index=table[hash_value&%uu];index!=0xffffffff;index=same_hash_next[index])"
													"{"
														"uint bin_value,c_value;"/*, use_local_bit_table ? "l" : ""*/, size_table);// x3 is bin_value; x4 is c_value
		
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				sprintf(source+strlen(source),	"ld.param.u%i ptr0,[binary_values];\n"
												"cvta.to.global.u%i ptr0,ptr0;\n"
												"mad.%s.u32 ptr0,x2,8,ptr0;\n", PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, (PTR_SIZE_IN_BITS==64)?"wide":"lo");
			// Check the first 32 bits
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
			{
				if(bits_to_check < 8)	sprintf(source+strlen(source),  "ld.global.%s.u8 x3,[ptr0];\n"
																		"and.b32 x4,c%u,0xff;\n"
																		"setp.ne.b32 pred0,x3,x4;\n"
																		"@pred0 bra continuefortable%u;\n", cache_other, j, j);
				if(bits_to_check < 16)	sprintf(source+strlen(source),  "ld.global.%s.u8 x3,[ptr0+1];\n"
																		"shr.b32 x4,c%u,8;\n"
																		"and.b32 x4,x4,0xff;\n"
																		"setp.ne.b32 pred0,x3,x4;\n"
																		"@pred0 bra continuefortable%u;\n", cache_other, j, j);
				if(bits_to_check < 24)	sprintf(source+strlen(source),  "ld.global.%s.u8 x3,[ptr0+2];\n"
																		"shr.b32 x4,c%u,16;\n"
																		"and.b32 x4,x4,0xff;\n"
																		"setp.ne.b32 pred0,x3,x4;\n"
																		"@pred0 bra continuefortable%u;\n", cache_other, j, j);
										sprintf(source+strlen(source),  "ld.global.%s.u8 x3,[ptr0+3];\n"
																		"shr.b32 x4,c%u,24;\n"
																		"setp.ne.b32 pred0,x3,x4;\n"
																		"@pred0 bra continuefortable%u;\n", cache_other, j, j);
			}
			else
			{
				if (c_memory_space[j] == MEMORY_REGISTER)
				{
					if (bits_to_check < 8)	sprintf(source + strlen(source), "if((c%u&0xFF)!=binary_values[index*8])continue;", j);
					if (bits_to_check < 16)	sprintf(source + strlen(source), "if(((c%u>>8)&0xFF)!=binary_values[index*8+1])continue;", j);
					if (bits_to_check < 24)	sprintf(source + strlen(source), "if(((c%u>>16)&0xFF)!=binary_values[index*8+2])continue;", j);
											sprintf(source + strlen(source), "if((c%u>>24)!=binary_values[index*8+3])continue;", j);
				}
				if (c_memory_space[j] == MEMORY_SHARED)
				{
					if (bits_to_check < 8)	sprintf(source + strlen(source), "if(( cs[get_local_id(0)+%uu] & 0xFF) != binary_values[index*8])continue;\n", cs_mapped[j] * gpu->lm_work_group_size);
					if (bits_to_check < 16)	sprintf(source + strlen(source), "if(((cs[get_local_id(0)+%uu] >> 8) & 0xFF) != binary_values[index*8+1])continue;", cs_mapped[j] * gpu->lm_work_group_size);
					if (bits_to_check < 24)	sprintf(source + strlen(source), "if(((cs[get_local_id(0)+%uu] >> 16) & 0xFF) != binary_values[index*8+2])continue;", cs_mapped[j] * gpu->lm_work_group_size);
											sprintf(source + strlen(source), "if(( cs[get_local_id(0)+%uu] >> 24) != binary_values[index*8+3])continue;", cs_mapped[j] * gpu->lm_work_group_size);
				}
			}

			for(i = 32, k = UINT_MAX; i < 64; i++)
			{
				if(k != (i >> 3))
				{
					char buffer[32];
					if(k != UINT_MAX)// Not first iteration
					{
						if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
							sprintf(source+strlen(source),	"setp.ne.b32 pred0,x3,x4;\n"
															"@pred0 bra continuefortable%u;\n", j);
						else
							strcat(source, "if(c_value!=bin_value)continue;");
						buffer[0] = 0;
					}
					else// First iteration: Use a mask for bin_value
						sprintf(buffer, "&%uU", (0xFF << (i&7)) & 0xFF);
					if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
					{
						sprintf(source+strlen(source), "ld.global.%s.u8 x3,[ptr0+%uU];\n", cache_other, i >> 3);
						if(buffer[0]) sprintf(source+strlen(source), "and.b32 x3,x3,%s;\n", buffer+1);

						sprintf(source+strlen(source), c_memory_space[i] == MEMORY_SHARED ?
														"ld.shared.b32 a5,[cs_ptr+%uU];\n"
														"bfe.u32 x4,a5,%u,1;\n"
														:
														"bfe.u32 x4,c%i,%u,1;\n", c_memory_space[i] == MEMORY_SHARED ? cs_mapped[i] * gpu->lm_work_group_size * 4 : i, j);

						if(i&7)	sprintf(source+strlen(source), "shl.b32 x4,x4,%i;\n", i&7);
					}
					else
					{
						sprintf(source+strlen(source), "bin_value=binary_values[(index<<3)+%i]%s;", i >> 3, buffer);
						if(c_memory_space[i] == MEMORY_SHARED)
							sprintf(source + strlen(source), "c_value=(cs[get_local_id(0)+%uU]&%uU)%s%i;", cs_mapped[i] * gpu->lm_work_group_size, 1 << j, j>(i & 7) ? ">>" : "<<", (int)abs(((int)i & 7) - ((int)j)));
						else// Registers
							sprintf(source+strlen(source), "c_value=(c%i&%uU)%s%i;", i, 1<<j, j>(i&7)?">>":"<<", (int)abs(((int)i&7)-((int)j)));
					}
					k = i >> 3;
				}
				else
				{
					if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
					{
						sprintf(source+strlen(source), c_memory_space[i] == MEMORY_SHARED ?
														"ld.shared.b32 a5,[cs_ptr+%uU];\n"
														"bfe.u32 x5,a5,%u,1;\n"
														:
														"bfe.u32 x5,c%i,%u,1;\n", c_memory_space[i] == MEMORY_SHARED ? cs_mapped[i] * gpu->lm_work_group_size * 4 : i, j);

						sprintf(source+strlen(source), "bfi.b32 x4,x5,x4,%i,1;\n", i&7);
					}
					else
					{
						if(c_memory_space[i] == MEMORY_SHARED)
							sprintf(source + strlen(source), "c_value|=(cs[get_local_id(0)+%uU]&%uU)%s%i;", cs_mapped[i] * gpu->lm_work_group_size, 1 << j, j>(i & 7) ? ">>" : "<<", (int)abs(((int)i & 7) - ((int)j)));
						else// Registers
							sprintf(source+strlen(source), "c_value|=(c%i&%uU)%s%i;", i, 1<<j, j>(i&7)?">>":"<<", (int)abs(((int)i&7)-((int)j)));
					}
				}
			}
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				sprintf(source+strlen(source),	"setp.ne.b32 pred0,x3,x4;\n"
												"@pred0 bra continuefortable%u;\n", j);
			else
				strcat(source, "if(c_value!=bin_value)continue;");

			// Total match
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				sprintf(source+strlen(source),	"ld.param.u%i ptr0,[output];\n"
												"cvta.to.global.u%i ptr0,ptr0;\n"
												"atom.global.add.u32 a4,[ptr0],1;\n"
												"mad.%s.u32 ptr1,a4,12,ptr0;\n"
												"st.global.cs.u32 [ptr1+4],x2;\n"

												"mov.b32 a0,kmask1;\n"
												"and.b32 a1,kmask0,0xffff0000;\n", PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, (PTR_SIZE_IN_BITS==64)?"wide":"lo");// a0 is key0; a1 is key1
			else
			{
				if (num_passwords_loaded == 1)
					strcat(source, "output[1]=0;");
				else
					strcat(source,	"uint found=atomic_inc(output)*3;"
									"output[found+1]=index;");

				strcat(source,	"a0=kmask1;"
								"a1=kmask0&0xffff0000;");
				}

			// Get last part of key
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
				sprintf(source+strlen(source),	"cvt.u%i.u16 ptr1,kmask0;\n"
												"mov.u%i ptr0,last;\n"
												"add.u%i ptr0,ptr1,ptr0;\n", PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS);

			for(k = 0; k < 8; k++)
				if(k_values_char[k] == VALUE_UNKNOW)
				{
					if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
					{
						sprintf(source+strlen(source),	"ld.const.u32 a2,[ptr0+%iU];\n"
														"bfe.u32 a2,a2,%u,1;\n"
														"bfi.b32 a%i,a2,a%i,%i,1;\n", k_mapped_to_last[k]*4, j
																				  , (key_lenght-2)/4, (key_lenght-2)/4, (3 - (key_lenght-2) & 3)*8+k);

						sprintf(source+strlen(source),	"ld.const.u32 a2,[ptr0+%iU];\n"
														"bfe.u32 a2,a2,%u,1;\n"
														"bfi.b32 a%i,a2,a%i,%i,1;\n", k_mapped_to_last[k]*4+num_char_in_charset*num_char_in_charset/32*4, j
																				  , (key_lenght-1)/4, (key_lenght-1)/4, (3 - (key_lenght-1) & 3)*8+k);
					}
					else
					{
						sprintf(source+strlen(source), "a%i|=((last[(kmask0&0xffff)+%uU]>>%u)&1)<<%i;", (key_lenght-2)/4, k_mapped_to_last[k], j,(3 - (key_lenght-2) & 3)*8+k);
						sprintf(source+strlen(source), "a%i|=((last[(kmask0&0xffff)+%uU]>>%u)&1)<<%i;", (key_lenght-1)/4, k_mapped_to_last[k]+num_char_in_charset*num_char_in_charset/32, j, (3 - (key_lenght-1) & 3)*8+k);
					}
				}
				else if(k_values_char[k] == VALUE_KNOW_ALL_1)
				{
					if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
					{
						sprintf(source+strlen(source), "or.b32 a%i,a%i,%i;\n", (key_lenght-2)/4, (key_lenght-2)/4, 1 << ((3 - (key_lenght-2) & 3)*8+k));
						sprintf(source+strlen(source), "or.b32 a%i,a%i,%i;\n", (key_lenght-1)/4, (key_lenght-1)/4, 1 << ((3 - (key_lenght-1) & 3)*8+k));
					}
					else
					{
						sprintf(source+strlen(source), "a%i|=%i;", (key_lenght-2)/4, 1 << ((3 - (key_lenght-2) & 3)*8+k));
						sprintf(source+strlen(source), "a%i|=%i;", (key_lenght-1)/4, 1 << ((3 - (key_lenght-1) & 3)*8+k));
					}
				}

			// Save the found key
			if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
			{
				sprintf(source+strlen(source),	"ld.param.u%i ptr0,[output];\n"
												"cvta.to.global.u%i ptr0,ptr0;\n"
												"mad.%s.u32 ptr1,a4,12,ptr0;\n"
												"st.global.cs.u32 [ptr1+8],a0;\n"
												"st.global.cs.u32 [ptr1+12],a1;\n", PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, (PTR_SIZE_IN_BITS==64)?"wide":"lo");

				// End of cycles
				sprintf(source+strlen(source),	"continuefortable%u:ld.param.u%i ptr0,[same_hash_next];\n"
												"cvta.to.global.u%i ptr0,ptr0;\n"
												"mad.%s.u32 ptr1,x2,4,ptr0;\n"
												"ld.global.%s.u32 x2,[ptr1];\n"
												"bra beginfortable%u;\n"
												"endfortable%u:", j, PTR_SIZE_IN_BITS, PTR_SIZE_IN_BITS, (PTR_SIZE_IN_BITS==64)?"wide":"lo", cache_other, j, j);
			}
			else
			{
				if (num_passwords_loaded == 1)
					sprintf(source+strlen(source),	"output[2]=a0;"
													"output[3]=a1;}");
				else
					sprintf(source+strlen(source),	"output[found+2]=a0;"
													"output[found+3]=a1;}");
			}
		}
	}

	if (gpu->flags & GPU_FLAG_SUPPORT_PTX) strcat(source, "ret;");

	strcat(source, "}");// Kernel finish
}
PRIVATE char* gen_opencl_code(GPUDevice* gpu, cl_uint lm_size_bit_table)
{
	cl_uint i, k, unknow_k_index;
	char* source = (char*)malloc(512 * 1024 * __max(1, max_lenght - current_key_lenght + 1));
	cl_uchar k_values_char[8];
	int k_mapped_to_last[8];// Mapped k position of char into pointer last

	memset(k_values_char, 0, sizeof(k_values_char));

	// Find same pattern in characters
	for(i = 0; i < num_char_in_charset; i++)
		for(k = 0; k < 8; k++)
			if(charset[i] & (1 << k))
				k_values_char[k]++;

	// Put the pattern in an easy way to interpret
	for(k = 0; k < 8; k++)
	{
		if(k_values_char[k] == 0)
			k_values_char[k] = VALUE_KNOW_0;
		else if(k_values_char[k] == num_char_in_charset)
			k_values_char[k] = VALUE_KNOW_ALL_1;
		else
			k_values_char[k] = VALUE_UNKNOW;
	}

	source[0] = 0;
	/* LM kernel (OpenCL 1.0 conformance)*/
	if (gpu->flags & GPU_FLAG_SUPPORT_PTX)
	{
		// Use lop3 instruction to reduce gate counts
		if (gpu->flags & GPU_FLAG_NVIDIA_LOP3)
			sprintf(source + strlen(source), ".version 4.3\n.target sm_50\n.address_size %i\n", PTR_SIZE_IN_BITS);
		else
			sprintf(source + strlen(source), ".version 2.3\n.target sm_20\n.address_size %i\n", PTR_SIZE_IN_BITS);
	}
	else
	{
		if(num_passwords_loaded > 1) strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");
		if(gpu->flags & GPU_FLAG_NATIVE_BITSELECT)	 strcat(source,	"#define bs(b,c,d)	bitselect(b,c,d)\n");
	}

	strcat(source, (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? ".const .b8 charset[]={" : "__constant uchar charset[]={");
	// Fill charset
	for(i = 0; i < num_char_in_charset; i++)
		sprintf(source + strlen(source), "%uU%s", (cl_uint)charset[i], i == num_char_in_charset - 1 ? "" : ",");
	strcat(source, "};\n");

	// The last character
	strcat(source, (gpu->flags & GPU_FLAG_SUPPORT_PTX) ? ".const .b32 last[]={" : "__constant uint last[]={");
	for(k = 0, unknow_k_index = 0; k < 8; k++)
	{
		if(k_values_char[k] != VALUE_UNKNOW) continue;

		k_mapped_to_last[k] = num_char_in_charset*num_char_in_charset/32*2*unknow_k_index;
		unknow_k_index++;

		// Calculate last-1
		for(i = 0; i < num_char_in_charset*num_char_in_charset/32; i++)
		{
			cl_uint val = 0, j;

			for(j = 0; j < 32; j++)
				val |= (charset[(j+i*32)%num_char_in_charset] & (1<<k)) ? (1 << j) : 0;

			sprintf(source+strlen(source), "%s%uU", (k || i) ? "," : "", val);
		}
		// Calculate last
		for(i = 0; i < num_char_in_charset*num_char_in_charset/32; i++)
		{
			cl_uint val = 0, j;

			for(j = 0; j < 32; j++)
				val |= (charset[(j+i*32)/num_char_in_charset] & (1<<k)) ? (1 << j) : 0;

			sprintf(source+strlen(source), ",%uU", val);
		}
	}
	strcat(source, "};\n");

	// Generate kernels
	for(i = current_key_lenght; i <= max_lenght ; i++)
		gen_kernel_with_lenght(i, source+strlen(source), k_values_char, gpu, k_mapped_to_last, lm_size_bit_table);

	return source;
}

PRIVATE void crypt_lm_protocol_opencl(OpenCL_Param* param)
{
	cl_uint lm_param[4];
	size_t work_group_size = param->max_work_group_size;
	cl_uint num_found, i, j, last_index;
	cl_uchar key_text[8];

	HS_SET_PRIORITY_GPU_THREAD;

#ifndef ANDROID
	if(param->use_ptx)
	{
		void *args[] = { &lm_param[0], &lm_param[1], &param->cu_mems[GPU_OUTPUT],
						 &param->cu_mems[GPU_TABLE], &param->cu_mems[GPU_BINARY_VALUES], &param->cu_mems[GPU_SAME_HASH_NEXT], &param->cu_mems[GPU_BIT_TABLE], CU_LAUNCH_PARAM_END };
		cuCtxPushCurrent(param->cu_context);

		while(continue_attack && param->gen(lm_param, param->NUM_KEYS_OPENCL, param->thread_id))
		{
			unsigned int key_lenght = lm_param[2];
			unsigned int blocksPerGrid = (lm_param[3] + (unsigned int)work_group_size - 1) / (unsigned int)work_group_size;

			// To maintain synchronization with CPU we need SSE2 (128 bits) length
			// so we need 4x integer length
			lm_param[1] *= 4;
			for(last_index = 0; last_index < 4; last_index++, lm_param[1]++)
			{
				CUresult res = cuLaunchKernel(param->cu_kernels[key_lenght], blocksPerGrid, 1, 1, (unsigned int)work_group_size, 1, 1, 0, NULL, args, NULL);
				cuCtxSynchronize();
				cuMemcpyDtoH(&num_found, param->cu_mems[GPU_OUTPUT], 4);

				// GPU found some passwords
				if(num_found)
				{
					cuMemcpyDtoH(param->output, param->cu_mems[GPU_OUTPUT] + 4, 3*sizeof(cl_uint)*num_found);
					// Iterate all found passwords
					for(i = 0; i < num_found; i++)
					{
						// Decode plaintext
						for(j = 0; j < 8; j++)
							key_text[3-(j&3)+4*(j/4)] = (param->output[3*i+1+j/4] >> ((j&3)*8)) & 0xFF;

						password_was_found(param->output[3*i], key_text);
					}

					num_found = 0;
					cuMemcpyHtoD(param->cu_mems[GPU_OUTPUT], &num_found, 4);
				}
			}

			report_keys_processed(lm_param[3] * V128_BIT_LENGHT);
		}
	}
	else
#endif
		while(continue_attack && param->gen(lm_param, param->NUM_KEYS_OPENCL, param->thread_id))
		{
			cl_uint key_lenght = lm_param[2];
			size_t num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(lm_param[3], work_group_size);// Convert to multiple of work_group_size
			pclSetKernelArg(param->kernels[key_lenght], 0, sizeof(cl_uint), &lm_param[0]);//current_key

			// To maintain synchronization with CPU we need SSE2 (128 bits) length
			// so we need 4x integer length
			lm_param[1] *= 4;
			for(last_index = 0; last_index < 4; last_index++, lm_param[1]++)
			{
				pclSetKernelArg(param->kernels[key_lenght], 1, sizeof(cl_uint), &lm_param[1]);//last_key_index
				pclEnqueueNDRangeKernel(param->queue, param->kernels[key_lenght], 1, NULL, &num_work_items, &work_group_size, 0, NULL, NULL);
				pclFlush(param->queue);
			}
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);

			// GPU found some passwords
			if(num_found)
			{
				pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 4, 3*sizeof(cl_uint)*num_found, param->output, 0, NULL, NULL);
				// Iterate all found passwords
				for(i = 0; i < num_found; i++)
				{
					// Decode plaintext
					for(j = 0; j < 8; j++)
						key_text[3-(j&3)+4*(j/4)] = (param->output[3*i+1+j/4] >> ((j&3)*8)) & 0xFF;

					password_was_found(param->output[3*i], key_text);
				}

				num_found = 0;
				pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_found, 0, NULL, NULL);
			}

			report_keys_processed(lm_param[3] * V128_BIT_LENGHT);
		}

	release_opencl_param(param);
	
	finish_thread();
}
PRIVATE void crypt_lm_protocol_opencl_init(OpenCL_Param* param, cl_uint gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_lm_crypt)
{
	cl_uint local_num_found = 0, i, lm_size_bit_table;
	char buffer[16];
	cl_uint output_size = 3 * sizeof(cl_uint)*num_passwords_loaded;

	create_opencl_param(param, gpu_device_index, gen, output_size, TRUE);

#ifdef ANDROID
	param->NUM_KEYS_OPENCL /= 1;
#else
	param->NUM_KEYS_OPENCL *= 4;
#endif
	if(!LM_BEGIN_USE_HASHTABLE)	param->NUM_KEYS_OPENCL *= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 3 * sizeof(cl_uint)*param->NUM_KEYS_OPENCL;
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Take into account the amount of cache
	if (gpu_devices[gpu_device_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		lm_size_bit_table = size_bit_table;
	else
		lm_size_bit_table = lm_get_bit_table_mask(num_passwords_loaded, gpu_devices[gpu_device_index].l1_cache_size*1024, gpu_devices[gpu_device_index].l2_cache_size*1024);
	
	// Generate opencl code
	char* source = gen_opencl_code(&gpu_devices[gpu_device_index], lm_size_bit_table);

	//size_t len = strlen(source);
	//{// Comment this code in release
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\lm_code.ptx","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}
	
	// Perform runtime source compilation
	if(!build_opencl_program(param, source, gpu_devices[gpu_device_index].lm_compiler_options))
	{
		release_opencl_param(param);
		return;
	}

	// Crypt method
	for(i = current_key_lenght; i <= max_lenght ; i++)
	{
		sprintf(buffer, "lm_crypt%u", i);
		cl_int code = create_kernel(param, i, buffer);
		if (code != CL_SUCCESS)
		{
			release_opencl_param(param);
			return;
		}
#ifndef ANDROID
		else if(param->use_ptx)
			cuFuncSetCacheConfig(param->cu_kernels[i], CU_FUNC_CACHE_PREFER_SHARED);
#endif
	}

	// Create memory objects
	create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, 4+output_size, NULL);

	if(LM_BEGIN_USE_HASHTABLE)
	{
		if (gpu_devices[gpu_device_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			create_opencl_mem(param, GPU_TABLE		   , CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, 4*(size_table+1), table);
			create_opencl_mem(param, GPU_BIT_TABLE	   , CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, 4*(size_bit_table/32+1), bit_table);
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
			create_opencl_mem(param, GPU_SAME_HASH_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, 4*num_passwords_loaded, same_hash_next);
		}
		else
		{
			create_opencl_mem(param, GPU_TABLE		   , CL_MEM_READ_ONLY, 4*(size_table+1), NULL);
			create_opencl_mem(param, GPU_BIT_TABLE	   , CL_MEM_READ_ONLY, 4*(lm_size_bit_table/32+1), NULL);
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_HASH_NEXT, CL_MEM_READ_ONLY, 4*num_passwords_loaded, NULL);
		}
	}

	// Set params
	if(!param->use_ptx)
		for(i = current_key_lenght; i <= max_lenght ; i++)
		{
			pclSetKernelArg(param->kernels[i], 2, sizeof(cl_mem), (void*) &param->mems[GPU_OUTPUT]);
			if(LM_BEGIN_USE_HASHTABLE)
			{
				pclSetKernelArg(param->kernels[i], 3, sizeof(cl_mem), (void*) &param->mems[GPU_TABLE]);
				pclSetKernelArg(param->kernels[i], 4, sizeof(cl_mem), (void*) &param->mems[GPU_BINARY_VALUES]);
				pclSetKernelArg(param->kernels[i], 5, sizeof(cl_mem), (void*) &param->mems[GPU_SAME_HASH_NEXT]);
				pclSetKernelArg(param->kernels[i], 6, sizeof(cl_mem), (void*) &param->mems[GPU_BIT_TABLE]);
			}
		}

	// Copy const data
	cl_write_buffer(param, GPU_OUTPUT, 4, &local_num_found);
	if (LM_BEGIN_USE_HASHTABLE && !(gpu_devices[gpu_device_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
	{
		// Create and initialize bitmaps
		cl_uint* my_bit_table = (cl_uint*)calloc(lm_size_bit_table / 32 + 1, sizeof(cl_uint));
		cl_uchar* out = (cl_uchar*)binary_values;

		for(i = 0; i < num_passwords_loaded; i++, out+=8)
		{
			cl_uint value_map = (out[0] | out[1] << 8 | out[2] << 16 | out[3] << 24) & lm_size_bit_table;
			my_bit_table[value_map >> 5] |= 1 << (value_map & 31);
		}

		cl_write_buffer(param, GPU_TABLE		 , 4*(size_table+1), table);
		cl_write_buffer(param, GPU_BIT_TABLE	 , 4*(lm_size_bit_table/32+1), my_bit_table);
		cl_write_buffer(param, GPU_BINARY_VALUES , BINARY_SIZE*num_passwords_loaded, binary_values);
		cl_write_buffer(param, GPU_SAME_HASH_NEXT, 4*num_passwords_loaded, same_hash_next);

		pclFinish(param->queue);

		free(my_bit_table);
	}

	if (!param->use_ptx)
		pclFinish(param->queue);

	free(source);

	// Check time spend in kernels
	param->max_work_group_size = gpu_devices[gpu_device_index].lm_work_group_size;
	if (!param->use_ptx)
	{
		pclSetKernelArg(param->kernels[max_lenght], 0, sizeof(cl_uint), &local_num_found);//current_key
		pclSetKernelArg(param->kernels[max_lenght], 1, sizeof(cl_uint), &local_num_found);//last_key_index
		size_t num_work_items = param->NUM_KEYS_OPENCL;

		// Warm up
		int64_t init = get_milliseconds();
		pclEnqueueNDRangeKernel(param->queue, param->kernels[max_lenght], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		pclFinish(param->queue);
		int64_t duration = get_milliseconds() - init;
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, sizeof(cl_uint), &local_num_found, 0, NULL, NULL);

		if (duration > (OCL_NORMAL_KERNEL_TIME * 4 / 3) || duration < (OCL_NORMAL_KERNEL_TIME / 2))
			hs_log(HS_LOG_WARNING, "LM calculate_best_work_group kernel",  "duration: %ums", (cl_uint)duration);

		// Select a good num_work_items
		change_value_proportionally(&param->NUM_KEYS_OPENCL, (cl_uint)duration);
		num_work_items = param->NUM_KEYS_OPENCL;

		init = get_milliseconds();
		pclEnqueueNDRangeKernel(param->queue, param->kernels[max_lenght], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		pclFinish(param->queue);
		duration = get_milliseconds() - init;
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, sizeof(cl_uint), &local_num_found, 0, NULL, NULL);

		// Select a good num_work_items
		change_value_proportionally(&param->NUM_KEYS_OPENCL, (cl_uint)duration);

		hs_log(HS_LOG_DEBUG, "LM calculate_best_work_group kernel", "duration: %ums\nkeys:%u\nwork_group_size:%u", (cl_uint)duration, param->NUM_KEYS_OPENCL, param->max_work_group_size);
	}
	else
	{
#ifndef ANDROID
		cl_uint lm_param_current_key = 0;
		cl_uint lm_param_last_key = 0;

		void *args[] = { &lm_param_current_key, &lm_param_last_key, &param->cu_mems[GPU_OUTPUT],
			&param->cu_mems[GPU_TABLE], &param->cu_mems[GPU_BINARY_VALUES], &param->cu_mems[GPU_SAME_HASH_NEXT], &param->cu_mems[GPU_BIT_TABLE], CU_LAUNCH_PARAM_END};
		
		// Warm up
		cl_uint blocksPerGrid = (param->NUM_KEYS_OPENCL + (cl_uint)param->max_work_group_size - 1) / (cl_uint)param->max_work_group_size;
		int64_t init = get_milliseconds(), duration;
		CUresult res = cuLaunchKernel(param->cu_kernels[max_lenght], blocksPerGrid, 1, 1, (unsigned int)param->max_work_group_size, 1, 1, 0, NULL, args, NULL);
		if (res == CUDA_SUCCESS)
			res = cuCtxSynchronize();
		duration = get_milliseconds() - init;
		cuMemcpyHtoD(param->cu_mems[GPU_OUTPUT], &lm_param_last_key, 4);

		if (duration > (OCL_NORMAL_KERNEL_TIME * 4 / 3) || duration < (OCL_NORMAL_KERNEL_TIME / 2))
			hs_log(HS_LOG_WARNING, "LM calculate_best_work_group kernel", "duration: %ums", (cl_uint)duration);

		// Select a good num_work_items
		if (res == CUDA_SUCCESS)
			change_value_proportionally(&param->NUM_KEYS_OPENCL, (cl_uint)duration);

		// Final test
		blocksPerGrid = (param->NUM_KEYS_OPENCL + (cl_uint)param->max_work_group_size - 1) / (cl_uint)param->max_work_group_size;
		init = get_milliseconds();
		res = cuLaunchKernel(param->cu_kernels[max_lenght], blocksPerGrid, 1, 1, (unsigned int)param->max_work_group_size, 1, 1, 0, NULL, args, NULL);
		if (res == CUDA_SUCCESS)
			res = cuCtxSynchronize();
		duration = get_milliseconds() - init;
		cuMemcpyHtoD(param->cu_mems[GPU_OUTPUT], &lm_param_last_key, 4);

		// Select a good num_work_items
		if (res == CUDA_SUCCESS)
			change_value_proportionally(&param->NUM_KEYS_OPENCL, (cl_uint)duration);

		hs_log(HS_LOG_DEBUG, "LM calculate_best_work_group kernel", "duration: %ums\nkeys:%u\nwork_group_size:%u", (cl_uint)duration, param->NUM_KEYS_OPENCL, param->max_work_group_size);
		cuCtxPopCurrent(&param->cu_context);
#endif
	}

	*gpu_lm_crypt = crypt_lm_protocol_opencl;
}
#endif

// TODO: Check this algorithm. Works in Nvidia and Intel but not in AMD
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*PRIVATE void ocl_write_lm_header(char* source, GPUDevice* gpu, cl_uint ntlm_size_bit_table)
{
	source[0] = 0;
	// Header definitions
	if(num_passwords_loaded > 1 )
		strcat(source,  "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n"
						"#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable\n");

	if(num_passwords_loaded > 1 )
		sprintf(source+strlen(source),
"#define SIZE_TABLE %uu\n"
"#define SIZE_BIT_TABLE %uu\n", size_table, ntlm_size_bit_table);

	strcat(source, "__constant uchar SBox_const[512]={"
			//S0
			"7,12,2,15,4,10,11,12,11,6,7,9,13,0,4,10,2,5,8,3,15,9,6,5,8,3,1,14,1,14,13,0,0,5,15,10,7,9,2,5,14,3,1,12,11,12,8,6,15,6,3,13,4,10,9,0,2,13,4,7,8,1,14,11,"
			//S1
			"240,192,128,176,96,240,208,64,16,32,112,224,192,16,32,112,144,48,224,0,48,96,0,144,64,128,176,80,160,208,80,160,0,176,112,16,80,192,32,240,224,80,208,128,176,32,128,64,160,208,16,96,144,0,192,160,48,224,96,48,64,112,240,144,"
			//S2
			"5,8,0,11,11,13,6,8,6,13,12,2,1,10,15,5,11,4,14,1,8,2,5,15,12,3,2,13,6,13,9,10,9,3,7,14,2,4,9,3,15,4,10,1,12,7,0,14,0,10,9,7,11,7,0,12,6,15,5,8,1,4,14,3,"
			//S3
			"224,80,176,192,176,96,16,240,0,48,96,80,96,208,240,128,128,240,32,144,64,128,224,32,208,160,128,48,48,64,80,224,112,144,208,0,192,0,160,96,144,224,0,176,80,176,192,16,16,192,64,160,160,112,48,208,32,16,112,64,240,32,144,112,"
			//S4
			"4,7,2,13,1,10,15,6,14,2,5,8,11,12,6,5,2,4,8,3,12,15,3,0,13,11,14,4,7,1,0,10,3,13,4,1,10,0,9,15,5,14,11,7,0,9,12,2,8,3,13,14,15,5,10,9,6,8,1,11,9,6,7,12,"
			//S5
			"48,128,80,240,80,240,32,64,144,64,224,48,96,16,144,160,0,176,96,128,192,32,176,112,112,224,0,208,160,208,192,16,144,112,32,192,240,160,64,48,64,16,144,160,48,192,240,80,224,0,208,112,32,80,128,224,128,176,96,0,208,96,16,176,"
			//S6
			"2,8,13,2,12,5,3,15,4,13,7,11,9,6,14,1,15,3,0,12,10,0,5,10,1,14,11,7,6,9,8,4,11,6,0,13,7,9,12,10,13,11,14,1,10,0,3,15,2,8,9,2,4,7,15,4,8,5,5,14,1,12,6,3,"
			//S7
			"176,64,128,240,96,240,80,192,16,32,176,16,208,128,224,32,80,144,48,160,160,0,0,112,192,112,96,208,48,224,144,64,224,208,64,128,144,48,32,80,32,128,112,224,112,64,16,176,0,96,240,48,240,192,192,160,80,176,144,0,160,16,96,208"
		"};\n");
}
PRIVATE void ocl_gen_kernel_with_lenght(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission, cl_uint workgroup)
{
	// Begin function code
	sprintf(source+strlen(source),	"ushort k0=0,k1=0,k2=0,k3=0,k4=0,k5=0,k6=0;"
									"uint indx;");

	// Prefetch in local memory
	sprintf(source + strlen(source), "local uchar SBox[512];");
	// Copy from global to local
	sprintf(source + strlen(source), "for(ushort i=get_local_id(0); i < 512; i+=get_local_size(0))"
										"SBox[i]=SBox_const[i];"
									"barrier(CLK_LOCAL_MEM_FENCE);");

#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
	cl_uint bits_by_char;
	_BitScanReverse(&bits_by_char, ceil_power_2(num_char_in_charset));
	cl_uint chars_in_reg = 32 / bits_by_char;
#endif
	
	for(cl_uint i = 1; i < key_lenght; i++)
	{
		cl_uint key_index = i;
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
		key_index--;
		sprintf(source + strlen(source), "max_number+=(current_key%i>>%uu)&%uu;", key_index / chars_in_reg, (key_index%chars_in_reg)*bits_by_char, ceil_power_2(num_char_in_charset) - 1);
#else
		sprintf(source + strlen(source), "max_number+=current_key[%i];", key_index);
#endif
		// Perform division
		if (div_param.magic)sprintf(source + strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
		else				sprintf(source + strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

		sprintf(source + strlen(source), "k%u=charset[max_number-NUM_CHAR_IN_CHARSET*indx];", i);

		sprintf(source + strlen(source), "max_number=indx;");
	}

	// Ks
	strcat(source,
		"uint  kp0 = 142^SBox[((k1 << 4) & 32) + ((k5 >> 1) & 16) + ( k6 & 8) + ( k3 & 4 ) + ((~k1 >> 6) & 2) + ((k5 >> 3) & 1)];"
		"uchar kp1 = ((k3 << 2) & 32) + ((k6 >> 2) & 16) + ((k2 >> 6) & 2) + ((~k4 >> 3) & 1) + 64;"
		"     kp0 += (((k2 << 3) & 32) + ((k6 >> 1) & 16) + ((k2 << 2) & 8) + ( k4 & 2)       + ((k3 >> 1) & 1) +((((k2 << 5) & 32) + ((k3 << 3) & 8)  + ((k1 << 2) & 4) + ((k4 >> 3) & 2) + ((k6 >> 4) & 1))<<6))<<8;"
		"     kp0 += (((k4 >> 2) & 32) + ((k5 << 4) & 16) + ((k4 >> 2) & 8) + ((k3 >> 5) & 4) + ((k2 >> 3) & 2) +((((k5 >> 1) & 32) + ((k3 >> 1) & 16) + ((k5 << 1) & 4) + ((k3 >> 5) & 2) + ((~k2 >> 3) & 1))<<6))<<20;"
		"uint kp6 = 41^SBox[6 * 64 + 9 ^(((k2 >> 1) & 32) + ((k4 >> 2) & 16) + ((k6 << 3) & 8) + ((k2 >> 3) & 4) + ((k1 >> 1) & 2) + ((k6 >> 2) & 1))];"
		"     kp6 ^=    SBox[7 * 64 + 13^(((k4 << 5) & 32) + ((k1 << 1) & 16) + ((k6 << 2) & 8) + ((k1 >> 2) & 4) + ((k3 >> 3) & 2) + ((k6 >> 7) & 1))];"

		"       kp6 +=  (((k4 >> 2) & 1 ) + ((k5 << 1) & 8 )+ ((k2 << 1) & 4 ) + ( k4 & 16) +((((k2 << 3) & 32) + ((k5 >> 1) & 16) + ((k6 >> 2) & 4 ) + ((k1 >> 5) & 2 ) + ((k3 >> 2) & 1 ))<<6))<<8;"
		"       kp6 +=  (((k6 >> 1) & 4 ) + ( k2 & 1 )      + ((k1 << 3) & 8 ) + ((k1 << 4) & 32) + ((k3 << 1) & 2 ) + ( k5 & 16)+((((k5 >> 3) & 1 ) + ((k6 >> 1) & 16) + ((k6 >> 3) & 8 ) + ((k2 >> 2) & 32) + ((k1 >> 5) & 4 ) + ((k3 >> 2) & 2 ))<<6))<<20;"
		"ushort kp12 =  ((k1 >> 2) & 2 ) + ((k2 >> 4) & 4 ) + ((k3 >> 1) & 8 ) + ((k5 >> 3) & 16) + ((k3 >> 1) & 32) + ( k6 & 1)      +((( k4 & 32)       + ( k2 & 16)       + ((k3 >> 4) & 8 ) + ((k4 << 2) & 4 ) + ((k1 >> 2) & 1 ) + ((k2 >> 4) & 2 ))<<6);"
		"ushort kp14 =  ((k5 >> 1) & 1 ) + ((k1 >> 2) & 4)  + ((k3 >> 1) & 16) + ((k6 >> 4) & 8 ) + ( k1 & 32)+((((k4 >> 2) & 32) + ((k5 << 3) & 8 ) + ((k5 >> 6) & 1 ) + ((k2 >> 2) & 2 ))<<6);"
		  			   
		"ushort kp16 =  ((k5 >> 2) & 2 ) + ( k2 & 1 )       + ((k1 >> 5) & 4 ) + ((k3 << 3) & 8 ) + ((k2 << 2) & 16) + ( k6 & 32)     +((((k3 << 1) & 16) + ( k4 & 4)        + ((k5 >> 1) & 8 ) + ((k6 >> 2) & 2)  + ( k1 & 1)       )<<6);"
		"ushort kp18 =  ((k4 << 1) & 4 ) + ((k1 >> 6) & 1 ) + ((k5 >> 4) & 2)  + ((k3 << 2) & 16) +((((k3 >> 1) & 1 ) + ((k4 << 1) & 16) + ((k4 >> 1) & 8 ) + ((k6 >> 2) & 4)  + ( k1 & 2)       )<<6);"
		"ushort kp20 =  ((k6 >> 1) & 2 ) + ((k1 << 1) & 8 ) + ((k3 >> 1) & 16) + ((k1 << 1) & 32) + ((k5 >> 6) & 1) +((((k2 << 2) & 32) + ((k1 >> 2) & 8 ) + ((k3 >> 4) & 4 ) + ((k6 >> 1) & 1) )<<6);"
		"ushort kp22 =  ((k4 >> 7) & 1 ) + ((k3 >> 5) & 4 ) + ((k1 << 1) & 16) + ((k4 >> 2) & 8 ) + ((k5 << 1) & 2)  + ((k6 << 5) & 32) +((( k2 & 32)       + ((k5 << 3) & 16) + ((k2 >> 4) & 4 ) + ((k4 >> 3) & 8 ) + ((k3 >> 4) & 1))<<6);"														
						 																									  
		"ushort kp24 =  ( k3 & 2)        + ((k1 >> 6) & 1)  + ((k6 >> 2) & 4)  + ((k5 >> 2) & 8)  + ((k4 << 2) & 32)+((( k6 & 32)       + ((k1 << 3) & 16) + ((k2 << 2) & 4)  + ((k3 << 1) & 8)  + ( k4 & 2))<<6);"
		"ushort kp26 =  ((k6 >> 4) & 4)  + ((k6 >> 3) & 1)  +  (k5 & 8)        + ((k5 << 1) & 32) + ((k3 >> 2) & 2)  + ((k1 << 4) & 16)+((((k2 >> 7) & 1)  + ((k2 << 3) & 16) + ((k2 << 1) & 8)  + ((k5 << 3) & 32) + ( k4 & 4))<<6);"
		"ushort kp28 =  ((k4 << 1) & 2)  + ((k6 >> 5) & 4)  + ((k6 << 2) & 8)  + ((k1 << 1) & 16) + ((k3 >> 2) & 32) + ((k3 >> 4) & 1) +((((k5 << 3) & 16) + ((k6 << 3) & 8)  + ((k1 >> 2) & 4)  + ((k5 >> 7) & 1)  + ((k2 >> 5) & 2) )<<6);"
		"ushort kp30 =  ((k2 >> 5) & 1)  + ((k1 >> 3) & 4)  + ((k6 << 2) & 16) + ( k2 & 8)        + ((k4 >> 5) & 2)  + ((k5 >> 1) & 32)+((((k4 >> 3) & 16) + ((k2 >> 1) & 8)  + ((k1 >> 2) & 1)  + ((k5 << 1) & 2) )<<6);"													
						 																									  
		"ushort kp32 =  ((k2 >> 6) & 2)  + ((k6 >> 3) & 1)  + ( k4 & 4)        + ( k3 & 8)        + ((k6 >> 1) & 16) + ((k2 << 4) & 32)+((((k4 << 2) & 32) + ((k1 >> 4) & 4)  + ((k1 << 3) & 8)  + ((k6 >> 5) & 2)  + ((k5 >> 3) & 1) )<<6);"
		"ushort kp34 =  ((k4 >> 2) & 4)  + ((k4 >> 1) & 1)  + ((k3 << 2) & 8)  + ((k3 << 3) & 32) + ( k1 & 2)        +((((k1 >> 3) & 16) + ((k3 << 5) & 32) + ((k2 << 2) & 4)  + ((k5 >> 3) & 2) )<<6);"
		"ushort kp36 =  ((k3 >> 5) & 2)  + ((k4 >> 3) & 4)  + ((k5 >> 4) & 8)  + ((k6 << 2) & 16) + ( k1 & 32)       + ((k1 >> 2) & 1) +((((k5 << 5) & 32) + ((k4 >> 3) & 16) + ((k5 >> 3) & 8)  + ((k3 >> 5) & 4)  + ((k3 >> 5) & 1))<<6);"
		"ushort kp38 =  ((k6 << 2) & 4)  + ((k4 << 4) & 16) + ((k2 >> 3) & 2)  + ((k3 << 1) & 32) +((((k2 >> 1) & 32) + ((k2 >> 1) & 16) + ((k6 >> 5) & 4)  + ((k6 >> 1) & 1)  + ((k4 >> 5) & 2) )<<6);"													
						 																									  
		"ushort kp40 =  ((k4 >> 1) & 1)  + ((k2 << 2) & 4)  + ((k1 << 2) & 8)  + ((k4 << 1) & 16) + ((k1 >> 2) & 32)+((((k2 << 4) & 32) + ( k5 & 16)       + ((k6 >> 1) & 4)  + ((k4 >> 3) & 2)  + ((k3 >> 1) & 1) )<<6);"
		"ushort kp42 =  ( k2 & 4)        + ((k6 >> 6) & 1)  + ((k2 >> 4) & 8)  + ((k1 << 5) & 32) + ((k5 << 1) & 16)+((((k5 >> 2) & 1)  + ( k6 & 16)       + ((k6 >> 2) & 8)  + ( k5 & 32)       + ((k1 >> 4) & 4)  + ((k3 >> 1) & 2) )<<6);"
		"ushort kp44 =  ((k1 >> 3) & 2)  + ((k2 >> 1) & 4)  + ((k3 >> 2) & 8)  + ((k4 << 4) & 16) + ((k6 << 5) & 32) + ((k6 >> 1) & 1) +((((k4 >> 1) & 32) + ((k2 >> 1) & 16) + ((k3 >> 1) & 8)  + ((k1 >> 3) & 4)  + ((k1 >> 3) & 1)  + ((k6 >> 6) & 2) )<<6);"
		"ushort kp46 =  ((k2 >> 6) & 1)  + ((k5 >> 4) & 4)  + ((k3 >> 2) & 16) + ((k5 << 3) & 8)  + ((k1 << 3) & 32) +((((k4 >> 3) & 4)  + ((k5 << 2) & 8)  + ((k5 >> 7) & 1)  + ((k2 >> 3) & 2) )<<6);"							 						
						  																									  
		"ushort kp48 =  ((k5 >> 1) & 2)  + ((k6 >> 6) & 1)  + ((k1 >> 4) & 4)  + ((k2 << 3) & 16) + ((k6 << 1) & 32)+((((k1 >> 2) & 32) + ((k3 << 2) & 16) + ((k4 << 1) & 4)  + ( k5 & 8)        + ((k2 >> 1) & 2)  + ((k2 >> 7) & 1) )<<6);"
		"ushort kp50 =  ((k4 >> 4) & 1)  + ((k5 >> 3) & 2)  + ((k3 << 3) & 16) +((( k3 & 1)       + ((k4 << 2) & 16) + ( k4 & 8)        + ((k3 << 2) & 32) + ((k6 >> 1) & 4)  + ((k1 << 1) & 2) )<<6);"
		"ushort kp52 =  ((k3 >> 6) & 2)  + ( k1 & 8)        + ((k3 >> 2) & 16) + ((k5 >> 1) & 32) + ((k5 >> 7) & 1) +((((k2 << 1) & 32) + ((k1 << 1) & 8)  + ((k6 << 2) & 4)  + ((k6 >> 2) & 1)  + ((k4 >> 4) & 2) )<<6);"
		"ushort kp54 =  ((k3 >> 2) & 4)  + ( k1 & 16)       + ((k4 >> 3) & 8)  + ( k5 & 2)        + ((k6 << 4) & 32)+((((k6 >> 2) & 32) + ((k2 >> 2) & 16) + ((k2 >> 1) & 4)  + ((k4 >> 4) & 8)  + ((k3 >> 5) & 1))<<6);"													
						 																									  
		"ushort kp56 =  ((k3 << 1) & 2)  + ((k4 >> 4) & 1)  + ((k6 >> 1) & 4)  + ((k5 >> 1) & 8)  + ((k1 >> 3) & 16) + ((k4 << 3) & 32)+((((k6 << 1) & 32) + ((k1 << 4) & 16) + ((k6 >> 4) & 4)  + ((k3 << 2) & 8))<<6);"
		"ushort kp58 =  ((k6 >> 3) & 4)  + ((k2 >> 2) & 1)  + ((k5 << 1) & 8)  + ((k5 << 2) & 32) + ((k3 >> 1) & 2)  + ((k2 >> 3) & 16)+((((k5 >> 5) & 1)  + ((k2 << 4) & 16) + ((k2 << 2) & 8)  + ((k1 << 4) & 32) + ((k4 << 1) & 4))<<6);"
		"ushort kp60 =  ((k1 >> 4) & 2)  + ((k5 << 2) & 4)  + ((k6 << 1) & 8)  + ( k1 & 16)       + ((k3 << 1) & 32) + ((k3 >> 5) & 1)+((((k2 >> 2) & 16) + ((k6 << 2) & 8)  + ((k5 >> 4) & 4)  + ( k4 & 1)        + ((k2 >> 2) & 2) )<<6);"
		"ushort kp62 =  ((k6 >> 7) & 1)  + ( k1 & 4)        + ((k3 >> 3) & 16) + ((k2 >> 1) & 8)  + ((k4 >> 6) & 2)  + ((k5 >> 2) & 32) +((( k4 & 32)       + ((k2 >> 2) & 8)  + ((k1 >> 3) & 1)  + ( k5 & 2)       )<<6);"					  				    		
						 			    																					  
		"ushort kp64 =  ((k6 >> 5) & 2)  + ((k3 >> 3) & 1)  + ( k5 & 4)        + ( k4 & 8)        + ((k3 << 4) & 32)+((((k5 << 2) & 32) + ((k1 >> 3) & 16) + ((k5 >> 3) & 4)  + ((k2 << 3) & 8)  + ((k6 >> 3) & 1) )<<6);"
		"ushort kp66 =  ((k5 >> 2) & 4)  + ((k1 >> 1) & 1)  + ((k4 << 2) & 8)  + ((k4 << 3) & 32) + ( k2 & 2)        + ((k1 >> 2) & 16)+((((k4 >> 4) & 1)  + ((k2 >> 3) & 16) + ((k1 << 3) & 8)  + ((k3 << 2) & 4)  + ((k6 >> 3) & 2) )<<6);"
		"ushort kp68 =  ((k5 >> 5) & 4)  + ((k5 << 2) & 8)  + ((k2 << 2) & 32) + ((k2 >> 4) & 1)  +((((k6 << 3) & 32) + ((k1 >> 1) & 16) + ((k5 << 3) & 8)  + ((k4 >> 3) & 4)  + ((k4 >> 7) & 1)  + ((k1 >> 1) & 2) )<<6);"
		"ushort kp70 =  ((k5 >> 6) & 1)  + ((k2 >> 2) & 16) + ( k1 & 8)        + ((k3 >> 5) & 2)  + ((k4 >> 1) & 32) +((((k3 << 1) & 32) + ((k6 << 4) & 16) + ((k6 << 1) & 4)  + ((k1 >> 1) & 8)  + ((k4 << 1) & 2) )<<6);"						  				    		
		  				 								  																  
		"ushort kp72 =  ((k4 >> 3) & 2)  + ((k1 >> 1) & 1)  + ((k3 << 2) & 4)  + ((k2 << 2) & 8)  + ((k5 << 1) & 16) + ((k2 >> 2) & 32) +((((k3 << 4) & 32) + ( k6 & 16)       + ((k3 >> 1) & 4)  + ((k1 >> 3) & 8)  + ((k5 >> 3) & 2)  + ((k4 >> 1) & 1) )<<6);"
		"ushort kp74 =  ( k3 & 4)        + ((k6 >> 3) & 8)  + ((k2 << 5) & 32) + ((k1 >> 6) & 2)  + ((k6 << 1) & 16)+((((k2 >> 2) & 1)  + ( k6 & 32)       + ((k5 >> 3) & 4)  + ((k4 >> 1) & 2) )<<6);"
		"ushort kp76 =  ((k6 >> 6) & 2)  + ((k3 >> 3) & 4)  + ((k4 >> 4) & 8)  + ((k2 >> 2) & 16) +((((k4 << 5) & 32) + ((k6 << 4) & 16) + ((k4 >> 3) & 8)  + ((k2 >> 1) & 4)  + ((k2 >> 5) & 1)  + ( k6 & 2)       )<<6);"
		"ushort kp78 =  ((k3 >> 4) & 1)  + ((k5 << 2) & 4)  + ((k6 << 1) & 8)  + ((k1 >> 3) & 2)  + ((k2 << 1) & 32)+((((k1 << 3) & 32) + ((k5 >> 2) & 16) + ((k5 >> 5) & 4)  + ((k3 >> 4) & 8)  + ((k5 >> 1) & 1)  + ((k3 >> 5) & 2) )<<6);"												
																															  
		"ushort kp80 =  ((k2 >> 1) & 2)  + ((k5 >> 3) & 4)  + ((k1 >> 4) & 8)  + ((k3 << 3) & 16) +((((k2 >> 2) & 32) + ((k4 << 2) & 16) + ((k1 << 1) & 4)  + ( k6 & 8)        + ((k3 >> 1) & 2)  + ((k6 >> 6) & 1) )<<6);"
		"ushort kp82 =  ((k1 << 2) & 4)  + ((k5 >> 4) & 1)  + ((k4 >> 1) & 8)  + ((k1 >> 1) & 32) + ((k6 >> 3) & 2)  + ((k4 << 3) & 16)+((((k5 << 2) & 16) + ( k5 & 8)        + ((k4 << 2) & 32) + ((k3 >> 1) & 4)  + ((k2 << 1) & 2) )<<6);"
		"ushort kp84 =  ((k4 >> 4) & 2)  + ((k1 >> 1) & 4)  + ((k2 >> 2) & 8)  + ((k5 << 5) & 32) + ((k5 >> 1) & 1) +((((k3 >> 1) & 32) + ((k5 >> 2) & 16) + ((k2 >> 1) & 8)  + ((k5 >> 6) & 2) )<<6);"
		"ushort kp86 =  ((k1 >> 2) & 1)  + ((k4 >> 4) & 4)  + ((k6 >> 3) & 16) + ((k4 << 3) & 8)  + ((k3 >> 6) & 2)+((((k6 << 4) & 32) + ( k3 & 16)       + ((k3 >> 3) & 4)  + ((k1 >> 2) & 8)  + ((k4 >> 7) & 1)  + ((k1 >> 3) & 2) )<<6);"						  				    		
	  			    													  													  
		"ushort kp88 =  ((k5 >> 4) & 1)  + ((k3 >> 1) & 4)  + ((k6 >> 1) & 8)  + ((k2 >> 3) & 16) + ((k5 << 3) & 32)+((((k2 << 4) & 16) + ((k4 << 2) & 8)  + ((k1 << 1) & 2)  + ((k4 >> 4) & 1) )<<6);"
		"ushort kp90 =  ((k3 >> 2) & 1)  + ((k2 << 1) & 8)  + ((k6 << 2) & 32) + ((k4 >> 1) & 2)  + ((k6 >> 2) & 16)+((((k6 >> 5) & 1)  + ((k3 << 4) & 16) + ((k3 << 2) & 8)  + ((k2 << 4) & 32) + ((k1 << 1) & 4)  + ((k1 >> 5) & 2) )<<6);"
		"ushort kp92 =  ((k2 >> 2) & 2)  + ( k6 & 4)        + ((k6 >> 3) & 16) + ((k4 >> 1) & 32) + ((k4 >> 7) & 1) +((((k1 << 1) & 32) + ( k3 & 16)       + ((k5 << 2) & 4)  + ((k2 >> 6) & 1)  + ((k3 >> 4) & 2) )<<6);"
		"ushort kp94 =  ((k6 >> 1) & 1)  + ((k2 >> 2) & 4)  + ((k4 >> 1) & 16) + ((k3 >> 3) & 8)  + ((k1 >> 4) & 2) +  ((k5 << 4) & 32) +((((k5 >> 2) & 32)+ ((k1 << 2) & 16) + ((k1 >> 1) & 4)  + ((k6 << 3) & 8)  + ((k2 >> 5) & 1)  + ((k3 >> 6) & 2) )<<6);"							  				    		
					  	 		    																						  
		"ushort kp96  = ((k6 >> 4) & 2)  + ((k3 >> 2) & 1)  + ((k1 << 1) & 4)  + ((k4 << 1) & 8)  + ((k3 << 5) & 32)+((((k5 << 3) & 32) + ((k1 >> 2) & 16) + ((k5 >> 2) & 4)  + ((k6 >> 3) & 8)  + ((k2 >> 2) & 1) )<<6);"
		"ushort kp98  = ((k5 >> 1) & 4)  + ( k1 & 1)        + ((k4 << 4) & 32) + ((k2 << 1) & 2)  + ( k4 & 16)      +((((k4 >> 3) & 1)  + ((k5 >> 1) & 16) + ((k2 >> 4) & 8)  + ((k1 >> 2) & 32) + ((k6 >> 2) & 2) )<<6);"
		"ushort kp100 = ((k4 << 2) & 4)  + ((k2 >> 3) & 8)  + ((k4 >> 1) & 16) + ((k2 << 1) & 32) + ((k2 >> 5) & 1) +((((k3 >> 2) & 32) + ((k1 << 2) & 16) + ((k5 << 2) & 8)  + ((k4 >> 4) & 4)  + ((k1 >> 2) & 2) )<<6);"
		"ushort kp102 = ((k5 >> 7) & 1)  + ((k2 << 1) & 16) + ((k1 >> 1) & 8)  + ((k6 << 1) & 2)  + ((k4 >> 2) & 32)+((( k3 & 32)       + ((k6 << 3) & 16) + ( k6 & 4)        + ((k5 >> 3) & 8)  + ((k1 >> 4) & 2) )<<6);"																	
						 																									  
		"ushort kp104 = ((k4 >> 2) & 2)  + ( k1 & 1)        + ((k2 << 3) & 8)  + ((k5 << 2) & 16) + ( k5 & 32)      +((((k3 << 5) & 32) + ((k6 << 1) & 16) + ( k3 & 4)        + ((k4 >> 1) & 8)  + ((k5 >> 2) & 2))<<6);"
		"ushort kp106 = ((k3 << 1) & 4)  + ((k6 >> 2) & 8)  + ((k6 >> 1) & 32) + ((k1 >> 5) & 2)  + ((k2 << 2) & 16)+((((k2 >> 1) & 1)  + ((k3 << 1) & 16) + ((k6 << 1) & 32) + ((k5 >> 2) & 4)  + ( k4 & 2)       )<<6);"
		"ushort kp108 = ((k5 << 1) & 2)  + ((k3 >> 4) & 4)  + ((k2 << 1) & 16) +((( k1 & 32)      + ((k6 << 3) & 16)+  ((k4 >> 4) & 8)  + ((k2 >> 2) & 4)  + ((k6 >> 7) & 1)  + ((k6 >> 1) & 2))<<6);"
		"ushort kp110 = ((k3 >> 5) & 1)  + ((k5 << 1) & 4)  + ((k3 >> 4) & 8)  + ((k5 >> 5) & 2)  + ( k2 & 32)      +((((k1 << 2) & 32) + ((k5 >> 3) & 16) + ((k4 << 2) & 4)  + ((k3 >> 1) & 8)  + ((k2 >> 6) & 1)  + ((k6 << 1) & 2))<<6);"												  				    		
						 																									  
		"ushort kp112 = ( k2 & 2)        + ((k5 >> 2) & 4)  + ((k1 >> 3) & 8)  + ((k3 << 4) & 16) + ((k3 << 2) & 32)+((( k5 & 32)      + ((k4 << 3) & 16) + ((k1 << 2) & 4)  + ((k2 << 1) & 8)  + ( k3 & 2)        + ((k6 >> 5) & 1))<<6);"
		"ushort kp114 = ((k2 >> 5) & 4)  + ((k5 >> 3) & 1)  + ( k4 & 8)        + ((k4 << 1) & 32) + ((k6 >> 2) & 2)+((((k1 >> 7) & 1)  + ((k1 << 3) & 16) + ((k5 << 1) & 8)  + ((k4 << 3) & 32) + ( k3       & 4)  + ((k6 >> 5) & 2))<<6);"
		"ushort kp116 = ((k4 >> 5) & 2)  + ((k1 >> 2) & 4)  + ((k6 >> 4) & 8)  + ((k5 << 4) & 32) + ((k2 >> 6) & 1) +((((k6 << 5) & 32)+ ((k5 >> 3) & 16) + ((k2 >> 2) & 8)  + ((k4 >> 5) & 1)  + ((k4 << 1) & 2))<<6);"
		"ushort kp118 = ((k1 >> 3) & 1)  + ((k4 >> 5) & 4)  + ((k5 << 4) & 16) + ((k1 >> 2) & 8)  + ((k3 >> 3) & 2)+((((k6 << 3) & 32) + ((k3 >> 1) & 16) + ((k3 >> 4) & 4)  + ((k1 << 1) & 8)  + ((k5 >> 5) & 2))<<6);"																							  				    		
			    		 											  														  
		"ushort kp120 = ((k1 << 1) & 2)  + ((k6 >> 4) & 1)  + ((k4 >> 1) & 4)  + ((k6 >> 2) & 16) + ((k2 << 3) & 32)+((((k4 << 1) & 32) + ((k3 << 4) & 16) + ((k1 >> 5) & 4)  + ((k1 << 2) & 8)  + ((k2 << 1) & 2)  + ((k5 >> 4) & 1) )<<6);"
		"ushort kp122 = ((k1 >> 4) & 4)  + ((k4 >> 2) & 1)  + ((k3 << 1) & 8)  + ((k3 << 2) & 32) + ((k5 >> 1) & 2)  +((((k4 << 2) & 8) + ((k3 << 4) & 32) + ((k2 << 1) & 4)  + ((k5 >> 4) & 2) )<<6);"
		"ushort kp124 = ((k3 >> 4) & 2)  + ((k5 >> 3) & 8)  + ((k6 << 3) & 16) + ((k4 << 5) & 32) + ((k1 >> 5) & 1)+((((k6 >> 2) & 32)  + ((k4 >> 2) & 16) + ((k1 >> 1) & 8)  + ( k6 & 4)        + ((k3 >> 4) & 1)  + ((k4 >> 6) & 2) )<<6);"
		"ushort kp126 = ((k3 >> 4) & 4)  + ((k5 >> 3) & 16) + ((k2 >> 2) & 2)  + ((k3 >> 2) & 32) +((((k5 << 4) & 32) + ( k2 & 16)       + ((k2 >> 3) & 4)  + ( k6 & 1)        + ((k4 >> 4) & 2))<<6);"
		);

	// Small optimization
	if( is_charset_consecutive(charset) )
		sprintf(source+strlen(source), "k0=%iU;", is_charset_consecutive(charset)-1);

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(ushort i=0;i<%uU;i++){", num_char_in_charset);

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "k0++;");
	else
		sprintf(source+strlen(source), "k0=charset[i];");

	sprintf(source + strlen(source),
		"ushort c0,c1,c2,c3,c4,c5,c6,c7, c0_4,c2_2,c2_1;"
		"ushort cp,kp;"

		"ushort k0_0 = (k0 & 1  ) ? 0xffff : 0;"
		"ushort k0_1 = (k0 & 2  ) ? 0xffff : 0;"
		"ushort k0_2 = (k0 & 4  ) ? 0xffff : 0;"
		"ushort k0_3 = (k0 & 8  ) ? 0xffff : 0;"
		"ushort k0_4 = (k0 & 16 ) ? 0xffff : 0;"
		"ushort k0_5 = (k0 & 32 ) ? 0xffff : 0;"
		"ushort k0_6 = (k0 & 64 ) ? 0xffff : 0;"
		"ushort k0_7 = (k0 & 128) ? 0xffff : 0;");

	// DES code
	sprintf(source+strlen(source), 
	// 1
													                                                                                                                              "c0=(kp0&0xff)^SBox[kp1 + (k0_0 & 8) + (k0_6 & 4)];"
													                                                              "kp = ((kp0>>8)&0xFFF) + (k0_5 & 4) + (k0_7 & 1024); cp=1081^kp; c1=12^SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
													                                                              "kp = (kp0>>20)        + (k0_4 & 1) + (k0_3 & 512) ;           ; c2=55^SBox[4 * 64 + (kp&63)] ^ SBox[5 * 64 + (kp>>6)];"
													                                                                                                                              "c3=kp6&0xff;"
	//2
	"c0_4=c0>>4;c2_2=c2<<2;c2_1=c2>>1;"
	"cp=((c3<<1)&34)+(c2&24)+(c0_4&4)+(c1>>7)+((((c2<<1)&34)+(c3&24)+((c1&8)>>1)+(c0&1))<<6)                     ; kp = ((kp6>>8)&0xFFF)+(k0_6 & 2)+(k0_0 & 32)+(k0_7 & 512); cp^=kp    ; c4=25^SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c0&17)+((c1>>3)&8)+(c2_2&4)+(c3&2)+((((c3>>1)&33)+(c0&18)+(c2_2&8)+((c1<<1)&4))<<6)           ;                                                           cp^=kp6>>20; c5=69^SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c1&34)+((c2>>3)&16)+(c0_4&8)+((c0<<1)&4)+(c3>>7)+(((c1&33)+((c3>>3)&16)+((c3<<1)&8)+(c0&4)+(c2_1&2))<<6);                                                           cp^=kp12   ; c6=64^SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c2&36)+(c1&145)+((c3>>2)&8)+(c0_4&2)+(((c0&40)+(c2_1&16)+(c1&4)+(c3&1))<<6)                             ; kp = kp14 + (k0_1 & 2) + (k0_2 & 1024) + (k0_3 & 256);    cp^=kp     ; c7=33^SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//3																																																																				 
	"c0_4=c4>>4;c2_2=c6<<2;c2_1=c6>>1;"																																																							 
	"cp=((c7&17)<<1)+(c6&24)+(c0_4&4)+(c5>>7)+((((c6&17)<<1)+(c7&24)+((c5&8)>>1)+(c4&1))<<6)                     ; kp = kp16 + (k0_0 & 2048);                        cp^=kp; c0 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c4&17)+((c5>>3)&8)+(c2_2&4)+(c7&2)+((((c7>>1)&33)+(c4&18)+(c2_2&8)+((c5<<1)&4))<<6)           ; kp = kp18 + (k0_6 & 8)+(k0_7 & 32)+(k0_5 & 2048); cp^=kp; c1 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c5&34)+((c6>>3)&16)+(c0_4&8)+((c4<<1)&4)+(c7>>7)+(((c5&33)+((c7>>3)&16)+((c7<<1)&8)+(c4&4)+(c2_1&2))<<6); kp = kp20 +(k0_4 & 4)+(k0_2 & 1024)+(k0_3 & 128); cp^=kp; c2 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c6&36)+(c5&145)+((c7>>2)&8)+(c0_4&2)+(((c4&40)+(c2_1&16)+(c5&4)+(c7&1))<<6)                             ; kp = kp22 + (k0_1 & 128);                         cp^=kp; c3 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//4																																																																				 
	"c0_4=c0>>4;c2_2=c2<<2;c2_1=c2>>1;"																																								 
	"cp=((c3<<1)&34)+(c2&24)+(c0_4&4)+(c1>>7)+((((c2<<1)&34)+(c3&24)+((c1&8)>>1)+(c0&1))<<6)                     ; kp = kp24 + (k0_0 & 16) + (k0_6 & 64)  ; cp^=kp; c4 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c0&17)+((c1>>3)&8)+(c2_2&4)+(c3&2)+((((c3>>1)&33)+(c0&18)+(c2_2&8)+((c1<<1)&4))<<6)           ; kp = kp26 + (k0_7 & 128)               ; cp^=kp; c5 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c1&34)+((c2>>3)&16)+(c0_4&8)+((c0<<1)&4)+(c3>>7)+(((c1&33)+((c3>>3)&16)+((c3<<1)&8)+(c0&4)+(c2_1&2))<<6); kp = kp28 + (k0_1 & 2048)              ; cp^=kp; c6 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c2&36)+(c1&145)+((c3>>2)&8)+(c0_4&2)+(((c0&40)+(c2_1&16)+(c1&4)+(c3&1))<<6)                             ; kp = kp30 + (k0_3 & 2048) +(k0_4 & 256); cp^=kp; c7 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//5																																																																				 
	"c0_4=c4>>4;c2_2=c6<<2;c2_1=c6>>1;"																																															 
	"cp=((c7&17)<<1)+(c6&24)+(c0_4&4)+(c5>>7)+((((c6&17)<<1)+(c7&24)+((c5&8)>>1)+(c4&1))<<6)                     ; kp = kp32 + (k0_7 & 1024)                            ; cp^=kp; c0 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c4&17)+((c5>>3)&8)+(c2_2&4)+(c7&2)+((((c7>>1)&33)+(c4&18)+(c2_2&8)+((c5<<1)&4))<<6)           ; kp = kp34 + (k0_6 & 16) + (k0_5 & 64) + (k0_0 & 512) ; cp^=kp; c1 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c5&34)+((c6>>3)&16)+(c0_4&8)+((c4<<1)&4)+(c7>>7)+(((c5&33)+((c7>>3)&16)+((c7<<1)&8)+(c4&4)+(c2_1&2))<<6); kp = kp36 + (k0_4 & 128)                             ; cp^=kp; c2 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c6&36)+(c5&145)+((c7>>2)&8)+(c0_4&2)+(((c4&40)+(c2_1&16)+(c5&4)+(c7&1))<<6)                             ; kp = kp38 + (k0_3 & 1)  + (k0_1 & 8) + (k0_2 & 512)  ; cp^=kp; c3 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//6																																																																				  
	"c0_4=c0>>4;c2_2=c2<<2;c2_1=c2>>1;"																																								  
	"cp=((c3<<1)&34)+(c2&24)+(c0_4&4)+(c1>>7)+((((c2<<1)&34)+(c3&24)+((c1&8)>>1)+(c0&1))<<6)                     ; kp = kp40 + (k0_5 & 2) + (k0_6 & 512)                ; cp^=kp; c4 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c0&17)+((c1>>3)&8)+(c2_2&4)+(c3&2)+((((c3>>1)&33)+(c0&18)+(c2_2&8)+((c1<<1)&4))<<6)           ; kp = kp42 + (k0_7 & 2)                               ; cp^=kp; c5 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c1&34)+((c2>>3)&16)+(c0_4&8)+((c0<<1)&4)+(c3>>7)+(((c1&33)+((c3>>3)&16)+((c3<<1)&8)+(c0&4)+(c2_1&2))<<6);                                                      cp^=kp44; c6 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c2&36)+(c1&145)+((c3>>2)&8)+(c0_4&2)+(((c0&40)+(c2_1&16)+(c1&4)+(c3&1))<<6)                             ; kp = kp46 + (k0_2 & 2) +(k0_4 & 2048) + (k0_3 & 1024); cp^=kp; c7 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//7																																								 																												 
	"c0_4=c4>>4;c2_2=c6<<2;c2_1=c6>>1;"																				 																											 
	"cp=((c7&17)<<1)+(c6&24)+(c0_4&4)+(c5>>7)+((((c6&17)<<1)+(c7&24)+((c5&8)>>1)+(c4&1))<<6)                     ; kp = kp48 + (k0_7 & 8)                           ; cp^=kp; c0 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c4&17)+((c5>>3)&8)+(c2_2&4)+(c7&2)+((((c7>>1)&33)+(c4&18)+(c2_2&8)+((c5<<1)&4))<<6)           ; kp = kp50 + (k0_0 & 4) + (k0_5 & 8) + (k0_6 & 32); cp^=kp; c1 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c5&34)+((c6>>3)&16)+(c0_4&8)+((c4<<1)&4)+(c7>>7)+(((c5&33)+((c7>>3)&16)+((c7<<1)&8)+(c4&4)+(c2_1&2))<<6); kp = kp52 + (k0_1 & 4) + (k0_3 & 1024)           ; cp^=kp; c2 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c6&36)+(c5&145)+((c7>>2)&8)+(c0_4&2)+(((c4&40)+(c2_1&16)+(c5&4)+(c7&1))<<6)                             ; kp = kp54 + (k0_4 & 1) + (k0_2 & 128)            ; cp^=kp; c3 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//8																																																																				  
	"c0_4=c0>>4;c2_2=c2<<2;c2_1=c2>>1;"													
	"cp=((c3<<1)&34)+(c2&24)+(c0_4&4)+(c1>>7)+((((c2<<1)&34)+(c3&24)+((c1&8)>>1)+(c0&1))<<6)                     ; kp = kp56 + (k0_0 & 128) + (k0_5 & 64)  ; cp^=kp; c4 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c0&17)+((c1>>3)&8)+(c2_2&4)+(c3&2)+((((c3>>1)&33)+(c0&18)+(c2_2&8)+((c1<<1)&4))<<6)           ; kp = kp58 + (k0_6 & 128)                ; cp^=kp; c5 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c1&34)+((c2>>3)&16)+(c0_4&8)+((c0<<1)&4)+(c3>>7)+(((c1&33)+((c3>>3)&16)+((c3<<1)&8)+(c0&4)+(c2_1&2))<<6); kp = kp60 + (k0_2 & 2048)               ; cp^=kp; c6 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c2&36)+(c1&145)+((c3>>2)&8)+(c0_4&2)+(((c0&40)+(c2_1&16)+(c1&4)+(c3&1))<<6)                             ; kp = kp62 + (k0_4 & 1024) + (k0_1 & 256); cp^=kp; c7 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//9																																							  				    														  										  
	"c0_4=c4>>4;c2_2=c6<<2;c2_1=c6>>1;"																			  				    														  									  
	"cp=((c7&17)<<1)+(c6&24)+(c0_4&4)+(c5>>7)+((((c6&17)<<1)+(c7&24)+((c5&8)>>1)+(c4&1))<<6)                     ; kp = kp64 + (k0_6 & 16) + (k0_7 & 128); cp^=kp; c0 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c4&17)+((c5>>3)&8)+(c2_2&4)+(c7&2)+((((c7>>1)&33)+(c4&18)+(c2_2&8)+((c5<<1)&4))<<6)           ; kp = kp66 + (k0_0 & 2048)             ; cp^=kp; c1 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c5&34)+((c6>>3)&16)+(c0_4&8)+((c4<<1)&4)+(c7>>7)+(((c5&33)+((c7>>3)&16)+((c7<<1)&8)+(c4&4)+(c2_1&2))<<6); kp = kp68 + (k0_4 & 2) + (k0_3 & 16)  ; cp^=kp; c2 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c6&36)+(c5&145)+((c7>>2)&8)+(c0_4&2)+(((c4&40)+(c2_1&16)+(c5&4)+(c7&1))<<6)                             ; kp = kp70 + (k0_1 & 4) + (k0_2 & 64)  ; cp^=kp; c3 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//10																																						  				    														  										  
	"c0_4=c0>>4;c2_2=c2<<2;c2_1=c2>>1;"											  				    														  									  
	"cp=((c3<<1)&34)+(c2&24)+(c0_4&4)+(c1>>7)+((((c2<<1)&34)+(c3&24)+((c1&8)>>1)+(c0&1))<<6)                     ;                                                      cp^=kp72; c4 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c0&17)+((c1>>3)&8)+(c2_2&4)+(c3&2)+((((c3>>1)&33)+(c0&18)+(c2_2&8)+((c1<<1)&4))<<6)           ; kp = kp74 + (k0_7 & 1) + (k0_5 & 1024) + (k0_6 & 512); cp^=kp; c5 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c1&34)+((c2>>3)&16)+(c0_4&8)+((c0<<1)&4)+(c3>>7)+(((c1&33)+((c3>>3)&16)+((c3<<1)&8)+(c0&4)+(c2_1&2))<<6); kp = kp76 + (k0_1 & 32)+ (k0_2 & 1)                  ; cp^=kp; c6 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c2&36)+(c1&145)+((c3>>2)&8)+(c0_4&2)+(((c0&40)+(c2_1&16)+(c1&4)+(c3&1))<<6)                             ; kp = kp78 + (k0_4 & 16)                              ; cp^=kp; c7 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//11																																																																			  
	"c0_4=c4>>4;c2_2=c6<<2;c2_1=c6>>1;"																																															  
	"cp=((c7&17)<<1)+(c6&24)+(c0_4&4)+(c5>>7)+((((c6&17)<<1)+(c7&24)+((c5&8)>>1)+(c4&1))<<6)                     ; kp = kp80 + (k0_7 & 1) + (k0_5 & 32)                ; cp^=kp; c0 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c4&17)+((c5>>3)&8)+(c2_2&4)+(c7&2)+((((c7>>1)&33)+(c4&18)+(c2_2&8)+((c5<<1)&4))<<6)           ; kp = kp82 + (k0_0 & 64)                             ; cp^=kp; c1 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c5&34)+((c6>>3)&16)+(c0_4&8)+((c4<<1)&4)+(c7>>7)+(((c5&33)+((c7>>3)&16)+((c7<<1)&8)+(c4&4)+(c2_1&2))<<6); kp = kp84 + (k0_4 & 16) + (k0_1 & 256) + (k0_3 & 64); cp^=kp; c2 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c6&36)+(c5&145)+((c7>>2)&8)+(c0_4&2)+(((c4&40)+(c2_1&16)+(c5&4)+(c7&1))<<6)                             ; kp = kp86 + (k0_2 & 32)                             ; cp^=kp; c3 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//12																																						  				    														  										  
	"c0_4=c0>>4;c2_2=c2<<2;c2_1=c2>>1;"												  				    														  									  
	"cp=((c3<<1)&34)+(c2&24)+(c0_4&4)+(c1>>7)+((((c2<<1)&34)+(c3&24)+((c1&8)>>1)+(c0&1))<<6)                     ; kp = kp88 + (k0_0 & 2) + (k0_5 & 2048) + (k0_7 & 256); cp^=kp; c4 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c0&17)+((c1>>3)&8)+(c2_2&4)+(c3&2)+((((c3>>1)&33)+(c0&18)+(c2_2&8)+((c1<<1)&4))<<6)           ; kp = kp90 + (k0_6 & 4)                               ; cp^=kp; c5 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c1&34)+((c2>>3)&16)+(c0_4&8)+((c0<<1)&4)+(c3>>7)+(((c1&33)+((c3>>3)&16)+((c3<<1)&8)+(c0&4)+(c2_1&2))<<6); kp = kp92 + (k0_3 & 8) + (k0_2 & 512)                ; cp^=kp; c6 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c2&36)+(c1&145)+((c3>>2)&8)+(c0_4&2)+(((c0&40)+(c2_1&16)+(c1&4)+(c3&1))<<6)                             ;                                                      cp^=kp94; c7 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//13																																						  				    														  										  
	"c0_4=c4>>4;c2_2=c6<<2;c2_1=c6>>1;"																			  				    														  									  
	"cp=((c7&17)<<1)+(c6&24)+(c0_4&4)+(c5>>7)+((((c6&17)<<1)+(c7&24)+((c5&8)>>1)+(c4&1))<<6)                     ; kp = kp96  + (k0_5 & 16)+ (k0_6 & 128); cp^=kp; c0 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c4&17)+((c5>>3)&8)+(c2_2&4)+(c7&2)+((((c7>>1)&33)+(c4&18)+(c2_2&8)+((c5<<1)&4))<<6)           ; kp = kp98  + (k0_0 & 8) + (k0_7 & 256); cp^=kp; c1 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c5&34)+((c6>>3)&16)+(c0_4&8)+((c4<<1)&4)+(c7>>7)+(((c5&33)+((c7>>3)&16)+((c7<<1)&8)+(c4&4)+(c2_1&2))<<6); kp = kp100 + (k0_1 & 2) + (k0_4 & 64) ; cp^=kp; c2 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c6&36)+(c5&145)+((c7>>2)&8)+(c0_4&2)+(((c4&40)+(c2_1&16)+(c5&4)+(c7&1))<<6)                             ; kp = kp102 + (k0_2 & 4) + (k0_3 & 64) ; cp^=kp; c3 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//14																																																																			  
	"c0_4=c0>>4;c2_2=c2<<2;c2_1=c2>>1;"																																								  
	"cp=((c3<<1)&34)+(c2&24)+(c0_4&4)+(c1>>7)+((((c2<<1)&34)+(c3&24)+((c1&8)>>1)+(c0&1))<<6)                     ; kp = kp104 + (k0_7 & 4) + (k0_0 & 64)             ; cp^=kp; c4 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c0&17)+((c1>>3)&8)+(c2_2&4)+(c3&2)+((((c3>>1)&33)+(c0&18)+(c2_2&8)+((c1<<1)&4))<<6)           ; kp = kp106 + (k0_6 & 1) + (k0_5 & 512)            ; cp^=kp; c5 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c1&34)+((c2>>3)&16)+(c0_4&8)+((c0<<1)&4)+(c3>>7)+(((c1&33)+((c3>>3)&16)+((c3<<1)&8)+(c0&4)+(c2_1&2))<<6); kp = kp108 + (k0_4 & 8) + (k0_2 & 32) + (k0_3 & 1); cp^=kp; c6 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c2&36)+(c1&145)+((c3>>2)&8)+(c0_4&2)+(((c0&40)+(c2_1&16)+(c1&4)+(c3&1))<<6)                             ; kp = kp110 + (k0_1 & 16)                          ; cp^=kp; c7 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//15																																						  				    														  										  
	"c0_4=c4>>4;c2_2=c6<<2;c2_1=c6>>1;"							
	"cp=((c7&17)<<1)+(c6&24)+(c0_4&4)+(c5>>7)+((((c6&17)<<1)+(c7&24)+((c5&8)>>1)+(c4&1))<<6)                     ; kp = kp112 + (k0_6 & 1)                ; cp^=kp; c0 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c4&17)+((c5>>3)&8)+(c2_2&4)+(c7&2)+((((c7>>1)&33)+(c4&18)+(c2_2&8)+((c5<<1)&4))<<6)           ; kp = kp114 + (k0_0 & 16)               ; cp^=kp; c1 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c5&34)+((c6>>3)&16)+(c0_4&8)+((c4<<1)&4)+(c7>>7)+(((c5&33)+((c7>>3)&16)+((c7<<1)&8)+(c4&4)+(c2_1&2))<<6); kp = kp116 + (k0_1 & 16) + (k0_2 & 256); cp^=kp; c2 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c6&36)+(c5&145)+((c7>>2)&8)+(c0_4&2)+(((c4&40)+(c2_1&16)+(c5&4)+(c7&1))<<6)                             ; kp = kp118 + (k0_3 & 32) + (k0_4 & 64) ; cp^=kp; c3 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	//16																																						  				    														  										  
	"c0_4=c0>>4;c2_2=c2<<2;c2_1=c2>>1;"												  				    														  									  
	"cp=((c3<<1)&34)+(c2&24)+(c0_4&4)+(c1>>7)+((((c2<<1)&34)+(c3&24)+((c1&8)>>1)+(c0&1))<<6)                     ; kp = kp120 + (k0_5 & 8)                             ; cp^=kp; c4 ^= SBox[cp&63] ^ SBox[64 + (cp>>6)];"
	"cp=(c2_1&32)+(c0&17)+((c1>>3)&8)+(c2_2&4)+(c3&2)+((((c3>>1)&33)+(c0&18)+(c2_2&8)+((c1<<1)&4))<<6)           ; kp = kp122 + (k0_7 & 16)+(k0_6 & 64) + (k0_0 & 1024); cp^=kp; c5 ^= SBox[2 * 64 + (cp&63)] ^ SBox[3 * 64 + (cp>>6)];"
	"cp=(c1&34)+((c2>>3)&16)+(c0_4&8)+((c0<<1)&4)+(c3>>7)+(((c1&33)+((c3>>3)&16)+((c3<<1)&8)+(c0&4)+(c2_1&2))<<6); kp = kp124 + (k0_3 & 4)                             ; cp^=kp; c6 ^= SBox[4 * 64 + (cp&63)] ^ SBox[5 * 64 + (cp>>6)];"
	"cp=(c2&36)+(c1&145)+((c3>>2)&8)+(c0_4&2)+(((c0&40)+(c2_1&16)+(c1&4)+(c3&1))<<6)                             ; kp = kp126 + (k0_2 & 1) + (k0_4 & 8) + (k0_1 & 512) ; cp^=kp; c7 ^= SBox[6 * 64 + (cp&63)] ^ SBox[7 * 64 + (cp>>6)];"
	
	"uint h0=c0+(c1<<8)+(c2<<16)+(c3<<24);"
	"uint h1=c4+(c5<<8)+(c6<<16)+(c7<<24);");

	if (num_passwords_loaded == 1)
	{
		sprintf(source + strlen(source), 
			"if(h0==%uu && h1==%uu)"
			"{"
				"output[0]=1;"
				"output[1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
				"output[2]=0;"
			"}"
			, ((cl_uint*)binary_values)[0], ((cl_uint*)binary_values)[1]);
	}
	else
	{
		// Find match
		sprintf(source + strlen(source),
				"indx=h0&SIZE_BIT_TABLE;"
				"indx=(bit_table[indx>>5u]>>(indx&31u))&1u;"

				"if(indx)"
				"{"
					"indx=table[h0&SIZE_TABLE];"

					"while(indx!=0xffffffff)"
					//"if(indx!=0xffffffff)"
					"{"
						"if(h0==binary_values[indx*2u]&&h1==binary_values[indx*2+1u])"
						"{"
							"uint found=atomic_inc(output);"
							"if(found<%uu){"
							"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
							"output[2*found+2]=indx;}"
						"}", output_size);

	strcat(source,  "indx=same_hash_next[indx];"
					"}"
				"}");
	}

	strcat(source, "}}");
}
PRIVATE OpenCL_Param* ocl_protocol_charset_init(cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	cl_uint lm_empy_hash[] = {0x0b178b1b, 0xcee2a0ba};
	return ocl_charset_init(gpu_index, gen, gpu_crypt, BINARY_SIZE, 0, ocl_write_lm_header, ocl_gen_kernel_with_lenght, lm_empy_hash, 0, 8);
}*/

PRIVATE int bench_values[] = {1,10,100,1000,10000,65536,100000,1000000};
Format lm_format = {
	"LM",
	"DES based.",
	PLAINTEXT_LENGTH,
	BINARY_SIZE,
	SALT_SIZE,
	1,
	bench_values,
	LENGHT(bench_values),
	get_binary,
	is_valid,
	NULL,
#ifdef _M_X64
	{{CPU_CAP_AVX2, PROTOCOL_FAST_LM, crypt_fast_lm_protocol_avx2}, {CPU_CAP_SSE2, PROTOCOL_FAST_LM, crypt_fast_lm_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_UTF8_LM, crypt_utf8_lm_protocol_sse2}},
#else
	#ifdef HS_ARM
		{{CPU_CAP_NEON, PROTOCOL_FAST_LM, crypt_fast_lm_protocol_neon}, {CPU_CAP_NEON, PROTOCOL_UTF8_LM, crypt_utf8_lm_protocol_neon}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_LM, crypt_utf8_lm_protocol_x86}},
	#else
		{{CPU_CAP_SSE2, PROTOCOL_FAST_LM, crypt_fast_lm_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_UTF8_LM, crypt_utf8_lm_protocol_sse2}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_LM, crypt_utf8_lm_protocol_x86}},
	#endif
#endif
	#ifdef HS_OPENCL_SUPPORT
		{{PROTOCOL_FAST_LM_OPENCL, crypt_lm_protocol_opencl_init}, {PROTOCOL_FAST_LM_OPENCL, crypt_lm_protocol_opencl_init}, {PROTOCOL_FAST_LM_OPENCL, crypt_lm_protocol_opencl_init}, {PROTOCOL_FAST_LM_OPENCL, crypt_lm_protocol_opencl_init}}
	#endif
};
