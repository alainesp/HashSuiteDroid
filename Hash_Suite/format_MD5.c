// This file is part of Hash Suite password cracker,
// Copyright (c) 2014-2015 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

//Initial values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define BINARY_SIZE			16
#define NTLM_MAX_KEY_LENGHT	27

PRIVATE int is_valid(char* user_name, char* md5, char* unused, char* unused1)
{
	if (user_name)
	{
		if (md5 && valid_hex_string(md5, 32))
			return TRUE;

		if (!md5 && !memcmp(user_name, "$dynamic_0$", 11) && valid_hex_string(user_name + 11, 32))
			return TRUE;
	}

	return FALSE;
}

PRIVATE void add_hash_from_line(ImportParam* param, char* user_name, char* md5, char* unused, char* unused1, sqlite3_int64 tag_id)
{
	if (user_name)
	{
		if (md5 && valid_hex_string(md5, 32))
			insert_hash_account(param, user_name, _strupr(md5), MD5_INDEX, tag_id);

		if (!md5 && !memcmp(user_name, "$dynamic_0$", 11) && valid_hex_string(user_name + 11, 32))
			insert_hash_account(param, "user", _strupr(user_name + 11), MD5_INDEX, tag_id);
	}
}
PRIVATE unsigned int get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	unsigned int* out = (unsigned int*)binary;

	for (unsigned int i = 0; i < 4; i++)
	{
		unsigned int temp = (hex_to_num[ciphertext[i * 8 + 0]]) << 4;
		temp |= (hex_to_num[ciphertext[i * 8 + 1]]);

		temp |= (hex_to_num[ciphertext[i * 8 + 2]]) << 12;
		temp |= (hex_to_num[ciphertext[i * 8 + 3]]) << 8;

		temp |= (hex_to_num[ciphertext[i * 8 + 4]]) << 20;
		temp |= (hex_to_num[ciphertext[i * 8 + 5]]) << 16;

		temp |= (hex_to_num[ciphertext[i * 8 + 6]]) << 28;
		temp |= (hex_to_num[ciphertext[i * 8 + 7]]) << 24;

		out[i] = temp;
	}

	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;

	// b
	out[1] = rotate(out[1] - out[2], 32 - 21);
	out[1] -= (out[3] ^ (out[2] | ~out[0])) + 0xeb86d391;

	// c
	out[2] = rotate(out[2] - out[3], 32 - 15);
	out[2] -= (out[0] ^ (out[3] | ~out[1])) + 0x2ad7d2bb;

	//d
	out[3] = rotate(out[3] - out[0], 32 - 10);
	out[3] -= 0xbd3af235;

	return out[2];
}

#ifdef HS_ARM
	#define NT_NUM_KEYS		    128
#endif

#ifdef HS_X86
	#define NT_NUM_KEYS		    256
#endif

PRIVATE void crypt_utf8_coalesc_protocol_body(CryptParam* param, crypt_kernel_asm_func* crypt_kernel_asm)
{
	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc((8+5) * sizeof(unsigned int) * NT_NUM_KEYS, 32);

	unsigned int* unpacked_as = (unsigned int*)(nt_buffer + 8 * NT_NUM_KEYS);
	unsigned int* unpacked_bs = (unsigned int*)(nt_buffer + 8 * NT_NUM_KEYS + 1 * NT_NUM_KEYS);
	unsigned int* unpacked_cs = (unsigned int*)(nt_buffer + 8 * NT_NUM_KEYS + 2 * NT_NUM_KEYS);
	unsigned int* unpacked_ds = (unsigned int*)(nt_buffer + 8 * NT_NUM_KEYS + 3 * NT_NUM_KEYS);
	unsigned int* indexs	  = (unsigned int*)(nt_buffer + 8 * NT_NUM_KEYS + 4 * NT_NUM_KEYS);

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, 8 * sizeof(unsigned int)* NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while (continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_kernel_asm(nt_buffer, bit_table, size_bit_table);

		for (unsigned int i = 0; i < NT_NUM_KEYS; i++)
			if (indexs[i])
			{
				unsigned int indx = table[unpacked_cs[i] & size_table];
				// Partial match
				while (indx != NO_ELEM)
				{
					unsigned int aa, bb, cc = unpacked_cs[i], dd;
					unsigned int* bin = ((unsigned int*)binary_values) + indx * 4;

					if (cc != bin[2]) goto next_iteration;

					cc -= nt_buffer[2 * NT_NUM_KEYS + i];
					bb = unpacked_bs[i] + (unpacked_ds[i] ^ (cc | ~unpacked_as[i])) + 0x4e0811a1; bb = rotate(bb, 21) + cc;
					if (bb != bin[1]) goto next_iteration;

					aa = unpacked_as[i] + (cc ^ (bb | ~unpacked_ds[i])) + nt_buffer[4 * NT_NUM_KEYS + i] + 0xf7537e82; aa = rotate(aa, 6) + bb;
					if (aa != bin[0]) goto next_iteration;

					dd = unpacked_ds[i] + (bb ^ (aa | ~cc));
					if (dd != bin[3]) goto next_iteration;

					// Total match
					password_was_found(indx, utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

				next_iteration:
					indx = same_hash_next[indx];
				}
			}

		report_keys_processed(NT_NUM_KEYS);
	}

	_aligned_free(nt_buffer);

	finish_thread();
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef _M_X64
PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	unsigned int nt_buffer[8 * NT_NUM_KEYS];
	unsigned int a, b, c, d, index;

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, sizeof(nt_buffer));
	memset(key, 0, sizeof(key));

	while (continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for (int i = 0; i < NT_NUM_KEYS; i++)
		{
			/* Round 1 */
			a =									nt_buffer[0*NT_NUM_KEYS + i] + 0xd76aa477; a = rotate(a, 7 ) + INIT_B;
			d = (INIT_C ^ (a & 0x77777777))	  +	nt_buffer[1*NT_NUM_KEYS + i] + 0xf8fa0bcc; d = rotate(d, 12) + a;
			c = (INIT_B ^ (d & (a ^ INIT_B))) + nt_buffer[2*NT_NUM_KEYS + i] + 0xbcdb4dd9; c = rotate(c, 17) + d;
			b = (a ^ (c & (d ^ a)))			  + nt_buffer[3*NT_NUM_KEYS + i] + 0xb18b7a77; b = rotate(b, 22) + c;
					 					  
			a += (d ^ (b & (c ^ d))) + nt_buffer[4*NT_NUM_KEYS+i] + 0xf57c0faf; a = rotate(a, 7 ) + b;
			d += (c ^ (a & (b ^ c))) + nt_buffer[5*NT_NUM_KEYS+i] + 0x4787c62a; d = rotate(d, 12) + a;
			c += (b ^ (d & (a ^ b))) + nt_buffer[6*NT_NUM_KEYS+i] + 0xa8304613; c = rotate(c, 17) + d;
			b += (a ^ (c & (d ^ a)))							  + 0xfd469501; b = rotate(b, 22) + c;
					 			 	
			a += (d ^ (b & (c ^ d)))							  + 0x698098d8; a = rotate(a, 7 ) + b;
			d += (c ^ (a & (b ^ c)))							  + 0x8b44f7af; d = rotate(d, 12) + a;
			c += (b ^ (d & (a ^ b)))							  + 0xffff5bb1; c = rotate(c, 17) + d;
			b += (a ^ (c & (d ^ a)))							  + 0x895cd7be; b = rotate(b, 22) + c;
					  		    								  
			a += (d ^ (b & (c ^ d)))							  + 0x6b901122; a = rotate(a, 7 ) + b;
			d += (c ^ (a & (b ^ c)))							  + 0xfd987193; d = rotate(d, 12) + a;
			c += (b ^ (d & (a ^ b))) + nt_buffer[7*NT_NUM_KEYS+i] + 0xa679438e; c = rotate(c, 17) + d;
			b += (a ^ (c & (d ^ a)))							  + 0x49b40821; b = rotate(b, 22) + c;

			/* Round 2 */
			a += (c ^ (d & (b ^ c))) + nt_buffer[1*NT_NUM_KEYS+i] + 0xf61e2562; a = rotate(a, 5 ) + b;
			d += (b ^ (c & (a ^ b))) + nt_buffer[6*NT_NUM_KEYS+i] + 0xc040b340; d = rotate(d, 9 ) + a;
			c += (a ^ (b & (d ^ a)))							  + 0x265e5a51; c = rotate(c, 14) + d;
			b += (d ^ (a & (c ^ d))) + nt_buffer[0*NT_NUM_KEYS+i] + 0xe9b6c7aa; b = rotate(b, 20) + c;
							    
			a += (c ^ (d & (b ^ c))) + nt_buffer[5*NT_NUM_KEYS+i] + 0xd62f105d; a = rotate(a, 5 ) + b;
			d += (b ^ (c & (a ^ b)))							  + 0x02441453; d = rotate(d, 9 ) + a;
			c += (a ^ (b & (d ^ a)))							  + 0xd8a1e681; c = rotate(c, 14) + d;
			b += (d ^ (a & (c ^ d))) + nt_buffer[4*NT_NUM_KEYS+i] + 0xe7d3fbc8; b = rotate(b, 20) + c;
							    
			a += (c ^ (d & (b ^ c)))							  + 0x21e1cde6; a = rotate(a, 5 ) + b;
			d += (b ^ (c & (a ^ b))) + nt_buffer[7*NT_NUM_KEYS+i] + 0xc33707d6; d = rotate(d, 9 ) + a;
			c += (a ^ (b & (d ^ a))) + nt_buffer[3*NT_NUM_KEYS+i] + 0xf4d50d87; c = rotate(c, 14) + d;
			b += (d ^ (a & (c ^ d)))							  + 0x455a14ed; b = rotate(b, 20) + c;
							    
			a += (c ^ (d & (b ^ c)))							  + 0xa9e3e905; a = rotate(a, 5 ) + b;
			d += (b ^ (c & (a ^ b))) + nt_buffer[2*NT_NUM_KEYS+i] + 0xfcefa3f8; d = rotate(d, 9 ) + a;
			c += (a ^ (b & (d ^ a)))							  + 0x676f02d9; c = rotate(c, 14) + d;
			b += (d ^ (a & (c ^ d)))							  + 0x8d2a4c8a; b = rotate(b, 20) + c;

			/* Round 3 */
			a += (b ^ c ^ d) + nt_buffer[5*NT_NUM_KEYS+i] + 0xfffa3942; a = rotate(a, 4 ) + b;
			d += (a ^ b ^ c)							  + 0x8771f681; d = rotate(d, 11) + a;
			c += (d ^ a ^ b)							  + 0x6d9d6122; c = rotate(c, 16) + d;
			b += (c ^ d ^ a) + nt_buffer[7*NT_NUM_KEYS+i] + 0xfde5380c; b = rotate(b, 23) + c;

			a += (b ^ c ^ d) + nt_buffer[1*NT_NUM_KEYS+i] + 0xa4beea44; a = rotate(a, 4 ) + b;
			d += (a ^ b ^ c) + nt_buffer[4*NT_NUM_KEYS+i] + 0x4bdecfa9; d = rotate(d, 11) + a;
			c += (d ^ a ^ b)							  + 0xf6bb4b60; c = rotate(c, 16) + d;
			b += (c ^ d ^ a)							  + 0xbebfbc70; b = rotate(b, 23) + c;

			a += (b ^ c ^ d)							  + 0x289b7ec6; a = rotate(a, 4 ) + b;
			d += (a ^ b ^ c) + nt_buffer[0*NT_NUM_KEYS+i] + 0xeaa127fa; d = rotate(d, 11) + a;
			c += (d ^ a ^ b) + nt_buffer[3*NT_NUM_KEYS+i] + 0xd4ef3085; c = rotate(c, 16) + d;
			b += (c ^ d ^ a) + nt_buffer[6*NT_NUM_KEYS+i] + 0x04881d05; b = rotate(b, 23) + c;

			a += (b ^ c ^ d)							  + 0xd9d4d039; a = rotate(a, 4 ) + b;
			d += (a ^ b ^ c)							  + 0xe6db99e5; d = rotate(d, 11) + a;
			c += (d ^ a ^ b)							  + 0x1fa27cf8; c = rotate(c, 16) + d;
			b += (c ^ d ^ a) + nt_buffer[2*NT_NUM_KEYS+i] + 0xc4ac5665; b = rotate(b, 23) + c;

			/* Round 4 */
			a += (c ^ (b | ~d)) + nt_buffer[0*NT_NUM_KEYS+i] + 0xf4292244; a = rotate(a, 6 ) + b;
			d += (b ^ (a | ~c))								 + 0x432aff97; d = rotate(d, 10) + a;
			c += (a ^ (d | ~b)) + nt_buffer[7*NT_NUM_KEYS+i] + 0xab9423a7; c = rotate(c, 15) + d;
			b += (d ^ (c | ~a)) + nt_buffer[5*NT_NUM_KEYS+i] + 0xfc93a039; b = rotate(b, 21) + c;
					  
			a += (c ^ (b | ~d))								 + 0x655b59c3; a = rotate(a, 6 ) + b;
			d += (b ^ (a | ~c)) + nt_buffer[3*NT_NUM_KEYS+i] + 0x8f0ccc92; d = rotate(d, 10) + a;
			c += (a ^ (d | ~b))								 + 0xffeff47d; c = rotate(c, 15) + d;
			b += (d ^ (c | ~a)) + nt_buffer[1*NT_NUM_KEYS+i] + 0x85845dd1; b = rotate(b, 21) + c;
					  
			a += (c ^ (b | ~d))								 + 0x6fa87e4f; a = rotate(a, 6 ) + b;
			d += (b ^ (a | ~c))								 + 0xfe2ce6e0; d = rotate(d, 10) + a;
			c += (a ^ (d | ~b)) + nt_buffer[6*NT_NUM_KEYS+i] + 0xa3014314; c = rotate(c, 15) + d;
			c += nt_buffer[2 * NT_NUM_KEYS + i];

			// Search for a match
			index = table[c & size_table];

			// Partial match
			while (index != NO_ELEM)
			{
				unsigned int aa, bb, cc, dd;
				unsigned int* bin = ((unsigned int*)binary_values) + index * 4;

				if (c != bin[2]) goto next_iteration;

				cc = c - nt_buffer[2 * NT_NUM_KEYS + i];
				bb = b + (d ^ (cc | ~a)) + 0x4e0811a1; bb = rotate(bb, 21) + cc;
				if (bb != bin[1]) goto next_iteration;

				aa = a + (cc ^ (bb | ~d)) + nt_buffer[4 * NT_NUM_KEYS + i] + 0xf7537e82; aa = rotate(aa, 6) + bb;
				if (aa != bin[0]) goto next_iteration;

				dd = d + (bb ^ (aa | ~cc));
				if (dd != bin[3]) goto next_iteration;
				
				// Total match
				password_was_found(index, utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

			next_iteration:
				index = same_hash_next[index];
			}
		}

		report_keys_processed(NT_NUM_KEYS);
	}

	finish_thread();
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Neon code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM
void crypt_md5_neon_kernel_asm(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_utf8_coalesc_protocol_neon(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_md5_neon_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include "arch_simd.h"

PRIVATE void crypt_kernel_sse2(SSE2_WORD* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table)
{
	for (int i = 0; i < NT_NUM_KEYS/4; i++)
	{
		/* Round 1 */
		SSE2_WORD a = SSE2_ADD(																				nt_buffer[0*NT_NUM_KEYS/4+i], SSE2_CONST(0xd76aa477)); a = SSE2_ADD(SSE2_ROTATE(a, 7 ), SSE2_CONST(INIT_B));
		SSE2_WORD d = SSE2_3ADD(SSE2_XOR(SSE2_CONST(INIT_C), SSE2_AND(a, SSE2_CONST(0x77777777))),			nt_buffer[1*NT_NUM_KEYS/4+i], SSE2_CONST(0xf8fa0bcc)); d = SSE2_ADD(SSE2_ROTATE(d, 12), a);
		SSE2_WORD c = SSE2_3ADD(SSE2_XOR(SSE2_CONST(INIT_B), SSE2_AND(d, SSE2_XOR(a, SSE2_CONST(INIT_B)))), nt_buffer[2*NT_NUM_KEYS/4+i], SSE2_CONST(0xbcdb4dd9)); c = SSE2_ADD(SSE2_ROTATE(c, 17), d);
		SSE2_WORD b = SSE2_3ADD(SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a))),									nt_buffer[3*NT_NUM_KEYS/4+i], SSE2_CONST(0xb18b7a77)); b = SSE2_ADD(SSE2_ROTATE(b, 22), c);
					 					  
		a = SSE2_4ADD(a, SSE2_XOR(d, SSE2_AND(b, SSE2_XOR(c, d))), nt_buffer[4*NT_NUM_KEYS/4+i], SSE2_CONST(0xf57c0faf)); a = SSE2_ADD(SSE2_ROTATE(a, 7 ), b);
		d = SSE2_4ADD(d, SSE2_XOR(c, SSE2_AND(a, SSE2_XOR(b, c))), nt_buffer[5*NT_NUM_KEYS/4+i], SSE2_CONST(0x4787c62a)); d = SSE2_ADD(SSE2_ROTATE(d, 12), a);
		c = SSE2_4ADD(c, SSE2_XOR(b, SSE2_AND(d, SSE2_XOR(a, b))), nt_buffer[6*NT_NUM_KEYS/4+i], SSE2_CONST(0xa8304613)); c = SSE2_ADD(SSE2_ROTATE(c, 17), d);
		b = SSE2_3ADD(b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a))),						         SSE2_CONST(0xfd469501)); b = SSE2_ADD(SSE2_ROTATE(b, 22), c);
																								 
		a = SSE2_3ADD(a, SSE2_XOR(d, SSE2_AND(b, SSE2_XOR(c, d))),						         SSE2_CONST(0x698098d8)); a = SSE2_ADD(SSE2_ROTATE(a, 7 ), b);
		d = SSE2_3ADD(d, SSE2_XOR(c, SSE2_AND(a, SSE2_XOR(b, c))),						         SSE2_CONST(0x8b44f7af)); d = SSE2_ADD(SSE2_ROTATE(d, 12), a);
		c = SSE2_3ADD(c, SSE2_XOR(b, SSE2_AND(d, SSE2_XOR(a, b))),						         SSE2_CONST(0xffff5bb1)); c = SSE2_ADD(SSE2_ROTATE(c, 17), d);
		b = SSE2_3ADD(b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a))),						         SSE2_CONST(0x895cd7be)); b = SSE2_ADD(SSE2_ROTATE(b, 22), c);
																								 
		a = SSE2_3ADD(a, SSE2_XOR(d, SSE2_AND(b, SSE2_XOR(c, d))),						         SSE2_CONST(0x6b901122)); a = SSE2_ADD(SSE2_ROTATE(a, 7 ), b);
		d = SSE2_3ADD(d, SSE2_XOR(c, SSE2_AND(a, SSE2_XOR(b, c))),						         SSE2_CONST(0xfd987193)); d = SSE2_ADD(SSE2_ROTATE(d, 12), a);
		c = SSE2_4ADD(c, SSE2_XOR(b, SSE2_AND(d, SSE2_XOR(a, b))), nt_buffer[7*NT_NUM_KEYS/4+i], SSE2_CONST(0xa679438e)); c = SSE2_ADD(SSE2_ROTATE(c, 17), d);
		b = SSE2_3ADD(b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a))),						         SSE2_CONST(0x49b40821)); b = SSE2_ADD(SSE2_ROTATE(b, 22), c);

		/* Round 2 */
		a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_AND(d, SSE2_XOR(b, c))), nt_buffer[1*NT_NUM_KEYS/4+i], SSE2_CONST(0xf61e2562)); a = SSE2_ADD(SSE2_ROTATE(a, 5 ), b);
		d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_AND(c, SSE2_XOR(a, b))), nt_buffer[6*NT_NUM_KEYS/4+i], SSE2_CONST(0xc040b340)); d = SSE2_ADD(SSE2_ROTATE(d, 9 ), a);
		c = SSE2_3ADD(c, SSE2_XOR(a, SSE2_AND(b, SSE2_XOR(d, a))),							     SSE2_CONST(0x265e5a51)); c = SSE2_ADD(SSE2_ROTATE(c, 14), d);
		b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_AND(a, SSE2_XOR(c, d))), nt_buffer[0*NT_NUM_KEYS/4+i], SSE2_CONST(0xe9b6c7aa)); b = SSE2_ADD(SSE2_ROTATE(b, 20), c);

		a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_AND(d, SSE2_XOR(b, c))), nt_buffer[5*NT_NUM_KEYS/4+i], SSE2_CONST(0xd62f105d)); a = SSE2_ADD(SSE2_ROTATE(a, 5 ), b);
		d = SSE2_3ADD(d, SSE2_XOR(b, SSE2_AND(c, SSE2_XOR(a, b))),						         SSE2_CONST(0x02441453)); d = SSE2_ADD(SSE2_ROTATE(d, 9 ), a);
		c = SSE2_3ADD(c, SSE2_XOR(a, SSE2_AND(b, SSE2_XOR(d, a))),						         SSE2_CONST(0xd8a1e681)); c = SSE2_ADD(SSE2_ROTATE(c, 14), d);
		b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_AND(a, SSE2_XOR(c, d))), nt_buffer[4*NT_NUM_KEYS/4+i], SSE2_CONST(0xe7d3fbc8)); b = SSE2_ADD(SSE2_ROTATE(b, 20), c);

		a = SSE2_3ADD(a, SSE2_XOR(c, SSE2_AND(d, SSE2_XOR(b, c))),						         SSE2_CONST(0x21e1cde6)); a = SSE2_ADD(SSE2_ROTATE(a, 5 ), b);
		d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_AND(c, SSE2_XOR(a, b))), nt_buffer[7*NT_NUM_KEYS/4+i], SSE2_CONST(0xc33707d6)); d = SSE2_ADD(SSE2_ROTATE(d, 9 ), a);
		c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_AND(b, SSE2_XOR(d, a))), nt_buffer[3*NT_NUM_KEYS/4+i], SSE2_CONST(0xf4d50d87)); c = SSE2_ADD(SSE2_ROTATE(c, 14), d);
		b = SSE2_3ADD(b, SSE2_XOR(d, SSE2_AND(a, SSE2_XOR(c, d))),						         SSE2_CONST(0x455a14ed)); b = SSE2_ADD(SSE2_ROTATE(b, 20), c);

		a = SSE2_3ADD(a, SSE2_XOR(c, SSE2_AND(d, SSE2_XOR(b, c))),						         SSE2_CONST(0xa9e3e905)); a = SSE2_ADD(SSE2_ROTATE(a, 5 ), b);
		d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_AND(c, SSE2_XOR(a, b))), nt_buffer[2*NT_NUM_KEYS/4+i], SSE2_CONST(0xfcefa3f8)); d = SSE2_ADD(SSE2_ROTATE(d, 9 ), a);
		c = SSE2_3ADD(c, SSE2_XOR(a, SSE2_AND(b, SSE2_XOR(d, a))),							     SSE2_CONST(0x676f02d9)); c = SSE2_ADD(SSE2_ROTATE(c, 14), d);
		b = SSE2_3ADD(b, SSE2_XOR(d, SSE2_AND(a, SSE2_XOR(c, d))),							     SSE2_CONST(0x8d2a4c8a)); b = SSE2_ADD(SSE2_ROTATE(b, 20), c);

		/* Round 3 */
		SSE2_WORD xx = SSE2_XOR(b, c);
		a = SSE2_4ADD(a, SSE2_XOR(xx, d), nt_buffer[5 * NT_NUM_KEYS / 4 + i], SSE2_CONST(0xfffa3942)); a = SSE2_ADD(SSE2_ROTATE(a, 4 ), b);
		d = SSE2_3ADD(d, SSE2_XOR(a, xx)									, SSE2_CONST(0x8771f681)); d = SSE2_ADD(SSE2_ROTATE(d, 11), a);xx = SSE2_XOR(d, a);
		c = SSE2_3ADD(c, SSE2_XOR(xx, b)									, SSE2_CONST(0x6d9d6122)); c = SSE2_ADD(SSE2_ROTATE(c, 16), d);
		b = SSE2_4ADD(b, SSE2_XOR(c, xx), nt_buffer[7 * NT_NUM_KEYS / 4 + i], SSE2_CONST(0xfde5380c)); b = SSE2_ADD(SSE2_ROTATE(b, 23), c); xx = SSE2_XOR(b, c);
									
		a = SSE2_4ADD(a, SSE2_XOR(xx, d), nt_buffer[1 * NT_NUM_KEYS / 4 + i], SSE2_CONST(0xa4beea44)); a = SSE2_ADD(SSE2_ROTATE(a, 4), b);
		d = SSE2_4ADD(d, SSE2_XOR(a, xx), nt_buffer[4 * NT_NUM_KEYS / 4 + i], SSE2_CONST(0x4bdecfa9)); d = SSE2_ADD(SSE2_ROTATE(d, 11), a); xx = SSE2_XOR(d, a);
		c = SSE2_3ADD(c, SSE2_XOR(xx, b)									, SSE2_CONST(0xf6bb4b60)); c = SSE2_ADD(SSE2_ROTATE(c, 16), d);
		b = SSE2_3ADD(b, SSE2_XOR(c, xx)									, SSE2_CONST(0xbebfbc70)); b = SSE2_ADD(SSE2_ROTATE(b, 23), c); xx = SSE2_XOR(b, c);
								
		a = SSE2_3ADD(a, SSE2_XOR(xx, d)									, SSE2_CONST(0x289b7ec6)); a = SSE2_ADD(SSE2_ROTATE(a, 4), b);
		d = SSE2_4ADD(d, SSE2_XOR(a, xx), nt_buffer[0 * NT_NUM_KEYS / 4 + i], SSE2_CONST(0xeaa127fa)); d = SSE2_ADD(SSE2_ROTATE(d, 11), a); xx = SSE2_XOR(d, a);
		c = SSE2_4ADD(c, SSE2_XOR(xx, b), nt_buffer[3 * NT_NUM_KEYS / 4 + i], SSE2_CONST(0xd4ef3085)); c = SSE2_ADD(SSE2_ROTATE(c, 16), d);
		b = SSE2_4ADD(b, SSE2_XOR(c, xx), nt_buffer[6 * NT_NUM_KEYS / 4 + i], SSE2_CONST(0x04881d05)); b = SSE2_ADD(SSE2_ROTATE(b, 23), c); xx = SSE2_XOR(b, c);
									
		a = SSE2_3ADD(a, SSE2_XOR(xx, d)									, SSE2_CONST(0xd9d4d039)); a = SSE2_ADD(SSE2_ROTATE(a, 4), b);
		d = SSE2_3ADD(d, SSE2_XOR(a, xx)									, SSE2_CONST(0xe6db99e5)); d = SSE2_ADD(SSE2_ROTATE(d, 11), a); xx = SSE2_XOR(d, a);
		c = SSE2_3ADD(c, SSE2_XOR(xx, b)									, SSE2_CONST(0x1fa27cf8)); c = SSE2_ADD(SSE2_ROTATE(c, 16), d);
		b = SSE2_4ADD(b, SSE2_XOR(c, xx), nt_buffer[2 * NT_NUM_KEYS / 4 + i], SSE2_CONST(0xc4ac5665)); b = SSE2_ADD(SSE2_ROTATE(b, 23), c);

		/* Round 4 */
		a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_OR(b, SSE2_NOT(d))), nt_buffer[0*NT_NUM_KEYS/4+i], SSE2_CONST(0xf4292244)); a = SSE2_ADD(SSE2_ROTATE(a, 6 ), b);
		d = SSE2_3ADD(d, SSE2_XOR(b, SSE2_OR(a, SSE2_NOT(c)))							   , SSE2_CONST(0x432aff97)); d = SSE2_ADD(SSE2_ROTATE(d, 10), a);
		c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_OR(d, SSE2_NOT(b))), nt_buffer[7*NT_NUM_KEYS/4+i], SSE2_CONST(0xab9423a7)); c = SSE2_ADD(SSE2_ROTATE(c, 15), d);
		b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_OR(c, SSE2_NOT(a))), nt_buffer[5*NT_NUM_KEYS/4+i], SSE2_CONST(0xfc93a039)); b = SSE2_ADD(SSE2_ROTATE(b, 21), c);

		a = SSE2_3ADD(a, SSE2_XOR(c, SSE2_OR(b, SSE2_NOT(d)))							   , SSE2_CONST(0x655b59c3)); a = SSE2_ADD(SSE2_ROTATE(a, 6 ), b);
		d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_OR(a, SSE2_NOT(c))), nt_buffer[3*NT_NUM_KEYS/4+i], SSE2_CONST(0x8f0ccc92)); d = SSE2_ADD(SSE2_ROTATE(d, 10), a);
		c = SSE2_3ADD(c, SSE2_XOR(a, SSE2_OR(d, SSE2_NOT(b)))							   , SSE2_CONST(0xffeff47d)); c = SSE2_ADD(SSE2_ROTATE(c, 15), d);
		b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_OR(c, SSE2_NOT(a))), nt_buffer[1*NT_NUM_KEYS/4+i], SSE2_CONST(0x85845dd1)); b = SSE2_ADD(SSE2_ROTATE(b, 21), c);

		a = SSE2_3ADD(a, SSE2_XOR(c, SSE2_OR(b, SSE2_NOT(d)))							   , SSE2_CONST(0x6fa87e4f)); a = SSE2_ADD(SSE2_ROTATE(a, 6 ), b);
		d = SSE2_3ADD(d, SSE2_XOR(b, SSE2_OR(a, SSE2_NOT(c)))							   , SSE2_CONST(0xfe2ce6e0)); d = SSE2_ADD(SSE2_ROTATE(d, 10), a);
		c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_OR(d, SSE2_NOT(b))), nt_buffer[6*NT_NUM_KEYS/4+i], SSE2_CONST(0xa3014314)); c = SSE2_ADD(SSE2_ROTATE(c, 15), d);
		c = SSE2_ADD(c, nt_buffer[2 * NT_NUM_KEYS/4 + i]);

		// Save
		nt_buffer[8 * NT_NUM_KEYS / 4 + i] = a;
		nt_buffer[8 * NT_NUM_KEYS / 4 + 1 * NT_NUM_KEYS / 4 + i] = b;
		nt_buffer[8 * NT_NUM_KEYS / 4 + 2 * NT_NUM_KEYS / 4 + i] = c;
		nt_buffer[8 * NT_NUM_KEYS / 4 + 3 * NT_NUM_KEYS / 4 + i] = d;

		c = SSE2_AND(c, SSE2_CONST(size_bit_table));
		for (int j = 0; j < 4; j++)
		{
			unsigned int val = ((unsigned int*)(&c))[j];

			((unsigned int*)nt_buffer)[8 * NT_NUM_KEYS + 4 * NT_NUM_KEYS + i*4+j] = (bit_table[val >> 5] >> (val & 31)) & 1;
		}
	}
}
PRIVATE void crypt_utf8_coalesc_protocol_sse2(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, (crypt_kernel_asm_func*)crypt_kernel_sse2);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void crypt_md5_avx_kernel_asm(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_utf8_coalesc_protocol_avx(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_md5_avx_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void crypt_md5_avx2_kernel_asm(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_utf8_coalesc_protocol_avx2(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_md5_avx2_kernel_asm);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_write_md5_header(char* source, GPUDevice* gpu, cl_uint ntlm_size_bit_table)
{
	source[0] = 0;
	// Header definitions
	if (num_passwords_loaded > 1)
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source + strlen(source), "#define bs(c,b,a) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
	sprintf(source + strlen(source), "#define I(y,x,z)  (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "(bitselect(0xffffffffU,(x),(z))^(y))" : "((y)^((x)|~(z)))");
	
	//Initial values
	sprintf(source + strlen(source),
		"#define INIT_B 0xefcdab89\n"
		"#define INIT_C 0x98badcfe\n");

	if (num_passwords_loaded > 1)
		sprintf(source + strlen(source),
		"#define SIZE_TABLE %uu\n"
		"#define SIZE_BIT_TABLE %uu\n", size_table, ntlm_size_bit_table);
}
PRIVATE void ocl_gen_kernel_with_lenght_onehash(char* source, cl_uint key_lenght, cl_uint vector_size, char** nt_buffer, char** str_comp)
{
	cl_uint a = ((cl_uint*)binary_values)[0];
	cl_uint b = ((cl_uint*)binary_values)[1];
	cl_uint c = ((cl_uint*)binary_values)[2];
	cl_uint d = ((cl_uint*)binary_values)[3];

	cl_uint max_char_in_charset = 0;
	for (cl_uint i = 0; i < num_char_in_charset; i++)
		if (max_char_in_charset < charset[i])
			max_char_in_charset = charset[i];

	if (max_char_in_charset <= 127 && key_lenght >= 4)
		sprintf(source + strlen(source),
			"uint val_a=0xd76aa477+nt_buffer0%s;val_a=rotate(val_a,7u)+(INIT_B+0xf57c0faf);"
			"val_a&=0xFF80007F;"
			, str_comp[0]);

	if (key_lenght <= 8)
	{
		if (key_lenght == 8)
			c -= 0x80;
		d -= b ^ (a | ~c);
		a = rotate(a - b, 32 - 6); a -= (c ^ (b | ~d)) + 0xf7537e82;

		b = rotate(b - c, 11u); b -= (d ^ (c | ~a)) + 0x4e0811a1;
		c = rotate(c - d, 17u); c -= (a ^ (d | ~b)) + 0xa3014314;
		d = rotate(d - a, 22u); d -= (b ^ (a | ~c)) + 0xfe2ce6e0;
		a = rotate(a - b, 26u); a -= (c ^ (b | ~d)) + 0x6fa87e4f;

		b = rotate(b - c, 11u); b -= (d ^ (c | ~a)) + 0x85845dd1;
		c = rotate(c - d, 17u); c -= 0xffeff47d;

		/* Round 4 */
		sprintf(source + strlen(source),
			"uint b1=%uu-(0%s);"//nt_buffer[1]
			"uint c1=%uu-I(%uu,%uu,b1);"
			"uint d1=%uu-I(b1,%uu,c1);"
			"uint a1=rotate(%uu-b1,26u);a1-=I(c1,b1,d1)+0x655b59c3;"

			"b1=rotate(b1-c1,11u);b1-=I(d1,c1,a1)+0xfc93a039;"
			"c1=rotate(c1-d1,17u);c1-=I(a1,d1,b1)+%uu;"
			"d1=rotate(d1-a1,22u);d1-=I(b1,a1,c1)+0x432aff97;"
			"a1=rotate(a1-b1,26u);a1-=I(c1,b1,d1)+0xf4292244;"

			"b1=rotate(b1-c1,9u)-0xc4ac5665;"
			"uint c_d=c1^d1;"
			"c1=rotate(c1-d1,16u)-0x1fa27cf8;"

			, b, nt_buffer[1]
			, c, a, d
			, rotate(d - a, 22u) - 0x8f0ccc92, a
			, a
			, (key_lenght << 3) + 0xab9423a7);
	}
	else
	{
		/* Round 4 */
		sprintf(source + strlen(source),
			"uint c1=%uu-(0%s);"
			"uint d1=%uu-I(%uu,%uu,c1);"
			"uint a1=%uu-(I(c1,%uu,d1)%s);"

			"uint b1=rotate(%uu-c1,11u);b1-=I(d1,c1,a1)+0x4e0811a1;"
			"c1=rotate(c1-d1,17u);c1-=I(a1,d1,b1)%s+0xa3014314;"
			"d1=rotate(d1-a1,22u);d1-=I(b1,a1,c1)+0xfe2ce6e0;"
			"a1=rotate(a1-b1,26u);a1-=I(c1,b1,d1)+0x6fa87e4f;"

			"b1=rotate(b1-c1,11u);b1-=I(d1,c1,a1)%s+0x85845dd1;"//nt_buffer[1]
			"c1=rotate(c1-d1,17u);c1-=I(a1,d1,b1)+0xffeff47d;"
			"d1=rotate(d1-a1,22u);d1-=I(b1,a1,c1)%s+0x8f0ccc92;"
			"a1=rotate(a1-b1,26u);a1-=I(c1,b1,d1)+0x655b59c3;"

			"b1=rotate(b1-c1,11u);b1-=I(d1,c1,a1)%s+0xfc93a039;"
			"c1=rotate(c1-d1,17u);c1-=I(a1,d1,b1)+%uu;"
			"d1=rotate(d1-a1,22u);d1-=I(b1,a1,c1)+0x432aff97;"
			"a1=rotate(a1-b1,26u);a1-=I(c1,b1,d1)+0xf4292244;"

			"b1=rotate(b1-c1,9u)-0xc4ac5665;"
			"uint c_d=c1^d1;"
			"c1=rotate(c1-d1,16u)-0x1fa27cf8;"
			, c, nt_buffer[2]
			, d, b, a
			, rotate(a - b, 32 - 6) - 0xf7537e82, b, nt_buffer[4]
			, b
			, nt_buffer[6], nt_buffer[1], nt_buffer[3], nt_buffer[5], (key_lenght << 3) + 0xab9423a7);
	}

	if (key_lenght > 4) strcat(source, "nt_buffer1+=0xa4beea44;");

	if (is_charset_consecutive(charset))
		for (cl_uint i = 0; i < vector_size; i++)
			sprintf(source + strlen(source), "nt_buffer0%s|=%iU;", str_comp[i], is_charset_consecutive(charset) - vector_size + i);

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "nt_buffer0+=%uU;", vector_size);
	else
		for (cl_uint i = 0; i < vector_size; i++)
			sprintf(source + strlen(source), "nt_buffer0%s^=charset[NUM_CHAR_IN_CHARSET+i+%uU];", str_comp[i], i);

	/* Round 3 */
	sprintf(source + strlen(source),
		"a=a1-nt_buffer0;"

		"b=b1-((c_d^a)%s);xx=a^b;"
		"c=c1-(d1^xx);"
		"d=rotate(d1-a,21u);d-=(xx^c)+0xe6db99e5;xx=c^d;"
		"a=rotate(a-b,28u);a-=(b^xx)+0xd9d4d039;"

		"b=rotate(b-c,9u);b-=(xx^a)%s+0x04881d05;xx=a^b;"
		"c=rotate(c-d,16u);c-=(d^xx)%s+0xd4ef3085;"
		"d=rotate(d-a,21u);d-=(xx^c)+nt_buffer0+0xeaa127fa;xx=c^d;"
		"a=rotate(a-b,28u);a-=(b^xx)+0x289b7ec6;"

		"b=rotate(b-c,9u);b-=(xx^a)+0xbebfbc70;xx=a^b;"
		"c=rotate(c-d,16u);c-=(d^xx)+0xf6bb4b60;"
		"d=rotate(d-a,21u);d-=(xx^c)%s+0x4bdecfa9;xx=c^d;"
		"a=rotate(a-b,28u);a-=(b^xx)%s%s;"

		"b=rotate(b-c,9u);b-=(xx^a)+%uu;xx=a^b;"
		"c=rotate(c-d,16u);c-=(d^xx)+0x6d9d6122;"
		"d=rotate(d-a,21u);d-=(xx^c)+0x8771f681;"
		"a=rotate(a-b,28u);a-=(b^c^d)%s+0xfffa3942;"
		, nt_buffer[2], nt_buffer[6], nt_buffer[3], nt_buffer[4], nt_buffer[1], (key_lenght > 4) ? "" : "+0xa4beea44", (key_lenght << 3) + 0xfde5380c, nt_buffer[5]);

	/* Round 2 */
	sprintf(source + strlen(source),
		"b=rotate(b-c,12u);b-=bs(d,c,a)+0x8d2a4c8a;"
		"c=rotate(c-d,18u);c-=bs(a,d,b)+0x676f02d9;"
		"d=rotate(d-a,23u);d-=bs(b,a,c)%s+0xfcefa3f8;"
		"a=rotate(a-b,27u);a-=bs(c,b,d)+0xa9e3e905;"

		"b=rotate(b-c,12u);b-=bs(d,c,a)+0x455a14ed;"
		"c=rotate(c-d,18u);c-=bs(a,d,b)%s+0xf4d50d87;"
		"d=rotate(d-a,23u);d-=bs(b,a,c)+%uu;"
		"a=rotate(a-b,27u);a-=bs(c,b,d)+0x21e1cde6;"

		"b=rotate(b-c,12u);b-=bs(d,c,a)%s+0xe7d3fbc8;"
		"c=rotate(c-d,18u);c-=bs(a,d,b)+0xd8a1e681;"
		"d=rotate(d-a,23u);d-=bs(b,a,c)+0x02441453;"
		"a=rotate(a-b,27u);a-=bs(c,b,d)%s+0xd62f105d;"

		"b=rotate(b-c,12u);b-=bs(d,c,a)+nt_buffer0+0xe9b6c7aa;"
		"c=rotate(c-d,18u);c-=bs(a,d,b)+0x265e5a51;"
		"d=rotate(d-a,23u);d-=bs(b,a,c)%s+0xc040b340;"
		"a=rotate(a-b,27u);a-=bs(c,b,d)%s%s;"
		, nt_buffer[2], nt_buffer[3], (key_lenght << 3) + 0xc33707d6, nt_buffer[4], nt_buffer[5], nt_buffer[6], nt_buffer[1], (key_lenght > 4) ? "+0x515f3b1e" : "+0xf61e2562");

	/* Round 1 */
	sprintf(source + strlen(source),
		"b=rotate(b-c,10u);b-=bs(a,d,c)+0x49b40821;"
		"c=rotate(c-d,15u);c-=bs(b,a,d)+%uu;"
		"d=rotate(d-a,20u);d-=bs(c,b,a)+0xfd987193;"
		"a=rotate(a-b,25u);a-=bs(d,c,b)+0x6b901122;"

		"b=rotate(b-c,10u);b-=bs(a,d,c)+0x895cd7be;"
		"c=rotate(c-d,15u);c-=bs(b,a,d)+0xffff5bb1;"
		"d=rotate(d-a,20u);d-=bs(c,b,a)+0x8b44f7af;"
		"a=rotate(a-b,25u);a-=bs(d,c,b)+0x698098d8;"

		"b=rotate(b-c,10u);b-=bs(a,d,c)+0xfd469501;"
		"c=rotate(c-d,15u);c-=bs(b,a,d)%s+0xa8304613;"
		"d=rotate(d-a,20u);d-=bs(c,b,a)%s+0x4787c62a;"
		"a=rotate(a-b,25u);a-=bs(d,c,b)%s;"
		, (key_lenght << 3) + 0xa679438e, nt_buffer[6], nt_buffer[5], nt_buffer[4]);

	if (max_char_in_charset <= 127 && key_lenght >= 4)
	{
		strcat(source, "xx=a&0xFF80007F;");
		// Find match
		for (cl_uint comp = 0; comp < vector_size; comp++)
			sprintf(source + strlen(source),
				"if(xx%s==val_a)"
				"{"
					"a%s-=0xf57c0faf;b%s=rotate(b%s-c%s,10u);b%s-=bs(a%s,d%s,c%s)%s;"

					"if(b%s==0xb18b7a77)"
					"{"
						"c%s=rotate(c%s-d%s,15u);c%s-=bs(INIT_B,a%s,d%s)%s;"
						"d%s=rotate(d%s-a%s,20u);d%s-=(INIT_C^(a%s&0x77777777))%s%s;"
						"a%s=rotate(a%s-INIT_B,25u);a%s-=nt_buffer0%s;"

						"if(c%s==0xbcdb4dd9&&d%s==0xf8fa0bcc&&a%s==0xd76aa477)"
						"{"
							"output[0]=1;"
							"output[1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
							"output[2]=0;"
						"}"
					"}"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3]
				, str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[1], (key_lenght) > 4 ? "-0xa4beea44" : ""
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]
				, comp);
	}
	else
	{
		sprintf(source + strlen(source), "a-=0xf57c0faf;b=rotate(b-c,10u);b-=bs(a,d,c)%s;", nt_buffer[3]);
		// Find match
		for (cl_uint comp = 0; comp < vector_size; comp++)
			sprintf(source + strlen(source),
				"if(b%s==0xb18b7a77)"
				"{"
					"c%s=rotate(c%s-d%s,15u);c%s-=bs(INIT_B,a%s,d%s)%s;"
					"d%s=rotate(d%s-a%s,20u);d%s-=(INIT_C^(a%s&0x77777777))%s%s;"
					"a%s=rotate(a%s-INIT_B,25u);a%s-=nt_buffer0%s;"

					"if(c%s==0xbcdb4dd9&&d%s==0xf8fa0bcc&&a%s==0xd76aa477)"
					"{"
						"output[0]=1;"
						"output[1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
						"output[2]=0;"
					"}"
				"}"
				, str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[1], (key_lenght) > 4 ? "-0xa4beea44" : ""
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]
				, comp);
	}

	strcat(source, "}}");
}

PRIVATE void ocl_gen_kernel_with_lenght(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission, cl_uint workgroup)
{
	cl_uint i;
	char* nt_buffer[] = {"+nt_buffer0", "+nt_buffer1", "+nt_buffer2", "+nt_buffer3", "+nt_buffer4", "+nt_buffer5", "+nt_buffer6"};
	char buffer[16];
	buffer[0] = 0;
	if (vector_size > 1) sprintf(buffer, "%u", vector_size);

	// Begin function code
	sprintf(source + strlen(source), "uint%s a,b,c,d,nt_buffer0=0,xx;uint indx;", buffer);

#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
	cl_uint bits_by_char;
	_BitScanReverse(&bits_by_char, ceil_power_2(num_char_in_charset));
	cl_uint chars_in_reg = 32 / bits_by_char;
#endif

	for (i = 0; i < key_lenght / 4; i++)
		for (cl_uint j = 0; j < 4; j++)
			if (i || j)
			{
				cl_uint key_index = 4 * i + j;
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
				key_index--;
				sprintf(source + strlen(source), "max_number+=(current_key%i>>%uu)&%uu;", key_index / chars_in_reg, (key_index%chars_in_reg)*bits_by_char, ceil_power_2(num_char_in_charset) - 1);
#else
				sprintf(source + strlen(source), "max_number+=current_key[%i];", key_index);
#endif
				// Perform division
				if (div_param.magic)sprintf(source + strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
				else				sprintf(source + strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

				if (j)
					sprintf(source + strlen(source), "nt_buffer%u+=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<%uu;", i, 8*j);
				else
					sprintf(source + strlen(source), "uint nt_buffer%u=charset[max_number-NUM_CHAR_IN_CHARSET*indx];", i);

				sprintf(source + strlen(source), "max_number=indx;");
			}

	if (key_lenght & 3)
	{
		for (cl_uint j = 0; j < (key_lenght & 3); j++)
			if (i || j)
			{
				cl_uint key_index = 4 * i + j;
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
				key_index--;
				sprintf(source + strlen(source), "max_number+=(current_key%i>>%uu)&%uu;", key_index / chars_in_reg, (key_index%chars_in_reg)*bits_by_char, ceil_power_2(num_char_in_charset) - 1);
#else
				sprintf(source + strlen(source), "max_number+=current_key[%i];", key_index);
#endif
				// Perform division
				if (div_param.magic)sprintf(source + strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
				else				sprintf(source + strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

				if (j)
					sprintf(source + strlen(source), "nt_buffer%u+=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<%uu;", i, 8 * j);
				else
					sprintf(source + strlen(source), "uint nt_buffer%u=charset[max_number-NUM_CHAR_IN_CHARSET*indx];", i);

				sprintf(source + strlen(source), "max_number=indx;");
			}

		sprintf(source + strlen(source), "nt_buffer%u+=0x80<<%uu;", i, 8 * (key_lenght & 3));
	}
	else
		nt_buffer[i] = "+0x80";

	for (i = key_lenght / 4 + 1; i < 7; i++)
		nt_buffer[i] = "";

	// Generate optimized code for particular case of only one hash
	if (num_passwords_loaded == 1)
	{
		ocl_gen_kernel_with_lenght_onehash(source + strlen(source), key_lenght, vector_size, nt_buffer, str_comp);
		return;
	}

	// Small optimization
	if (is_charset_consecutive(charset))
		for (i = 0; i < vector_size; i++)
			sprintf(source + strlen(source), "nt_buffer0%s|=%iU;", str_comp[i], is_charset_consecutive(charset) - vector_size + i);

	// TODO:
	//if (key_lenght > 4) sprintf(source + strlen(source), "nt_buffer1+=0xf8fa0bcc;");
	//if (key_lenght > 8) sprintf(source + strlen(source), "nt_buffer2+=0xbcdb4dd9;");

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "nt_buffer0+=%uU;", vector_size);
	else
		for (i = 0; i < vector_size; i++)
			sprintf(source + strlen(source), "nt_buffer0%s^=charset[NUM_CHAR_IN_CHARSET+i+%uU];", str_comp[i], i);

	/* Round 1 */
	sprintf(source + strlen(source),
	"a=nt_buffer0+0xd76aa477;a=rotate(a,7u)+INIT_B;"
	"d=(INIT_C^(a&0x77777777))%s+0xf8fa0bcc;d=rotate(d,12u)+a;"
	"c=bs(INIT_B,a,d)%s+0xbcdb4dd9;c=rotate(c,17u)+d;"
	"b=bs(a,d,c)%s+0xb18b7a77;b=rotate(b,22u)+c;"

	"a+=bs(d,c,b)%s+0xf57c0faf;a=rotate(a,7u)+b;"
	"d+=bs(c,b,a)%s+0x4787c62a;d=rotate(d,12u)+a;"
	"c+=bs(b,a,d)%s+0xa8304613;c=rotate(c,17u)+d;"
	"b+=bs(a,d,c)+0xfd469501;b=rotate(b,22u)+c;"

	"a+=bs(d,c,b)+0x698098d8;a=rotate(a,7u)+b;"
	"d+=bs(c,b,a)+0x8b44f7af;d=rotate(d,12u)+a;"
	"c+=bs(b,a,d)+0xffff5bb1;c=rotate(c,17u)+d;"
	"b+=bs(a,d,c)+0x895cd7be;b=rotate(b,22u)+c;"

	"a+=bs(d,c,b)+0x6b901122;a=rotate(a,7u)+b;"
	"d+=bs(c,b,a)+0xfd987193;d=rotate(d,12u)+a;"
	"c+=bs(b,a,d)+%uu;c=rotate(c,17u)+d;"
	"b+=bs(a,d,c)+0x49b40821;b=rotate(b,22u)+c;"
	, nt_buffer[1], nt_buffer[2], nt_buffer[3], nt_buffer[4], nt_buffer[5], nt_buffer[6], (key_lenght << 3) + 0xa679438e);

	/* Round 2 */
	sprintf(source + strlen(source),
	"a+=bs(c,b,d)%s+0xf61e2562;a=rotate(a,5u)+b;"
	"d+=bs(b,a,c)%s+0xc040b340;d=rotate(d,9u)+a;"
	"c+=bs(a,d,b)+0x265e5a51;c=rotate(c,14u)+d;"
	"b+=bs(d,c,a)+nt_buffer0+0xe9b6c7aa;b=rotate(b,20u)+c;"

	"a+=bs(c,b,d)%s+0xd62f105d;a=rotate(a,5u)+b;"
	"d+=bs(b,a,c)+0x02441453;d=rotate(d,9u)+a;"
	"c+=bs(a,d,b)+0xd8a1e681;c=rotate(c,14u)+d;"
	"b+=bs(d,c,a)%s+0xe7d3fbc8;b=rotate(b,20u)+c;"

	"a+=bs(c,b,d)+0x21e1cde6;a=rotate(a,5u)+b;"
	"d+=bs(b,a,c)+%uu;d=rotate(d,9u)+a;"
	"c+=bs(a,d,b)%s+0xf4d50d87;c=rotate(c,14u)+d;"
	"b+=bs(d,c,a)+0x455a14ed;b=rotate(b,20u)+c;"

	"a+=bs(c,b,d)+0xa9e3e905;a=rotate(a,5u)+b;"
	"d+=bs(b,a,c)%s+0xfcefa3f8;d=rotate(d,9u)+a;"
	"c+=bs(a,d,b)+0x676f02d9;c=rotate(c,14u)+d;"
	"b+=bs(d,c,a)+0x8d2a4c8a;b=rotate(b,20u)+c;"
	, nt_buffer[1], nt_buffer[6], nt_buffer[5], nt_buffer[4], (key_lenght << 3) + 0xc33707d6, nt_buffer[3], nt_buffer[2]);

	/* Round 3 */
	sprintf(source + strlen(source),
	"xx=b^c;"
	"a+=(xx^d)%s+0xfffa3942;a=rotate(a,4u)+b;"
	"d+=(a^xx)+0x8771f681;d=rotate(d,11u)+a;xx=d^a;"
	"c+=(xx^b)+0x6d9d6122;c=rotate(c,16u)+d;"
	"b+=(c^xx)+%uu;b=rotate(b,23u)+c;xx=b^c;"

	"a+=(xx^d)%s+0xa4beea44;a=rotate(a,4u)+b;"
	"d+=(a^xx)%s+0x4bdecfa9;d=rotate(d,11u)+a;xx=d^a;"
	"c+=(xx^b)+0xf6bb4b60;c=rotate(c,16u)+d;"
	"b+=(c^xx)+0xbebfbc70;b=rotate(b,23u)+c;xx=b^c;"

	"a+=(xx^d)+0x289b7ec6;a=rotate(a,4u)+b;"
	"d+=(a^xx)+nt_buffer0+0xeaa127fa;d=rotate(d,11u)+a;xx=d^a;"
	"c+=(xx^b)%s+0xd4ef3085;c=rotate(c,16u)+d;"
	"b+=(c^xx)%s+0x04881d05;b=rotate(b,23u)+c;xx=b^c;"

	"a+=(xx^d)+0xd9d4d039;a=rotate(a,4u)+b;"
	"d+=(a^xx)+0xe6db99e5;d=rotate(d,11u)+a;xx=d^a;"
	"c+=(xx^b)+0x1fa27cf8;c=rotate(c,16u)+d;"
	"b+=(c^xx)%s+0xc4ac5665;b=rotate(b,23u)+c;"
	, nt_buffer[5], (key_lenght << 3) + 0xfde5380c, nt_buffer[1], nt_buffer[4], nt_buffer[3], nt_buffer[6], nt_buffer[2]);

	/* Round 4 */
	sprintf(source + strlen(source),
	"a+=I(c,b,d)+nt_buffer0+0xf4292244;a=rotate(a,6u)+b;"
	"d+=I(b,a,c)+0x432aff97;d=rotate(d,10u)+a;"
	"c+=I(a,d,b)+%uu;c=rotate(c,15u)+d;"
	"b+=I(d,c,a)%s+0xfc93a039;b=rotate(b,21u)+c;"
	, (key_lenght << 3) + 0xab9423a7, nt_buffer[5]);
	
	if (key_lenght <= 8 && (max_lenght <= 7 || (current_key_lenght == 8 && max_lenght == 8)))
	{
		sprintf(source + strlen(source), "b+=0%s;", nt_buffer[1]);

		// Find match
		{
			//"indx=b & SIZE_BIT_TABLE;"
			//"if((bit_table[indx>>5]>>(indx&31))&1)"
			sprintf(source + strlen(source),
				"xx=b&SIZE_BIT_TABLE;"
				"uint%s bit_table_val=xx>>5u;"
				"xx&=31u;", buffer);

			for (unsigned int comp = 0; comp < vector_size; comp++)
				sprintf(source + strlen(source),
					"bit_table_val%s=bit_table[bit_table_val%s];", str_comp[comp], str_comp[comp]);

			strcat(source, "bit_table_val=(bit_table_val>>xx)&1u;");

			for (unsigned int comp = 0; comp < vector_size; comp++)
			{
				sprintf(source + strlen(source),
					"if(bit_table_val%s)"
					"{"
						"indx=table[(b%s)&SIZE_TABLE];"

						"while(indx!=0xffffffff)"
						//"if(indx!=0xffffffff)"
						"{"
							"if(b%s==binary_values[indx*4u+1u])"
							"{"
								"b%s-=0%s;"
								"a%s+=I(c%s,b%s,d%s)+0x655b59c3;a%s=rotate(a%s,6u)+b%s;"
								"d%s+=I(b%s,a%s,c%s)+0x8f0ccc92;d%s=rotate(d%s,10u)+a%s;"
								"c%s+=I(a%s,d%s,b%s)+0xffeff47d;c%s=rotate(c%s,15u)+d%s;"	

								"if(a%s==binary_values[indx*4u]&&d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u])"
								"{"
									"uint found=atomic_inc(output);"
									"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
									"output[2*found+2]=indx;}"
								"}",
						str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[1],
						str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
						str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
						str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
						str_comp[comp], str_comp[comp], str_comp[comp]
						, output_size, comp);
				// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same b
				if (value_map_collission)
					sprintf(source + strlen(source), 
								"c%s=rotate(c%s-d%s,32u-15u);c%s-=I(a%s,d%s,b%s)+0xffeff47d;"
								"d%s=rotate(d%s-a%s,32u-10u);d%s-=I(b%s,a%s,c%s)+0x8f0ccc92;"
								"a%s=rotate(a%s-b%s,32u-6u) ;a%s-=I(c%s,b%s,d%s)+0x655b59c3;"
								"b%s+=0%s;",
								str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
								str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
								str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
								str_comp[comp], nt_buffer[1]);

			strcat(source, "}"
							"indx=same_hash_next[indx];"
						"}"
					"}");
			}
		}
	}
	else
	{
		sprintf(source + strlen(source),
		"a+=I(c,b,d)+0x655b59c3;a=rotate(a,6u)+b;"
		"d+=I(b,a,c)%s+0x8f0ccc92;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)+0xffeff47d;c=rotate(c,15u)+d;"
		"b+=I(d,c,a)%s+0x85845dd1;b=rotate(b,21u)+c;"

		"a+=I(c,b,d)+0x6fa87e4f;a=rotate(a,6u)+b;"
		"d+=I(b,a,c)+0xfe2ce6e0;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)%s+0xa3014314;c=rotate(c,15u)+d%s;"
		, nt_buffer[3], nt_buffer[1], nt_buffer[6], nt_buffer[2]);

		// Find match
		{
			//"indx=c & SIZE_BIT_TABLE;"
			//"if((bit_table[indx>>5]>>(indx&31))&1)"
			sprintf(source + strlen(source),
				"xx=c&SIZE_BIT_TABLE;"
				"uint%s bit_table_val=xx>>5u;"
				"xx&=31u;", buffer);

			for (unsigned int comp = 0; comp < vector_size; comp++)
				sprintf(source + strlen(source),
					"bit_table_val%s=bit_table[bit_table_val%s];", str_comp[comp], str_comp[comp]);

			strcat(source, "bit_table_val=(bit_table_val>>xx)&1u;");

			for (unsigned int comp = 0; comp < vector_size; comp++)
			{
				sprintf(source + strlen(source),
					"if(bit_table_val%s)"
					"{"
						"indx=table[(c%s)&SIZE_TABLE];"

						"while(indx!=0xffffffff)"
						//"if(indx!=0xffffffff)"
						"{"
							"if(c%s==binary_values[indx*4u+2u])"
							"{"
								"c%s-=0%s;"
								"b%s+=I(d%s,c%s,a%s)+0x4e0811a1;b%s=rotate(b%s,21u)+c%s;"
								"a%s+=I(c%s,b%s,d%s)%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
								"d%s+=I(b%s,a%s,c%s);"

								"if(a%s==binary_values[indx*4u]&&d%s==binary_values[indx*4u+3u]&&b%s==binary_values[indx*4u+1u])"
								"{"
									"uint found=atomic_inc(output);"
									"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
									"output[2*found+2]=indx;}"
								"}",
						str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[2],
						str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
						str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], str_comp[comp], str_comp[comp], str_comp[comp],
						str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
						str_comp[comp], str_comp[comp], str_comp[comp], output_size, comp);
				// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same c
				if (value_map_collission)
					sprintf(source + strlen(source), 
								"d%s-=I(b%s,a%s,c%s);"
								"a%s-=b%s;a%s=rotate(a%s,32u-6u);a%s-=I(c%s,b%s,d%s)%s+0xf7537e82;"
								"b%s-=c%s;b%s=rotate(b%s,32u-21u);b%s-=I(d%s,c%s,a%s)+0x4e0811a1;"
								"c%s+=0%s;"
								, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
								, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4]
								, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
								, str_comp[comp], nt_buffer[2]);

			strcat(source, "}"
							"indx=same_hash_next[indx];"
						"}"
					"}");
			}
		}
	}

	strcat(source, "}}");
}

PRIVATE void ocl_protocol_charset_init(OpenCL_Param* result, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	if (num_passwords_loaded > 1 && (max_lenght <= 7 || (current_key_lenght == 8 && max_lenght == 8)))
	{
		unsigned int* old_table = table;
		unsigned int* old_bit_table = bit_table;
		unsigned int* old_same_hash_next = same_hash_next;
		void* old_bins = malloc(BINARY_SIZE*num_passwords_loaded);

		table = (unsigned int*)_aligned_malloc(sizeof(unsigned int)* (size_table + 1), 4096);
		bit_table = (unsigned int*)_aligned_malloc((size_bit_table / 32 + 1) * sizeof(unsigned int), 4096);
		same_hash_next = (unsigned int*)_aligned_malloc(sizeof(unsigned int)* num_passwords_loaded, 4096);

		// Initialize table map
		memcpy(old_bins, binary_values, BINARY_SIZE*num_passwords_loaded);
		memset(bit_table, 0, (size_bit_table / 32 + 1) * sizeof(unsigned int));
		memset(table, 0xff, sizeof(unsigned int)* (size_table + 1));
		memset(same_hash_next, 0xff, sizeof(unsigned int)* num_passwords_loaded);

		// Reverse last steps
		cl_uint* bin = (cl_uint*)binary_values;
		if (current_key_lenght==8)
			for (cl_uint current_index = 0; current_index < num_passwords_loaded; current_index++, bin += 4)
				// c += nt_buffer[2 * NT_NUM_KEYS + i];
				bin[2] -= 0x80;

		bin = (cl_uint*)binary_values;
		for (cl_uint current_index = 0; current_index < num_passwords_loaded; current_index++, bin += 4)
		{
			// d += (b ^ (a | ~c));
			bin[3] -= bin[1] ^ (bin[0] | ~bin[2]);
			// a += (c ^ (b | ~d)) + nt_buffer[4 * NT_NUM_KEYS + i] + 0xf7537e82; a = rotate(a, 6) + b;
			bin[0] = rotate(bin[0] - bin[1], 32 - 6);
			bin[0] -= (bin[2] ^ (bin[1] | ~bin[3])) + 0xf7537e82;

			// b += (d ^ (c | ~a)) + 0x4e0811a1; b = rotate(b, 21) + c;
			bin[1] = rotate(bin[1] - bin[2], 32 - 21);
			bin[1] -= (bin[3] ^ (bin[2] | ~bin[0])) + 0x4e0811a1;
			//c += (a ^ (d | ~b)) + nt_buffer[6*NT_NUM_KEYS+i] + 0xa3014314; c = rotate(c, 15) + d;
			bin[2] = rotate(bin[2] - bin[3], 32 - 15);
			bin[2] -= (bin[0] ^ (bin[3] | ~bin[1])) + 0xa3014314;
			//d += (b ^ (a | ~c))								 + 0xfe2ce6e0; d = rotate(d, 10) + a;
			bin[3] = rotate(bin[3] - bin[0], 32 - 10);
			bin[3] -= (bin[1] ^ (bin[0] | ~bin[2])) + 0xfe2ce6e0;
			//a += (c ^ (b | ~d))								 + 0x6fa87e4f; a = rotate(a, 6 ) + b;
			bin[0] = rotate(bin[0] - bin[1], 32 - 6);
			bin[0] -= (bin[2] ^ (bin[1] | ~bin[3])) + 0x6fa87e4f;

			//b += (d ^ (c | ~a)) + nt_buffer[1*NT_NUM_KEYS+i] + 0x85845dd1; b = rotate(b, 21) + c;
			bin[1] = rotate(bin[1] - bin[2], 32 - 21);
			bin[1] -= (bin[3] ^ (bin[2] | ~bin[0])) + 0x85845dd1;

			// Calculate bit_table, table and other data
			cl_uint value_map = bin[1];
			bit_table[(value_map & size_bit_table) >> 5] |= 1 << ((value_map & size_bit_table) & 31);
			// Put the password in the table map
			if (table[value_map & size_table] == NO_ELEM)
			{
				table[value_map & size_table] = current_index;
			}
			else
			{
				unsigned int last_index = table[value_map & size_table];
				while (same_hash_next[last_index] != NO_ELEM)
					last_index = same_hash_next[last_index];

				same_hash_next[last_index] = current_index;
			}
		}

		cl_bool has_unified_memory = gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY;
		GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_HAD_UNIFIED_MEMORY);

		cl_uint md5_empty_hash[] = { 0x5625a114, 0x561e0689, 0x392ad0d0, 0x3450f42b };
		ocl_charset_init(result, gpu_index, gen, gpu_crypt, BINARY_SIZE, 1, ocl_write_md5_header, ocl_gen_kernel_with_lenght, md5_empty_hash, FALSE, 2);

		// Change values back
		if (has_unified_memory)
			gpu_devices[gpu_index].flags |= GPU_FLAG_HAD_UNIFIED_MEMORY;
		memcpy(binary_values, old_bins, BINARY_SIZE*num_passwords_loaded);
		
		_aligned_free(table);
		_aligned_free(bit_table);
		_aligned_free(same_hash_next);
		free(old_bins);

		table = old_table;
		bit_table = old_bit_table;
		same_hash_next = old_same_hash_next;
	}
	else
	{
		cl_uint md5_empty_hash[] = { 0x7246fad3, 0x30130182, 0x36594b14, 0xabc40035 };

		// TODO: Patch-> I am not sure why this is significant faster
		if (num_passwords_loaded == 1 && gpu_devices[gpu_index].vector_int_size == 1 && gpu_devices[gpu_index].vendor == OCL_VENDOR_AMD)
			gpu_devices[gpu_index].vector_int_size = 2;

		ocl_charset_init(result, gpu_index, gen, gpu_crypt, BINARY_SIZE, 2, ocl_write_md5_header, ocl_gen_kernel_with_lenght, md5_empty_hash, FALSE, 2);

		if (num_passwords_loaded == 1 && gpu_devices[gpu_index].vector_int_size == 1 && gpu_devices[gpu_index].vendor == OCL_VENDOR_AMD)
			gpu_devices[gpu_index].vector_int_size = 1;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_md5(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint value_map_collission, void* salt_param, cl_uint prefered_vector_size)
{
	char nt_buffer[16][16];
	char buffer_vector_size[16];
	// Needed when use a rule with more than one param
	int found_multiplier = found_param_3 ? 3 : 2;
	char output_3[64];
	output_3[0] = 0;

	// NTLM Function definition
	sprintf(source + strlen(source), "\n__kernel void %s(const __global uint* keys,__global uint* restrict output", kernel_name);

	if (num_passwords_loaded > 1)
		strcat(source, ",const __global uint* restrict table,const __global uint* restrict binary_values,const __global uint* restrict same_hash_next,const __global uint* restrict bit_table");

	if (aditional_param)
	{
		sprintf(source + strlen(source), ",uint param");
		*aditional_param = num_passwords_loaded > 1 ? 6 : 2;
	}

	// Begin function code
	sprintf(source + strlen(source), "){uint indx;");

	// Convert the key into a nt_buffer
	memset(buffer_vector_size, 1, sizeof(buffer_vector_size));
	cl_uint vector_size = ocl_load(source, nt_buffer, buffer_vector_size, lenght, NUM_KEYS_OPENCL, prefered_vector_size);
	char buffer[16];
	buffer[0] = 0;
	if (vector_size > 1) sprintf(buffer, "%u", vector_size);

	sprintf(source + strlen(source), "uint%s a,b,c,d,xx;", buffer);

	/* Round 1 */
	sprintf(source + strlen(source),
		"a=0xd76aa477%s;a=rotate(a,7u)+INIT_B;"
		"d=(INIT_C^(a&0x77777777))%s+0xf8fa0bcc;d=rotate(d,12u)+a;"
		"c=bs(INIT_B,a,d)%s+0xbcdb4dd9;c=rotate(c,17u)+d;"
		"b=bs(a,d,c)%s+0xb18b7a77;b=rotate(b,22u)+c;"

		"a+=bs(d,c,b)%s+0xf57c0faf;a=rotate(a,7u)+b;"
		"d+=bs(c,b,a)%s+0x4787c62a;d=rotate(d,12u)+a;"
		"c+=bs(b,a,d)%s+0xa8304613;c=rotate(c,17u)+d;"
		"b+=bs(a,d,c)+0xfd469501;b=rotate(b,22u)+c;"

		"a+=bs(d,c,b)+0x698098d8;a=rotate(a,7u)+b;"
		"d+=bs(c,b,a)+0x8b44f7af;d=rotate(d,12u)+a;"
		"c+=bs(b,a,d)+0xffff5bb1;c=rotate(c,17u)+d;"
		"b+=bs(a,d,c)+0x895cd7be;b=rotate(b,22u)+c;"

		"a+=bs(d,c,b)+0x6b901122;a=rotate(a,7u)+b;"
		"d+=bs(c,b,a)+0xfd987193;d=rotate(d,12u)+a;"
		"c+=bs(b,a,d)%s+0xa679438e;c=rotate(c,17u)+d;"
		"b+=bs(a,d,c)+0x49b40821;b=rotate(b,22u)+c;"
		, nt_buffer[0], nt_buffer[1], nt_buffer[2], nt_buffer[3], nt_buffer[4], nt_buffer[5], nt_buffer[6], nt_buffer[7]);

	/* Round 2 */
	sprintf(source + strlen(source),
		"a+=bs(c,b,d)%s+0xf61e2562;a=rotate(a,5u)+b;"
		"d+=bs(b,a,c)%s+0xc040b340;d=rotate(d,9u)+a;"
		"c+=bs(a,d,b)+0x265e5a51;c=rotate(c,14u)+d;"
		"b+=bs(d,c,a)%s+0xe9b6c7aa;b=rotate(b,20u)+c;"

		"a+=bs(c,b,d)%s+0xd62f105d;a=rotate(a,5u)+b;"
		"d+=bs(b,a,c)+0x02441453;d=rotate(d,9u)+a;"
		"c+=bs(a,d,b)+0xd8a1e681;c=rotate(c,14u)+d;"
		"b+=bs(d,c,a)%s+0xe7d3fbc8;b=rotate(b,20u)+c;"

		"a+=bs(c,b,d)+0x21e1cde6;a=rotate(a,5u)+b;"
		"d+=bs(b,a,c)%s+0xc33707d6;d=rotate(d,9u)+a;"
		"c+=bs(a,d,b)%s+0xf4d50d87;c=rotate(c,14u)+d;"
		"b+=bs(d,c,a)+0x455a14ed;b=rotate(b,20u)+c;"

		"a+=bs(c,b,d)+0xa9e3e905;a=rotate(a,5u)+b;"
		"d+=bs(b,a,c)%s+0xfcefa3f8;d=rotate(d,9u)+a;"
		"c+=bs(a,d,b)+0x676f02d9;c=rotate(c,14u)+d;"
		"b+=bs(d,c,a)+0x8d2a4c8a;b=rotate(b,20u)+c;"
		, nt_buffer[1], nt_buffer[6], nt_buffer[0], nt_buffer[5], nt_buffer[4], nt_buffer[7], nt_buffer[3], nt_buffer[2]);

	/* Round 3 */
	sprintf(source + strlen(source),
		"xx=b^c;"
		"a+=(xx^d)%s+0xfffa3942;a=rotate(a,4u)+b;"
		"d+=(a^xx)+0x8771f681;d=rotate(d,11u)+a;xx=d^a;"
		"c+=(xx^b)+0x6d9d6122;c=rotate(c,16u)+d;"
		"b+=(c^xx)%s+0xfde5380c;b=rotate(b,23u)+c;xx=b^c;"

		"a+=(xx^d)%s+0xa4beea44;a=rotate(a,4u)+b;"
		"d+=(a^xx)%s+0x4bdecfa9;d=rotate(d,11u)+a;xx=d^a;"
		"c+=(xx^b)+0xf6bb4b60;c=rotate(c,16u)+d;"
		"b+=(c^xx)+0xbebfbc70;b=rotate(b,23u)+c;xx=b^c;"

		"a+=(xx^d)+0x289b7ec6;a=rotate(a,4u)+b;"
		"d+=(a^xx)%s+0xeaa127fa;d=rotate(d,11u)+a;xx=d^a;"
		"c+=(xx^b)%s+0xd4ef3085;c=rotate(c,16u)+d;"
		"b+=(c^xx)%s+0x04881d05;b=rotate(b,23u)+c;xx=b^c;"

		"a+=(xx^d)+0xd9d4d039;a=rotate(a,4u)+b;"
		"d+=(a^xx)+0xe6db99e5;d=rotate(d,11u)+a;xx=d^a;"
		"c+=(xx^b)+0x1fa27cf8;c=rotate(c,16u)+d;"
		"b+=(c^xx)%s+0xc4ac5665;b=rotate(b,23u)+c;"
		, nt_buffer[5], nt_buffer[7], nt_buffer[1], nt_buffer[4], nt_buffer[0], nt_buffer[3], nt_buffer[6], nt_buffer[2]);

	/* Round 4 */
	sprintf(source + strlen(source),
		"a+=I(c,b,d)%s+0xf4292244;a=rotate(a,6u)+b;"
		"d+=I(b,a,c)+0x432aff97;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)%s+0xab9423a7;c=rotate(c,15u)+d;"
		"b+=I(d,c,a)%s+0xfc93a039;b=rotate(b,21u)+c;"

		"a+=I(c,b,d)+0x655b59c3;a=rotate(a,6u)+b;"
		"d+=I(b,a,c)%s+0x8f0ccc92;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)+0xffeff47d;c=rotate(c,15u)+d;"
		"b+=I(d,c,a)%s+0x85845dd1;b=rotate(b,21u)+c;"

		"a+=I(c,b,d)+0x6fa87e4f;a=rotate(a,6u)+b;"
		"d+=I(b,a,c)+0xfe2ce6e0;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)%s+0xa3014314;c=rotate(c,15u)+d%s;"
		, nt_buffer[0], nt_buffer[7], nt_buffer[5], nt_buffer[3], nt_buffer[1], nt_buffer[6], nt_buffer[2]);

	// Match
	char* str_comp[] = { ".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf" };
	if (vector_size == 1)str_comp[0] = "";

	if (num_passwords_loaded == 1)
	{
		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			if (found_param_3)
				sprintf(output_3, "output[3u]=%s+%uu;", found_param_3, comp);

			sprintf(source + strlen(source),
			"if(c%s==%uu)"
			"{"
				"c%s-=0%s%s;"
				"b%s+=I(d%s,c%s,a%s)+0x4e0811a1;b%s=rotate(b%s,21u)+c%s;"
				"a%s+=I(c%s,b%s,d%s)%s%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
				"d%s+=I(b%s,a%s,c%s);"
				"if(a%s==%uu&&b%s==%uu&&d%s==%uu)"
				"{"
					"output[0]=1;"
					"output[1]=get_global_id(0);"
					"output[2]=0;"
					"%s"
				"}"
			"}"
			, str_comp[comp], ((cl_uint*)binary_values)[2]
			, str_comp[comp], nt_buffer[2], buffer_vector_size[2] == 1 ? "" : str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], buffer_vector_size[4] == 1 ? "" : str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
			, str_comp[comp], ((cl_uint*)binary_values)[0], str_comp[comp], ((cl_uint*)binary_values)[1], str_comp[comp], ((cl_uint*)binary_values)[3], output_3);
		}
	}
	else
	{
		//"indx=c & SIZE_BIT_TABLE;"
		//"if((bit_table[indx>>5]>>(indx&31))&1)"
		sprintf(source + strlen(source),
			"xx=c&SIZE_BIT_TABLE;"
			"uint%s bit_table_val=xx>>5u;"
			"xx&=31u;", buffer);

		for (cl_uint comp = 0; comp < vector_size; comp++)
			sprintf(source + strlen(source),
				"bit_table_val%s=bit_table[bit_table_val%s];", str_comp[comp], str_comp[comp]);

		strcat(source, "bit_table_val=(bit_table_val>>xx)&1u;");

		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			if (found_param_3)
				sprintf(output_3, "output[3u*found+3u]=%s+%uu;", found_param_3, comp);

			sprintf(source + strlen(source),
				"if(bit_table_val%s)"
				"{"
					"indx=table[(c%s)&SIZE_TABLE];"

					"while(indx!=0xffffffff)"
					//"if(indx!=0xffffffff)"
					"{"
						"if(c%s==binary_values[indx*4u+2u])"
						"{"
							"c%s-=0%s%s;"
							"b%s+=I(d%s,c%s,a%s)+0x4e0811a1;b%s=rotate(b%s,21u)+c%s;"
							"a%s+=I(c%s,b%s,d%s)%s%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
							"d%s+=I(b%s,a%s,c%s);"

							"if(a%s==binary_values[indx*4u]&&d%s==binary_values[indx*4u+3u]&&b%s==binary_values[indx*4u+1u])"
							"{"
								"uint found=atomic_inc(output);"
								"output[%iu*found+1u]=get_global_id(0);"
								"output[%iu*found+2u]=indx;"
								"%s"
							"}",
					str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[2], buffer_vector_size[2] == 1 ? "" : str_comp[comp],
					str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
					str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], buffer_vector_size[4] == 1 ? "" : str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
					str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
					str_comp[comp], str_comp[comp], str_comp[comp], found_multiplier, found_multiplier, output_3);
			// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same c
			if (value_map_collission)
				sprintf(source + strlen(source), 
							"d%s-=I(b%s,a%s,c%s);"
							"a%s-=b%s;a%s=rotate(a%s,32u-6u);a%s-=I(c%s,b%s,d%s)%s%s+0xf7537e82;"
							"b%s-=c%s;b%s=rotate(b%s,32u-21u);b%s-=I(d%s,c%s,a%s)+0x4e0811a1;"
							"c%s+=0%s%s;"
							, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
							, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], buffer_vector_size[4] == 1 ? "" : str_comp[comp]
							, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
							, str_comp[comp], nt_buffer[2], buffer_vector_size[2] == 1 ? "" : str_comp[comp]);

		strcat(source, "}"
						"indx=same_hash_next[indx];"
					"}"
				"}");
		}
	}

	if (ocl_end)	ocl_end(source);
	// End of kernel
	strcat(source, "}");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
#ifdef ANDROID
	ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 2, ocl_write_md5_header, ocl_gen_kernel_md5, kernels2common + UTF8_INDEX_IN_KERNELS, 32, ocl_rule_simple_copy_utf8_le);
#else
	ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 2, ocl_write_md5_header, ocl_gen_kernel_md5, kernels2common + UTF8_INDEX_IN_KERNELS, 4/*consider 2 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
#endif
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 2, ocl_write_md5_header, ocl_gen_kernel_md5, kernels2common + PHRASES_INDEX_IN_KERNELS, 64/*consider 32 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	ocl_rules_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 2, ocl_write_md5_header, ocl_gen_kernel_md5, RULE_UTF8_LE_INDEX, 1);
}
#endif

PRIVATE int bench_values[] = { 1, 10, 100, 1000, 10000, 65536, 100000, 1000000 };
Format raw_md5_format = {
	"Raw-MD5",
	"Raw MD5 format.",
	NTLM_MAX_KEY_LENGHT,
	BINARY_SIZE,
	0,
	5,
	bench_values,
	LENGHT(bench_values),
	get_binary,
	is_valid,
	add_hash_from_line,
#ifdef _M_X64
	{{CPU_CAP_AVX2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_avx2}, {CPU_CAP_AVX, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_avx}, {CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_sse2}},
#else
#ifdef HS_ARM
	{{CPU_CAP_NEON, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_neon}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code}},
#else
	{{CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_sse2}, {CPU_CAP_C_CODE, PROTOCOL_UTF8_COALESC_LE, crypt_utf8_coalesc_protocol_c_code } },
#endif
#endif
#ifdef HS_OPENCL_SUPPORT
	{{PROTOCOL_CHARSET_OCL, ocl_protocol_charset_init}, {PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init}, {PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init}, {PROTOCOL_UTF8, ocl_protocol_utf8_init}}
#endif
};