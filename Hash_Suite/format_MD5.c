// This file is part of Hash Suite password cracker,
// Copyright (c) 2014-2018 by Alain Espinosa. See LICENSE.

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

		if (!memcmp(user_name, "$dynamic_0$", 11) && valid_hex_string(user_name + 11, 32))
			return TRUE;

		if (valid_hex_string(user_name, 32))
			return TRUE;
	}

	return FALSE;
}

PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* user_name, char* md5, char* unused, char* unused1)
{
	if (user_name)
	{
		if (md5 && valid_hex_string(md5, 32))
			return insert_hash_account1(param, user_name, _strupr(md5), MD5_INDEX);

		if (!memcmp(user_name, "$dynamic_0$", 11) && valid_hex_string(user_name + 11, 32))
			return insert_hash_account1(param, NULL, _strupr(user_name + 11), MD5_INDEX);

		if (valid_hex_string(user_name, 32))
			return insert_hash_account1(param, NULL, _strupr(user_name), MD5_INDEX);
	}
	return -1;
}
#define VALUE_MAP_INDEX0 2
#define VALUE_MAP_INDEX1 1
PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	uint32_t* out = (uint32_t*)binary;

	for (uint32_t i = 0; i < 4; i++)
	{
		uint32_t temp = (hex_to_num[ciphertext[i * 8 + 0]]) << 4;
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
	out[1] = ROTATE(out[1] - out[2], 32 - 21);
	out[1] -= (out[3] ^ (out[2] | ~out[0])) + 0xeb86d391;

	// c
	out[2] = ROTATE(out[2] - out[3], 32 - 15);
	out[2] -= (out[0] ^ (out[3] | ~out[1])) + 0x2ad7d2bb;

	//d
	out[3] = ROTATE(out[3] - out[0], 32 - 10);
	out[3] -= 0xbd3af235;

	return out[VALUE_MAP_INDEX0];
}
PRIVATE void binary2hex(const void* binary, const void* salt, unsigned char* ciphertext)
{
	uint32_t bin[BINARY_SIZE / sizeof(uint32_t)];
	memcpy(bin, binary, BINARY_SIZE);

	//d
	bin[3] += 0xbd3af235;
	bin[3]  = ROTATE(bin[3], 10) + bin[0];
	
	// c
	bin[2] += (bin[0] ^ (bin[3] | ~bin[1])) + 0x2ad7d2bb;
	bin[2]  = ROTATE(bin[2], 15) + bin[3];
	
	// b
	bin[1] += (bin[3] ^ (bin[2] | ~bin[0])) + 0xeb86d391;
	bin[1]  = ROTATE(bin[1], 21) + bin[2];
	
	bin[0] += INIT_A;
	bin[1] += INIT_B;
	bin[2] += INIT_C;
	bin[3] += INIT_D;

	binary_to_hex(bin, ciphertext, BINARY_SIZE / sizeof(uint32_t), TRUE);
}

#ifdef HS_ARM
	#define NT_NUM_KEYS		    128
#endif

#ifdef HS_X86
	#define NT_NUM_KEYS		    256
#endif

PRIVATE uint32_t compare_elem(uint32_t i, uint32_t cbg_table_pos, uint32_t* nt_buffer)
{
	if (cbg_table_pos == NO_ELEM) return FALSE;

	uint32_t* bin = ((uint32_t*)binary_values) + cbg_table_pos * 4;

	uint32_t* unpacked_as = (uint32_t*)(nt_buffer + 8 * NT_NUM_KEYS);
	uint32_t* unpacked_bs = (uint32_t*)(nt_buffer + 8 * NT_NUM_KEYS + 1 * NT_NUM_KEYS);
	uint32_t* unpacked_cs = (uint32_t*)(nt_buffer + 8 * NT_NUM_KEYS + 2 * NT_NUM_KEYS);
	uint32_t* unpacked_ds = (uint32_t*)(nt_buffer + 8 * NT_NUM_KEYS + 3 * NT_NUM_KEYS);

	if (unpacked_cs[i] != bin[2] || unpacked_bs[i] != bin[1]) return FALSE;
	uint32_t cc = unpacked_cs[i] - nt_buffer[2 * NT_NUM_KEYS + i];

	uint32_t aa = unpacked_as[i] + (cc ^ (unpacked_bs[i] | ~unpacked_ds[i])) + nt_buffer[4 * NT_NUM_KEYS + i] +0xf7537e82; aa = ROTATE(aa, 6) + unpacked_bs[i];
	if (aa != bin[0])  return FALSE;

	uint32_t dd = unpacked_ds[i] + (unpacked_bs[i] ^ (aa | ~cc));
	if (cc != bin[2])  return FALSE;

	return TRUE;
}

PRIVATE void crypt_utf8_coalesc_protocol_body(CryptParam* param, crypt_kernel_asm_func* crypt_kernel_asm)
{
	uint32_t* nt_buffer = (uint32_t*)_aligned_malloc((8 + 4) * sizeof(uint32_t) * NT_NUM_KEYS, 64);

	uint32_t* unpacked_as = (uint32_t*)(nt_buffer + 8 * NT_NUM_KEYS);
	uint32_t* unpacked_bs = (uint32_t*)(nt_buffer + 8 * NT_NUM_KEYS + 1 * NT_NUM_KEYS);
	uint32_t* unpacked_cs = (uint32_t*)(nt_buffer + 8 * NT_NUM_KEYS + 2 * NT_NUM_KEYS);
	uint32_t* unpacked_ds = (uint32_t*)(nt_buffer + 8 * NT_NUM_KEYS + 3 * NT_NUM_KEYS);

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, 8 * sizeof(uint32_t)* NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while (continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_kernel_asm(nt_buffer);

		for (uint32_t i = 0; i < NT_NUM_KEYS; i++)
		{
			uint32_t up0 = unpacked_cs[i];
			uint32_t up1 = unpacked_bs[i];

			uint32_t pos = up0 & cbg_mask;
			uint_fast16_t data = cbg_filter[pos];
			if (((data ^ up1) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], nt_buffer))
				password_was_found(cbg_table[pos], utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match

			// 2nd pos
			if (data & 0b110)
			{
				pos += data & 0b1 ? -1 : 1;
				uint_fast16_t hash = cbg_filter[pos];
				if (((hash ^ up1) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], nt_buffer))
					password_was_found(cbg_table[pos], utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match

				// Unluky bucket
				if (data & 0b10)
				{
					pos = up1 & cbg_mask;
					data = cbg_filter[pos];
					if (((data ^ up0) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], nt_buffer))
						password_was_found(cbg_table[pos], utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match

					// 2nd pos
					pos += data & 0b1 ? -1 : 1;
					hash = cbg_filter[pos];
					if (((hash ^ up0) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], nt_buffer))
						password_was_found(cbg_table[pos], utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match
				}
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
PRIVATE void crypt_kernel_c(uint32_t* nt_buffer)
{
	for (int i = 0; i < NT_NUM_KEYS; i++)
	{
		/* Round 1 */
		uint32_t a = nt_buffer[0 * NT_NUM_KEYS + i] + 0xd76aa477; a = ROTATE(a, 7) + INIT_B;
		uint32_t d = (INIT_C ^ (a & 0x77777777)) + nt_buffer[1 * NT_NUM_KEYS + i] + 0xf8fa0bcc; d = ROTATE(d, 12) + a;
		uint32_t c = (INIT_B ^ (d & (a ^ INIT_B))) + nt_buffer[2 * NT_NUM_KEYS + i] + 0xbcdb4dd9; c = ROTATE(c, 17) + d;
		uint32_t b = (a ^ (c & (d ^ a))) + nt_buffer[3 * NT_NUM_KEYS + i] + 0xb18b7a77; b = ROTATE(b, 22) + c;

		a += (d ^ (b & (c ^ d))) + nt_buffer[4 * NT_NUM_KEYS + i] + 0xf57c0faf; a = ROTATE(a, 7) + b;
		d += (c ^ (a & (b ^ c))) + nt_buffer[5 * NT_NUM_KEYS + i] + 0x4787c62a; d = ROTATE(d, 12) + a;
		c += (b ^ (d & (a ^ b))) + nt_buffer[6 * NT_NUM_KEYS + i] + 0xa8304613; c = ROTATE(c, 17) + d;
		b += (a ^ (c & (d ^ a))) + 0xfd469501; b = ROTATE(b, 22) + c;

		a += (d ^ (b & (c ^ d))) + 0x698098d8; a = ROTATE(a, 7) + b;
		d += (c ^ (a & (b ^ c))) + 0x8b44f7af; d = ROTATE(d, 12) + a;
		c += (b ^ (d & (a ^ b))) + 0xffff5bb1; c = ROTATE(c, 17) + d;
		b += (a ^ (c & (d ^ a))) + 0x895cd7be; b = ROTATE(b, 22) + c;

		a += (d ^ (b & (c ^ d))) + 0x6b901122; a = ROTATE(a, 7) + b;
		d += (c ^ (a & (b ^ c))) + 0xfd987193; d = ROTATE(d, 12) + a;
		c += (b ^ (d & (a ^ b))) + nt_buffer[7 * NT_NUM_KEYS + i] + 0xa679438e; c = ROTATE(c, 17) + d;
		b += (a ^ (c & (d ^ a))) + 0x49b40821; b = ROTATE(b, 22) + c;

		/* Round 2 */
		a += (c ^ (d & (b ^ c))) + nt_buffer[1 * NT_NUM_KEYS + i] + 0xf61e2562; a = ROTATE(a, 5) + b;
		d += (b ^ (c & (a ^ b))) + nt_buffer[6 * NT_NUM_KEYS + i] + 0xc040b340; d = ROTATE(d, 9) + a;
		c += (a ^ (b & (d ^ a))) + 0x265e5a51; c = ROTATE(c, 14) + d;
		b += (d ^ (a & (c ^ d))) + nt_buffer[0 * NT_NUM_KEYS + i] + 0xe9b6c7aa; b = ROTATE(b, 20) + c;

		a += (c ^ (d & (b ^ c))) + nt_buffer[5 * NT_NUM_KEYS + i] + 0xd62f105d; a = ROTATE(a, 5) + b;
		d += (b ^ (c & (a ^ b))) + 0x02441453; d = ROTATE(d, 9) + a;
		c += (a ^ (b & (d ^ a))) + 0xd8a1e681; c = ROTATE(c, 14) + d;
		b += (d ^ (a & (c ^ d))) + nt_buffer[4 * NT_NUM_KEYS + i] + 0xe7d3fbc8; b = ROTATE(b, 20) + c;

		a += (c ^ (d & (b ^ c))) + 0x21e1cde6; a = ROTATE(a, 5) + b;
		d += (b ^ (c & (a ^ b))) + nt_buffer[7 * NT_NUM_KEYS + i] + 0xc33707d6; d = ROTATE(d, 9) + a;
		c += (a ^ (b & (d ^ a))) + nt_buffer[3 * NT_NUM_KEYS + i] + 0xf4d50d87; c = ROTATE(c, 14) + d;
		b += (d ^ (a & (c ^ d))) + 0x455a14ed; b = ROTATE(b, 20) + c;

		a += (c ^ (d & (b ^ c))) + 0xa9e3e905; a = ROTATE(a, 5) + b;
		d += (b ^ (c & (a ^ b))) + nt_buffer[2 * NT_NUM_KEYS + i] + 0xfcefa3f8; d = ROTATE(d, 9) + a;
		c += (a ^ (b & (d ^ a))) + 0x676f02d9; c = ROTATE(c, 14) + d;
		b += (d ^ (a & (c ^ d))) + 0x8d2a4c8a; b = ROTATE(b, 20) + c;

		/* Round 3 */
		a += (b ^ c ^ d) + nt_buffer[5 * NT_NUM_KEYS + i] + 0xfffa3942; a = ROTATE(a, 4) + b;
		d += (a ^ b ^ c) + 0x8771f681; d = ROTATE(d, 11) + a;
		c += (d ^ a ^ b) + 0x6d9d6122; c = ROTATE(c, 16) + d;
		b += (c ^ d ^ a) + nt_buffer[7 * NT_NUM_KEYS + i] + 0xfde5380c; b = ROTATE(b, 23) + c;

		a += (b ^ c ^ d) + nt_buffer[1 * NT_NUM_KEYS + i] + 0xa4beea44; a = ROTATE(a, 4) + b;
		d += (a ^ b ^ c) + nt_buffer[4 * NT_NUM_KEYS + i] + 0x4bdecfa9; d = ROTATE(d, 11) + a;
		c += (d ^ a ^ b) + 0xf6bb4b60; c = ROTATE(c, 16) + d;
		b += (c ^ d ^ a) + 0xbebfbc70; b = ROTATE(b, 23) + c;

		a += (b ^ c ^ d) + 0x289b7ec6; a = ROTATE(a, 4) + b;
		d += (a ^ b ^ c) + nt_buffer[0 * NT_NUM_KEYS + i] + 0xeaa127fa; d = ROTATE(d, 11) + a;
		c += (d ^ a ^ b) + nt_buffer[3 * NT_NUM_KEYS + i] + 0xd4ef3085; c = ROTATE(c, 16) + d;
		b += (c ^ d ^ a) + nt_buffer[6 * NT_NUM_KEYS + i] + 0x04881d05; b = ROTATE(b, 23) + c;

		a += (b ^ c ^ d) + 0xd9d4d039; a = ROTATE(a, 4) + b;
		d += (a ^ b ^ c) + 0xe6db99e5; d = ROTATE(d, 11) + a;
		c += (d ^ a ^ b) + 0x1fa27cf8; c = ROTATE(c, 16) + d;
		b += (c ^ d ^ a) + nt_buffer[2 * NT_NUM_KEYS + i] + 0xc4ac5665; b = ROTATE(b, 23) + c;

		/* Round 4 */
		a += (c ^ (b | ~d)) + nt_buffer[0 * NT_NUM_KEYS + i] + 0xf4292244; a = ROTATE(a, 6) + b;
		d += (b ^ (a | ~c)) + 0x432aff97; d = ROTATE(d, 10) + a;
		c += (a ^ (d | ~b)) + nt_buffer[7 * NT_NUM_KEYS + i] + 0xab9423a7; c = ROTATE(c, 15) + d;
		b += (d ^ (c | ~a)) + nt_buffer[5 * NT_NUM_KEYS + i] + 0xfc93a039; b = ROTATE(b, 21) + c;

		a += (c ^ (b | ~d)) + 0x655b59c3; a = ROTATE(a, 6) + b;
		d += (b ^ (a | ~c)) + nt_buffer[3 * NT_NUM_KEYS + i] + 0x8f0ccc92; d = ROTATE(d, 10) + a;
		c += (a ^ (d | ~b)) + 0xffeff47d; c = ROTATE(c, 15) + d;
		b += (d ^ (c | ~a)) + nt_buffer[1 * NT_NUM_KEYS + i] + 0x85845dd1; b = ROTATE(b, 21) + c;

		a += (c ^ (b | ~d)) + 0x6fa87e4f; a = ROTATE(a, 6) + b;
		d += (b ^ (a | ~c)) + 0xfe2ce6e0; d = ROTATE(d, 10) + a;
		c += (a ^ (d | ~b)) + nt_buffer[6 * NT_NUM_KEYS + i] + 0xa3014314; c = ROTATE(c, 15) + d;
		b += (d ^ (c | ~a))  + 0x4e0811a1; b = ROTATE(b, 21) + c;
		c += nt_buffer[2 * NT_NUM_KEYS + i];

		// Save
		nt_buffer[8 * NT_NUM_KEYS + i] = a;
		nt_buffer[8 * NT_NUM_KEYS + 1 * NT_NUM_KEYS + i] = b;
		nt_buffer[8 * NT_NUM_KEYS + 2 * NT_NUM_KEYS + i] = c;
		nt_buffer[8 * NT_NUM_KEYS + 3 * NT_NUM_KEYS + i] = d;
	}
}
PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_kernel_c);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Neon code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM
void crypt_md5_neon_kernel_asm(uint32_t* nt_buffer);
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

PRIVATE void crypt_kernel_sse2(SSE2_WORD* nt_buffer)
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
		b = SSE2_3ADD(b, SSE2_XOR(d, SSE2_OR(c, SSE2_NOT(a)))                              , SSE2_CONST(0x4e0811a1)); b = SSE2_ADD(SSE2_ROTATE(b, 21), c);
		c = SSE2_ADD(c, nt_buffer[2 * NT_NUM_KEYS/4 + i]);

		// Save
		nt_buffer[8 * NT_NUM_KEYS / 4 + i] = a;
		nt_buffer[8 * NT_NUM_KEYS / 4 + 1 * NT_NUM_KEYS / 4 + i] = b;
		nt_buffer[8 * NT_NUM_KEYS / 4 + 2 * NT_NUM_KEYS / 4 + i] = c;
		nt_buffer[8 * NT_NUM_KEYS / 4 + 3 * NT_NUM_KEYS / 4 + i] = d;
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

void crypt_md5_avx_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_utf8_coalesc_protocol_avx(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_md5_avx_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void crypt_md5_avx2_kernel_asm(uint32_t* nt_buffer);
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
PRIVATE void ocl_write_md5_header(char* source, GPUDevice* gpu, cl_uint ntlm_size_bit_table1)
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
		a = ROTATE(a - b, 32 - 6); a -= (c ^ (b | ~d)) + 0xf7537e82;

		b = ROTATE(b - c, 11u); b -= (d ^ (c | ~a)) + 0x4e0811a1;
		c = ROTATE(c - d, 17u); c -= (a ^ (d | ~b)) + 0xa3014314;
		d = ROTATE(d - a, 22u); d -= (b ^ (a | ~c)) + 0xfe2ce6e0;
		a = ROTATE(a - b, 26u); a -= (c ^ (b | ~d)) + 0x6fa87e4f;

		b = ROTATE(b - c, 11u); b -= (d ^ (c | ~a)) + 0x85845dd1;
		c = ROTATE(c - d, 17u); c -= 0xffeff47d;

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
			, ROTATE(d - a, 22u) - 0x8f0ccc92, a
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
			, ROTATE(a - b, 32 - 6) - 0xf7537e82, b, nt_buffer[4]
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

PRIVATE void ocl_gen_kernel_with_lenght(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table1, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission1, cl_uint workgroup)
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
	"a+=I(c,b,d)+0x655b59c3;a=rotate(a,6u)+b;"
	, (key_lenght << 3) + 0xab9423a7, nt_buffer[5]);
	
	if (key_lenght <= 8 && (max_lenght <= 7 || (current_key_lenght == 8 && max_lenght == 8)))
	{
		sprintf(source + strlen(source), "b+=0%s;", nt_buffer[1]);

		// Find match
		sprintf(source + strlen(source), "xx=b&%uu;uint fdata;", cbg_mask);

		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			sprintf(source + strlen(source),
				"fdata=(uint)(cbg_filter[xx%s]);"

				"if(((fdata^a%s)&0xFFF8)==0){"
					"indx=cbg_table[xx%s];"
					"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
						
						"uint bb=b%s-(0%s);"
						"d%s+=I(bb,a%s,c%s)+0x8f0ccc92;d%s=rotate(d%s,10u)+a%s;"
						"c%s+=I(a%s,d%s,bb)+0xffeff47d;c%s=rotate(c%s,15u)+d%s;"

						"if(d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u]){"
							"uint found=atomic_inc(output);"
							"if(found<%uu){"
								"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
								"output[2*found+2]=indx;}"
						"}"
						// TODO: Reverse c,d to their last value for the unlikely case of 2 hashes with same a,b
						// TODO: if (value_map_collission1) do_smothing
					"}"
				"}"
				, str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], nt_buffer[1]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, output_size, comp);
				
			sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx%s+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx%s])^a%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
							
							"uint bb=b%s-(0%s);"
							"d%s+=I(bb,a%s,c%s)+0x8f0ccc92;d%s=rotate(d%s,10u)+a%s;"
							"c%s+=I(a%s,d%s,bb)+0xffeff47d;c%s=rotate(c%s,15u)+d%s;"

							"if(d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u]){"
								"uint found=atomic_inc(output);"
								"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
									"output[2*found+2]=indx;}"
							"}"
						"}"
					"}"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				
				, str_comp[comp], nt_buffer[1]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, output_size, comp);

			sprintf(source + strlen(source),
				"if(fdata&2){"// Is unlucky
					"xx%s=a%s&%uu;"
					"fdata=(uint)(cbg_filter[xx%s]);"
					"if(((fdata^b%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
							
							"uint bb=b%s-(0%s);"
							"d%s+=I(bb,a%s,c%s)+0x8f0ccc92;d%s=rotate(d%s,10u)+a%s;"
							"c%s+=I(a%s,d%s,bb)+0xffeff47d;c%s=rotate(c%s,15u)+d%s;"

							"if(d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u]){"
								"uint found=atomic_inc(output);"
								"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
									"output[2*found+2]=indx;}"
							"}"
						"}"
					"}"
				, str_comp[comp], str_comp[comp], cbg_mask
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				
				, str_comp[comp], nt_buffer[1]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, output_size, comp);

			sprintf(source + strlen(source),
					"if(fdata&4){"// Is second
						"xx%s+=fdata&1?-1:1;"
						"if(((((uint)cbg_filter[xx%s])^b%s)&0xFFF8)==0){"
							"indx=cbg_table[xx%s];"
							"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
								
								"uint bb=b%s-(0%s);"
								"d%s+=I(bb,a%s,c%s)+0x8f0ccc92;d%s=rotate(d%s,10u)+a%s;"
								"c%s+=I(a%s,d%s,bb)+0xffeff47d;c%s=rotate(c%s,15u)+d%s;"

								"if(d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u]){"
									"uint found=atomic_inc(output);"
									"if(found<%uu){"
										"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
										"output[2*found+2]=indx;}"
								"}"
							"}"
						"}"
					"}"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				
				, str_comp[comp], nt_buffer[1]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, output_size, comp);
		}
	}
	else
	{
		sprintf(source + strlen(source),
		"d+=I(b,a,c)%s+0x8f0ccc92;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)+0xffeff47d;c=rotate(c,15u)+d;"
		"b+=I(d,c,a)%s+0x85845dd1;b=rotate(b,21u)+c;"

		"a+=I(c,b,d)+0x6fa87e4f;a=rotate(a,6u)+b;"
		"d+=I(b,a,c)+0xfe2ce6e0;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)%s+0xa3014314;c=rotate(c,15u)+d;"
		"b+=I(d,c,a)+0x4e0811a1;b=rotate(b,21u)+c;"
		"c+=0%s;"
		, nt_buffer[3], nt_buffer[1], nt_buffer[6], nt_buffer[2]);

		// Find match
		sprintf(source + strlen(source), "xx=c&%uu;uint fdata;", cbg_mask);

		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			sprintf(source + strlen(source),
				"fdata=(uint)(cbg_filter[xx%s]);"

				"if(((fdata^b%s)&0xFFF8)==0){"
					"indx=cbg_table[xx%s];"
					"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"

						"uint cc=c%s-(0%s);"
						"a%s+=I(cc,b%s,d%s)%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
						"d%s+=I(b%s,a%s,cc);"

						"if(d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"
							"uint found=atomic_inc(output);"
							"if(found<%uu){"
								"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
								"output[2*found+2]=indx;}"
						"}"
						// TODO: Reverse a,d to their last value for the unlikely case of 2 hashes with same c,b
						// TODO: if (value_map_collission1) do_smothing
					"}"
				"}"
				, str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, output_size, comp);
				
			sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx%s+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx%s])^b%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
							
							"uint cc=c%s-(0%s);"
							"a%s+=I(cc,b%s,d%s)%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
							"d%s+=I(b%s,a%s,cc);"

							"if(d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"
								"uint found=atomic_inc(output);"
								"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
									"output[2*found+2]=indx;}"
							"}"
						"}"
					"}"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				
				, str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, output_size, comp);

			sprintf(source + strlen(source),
				"if(fdata&2){"// Is unlucky
					"xx%s=b%s&%uu;"
					"fdata=(uint)(cbg_filter[xx%s]);"
					"if(((fdata^c%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
							
							"uint cc=c%s-(0%s);"
							"a%s+=I(cc,b%s,d%s)%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
							"d%s+=I(b%s,a%s,cc);"

							"if(d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"
								"uint found=atomic_inc(output);"
								"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
									"output[2*found+2]=indx;}"
							"}"
						"}"
					"}"
				, str_comp[comp], str_comp[comp], cbg_mask
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				
				, str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, output_size, comp);

			sprintf(source + strlen(source),
					"if(fdata&4){"// Is second
						"xx%s+=fdata&1?-1:1;"
						"if(((((uint)cbg_filter[xx%s])^c%s)&0xFFF8)==0){"
							"indx=cbg_table[xx%s];"
							"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
								
								"uint cc=c%s-(0%s);"
								"a%s+=I(cc,b%s,d%s)%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
								"d%s+=I(b%s,a%s,cc);"

								"if(d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"
									"uint found=atomic_inc(output);"
									"if(found<%uu){"
										"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
										"output[2*found+2]=indx;}"
								"}"
							"}"
						"}"
					"}"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				
				, str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, output_size, comp);
		}
	}

	strcat(source, "}}");
}

PRIVATE int ocl_protocol_charset_init(OpenCL_Param* result, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	int r = TRUE;
	if (num_passwords_loaded > 1 && (max_lenght <= 7 || (current_key_lenght == 8 && max_lenght == 8)))
	{
		uint32_t* old_cbg_table = cbg_table;
		uint16_t* old_cbg_filter = cbg_filter;
		uint32_t old_cbg_mask = cbg_mask;
		uint32_t old_cbg_count_moved = cbg_count_moved;
		uint32_t old_cbg_count_unlucky = cbg_count_unlucky;

		// Reverse last steps
		cl_uint* bin = (cl_uint*)binary_values;
		for (cl_uint current_index = 0; current_index < num_passwords_loaded; current_index++, bin += 4)
		{
			if (current_key_lenght == 8)
				// c += nt_buffer[2 * NT_NUM_KEYS + i];
				bin[2] -= 0x80;

			// d += (b ^ (a | ~c));
			bin[3] -= bin[1] ^ (bin[0] | ~bin[2]);
			// a += (c ^ (b | ~d)) + nt_buffer[4 * NT_NUM_KEYS + i] + 0xf7537e82; a = ROTATE(a, 6) + b;
			bin[0] = ROTATE(bin[0] - bin[1], 32 - 6);
			bin[0] -= (bin[2] ^ (bin[1] | ~bin[3])) + 0xf7537e82;

			// b += (d ^ (c | ~a)) + 0x4e0811a1; b = ROTATE(b, 21) + c;
			bin[1] = ROTATE(bin[1] - bin[2], 32 - 21);
			bin[1] -= (bin[3] ^ (bin[2] | ~bin[0])) + 0x4e0811a1;
			//c += (a ^ (d | ~b)) + nt_buffer[6*NT_NUM_KEYS+i] + 0xa3014314; c = ROTATE(c, 15) + d;
			bin[2] = ROTATE(bin[2] - bin[3], 32 - 15);
			bin[2] -= (bin[0] ^ (bin[3] | ~bin[1])) + 0xa3014314;
			//d += (b ^ (a | ~c))								 + 0xfe2ce6e0; d = ROTATE(d, 10) + a;
			bin[3] = ROTATE(bin[3] - bin[0], 32 - 10);
			bin[3] -= (bin[1] ^ (bin[0] | ~bin[2])) + 0xfe2ce6e0;
			//a += (c ^ (b | ~d))								 + 0x6fa87e4f; a = ROTATE(a, 6 ) + b;
			bin[0] = ROTATE(bin[0] - bin[1], 32 - 6);
			bin[0] -= (bin[2] ^ (bin[1] | ~bin[3])) + 0x6fa87e4f;

			//b += (d ^ (c | ~a)) + nt_buffer[1*NT_NUM_KEYS+i] + 0x85845dd1; b = ROTATE(b, 21) + c;
			bin[1] = ROTATE(bin[1] - bin[2], 32 - 21);
			bin[1] -= (bin[3] ^ (bin[2] | ~bin[0])) + 0x85845dd1;
		}
		// Initialize table map
		build_cbg_table(NTLM_INDEX, 1, 0);

		cl_bool has_unified_memory = gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY;
		GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_HAD_UNIFIED_MEMORY);

		cl_uint md5_empty_hash[] = { 0x5625a114, 0x561e0689, 0x392ad0d0, 0x3450f42b };
		r = ocl_charset_init(result, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_md5_header, ocl_gen_kernel_with_lenght, md5_empty_hash, FALSE, 2);

		// Change values back
		if (has_unified_memory)
			gpu_devices[gpu_index].flags |= GPU_FLAG_HAD_UNIFIED_MEMORY;
		
		bin = (cl_uint*)binary_values;
		// Reverse binary_values modification
		for (cl_uint current_index = 0; current_index < num_passwords_loaded; current_index++, bin += 4)
		{
			bin[1] += (bin[3] ^ (bin[2] | ~bin[0])) + 0x85845dd1; bin[1] = ROTATE(bin[1], 21) + bin[2];			
			bin[0] += (bin[2] ^ (bin[1] | ~bin[3])) + 0x6fa87e4f; bin[0] = ROTATE(bin[0],  6) + bin[1];
			bin[3] += (bin[1] ^ (bin[0] | ~bin[2])) + 0xfe2ce6e0; bin[3] = ROTATE(bin[3], 10) + bin[0];
			bin[2] += (bin[0] ^ (bin[3] | ~bin[1])) + 0xa3014314; bin[2] = ROTATE(bin[2], 15) + bin[3];

			bin[1] += (bin[3] ^ (bin[2] | ~bin[0])) + 0x4e0811a1; bin[1] = ROTATE(bin[1], 21) + bin[2];
			bin[0] += (bin[2] ^ (bin[1] | ~bin[3])) + 0xf7537e82; bin[0] = ROTATE(bin[0],  6) + bin[1];

			bin[3] += bin[1] ^ (bin[0] | ~bin[2]);
			if (current_key_lenght == 8)
				bin[2] += 0x80;
		}

		free(cbg_table);
		large_page_free(cbg_filter);

		cbg_table = old_cbg_table;
		cbg_filter = old_cbg_filter;
		cbg_mask = old_cbg_mask;
		cbg_count_moved = old_cbg_count_moved;
		cbg_count_unlucky = old_cbg_count_unlucky;
	}
	else
	{
		cl_uint md5_empty_hash[] = { 0x7246fad3, 0x30130182, 0x36594b14, 0xabc40035 };

		// TODO: Patch-> I am not sure why this is significant faster
		if (num_passwords_loaded == 1 && gpu_devices[gpu_index].vector_int_size == 1 && gpu_devices[gpu_index].vendor == OCL_VENDOR_AMD)
			gpu_devices[gpu_index].vector_int_size = 2;

		r = ocl_charset_init(result, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_md5_header, ocl_gen_kernel_with_lenght, md5_empty_hash, FALSE, 2);

		if (num_passwords_loaded == 1 && gpu_devices[gpu_index].vector_int_size == 2 && gpu_devices[gpu_index].vendor == OCL_VENDOR_AMD)
			gpu_devices[gpu_index].vector_int_size = 1;
	}

	return r;
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

	// MD% Function definition
	sprintf(source + strlen(source), "\n__kernel void %s(const __global uint* keys,__global uint* restrict output", kernel_name);

	if (num_passwords_loaded > 1)
		strcat(source, ",const __global uint* restrict cbg_table,const __global uint* restrict binary_values,const __global ushort* restrict cbg_filter");

	if (aditional_param)
	{
		sprintf(source + strlen(source), ",uint param");
		*aditional_param = num_passwords_loaded > 1 ? 5 : 2;
	}

	// Begin function code
	sprintf(source + strlen(source), "){uint indx=get_global_id(0);");

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
		"c+=I(a,d,b)%s+0xa3014314;c=rotate(c,15u)+d;"
		, nt_buffer[0], nt_buffer[7], nt_buffer[5], nt_buffer[3], nt_buffer[1], nt_buffer[6]);

	// Match
	char* str_comp[] = { ".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf" };
	if (vector_size == 1)str_comp[0] = "";

	if (num_passwords_loaded == 1)
	{
		sprintf(source + strlen(source), "c+=0%s;", nt_buffer[2]);

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
		sprintf(source + strlen(source),
		"b+=I(d,c,a)+0x4e0811a1;b=rotate(b,21u)+c;"
		"c+=0%s;", nt_buffer[2]);

		// Find match
		sprintf(source + strlen(source), "xx=c&%uu;uint fdata;", cbg_mask);

		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			if (found_param_3)
				sprintf(output_3, "output[3u*found+3u]=%s+%uu;", found_param_3, comp);

			sprintf(source + strlen(source),
				"fdata=(uint)(cbg_filter[xx%s]);"

				"if(((fdata^b%s)&0xFFF8)==0){"
					"indx=cbg_table[xx%s];"
					"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"

						"uint cc=c%s-(0%s);"
						"a%s+=I(cc,b%s,d%s)%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
						"d%s+=I(b%s,a%s,cc);"

						"if(d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"
							"uint found=atomic_inc(output);"
							"output[%iu*found+1u]=get_global_id(0);"
							"output[%iu*found+2u]=indx;"
							"%s"
						"}"
						// TODO: Reverse a,d to their last value for the unlikely case of 2 hashes with same c,b
						// TODO: if (value_map_collission1) do_smothing
					"}"
				"}"
				, str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, found_multiplier, found_multiplier, output_3);
				
			sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx%s+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx%s])^b%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
							
							"uint cc=c%s-(0%s);"
							"a%s+=I(cc,b%s,d%s)%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
							"d%s+=I(b%s,a%s,cc);"

							"if(d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"
								"uint found=atomic_inc(output);"
								"output[%iu*found+1u]=get_global_id(0);"
								"output[%iu*found+2u]=indx;"
								"%s"
							"}"
						"}"
					"}"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				
				, str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, found_multiplier, found_multiplier, output_3);

			sprintf(source + strlen(source),
				"if(fdata&2){"// Is unlucky
					"xx%s=b%s&%uu;"
					"fdata=(uint)(cbg_filter[xx%s]);"
					"if(((fdata^c%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
							
							"uint cc=c%s-(0%s);"
							"a%s+=I(cc,b%s,d%s)%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
							"d%s+=I(b%s,a%s,cc);"

							"if(d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"
								"uint found=atomic_inc(output);"
								"output[%iu*found+1u]=get_global_id(0);"
								"output[%iu*found+2u]=indx;"
								"%s"
							"}"
						"}"
					"}"
				, str_comp[comp], str_comp[comp], cbg_mask
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				
				, str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, found_multiplier, found_multiplier, output_3);

			sprintf(source + strlen(source),
					"if(fdata&4){"// Is second
						"xx%s+=fdata&1?-1:1;"
						"if(((((uint)cbg_filter[xx%s])^c%s)&0xFFF8)==0){"
							"indx=cbg_table[xx%s];"
							"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
								
								"uint cc=c%s-(0%s);"
								"a%s+=I(cc,b%s,d%s)%s+0xf7537e82;a%s=rotate(a%s,6u)+b%s;"
								"d%s+=I(b%s,a%s,cc);"

								"if(d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"
									"uint found=atomic_inc(output);"
									"output[%iu*found+1u]=get_global_id(0);"
									"output[%iu*found+2u]=indx;"
									"%s"
								"}"
							"}"
						"}"
					"}"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				
				, str_comp[comp], nt_buffer[2]
				, str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[4], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp]

				, str_comp[comp], str_comp[comp]
				, found_multiplier, found_multiplier, output_3);
		}
	}

	if (ocl_end)	ocl_end(source);
	// End of kernel
	strcat(source, "}");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
#ifdef __ANDROID__
	return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_md5_header, ocl_gen_kernel_md5, kernels2common + UTF8_INDEX_IN_KERNELS, 32, ocl_rule_simple_copy_utf8_le);
#else
	return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_md5_header, ocl_gen_kernel_md5, kernels2common + UTF8_INDEX_IN_KERNELS, 4/*consider 2 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
#endif
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
extern uint32_t num_words;

PRIVATE void ocl_load_phrase_utf8_le(char* source, cl_uint lenght, cl_uint size_new_word)
{
	// Define the kernel to process the keys from phrases into a "fast-to-use" format
	sprintf(source + strlen(source),
							"uint max_number=get_global_id(0);"
							"uint i,out_idx=0;");

	for (cl_uint i = 0; i < 7; i++)
		sprintf(source + strlen(source), "uint buffer%u=0;", i);

	DivisionParams div_param = get_div_params(num_words);
	for (cl_uint i = lenght - 1; i < lenght; i--)
	{
		sprintf(source + strlen(source), "max_number+=keys[%uu];", i + 1);
		// Perform division
		if (div_param.magic)sprintf(source + strlen(source), "i=mul_hi(max_number+%iu,%uu)>>%uu;", (int)div_param.sum_one, div_param.magic, div_param.shift);// Normal division
		else				sprintf(source + strlen(source), "i=max_number>>%uu;", div_param.shift);// Power of two division

		sprintf(source + strlen(source),
							"uint current_sentence%u=keys[%uu+max_number-i*%uu];"
							"max_number=i;"
							, i, MAX_KEY_LENGHT_SMALL + size_new_word/4, num_words);
	}
		
	sprintf(source + strlen(source),
							// First word----------------------------------------
							"uint word_pos_j=current_sentence0;"
							"uint len=word_pos_j>>27u;"
							"word_pos_j&=0x07ffffff;"

							"uint total_len=len;"
							"uint buffer=0;"
							"uint chars_in_buffer=0;"
							// Body part of the string to copy
							"for(i=0;i<len/4;i++)"
							"{"
								"uint qword_copy=keys[word_pos_j+i];"
								"REG_ASSIGN(out_idx,qword_copy);"
								"out_idx++;"
							"}"
							// Last part
							"len&=3u;"
							"if(len)"
							"{"
								"buffer=keys[word_pos_j+i];"
								"chars_in_buffer=len;"
							"}");
							// end of first word---------------------------------------------------
							// Common copy
	for (cl_uint i = 1; i < lenght; i++)
		sprintf(source + strlen(source),
							"word_pos_j=current_sentence%u;"
							"len=word_pos_j>>27u;"
							"word_pos_j&=0x07ffffff;"

							"if((total_len+len)<=27u)"
							"{"
								// Body part of the string to copy
								"for(i=0;i<len/4;i++)"
								"{"
									"uint qword_copy=keys[word_pos_j+i];"
									"buffer|=qword_copy<<(8u*chars_in_buffer);"
									"REG_ASSIGN(out_idx,buffer);"
									"out_idx++;"
									"buffer=chars_in_buffer?(qword_copy>>(8u*(4u-chars_in_buffer))):0;"
								"}"
								"total_len+=len;"
								// Last part of the string to copy
								"len&=3;"
								"if(len)"
								"{"
									"uint qword_copy=keys[word_pos_j+i];"
									"buffer|=qword_copy<<(8u*chars_in_buffer);"
									"chars_in_buffer+=len;"
									"if(chars_in_buffer>=4u)"
									"{"
										"REG_ASSIGN(out_idx,buffer);"
										"out_idx++;"
										"chars_in_buffer-=4u;"
										"buffer=chars_in_buffer?(qword_copy>>(8u*(len-chars_in_buffer))):0;"
									"}"
								"}"
							"}", i);

	sprintf(source + strlen(source),
						// Put padding
						"buffer|=0x80u<<(8u*chars_in_buffer);"
						"REG_ASSIGN(out_idx,buffer);"

						// Put length
						"total_len<<=3u;");
}
PRIVATE char* ocl_gen_kernel_phrases(char* kernel_name, cl_uint value_map_collission, GPUDevice* gpu, cl_uint ntlm_size_bit_table, cl_uint size_new_word)
{
	char* source = (char*)malloc(1024 * 16);

	ocl_write_md5_header(source, gpu, ntlm_size_bit_table);

	sprintf(source + strlen(source),
		"#define REG_ASSIGN(index,val) "

		"switch(index)"
		"{"
			"case 0: buffer0=val; break;"
			"case 1: buffer1=val; break;"
			"case 2: buffer2=val; break;"
			"case 3: buffer3=val; break;"
			"case 4: buffer4=val; break;"
			"case 5: buffer5=val; break;"
			"case 6: buffer6=val; break;"
		"}\n");

	// NTLM Function definition
	sprintf(source + strlen(source), "\n__kernel void %s(const __global uint* restrict keys,__global uint* restrict output", kernel_name);

	if (num_passwords_loaded > 1)
		strcat(source, ",const __global uint* restrict cbg_table,const __global uint* restrict binary_values,const __global ushort* restrict cbg_filter");

	// Begin function code
	sprintf(source + strlen(source), "){");

	// Convert the key into a nt_buffer
	ocl_load_phrase_utf8_le(source, max_lenght, size_new_word);

	sprintf(source + strlen(source), "uint a,b,c,d,xx;");

	/* Round 1 */
	sprintf(source + strlen(source),
		"a=0xd76aa477+buffer0;a=rotate(a,7u)+INIT_B;"
		"d=(INIT_C^(a&0x77777777))+buffer1+0xf8fa0bcc;d=rotate(d,12u)+a;"
		"c=bs(INIT_B,a,d)+buffer2+0xbcdb4dd9;c=rotate(c,17u)+d;"
		"b=bs(a,d,c)+buffer3+0xb18b7a77;b=rotate(b,22u)+c;"

		"a+=bs(d,c,b)+buffer4+0xf57c0faf;a=rotate(a,7u)+b;"
		"d+=bs(c,b,a)+buffer5+0x4787c62a;d=rotate(d,12u)+a;"
		"c+=bs(b,a,d)+buffer6+0xa8304613;c=rotate(c,17u)+d;"
		"b+=bs(a,d,c)+0xfd469501;b=rotate(b,22u)+c;"

		"a+=bs(d,c,b)+0x698098d8;a=rotate(a,7u)+b;"
		"d+=bs(c,b,a)+0x8b44f7af;d=rotate(d,12u)+a;"
		"c+=bs(b,a,d)+0xffff5bb1;c=rotate(c,17u)+d;"
		"b+=bs(a,d,c)+0x895cd7be;b=rotate(b,22u)+c;"

		"a+=bs(d,c,b)+0x6b901122;a=rotate(a,7u)+b;"
		"d+=bs(c,b,a)+0xfd987193;d=rotate(d,12u)+a;"
		"c+=bs(b,a,d)+total_len+0xa679438e;c=rotate(c,17u)+d;"
		"b+=bs(a,d,c)+0x49b40821;b=rotate(b,22u)+c;");

	/* Round 2 */
	sprintf(source + strlen(source),
		"a+=bs(c,b,d)+buffer1+0xf61e2562;a=rotate(a,5u)+b;"
		"d+=bs(b,a,c)+buffer6+0xc040b340;d=rotate(d,9u)+a;"
		"c+=bs(a,d,b)+0x265e5a51;c=rotate(c,14u)+d;"
		"b+=bs(d,c,a)+buffer0+0xe9b6c7aa;b=rotate(b,20u)+c;"

		"a+=bs(c,b,d)+buffer5+0xd62f105d;a=rotate(a,5u)+b;"
		"d+=bs(b,a,c)+0x02441453;d=rotate(d,9u)+a;"
		"c+=bs(a,d,b)+0xd8a1e681;c=rotate(c,14u)+d;"
		"b+=bs(d,c,a)+buffer4+0xe7d3fbc8;b=rotate(b,20u)+c;"

		"a+=bs(c,b,d)+0x21e1cde6;a=rotate(a,5u)+b;"
		"d+=bs(b,a,c)+total_len+0xc33707d6;d=rotate(d,9u)+a;"
		"c+=bs(a,d,b)+buffer3+0xf4d50d87;c=rotate(c,14u)+d;"
		"b+=bs(d,c,a)+0x455a14ed;b=rotate(b,20u)+c;"

		"a+=bs(c,b,d)+0xa9e3e905;a=rotate(a,5u)+b;"
		"d+=bs(b,a,c)+buffer2+0xfcefa3f8;d=rotate(d,9u)+a;"
		"c+=bs(a,d,b)+0x676f02d9;c=rotate(c,14u)+d;"
		"b+=bs(d,c,a)+0x8d2a4c8a;b=rotate(b,20u)+c;");

	/* Round 3 */
	sprintf(source + strlen(source),
		"xx=b^c;"
		"a+=(xx^d)+buffer5+0xfffa3942;a=rotate(a,4u)+b;"
		"d+=(a^xx)+0x8771f681;d=rotate(d,11u)+a;xx=d^a;"
		"c+=(xx^b)+0x6d9d6122;c=rotate(c,16u)+d;"
		"b+=(c^xx)+total_len+0xfde5380c;b=rotate(b,23u)+c;xx=b^c;"

		"a+=(xx^d)+buffer1+0xa4beea44;a=rotate(a,4u)+b;"
		"d+=(a^xx)+buffer4+0x4bdecfa9;d=rotate(d,11u)+a;xx=d^a;"
		"c+=(xx^b)+0xf6bb4b60;c=rotate(c,16u)+d;"
		"b+=(c^xx)+0xbebfbc70;b=rotate(b,23u)+c;xx=b^c;"

		"a+=(xx^d)+0x289b7ec6;a=rotate(a,4u)+b;"
		"d+=(a^xx)+buffer0+0xeaa127fa;d=rotate(d,11u)+a;xx=d^a;"
		"c+=(xx^b)+buffer3+0xd4ef3085;c=rotate(c,16u)+d;"
		"b+=(c^xx)+buffer6+0x04881d05;b=rotate(b,23u)+c;xx=b^c;"

		"a+=(xx^d)+0xd9d4d039;a=rotate(a,4u)+b;"
		"d+=(a^xx)+0xe6db99e5;d=rotate(d,11u)+a;xx=d^a;"
		"c+=(xx^b)+0x1fa27cf8;c=rotate(c,16u)+d;"
		"b+=(c^xx)+buffer2+0xc4ac5665;b=rotate(b,23u)+c;");

	/* Round 4 */
	sprintf(source + strlen(source),
		"a+=I(c,b,d)+buffer0+0xf4292244;a=rotate(a,6u)+b;"
		"d+=I(b,a,c)+0x432aff97;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)+total_len+0xab9423a7;c=rotate(c,15u)+d;"
		"b+=I(d,c,a)+buffer5+0xfc93a039;b=rotate(b,21u)+c;"

		"a+=I(c,b,d)+0x655b59c3;a=rotate(a,6u)+b;"
		"d+=I(b,a,c)+buffer3+0x8f0ccc92;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)+0xffeff47d;c=rotate(c,15u)+d;"
		"b+=I(d,c,a)+buffer1+0x85845dd1;b=rotate(b,21u)+c;"

		"a+=I(c,b,d)+0x6fa87e4f;a=rotate(a,6u)+b;"
		"d+=I(b,a,c)+0xfe2ce6e0;d=rotate(d,10u)+a;"
		"c+=I(a,d,b)+buffer6+0xa3014314;c=rotate(c,15u)+d;");

	// Match
	if (num_passwords_loaded == 1)
	{
		sprintf(source + strlen(source),
			"c+=buffer2;"

			"if(c==%uu)"
			"{"
				"c-=buffer2;"
				"b+=I(d,c,a)+0x4e0811a1;b=rotate(b,21u)+c;"
				"a+=I(c,b,d)+buffer4+0xf7537e82;a=rotate(a,6u)+b;"
				"d+=I(b,a,c);"
				"if(a==%uu&&b==%uu&&d==%uu)"
				"{"
					"output[0]=1;"
					"output[1]=get_global_id(0);"
					"output[2]=0;"
				"}"
			"}", ((cl_uint*)binary_values)[2], ((cl_uint*)binary_values)[0], ((cl_uint*)binary_values)[1], ((cl_uint*)binary_values)[3]);
	}
	else
	{
		sprintf(source + strlen(source),
			"b+=I(d,c,a)+0x4e0811a1;b=rotate(b,21u)+c;"
			"c+=buffer2;");

		// Find match
		sprintf(source + strlen(source), "xx=c&%uu;uint fdata, indx;", cbg_mask);

		sprintf(source + strlen(source),
			"fdata=(uint)(cbg_filter[xx]);"

			"if(((fdata^b)&0xFFF8)==0){"
				"indx=cbg_table[xx];"
				"if(indx!=0xffffffff&&b==binary_values[indx*4u+1u]&&c==binary_values[indx*4u+2u]){"

					"uint cc=c-buffer2;"
					"a+=I(cc,b,d)+buffer4+0xf7537e82;a=rotate(a,6u)+b;"
					"d+=I(b,a,cc);"

					"if(d==binary_values[indx*4u+3u]&&a==binary_values[indx*4u]){"
						"uint found=atomic_inc(output);"
						"output[2*found+1u]=get_global_id(0);"
						"output[2*found+2u]=indx;"
					"}"
					// TODO: Reverse a,d to their last value for the unlikely case of 2 hashes with same c,b
					// TODO: if (value_map_collission1) do_smothing
				"}"
			"}");
				
		sprintf(source + strlen(source),
			"if(fdata&4){"// Is second
				"xx+=fdata&1?-1:1;"
				"if(((((uint)cbg_filter[xx])^b)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&b==binary_values[indx*4u+1u]&&c==binary_values[indx*4u+2u]){"
							
						"uint cc=c-buffer2;"
						"a+=I(cc,b,d)+buffer4+0xf7537e82;a=rotate(a,6u)+b;"
						"d+=I(b,a,cc);"

						"if(d==binary_values[indx*4u+3u]&&a==binary_values[indx*4u]){"
							"uint found=atomic_inc(output);"
							"output[2*found+1u]=get_global_id(0);"
							"output[2*found+2u]=indx;"
						"}"
					"}"
				"}"
			"}");

		sprintf(source + strlen(source),
			"if(fdata&2){"// Is unlucky
				"xx=b&%uu;"
				"fdata=(uint)(cbg_filter[xx]);"
				"if(((fdata^c)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&b==binary_values[indx*4u+1u]&&c==binary_values[indx*4u+2u]){"
							
						"uint cc=c-buffer2;"
						"a+=I(cc,b,d)+buffer4+0xf7537e82;a=rotate(a,6u)+b;"
						"d+=I(b,a,cc);"

						"if(d==binary_values[indx*4u+3u]&&a==binary_values[indx*4u]){"
							"uint found=atomic_inc(output);"
							"output[2*found+1u]=get_global_id(0);"
							"output[2*found+2u]=indx;"
						"}"
					"}"
				"}", cbg_mask);

		sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx])^c)&0xFFF8)==0){"
						"indx=cbg_table[xx];"
						"if(indx!=0xffffffff&&b==binary_values[indx*4u+1u]&&c==binary_values[indx*4u+2u]){"
								
							"uint cc=c-buffer2;"
							"a+=I(cc,b,d)+buffer4+0xf7537e82;a=rotate(a,6u)+b;"
							"d+=I(b,a,cc);"

							"if(d==binary_values[indx*4u+3u]&&a==binary_values[indx*4u]){"
								"uint found=atomic_inc(output);"
								"output[2*found+1u]=get_global_id(0);"
								"output[2*found+2u]=indx;"
							"}"
						"}"
					"}"
				"}"
			"}");
	}

	// End of kernel
	strcat(source, "}");

	return source;
}

PRIVATE int ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	// Teoretical: 6.99G	Nvidia Geforce 970
	// Baseline  : 2.36G
	// Now------>: 3.33G
	return ocl_phrases_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_gen_kernel_phrases, 128);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	return ocl_rules_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_md5_header, ocl_gen_kernel_md5, RULE_UTF8_LE_INDEX, 1);
}
#endif

Format raw_md5_format = {
	"Raw-MD5",
	"Raw MD5 format.",
	"$dynamic_0$",
	NTLM_MAX_KEY_LENGHT,
	BINARY_SIZE,
	0,
	5,
	NULL,
	0,
	get_binary,
	binary2hex,
	VALUE_MAP_INDEX0,
	VALUE_MAP_INDEX1,
	is_valid,
	add_hash_from_line,
	NULL,
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