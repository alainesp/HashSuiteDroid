// This file is part of Hash Suite password cracker,
// Copyright (c) 2015-2016 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"
#include <memory.h>

//Initial values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476
#define INIT_E 0xC3D2E1F0

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

#define BINARY_SIZE				20
#define MAX_SALT_SIZE			16
#define SALT_SIZE				17
#define SSHA_SALT_SIZE_INDEX	16
#define NTLM_MAX_KEY_LENGHT		27

// This is MIME Base64 (as opposed to crypt(3) encoding found in common.[ch])
PRIVATE int lenght_mime_base64_string(const char *in, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		int char_is_valid = FALSE;

		if (in[i] >= 'A' && in[i] <= 'Z') char_is_valid = TRUE;
		if (in[i] >= 'a' && in[i] <= 'z') char_is_valid = TRUE;
		if (in[i] == '+') char_is_valid = TRUE;
		if (in[i] == '/') char_is_valid = TRUE;
		if (in[i] >= '0' && in[i] <= '9') char_is_valid = TRUE;

		if (!char_is_valid) break;
	}

	return i;
}

PRIVATE int is_valid(char* user_name, char* sha1, char* unused, char* unused1)
{
	if (user_name)
	{
		char* ssha = sha1 ? sha1 : user_name;

		if (!_strnicmp(ssha, "{SSHA}", 6))
		{
			int lenght = lenght_mime_base64_string(ssha + 6, (int)strlen(ssha + 6));
			if (lenght >= (BINARY_SIZE + 2) / 3 * 4 && lenght <= (BINARY_SIZE+MAX_SALT_SIZE+2)/3*4)
				return TRUE;
		}
	}

	return FALSE;
}

PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* user_name, char* sha1, char* unused, char* unused1)
{
	if (user_name)
	{
		char* ssha = sha1 ? sha1 : user_name;

		if (!_strnicmp(ssha, "{SSHA}", 6))
		{
			int lenght = lenght_mime_base64_string(ssha + 6, (int)strlen(ssha + 6));
			if (lenght >= (BINARY_SIZE + 2) / 3 * 4 && lenght <= (BINARY_SIZE + MAX_SALT_SIZE + 2) / 3 * 4)
			{
				if (sha1)
					return insert_hash_account1(param, user_name, sha1 + 6, SSHA_INDEX);
				else
					return insert_hash_account1(param, NULL, user_name + 6, SSHA_INDEX);
			}
		}
	}

	return -1;
}
PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	uint8_t binary_buffer[BINARY_SIZE + SALT_SIZE + 3];
	uint32_t* out = (uint32_t*)binary;

	// Decode data
	memset(binary_buffer, 0, sizeof(binary_buffer));
	int salt_len = base64_decode_mime(ciphertext, (int)strlen(ciphertext), binary_buffer) - BINARY_SIZE;
	// Copy binary
	memcpy(out, binary_buffer, BINARY_SIZE);
	swap_endianness_array(out, 5);
	// Copy salt
	memset(salt, 0, SALT_SIZE);
	memcpy(salt, binary_buffer + BINARY_SIZE, salt_len);
	((uint8_t*)salt)[salt_len] = 0x80;
	((uint8_t*)salt)[SSHA_SALT_SIZE_INDEX] = salt_len;
	swap_endianness_array(salt, salt_len/4+1);

	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;
	out[4] -= INIT_E;

	// C
	out[2] = ROTATE(out[2], 32-30);
	// A
	out[0] -= ROTATE(out[1], 5) + (out[2] ^ out[3] ^ out[4]) + 0xCA62C1D6;
	// D
	out[3] = ROTATE(out[3], 32-30);
	// B
	out[1] -= ROTATE(out[2], 5) + 0xCA62C1D6;
	//E
	out[4] = ROTATE(out[4], 32-30);

	return out[0];
}
PRIVATE void binary2hex(const void* binary, const uint8_t* salt, unsigned char* ciphertext)
{
	uint32_t bin[(BINARY_SIZE+SALT_SIZE) / sizeof(uint32_t) + 1];
	memset(bin, 0, sizeof(bin));
	memcpy(bin, binary, BINARY_SIZE);
	memcpy(bin + BINARY_SIZE / sizeof(uint32_t), salt, SALT_SIZE-1);

	uint32_t salt_size = salt[SSHA_SALT_SIZE_INDEX];
	
	//E
	bin[4]  = ROTATE(bin[4], 30);
	// B
	bin[1] += ROTATE(bin[2], 5) + 0xCA62C1D6;
	// D
	bin[3]  = ROTATE(bin[3], 30);
	// A
	bin[0] += ROTATE(bin[1], 5) + (bin[2] ^ bin[3] ^ bin[4]) + 0xCA62C1D6;
	// C
	bin[2]  = ROTATE(bin[2], 30);

	bin[0] += INIT_A;
	bin[1] += INIT_B;
	bin[2] += INIT_C;
	bin[3] += INIT_D;
	bin[4] += INIT_E;
	
	swap_endianness_array(bin, 5 + (salt_size/4 + 1));

	base64_encode_mime((const unsigned char*)bin, BINARY_SIZE + salt_size, (char*)ciphertext);
}

PRIVATE uint32_t max_salt_len;
PRIVATE uint32_t MAX_SIZE_SALT;
PRIVATE void optimize_hashes()
{
	// Find the max lenght
	max_salt_len = 0;
	unsigned char* salt_buffer = (unsigned char*)salts_values;
	for (uint32_t i = 0; i < num_diff_salts; i++, salt_buffer += SALT_SIZE)
	{
		uint32_t salt_len = salt_buffer[SSHA_SALT_SIZE_INDEX];
		if(max_salt_len < salt_len)
			max_salt_len = salt_len;
	}
	MAX_SIZE_SALT = (max_salt_len + 3) / 4 + 1;

	uint32_t* salt_by_len = (uint32_t*)_aligned_malloc(num_diff_salts*sizeof(uint32_t)*(MAX_SIZE_SALT*4+1), 4096);
	memset(salt_by_len, 0, num_diff_salts*sizeof(uint32_t)*(MAX_SIZE_SALT * 4 + 1));

	salt_buffer = (unsigned char*)salts_values;
	for (uint32_t i = 0; i < num_diff_salts; i++, salt_buffer += SALT_SIZE)
	{
		uint32_t salt_len = salt_buffer[SSHA_SALT_SIZE_INDEX];
		uint32_t* salt = (uint32_t*)salt_buffer;

		// Len = 0
		for (uint32_t j = 0; j < (salt_len / 4 + 1); j++)
			salt_by_len[MAX_SIZE_SALT*i+j] = salt[j];

		for (uint32_t len = 1, bits_shift=8; len < 4; len++, bits_shift+=8)
		{
			// Append salt
			uint32_t last_salt = 0;
			uint32_t j = 0;
			for (; j < (salt_len / 4 + 1); j++)
			{
				salt_by_len[MAX_SIZE_SALT*len*num_diff_salts+MAX_SIZE_SALT*i+j] = (salt[j] >> bits_shift) | last_salt;
				last_salt = salt[j] << (32 - bits_shift);
			}
			if (((salt_len&3)+len) >= 4)
				salt_by_len[MAX_SIZE_SALT*len*num_diff_salts+MAX_SIZE_SALT*i+j] = last_salt;
		}

		// Put salt len
		salt_by_len[MAX_SIZE_SALT*4*num_diff_salts + i] = salt_len;
	}

	_aligned_free(salts_values);
	salts_values = salt_by_len;
}

#ifdef HS_ARM
	#define NT_NUM_KEYS		    128
#endif

#ifdef HS_X86
	#define NT_NUM_KEYS		    256
#endif

typedef void ssha_kernel_asm_func(void* nt_buffer);
typedef uint32_t convert_big_endian_func(void* keys_buffer, uint32_t NUM_KEYS);
// Return the max lenght
PRIVATE uint32_t convert_big_endian_c_code(uint32_t* keys_buffer, uint32_t NUM_KEYS)
{
	// Find max_len
	uint32_t max_len = 0;
	for (uint32_t i = 7*NUM_KEYS; i < 8*NUM_KEYS; i++)
	{
		uint32_t len = keys_buffer[i] >> 3;
		if (max_len < len) max_len = len;
	}

	// Convert
	uint32_t len = (max_len/4 + 1) * NUM_KEYS;
	for (uint32_t i = 0; i < len; i++, keys_buffer++)
		*keys_buffer = _byteswap_ulong(*keys_buffer);

	return max_len;
}

#include "arch_simd.h"
#ifdef HS_X86
#define LOAD_BIG_ENDIAN_SSE2(x,data) x = SSE2_ROTATE(data, 16); x = SSE2_ADD(SSE2_SL(SSE2_AND(x, mask), 8), SSE2_AND(SSE2_SR(x, 8), mask));
PRIVATE uint32_t convert_big_endian_sse2(uint32_t* keys_buffer, uint32_t NUM_KEYS)
{
	// Find max_len
	uint32_t max_len = 0;
	for (uint32_t i = 7*NUM_KEYS; i < 8*NUM_KEYS; i++)
	{
		uint32_t len = keys_buffer[i] >> 3;
		if (max_len < len) max_len = len;
	}

	// Convert
	uint32_t len = (max_len/4 + 1) * NUM_KEYS/4;

	SSE2_WORD mask = SSE2_CONST(0x00FF00FF);
	SSE2_WORD* keys_buffer_sse2 = (SSE2_WORD*)keys_buffer;
	for (uint32_t i = 0; i < len; i++, keys_buffer_sse2++)
	{
		SSE2_WORD swap = _mm_load_si128(keys_buffer_sse2);
		LOAD_BIG_ENDIAN_SSE2(swap, swap);
		_mm_store_si128(keys_buffer_sse2, swap);
	}

	return max_len;
}
#endif
PRIVATE void copy_2_W(uint32_t* keys_buffer, uint32_t salt_index, uint32_t max_len)
{
	uint32_t* salt_by_len = (uint32_t*)salts_values;
	uint32_t salt_len = salt_by_len[MAX_SIZE_SALT*4*num_diff_salts+salt_index];
	salt_index *= MAX_SIZE_SALT;
	uint32_t pos_len_multiplier = MAX_SIZE_SALT*num_diff_salts;
	uint32_t* W = keys_buffer + 8 * NT_NUM_KEYS;
	// Copy and Clear W
	max_len /= 4;
	memcpy(W, keys_buffer, max_len * NT_NUM_KEYS * sizeof(uint32_t));
	memset(W + max_len*NT_NUM_KEYS, 0, (15-max_len) * NT_NUM_KEYS * sizeof(uint32_t));

	for (uint32_t i = 0; i < NT_NUM_KEYS; i++, W++, keys_buffer++)
	{
		// Copy to W
		uint32_t len = keys_buffer[7 * NT_NUM_KEYS] >> 3;
		uint32_t len3 = len & 3;
		uint32_t wj = len / 4 * NT_NUM_KEYS;

		// Append salt
		uint32_t j = len3*pos_len_multiplier + salt_index;
		uint32_t size_salt = (salt_len + len3) / 4 + 1 + j;
		if (len3)
		{
			uint32_t last_salt = keys_buffer[wj] & (0xffffffff << (32 - len3 * 8));// eliminate the last 0x80
			W[wj] = salt_by_len[j] | last_salt;

			wj += NT_NUM_KEYS;
			j++;
		}

		for (; j < size_salt; j++, wj += NT_NUM_KEYS)
			W[wj] = salt_by_len[j];

		W[15 * NT_NUM_KEYS] = (len + salt_len) << 3;
	}
}
PRIVATE void crypt_utf8_coalesc_protocol_body(CryptParam* param, ssha_kernel_asm_func* ssha_kernel_asm, convert_big_endian_func* convert_big_endian)
{
	uint32_t* nt_buffer = (uint32_t*)_aligned_malloc((8+16+2) * sizeof(uint32_t) * NT_NUM_KEYS, 32);

	uint32_t* unpacked_W  = nt_buffer  + 8 * NT_NUM_KEYS;
	uint32_t* unpacked_as = unpacked_W + 2 * NT_NUM_KEYS;
	uint32_t* unpacked_bs = unpacked_W + 4 * NT_NUM_KEYS;
	uint32_t* unpacked_cs = unpacked_W + 9 * NT_NUM_KEYS;
	uint32_t* unpacked_ds = unpacked_W + 16 * NT_NUM_KEYS;
	uint32_t* unpacked_es = unpacked_W + 17 * NT_NUM_KEYS;

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, 8 * sizeof(uint32_t)* NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while (continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		// Convert to big-endian
		uint32_t max_len = convert_big_endian(nt_buffer, NT_NUM_KEYS);

		// Hash: AVX2 raw SHA1: 49.6M
		//       AVX2 SSHA1   : 42.5M (17% slower)
		for (uint32_t j = 0; j < num_diff_salts; j++)
		{
			// Generate the initial W
			copy_2_W(nt_buffer, j, max_len);
			ssha_kernel_asm(nt_buffer);

			// All salts differents
			if (num_passwords_loaded == num_diff_salts)
			{
				uint32_t* bin = ((uint32_t*)binary_values) + j * 5;

				for (uint32_t i = 0; i < NT_NUM_KEYS; i++)
				{
					// Search for a match
					uint32_t aa = unpacked_as[i], bb, cc, dd, ee, W11, W15;
						
					if (aa != bin[0]) continue;
					// W: 0,1,3,5,6,7,8,10,11,12,13,14,15
					aa = ROTATE(aa - unpacked_W[15 * NT_NUM_KEYS + i], 32 - 30);
					cc = ROTATE(unpacked_cs[i], 30);
					W11 = ROTATE(unpacked_W[11 * NT_NUM_KEYS + i] ^ unpacked_W[8 * NT_NUM_KEYS + i] ^ unpacked_W[3 * NT_NUM_KEYS + i] ^ unpacked_W[13 * NT_NUM_KEYS + i], 1);
					ee = unpacked_es[i] + ROTATE(aa, 5) + (unpacked_bs[i] ^ cc ^ unpacked_ds[i]) + 0xCA62C1D6 + W11; bb = ROTATE(unpacked_bs[i], 30);
					if (ee != bin[4]) continue;

					dd = unpacked_ds[i] + ROTATE(ee, 5) + (aa ^ bb ^ cc) + 0xCA62C1D6 + unpacked_W[12 * NT_NUM_KEYS + i]; aa = ROTATE(aa, 30);
					if (dd != bin[3]) continue;

					W15 = ROTATE(unpacked_W[15 * NT_NUM_KEYS + i], 32 - 1); W15 ^= unpacked_W[12 * NT_NUM_KEYS + i] ^ unpacked_W[7 * NT_NUM_KEYS + i] ^ unpacked_W[1 * NT_NUM_KEYS + i];
					cc += ROTATE(dd, 5) + (ee ^ aa ^ bb) + 0xCA62C1D6 + ROTATE(unpacked_W[13 * NT_NUM_KEYS + i] ^ unpacked_W[10 * NT_NUM_KEYS + i] ^ unpacked_W[5 * NT_NUM_KEYS + i] ^ W15, 1); ee = ROTATE(ee, 30);
					if (cc != bin[2]) continue;

					bb += (dd ^ ee ^ aa) + ROTATE(unpacked_W[14 * NT_NUM_KEYS + i] ^ W11 ^ unpacked_W[6 * NT_NUM_KEYS + i] ^ unpacked_W[0 * NT_NUM_KEYS + i], 1);
					if (bb != bin[1]) continue;

					// Total match
					password_was_found(j, utf8_be_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));
				}
			}
			else
				for (uint32_t i = 0; i < NT_NUM_KEYS; i++)
				{
					// Search for a match
					uint32_t indx = salt_index[j];

					// Partial match
					while (indx != NO_ELEM)
					{
						uint32_t aa = unpacked_as[i], bb, cc, dd, ee, W11, W15;
						uint32_t* bin = ((uint32_t*)binary_values) + indx * 5;

						if (aa != bin[0]) goto next_iteration;
						// W: 0,1,3,5,6,7,8,10,11,12,13,14,15
						aa = ROTATE(aa - unpacked_W[15 * NT_NUM_KEYS + i], 32 - 30);
						cc = ROTATE(unpacked_cs[i], 30);
						W11 = ROTATE(unpacked_W[11 * NT_NUM_KEYS + i] ^ unpacked_W[8 * NT_NUM_KEYS + i] ^ unpacked_W[3 * NT_NUM_KEYS + i] ^ unpacked_W[13 * NT_NUM_KEYS + i], 1);
						ee = unpacked_es[i] + ROTATE(aa, 5) + (unpacked_bs[i] ^ cc ^ unpacked_ds[i]) + 0xCA62C1D6 + W11; bb = ROTATE(unpacked_bs[i], 30);
						if (ee != bin[4]) goto next_iteration;

						dd = unpacked_ds[i] + ROTATE(ee, 5) + (aa ^ bb ^ cc) + 0xCA62C1D6 + unpacked_W[12 * NT_NUM_KEYS + i]; aa = ROTATE(aa, 30);
						if (dd != bin[3]) goto next_iteration;

						W15 = ROTATE(unpacked_W[15 * NT_NUM_KEYS + i], 32 - 1); W15 ^= unpacked_W[12 * NT_NUM_KEYS + i] ^ unpacked_W[7 * NT_NUM_KEYS + i] ^ unpacked_W[1 * NT_NUM_KEYS + i];
						cc += ROTATE(dd, 5) + (ee ^ aa ^ bb) + 0xCA62C1D6 + ROTATE(unpacked_W[13 * NT_NUM_KEYS + i] ^ unpacked_W[10 * NT_NUM_KEYS + i] ^ unpacked_W[5 * NT_NUM_KEYS + i] ^ W15, 1); ee = ROTATE(ee, 30);
						if (cc != bin[2]) goto next_iteration;

						bb += (dd ^ ee ^ aa) + ROTATE(unpacked_W[14 * NT_NUM_KEYS + i] ^ W11 ^ unpacked_W[6 * NT_NUM_KEYS + i] ^ unpacked_W[0 * NT_NUM_KEYS + i], 1);
						if (bb != bin[1]) goto next_iteration;

						// Total match
						password_was_found(indx, utf8_be_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

					next_iteration:
						indx = same_salt_next[indx];
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
#define DCC2_R(w0, w1, w2, w3)	(W[w0*NT_NUM_KEYS] = ROTATE((W[w0*NT_NUM_KEYS] ^ W[w1*NT_NUM_KEYS] ^ W[w2*NT_NUM_KEYS] ^ W[w3*NT_NUM_KEYS]), 1))
PRIVATE void crypt_c_code_kernel(uint32_t* nt_buffer)
{
	uint32_t* W = nt_buffer + 8 * NT_NUM_KEYS;
	uint32_t A, B, C, D, E;

	for (uint32_t i = 0; i < NT_NUM_KEYS; i++, W++)
	{
		/* Round 1 */
		E = 0x9fb498b3 + W[0*NT_NUM_KEYS];
		D = ROTATE(E, 5) + 0x66b0cd0d + W[1*NT_NUM_KEYS];
		C = ROTATE(D, 5) + (0x7bf36ae2 ^ (E & 0x22222222)) + 0xf33d5697 + W[2*NT_NUM_KEYS]; E = ROTATE(E, 30);
		B = ROTATE(C, 5) + (0x59d148c0 ^ (D & (E ^ 0x59d148c0))) + 0xd675e47b + W[3*NT_NUM_KEYS]; D = ROTATE(D, 30);
		A = ROTATE(B, 5) + (E ^ (C & (D ^ E))) + 0xb453c259 + W[4*NT_NUM_KEYS ]; C = ROTATE(C, 30);

		E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[5*NT_NUM_KEYS ]; B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[6*NT_NUM_KEYS ]; A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[7*NT_NUM_KEYS ]; E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[8*NT_NUM_KEYS ]; D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[9*NT_NUM_KEYS ]; C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[10*NT_NUM_KEYS]; B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + W[11*NT_NUM_KEYS]; A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + W[12*NT_NUM_KEYS]; E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + W[13*NT_NUM_KEYS]; D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + W[14*NT_NUM_KEYS]; C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (D ^ (B & (C ^ D))) + SQRT_2 + W[15*NT_NUM_KEYS]; B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (C ^ (A & (B ^ C))) + SQRT_2 + DCC2_R(0, 13,  8, 2); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (B ^ (E & (A ^ B))) + SQRT_2 + DCC2_R(1, 14,  9, 3); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (A ^ (D & (E ^ A))) + SQRT_2 + DCC2_R(2, 15, 10, 4); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (E ^ (C & (D ^ E))) + SQRT_2 + DCC2_R(3,  0, 11, 5); C = ROTATE(C, 30);

		/* Round 2 */
		E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + DCC2_R( 4,  1, 12,  6); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + DCC2_R( 5,  2, 13,  7); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R( 6,  3, 14,  8); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R( 7,  4, 15,  9); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R( 8,  5,  0, 10); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + DCC2_R( 9,  6,  1, 11); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + DCC2_R(10,  7,  2, 12); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R(11,  8,  3, 13); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R(12,  9,  4, 14); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R(13, 10,  5, 15); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + DCC2_R(14, 11,  6,  0); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + DCC2_R(15, 12,  7,  1); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R(0 , 13,  8,  2); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R(1 , 14,  9,  3); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R(2 , 15, 10,  4); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + SQRT_3 + DCC2_R(3 ,  0, 11,  5); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + SQRT_3 + DCC2_R(4 ,  1, 12,  6); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + SQRT_3 + DCC2_R(5 ,  2, 13,  7); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + SQRT_3 + DCC2_R(6 ,  3, 14,  8); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + SQRT_3 + DCC2_R(7 ,  4, 15,  9); C = ROTATE(C, 30);

		/* Round 3 */
		E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R( 8, 5,  0, 10); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R( 9, 6,  1, 11); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(10, 7,  2, 12); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(11, 8,  3, 13); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(12, 9,  4, 14); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R(13, 10, 5, 15); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R(14, 11, 6,  0); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R(15, 12, 7,  1); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R( 0, 13, 8,  2); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R( 1, 14, 9,  3); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R( 2, 15, 10, 4); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R( 3, 0, 11,  5); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R( 4, 1, 12,  6); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R( 5, 2, 13,  7); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R( 6, 3, 14,  8); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + ((B & C) | (D & (B | C))) + 0x8F1BBCDC + DCC2_R( 7, 4, 15,  9); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + ((A & B) | (C & (A | B))) + 0x8F1BBCDC + DCC2_R( 8, 5,  0, 10); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + ((E & A) | (B & (E | A))) + 0x8F1BBCDC + DCC2_R( 9, 6,  1, 11); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + ((D & E) | (A & (D | E))) + 0x8F1BBCDC + DCC2_R(10, 7,  2, 12); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + ((C & D) | (E & (C | D))) + 0x8F1BBCDC + DCC2_R(11, 8,  3, 13); C = ROTATE(C, 30);

		/* Round 4 */
		E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R(12, 9, 4, 14); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(13,10, 5, 15); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R(14, 11, 6, 0); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R(15, 12, 7, 1); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R( 0, 13, 8, 2); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R( 1, 14, 9, 3); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R(2, 15, 10, 4); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R( 3, 0, 11, 5); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R( 4, 1, 12, 6); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R( 5, 2, 13, 7); C = ROTATE(C, 30);
		E += ROTATE(A, 5) + (B ^ C ^ D) + 0xCA62C1D6 + DCC2_R( 6, 3, 14, 8); B = ROTATE(B, 30);
		D += ROTATE(E, 5) + (A ^ B ^ C) + 0xCA62C1D6 + DCC2_R( 7, 4, 15, 9); A = ROTATE(A, 30);
		C += ROTATE(D, 5) + (E ^ A ^ B) + 0xCA62C1D6 + DCC2_R( 8, 5, 0, 10); E = ROTATE(E, 30);
		B += ROTATE(C, 5) + (D ^ E ^ A) + 0xCA62C1D6 + DCC2_R( 9, 6, 1, 11); D = ROTATE(D, 30);
		A += ROTATE(B, 5) + (C ^ D ^ E) + 0xCA62C1D6 + DCC2_R(10, 7, 2, 12); 
			
		DCC2_R(12, 9, 4, 14); A = ROTATE(A, 30) + DCC2_R(15, 12, 7, 1);

		// Save
		W[2  * NT_NUM_KEYS] = A;
		W[4  * NT_NUM_KEYS] = B;
		W[9  * NT_NUM_KEYS] = C;
		W[16 * NT_NUM_KEYS] = D;
		W[17 * NT_NUM_KEYS] = E;
	}
}
PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_c_code_kernel, convert_big_endian_c_code);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TODO: Neon code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM

//void crypt_ssha_neon_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_utf8_coalesc_protocol_neon(CryptParam* param)
{
	//crypt_utf8_coalesc_protocol_body(param, crypt_ssha_neon_kernel_asm, convert_big_endian_c_code);
	crypt_utf8_coalesc_protocol_body(param, crypt_c_code_kernel, convert_big_endian_c_code);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include "arch_simd.h"

#define SHA1_NUM		(NT_NUM_KEYS/4)
#undef DCC2_R
#define DCC2_R(w0, w1, w2, w3)	W[w0*SHA1_NUM] = SSE2_ROTATE(SSE2_4XOR(W[w0*SHA1_NUM], W[w1*SHA1_NUM], W[w2*SHA1_NUM], W[w3*SHA1_NUM]), 1)
PRIVATE void crypt_kernel_sse2(SSE2_WORD* nt_buffer)
{
	SSE2_WORD* W = nt_buffer + 8 * SHA1_NUM;
	SSE2_WORD step_const;
	for (uint32_t i = 0; i < SHA1_NUM; i++, W++)
	{
		/* Round 1 */
		SSE2_WORD E = SSE2_ADD(SSE2_CONST(0x9fb498b3), W[0*SHA1_NUM]);
		SSE2_WORD D = SSE2_3ADD(SSE2_ROTATE(E, 5), SSE2_CONST(0x66b0cd0d), W[1*SHA1_NUM]);
		SSE2_WORD C = SSE2_4ADD(SSE2_ROTATE(D, 5), SSE2_XOR(SSE2_CONST(0x7bf36ae2), SSE2_AND(E, SSE2_CONST(0x22222222))), SSE2_CONST(0xf33d5697), W[2*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		SSE2_WORD B = SSE2_4ADD(SSE2_ROTATE(C, 5), SSE2_XOR(SSE2_CONST(0x59d148c0), SSE2_AND(D, SSE2_XOR(E, SSE2_CONST(0x59d148c0)))), SSE2_CONST(0xd675e47b), W[3*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		SSE2_WORD A = SSE2_4ADD(SSE2_ROTATE(B, 5), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0xb453c259), W[4*SHA1_NUM]); C = SSE2_ROTATE(C, 30);

		step_const = _mm_set1_epi32(SQRT_2);
							   E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), step_const, W[5 *SHA1_NUM]); B = SSE2_ROTATE(B, 30);
							   D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), step_const, W[6 *SHA1_NUM]); A = SSE2_ROTATE(A, 30);
							   C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_XOR(B, SSE2_AND(E, SSE2_XOR(A, B))), step_const, W[7 *SHA1_NUM]); E = SSE2_ROTATE(E, 30);
							   B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_XOR(A, SSE2_AND(D, SSE2_XOR(E, A))), step_const, W[8 *SHA1_NUM]); D = SSE2_ROTATE(D, 30);
							   A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), step_const, W[9 *SHA1_NUM]); C = SSE2_ROTATE(C, 30);
							   E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), step_const, W[10*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
							   D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), step_const, W[11*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
							   C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_XOR(B, SSE2_AND(E, SSE2_XOR(A, B))), step_const, W[12*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
							   B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_XOR(A, SSE2_AND(D, SSE2_XOR(E, A))), step_const, W[13*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
							   A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), step_const, W[14*SHA1_NUM]); C = SSE2_ROTATE(C, 30);
							   E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), step_const, W[15*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R(0 , 13, 8,  2); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), step_const, W[0 *SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R(1 , 14, 9,  3); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_XOR(B, SSE2_AND(E, SSE2_XOR(A, B))), step_const, W[1 *SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R(2 , 15, 10, 4); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_XOR(A, SSE2_AND(D, SSE2_XOR(E, A))), step_const, W[2 *SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R(3 ,  0, 11, 5); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), step_const, W[3 *SHA1_NUM]); C = SSE2_ROTATE(C, 30);

		/* Round 2 */
		step_const = _mm_set1_epi32(SQRT_3);
		DCC2_R(4 ,  1, 12, 6); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[4 *SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R(5 ,  2, 13, 7); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[5 *SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R(6 ,  3, 14, 8); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[6 *SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R(7 ,  4, 15, 9); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[7 *SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R( 8, 5,  0, 10); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[8 *SHA1_NUM]); C = SSE2_ROTATE(C, 30);
		DCC2_R( 9, 6,  1, 11); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[9 *SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R(10, 7,  2, 12); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[10*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R(11, 8,  3, 13); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[11*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R(12, 9,  4, 14); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[12*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R(13, 10, 5, 15); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[13*SHA1_NUM]); C = SSE2_ROTATE(C, 30);
		DCC2_R(14, 11, 6,  0); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[14*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R(15, 12, 7,  1); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[15*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R(0 , 13, 8,  2); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[0 *SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R(1 , 14, 9,  3); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[1 *SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R(2 , 15, 10, 4); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[2 *SHA1_NUM]); C = SSE2_ROTATE(C, 30);
		DCC2_R(3 ,  0, 11, 5); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[3 *SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R(4 ,  1, 12, 6); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[4 *SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R(5 ,  2, 13, 7); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[5 *SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R(6 ,  3, 14, 8); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[6 *SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R(7 ,  4, 15, 9); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[7 *SHA1_NUM]); C = SSE2_ROTATE(C, 30);
										  
		/* Round 3 */
		step_const = _mm_set1_epi32(0x8F1BBCDC);
		DCC2_R( 8, 5,  0, 10); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))), step_const, W[ 8*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R( 9, 6,  1, 11); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))), step_const, W[ 9*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R(10, 7,  2, 12); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_OR(SSE2_AND(E, A), SSE2_AND(B, SSE2_OR(E, A))), step_const, W[10*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R(11, 8,  3, 13); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_OR(SSE2_AND(D, E), SSE2_AND(A, SSE2_OR(D, E))), step_const, W[11*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R(12, 9,  4, 14); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))), step_const, W[12*SHA1_NUM]); C = SSE2_ROTATE(C, 30);
		DCC2_R(13, 10, 5, 15); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))), step_const, W[13*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R(14, 11, 6,  0); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))), step_const, W[14*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R(15, 12, 7,  1); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_OR(SSE2_AND(E, A), SSE2_AND(B, SSE2_OR(E, A))), step_const, W[15*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R( 0, 13, 8,  2); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_OR(SSE2_AND(D, E), SSE2_AND(A, SSE2_OR(D, E))), step_const, W[ 0*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R( 1, 14, 9,  3); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))), step_const, W[ 1*SHA1_NUM]); C = SSE2_ROTATE(C, 30);
		DCC2_R( 2, 15, 10, 4); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))), step_const, W[ 2*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R( 3, 0, 11,  5); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))), step_const, W[ 3*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R( 4, 1, 12,  6); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_OR(SSE2_AND(E, A), SSE2_AND(B, SSE2_OR(E, A))), step_const, W[ 4*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R( 5, 2, 13,  7); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_OR(SSE2_AND(D, E), SSE2_AND(A, SSE2_OR(D, E))), step_const, W[ 5*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R( 6, 3, 14,  8); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))), step_const, W[ 6*SHA1_NUM]); C = SSE2_ROTATE(C, 30);
		DCC2_R( 7, 4, 15,  9); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))), step_const, W[ 7*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R( 8, 5,  0, 10); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))), step_const, W[ 8*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R( 9, 6,  1, 11); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_OR(SSE2_AND(E, A), SSE2_AND(B, SSE2_OR(E, A))), step_const, W[ 9*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R(10, 7,  2, 12); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_OR(SSE2_AND(D, E), SSE2_AND(A, SSE2_OR(D, E))), step_const, W[10*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R(11, 8,  3, 13); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))), step_const, W[11*SHA1_NUM]); C = SSE2_ROTATE(C, 30);
										  
		/* Round 4 */
		step_const = _mm_set1_epi32(0xCA62C1D6);
		DCC2_R(12, 9, 4, 14); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[12*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R(13,10, 5, 15); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[13*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R(14, 11, 6, 0); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[14*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R(15, 12, 7, 1); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[15*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R( 0, 13, 8, 2); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[ 0*SHA1_NUM]); C = SSE2_ROTATE(C, 30);
		DCC2_R( 1, 14, 9, 3); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[ 1*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R(2, 15, 10, 4); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[ 2*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R( 3, 0, 11, 5); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[ 3*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R( 4, 1, 12, 6); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[ 4*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R( 5, 2, 13, 7); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[ 5*SHA1_NUM]); C = SSE2_ROTATE(C, 30);
		DCC2_R( 6, 3, 14, 8); E = SSE2_5ADD(E, SSE2_ROTATE(A, 5), SSE2_3XOR(B, C, D), step_const, W[ 6*SHA1_NUM]); B = SSE2_ROTATE(B, 30);
		DCC2_R( 7, 4, 15, 9); D = SSE2_5ADD(D, SSE2_ROTATE(E, 5), SSE2_3XOR(A, B, C), step_const, W[ 7*SHA1_NUM]); A = SSE2_ROTATE(A, 30);
		DCC2_R( 8, 5, 0, 10); C = SSE2_5ADD(C, SSE2_ROTATE(D, 5), SSE2_3XOR(E, A, B), step_const, W[ 8*SHA1_NUM]); E = SSE2_ROTATE(E, 30);
		DCC2_R( 9, 6, 1, 11); B = SSE2_5ADD(B, SSE2_ROTATE(C, 5), SSE2_3XOR(D, E, A), step_const, W[ 9*SHA1_NUM]); D = SSE2_ROTATE(D, 30);
		DCC2_R(10, 7, 2, 12); A = SSE2_5ADD(A, SSE2_ROTATE(B, 5), SSE2_3XOR(C, D, E), step_const, W[10*SHA1_NUM]); 
			
		DCC2_R(12, 9, 4, 14); DCC2_R(15, 12, 7, 1); A = SSE2_ADD(SSE2_ROTATE(A, 30), W[15*SHA1_NUM]);

		// Save
		W[2  * SHA1_NUM] = A;
		W[4  * SHA1_NUM] = B;
		W[9  * SHA1_NUM] = C;
		W[16 * SHA1_NUM] = D;
		W[17 * SHA1_NUM] = E;
	}
}
PRIVATE void crypt_utf8_coalesc_protocol_sse2(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_kernel_sse2, convert_big_endian_sse2);
}
#endif
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void crypt_ssha_avx_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_utf8_coalesc_protocol_avx(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_ssha_avx_kernel_asm, convert_big_endian_sse2);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void crypt_ssha_avx2_kernel_asm(uint32_t* nt_buffer);

#include <immintrin.h>
PRIVATE uint32_t convert_big_endian_avx2(__m256i* keys_buffer, uint32_t NUM_KEYS)
{
	// Find max_len
	__m256i max_len_vec = _mm256_set1_epi32(0);
	for (uint32_t i = 7 * NUM_KEYS/8; i < 8 * NUM_KEYS/8; i++)
	{
		__m256i len = _mm256_srli_epi32(keys_buffer[i], 3);
		max_len_vec = _mm256_max_epu32(len, max_len_vec);
	}
	uint32_t max_len = 0;
	for (uint32_t i = 0; i < 8; i++)
		if (max_len_vec.m256i_u32[i] > max_len)
			max_len = max_len_vec.m256i_u32[i];

	// Convert
	uint32_t len = (max_len / 4 + 1) * NUM_KEYS / 8;
	__m256i BSWAP_MASK = _mm256_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
	for (uint32_t i = 0; i < len; i++, keys_buffer++)
		keys_buffer[0] = _mm256_shuffle_epi8(keys_buffer[0], BSWAP_MASK);

	return max_len;
}
PRIVATE void crypt_utf8_coalesc_protocol_avx2(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_ssha_avx2_kernel_asm, convert_big_endian_avx2);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_write_ssha_header(char* source, GPUDevice* gpu)
{
	source[0] = 0;
	// Header definitions
	if (num_passwords_loaded > 1)
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source + strlen(source), "#define bs(c,b,a) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
#ifdef USE_MAJ_SELECTOR
	switch (MAJ_SELECTOR)
	{
	case 0:
		sprintf(source + strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 1:
		sprintf(source + strlen(source), "#define MAJ(b,d,c) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 2:
		sprintf(source + strlen(source), "#define MAJ(c,b,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 3:
		sprintf(source + strlen(source), "#define MAJ(c,d,b) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 4:
		sprintf(source + strlen(source), "#define MAJ(d,b,c) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	case 5:
		sprintf(source + strlen(source), "#define MAJ(d,c,b) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		break;
	}
#else
	sprintf(source + strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
#endif
	
	// Initial values
	sprintf(source + strlen(source),
		"#define SQRT_2 0x5a827999\n"
		"#define SQRT_3 0x6ed9eba1\n"
		"#define CONST3 0x8F1BBCDC\n"
		"#define CONST4 0xCA62C1D6\n"
		"#define DCC2_R(w0,w1,w2,w3)	(W ## w0)=rotate((W ## w0)^(W ## w1)^(W ## w2)^(W ## w3),1U)\n");
}
PRIVATE void ocl_ssha_test_empty()
{
	uint32_t* nt_buffer = (uint32_t*)_aligned_malloc((8 + 16 + 2) * sizeof(uint32_t) * NT_NUM_KEYS, 32);

	uint32_t* unpacked_W = nt_buffer + 8 * NT_NUM_KEYS;
	uint32_t* unpacked_as = unpacked_W + 2 * NT_NUM_KEYS;
	uint32_t* unpacked_bs = unpacked_W + 4 * NT_NUM_KEYS;
	uint32_t* unpacked_cs = unpacked_W + 9 * NT_NUM_KEYS;
	uint32_t* unpacked_ds = unpacked_W + 16 * NT_NUM_KEYS;
	uint32_t* unpacked_es = unpacked_W + 17 * NT_NUM_KEYS;

	ssha_kernel_asm_func* ssha_kernel_asm;
#ifdef HS_ARM
	ssha_kernel_asm = crypt_c_code_kernel;//crypt_ssha_neon_kernel_asm;
#endif
#ifdef HS_X86
	#ifdef _M_X64
		if (current_cpu.capabilites[CPU_CAP_AVX2])
			ssha_kernel_asm = crypt_ssha_avx2_kernel_asm;
		else if (current_cpu.capabilites[CPU_CAP_AVX])
			ssha_kernel_asm = crypt_ssha_avx_kernel_asm;
		else if (current_cpu.capabilites[CPU_CAP_SSE2])
			ssha_kernel_asm = crypt_kernel_sse2;
	#else
		if (current_cpu.capabilites[CPU_CAP_SSE2])
			ssha_kernel_asm = crypt_kernel_sse2;
		else
			ssha_kernel_asm = crypt_c_code_kernel;
	#endif
#endif

	for (uint32_t salt_index_base = 0; salt_index_base < num_diff_salts; salt_index_base += NT_NUM_KEYS)
	{
		memset(unpacked_W, 0, 15 * NT_NUM_KEYS * sizeof(uint32_t));

		for (uint32_t j = salt_index_base; j < __min(NT_NUM_KEYS, num_diff_salts - salt_index_base); j++)
		{
			// Generate the initial W
			uint32_t* salt_by_len = (uint32_t*)salts_values;
			uint32_t salt_len = salt_by_len[MAX_SIZE_SALT * 4 * num_diff_salts + j];

			for (uint32_t i = 0; i < (salt_len / 4 + 1); i++)
				unpacked_W[i*NT_NUM_KEYS + j] = salt_by_len[MAX_SIZE_SALT*j + i];

			unpacked_W[15 * NT_NUM_KEYS + j] = salt_len << 3;
		}

		ssha_kernel_asm(nt_buffer);

		for (uint32_t i = 0; i < __min(NT_NUM_KEYS, num_diff_salts - salt_index_base); i++)
		{
			// Search for a match
			uint32_t indx = salt_index[salt_index_base+i];

			// Partial match
			while (indx != NO_ELEM)
			{
				uint32_t aa = unpacked_as[i], bb, cc, dd, ee, W11, W15;
				uint32_t* bin = ((uint32_t*)binary_values) + indx * 5;

				if (aa != bin[0]) goto next_iteration;
				// W: 0,1,3,5,6,7,8,10,11,12,13,14,15
				aa = ROTATE(aa - unpacked_W[15 * NT_NUM_KEYS + i], 32 - 30);
				cc = ROTATE(unpacked_cs[i], 30);
				W11 = ROTATE(unpacked_W[11 * NT_NUM_KEYS + i] ^ unpacked_W[8 * NT_NUM_KEYS + i] ^ unpacked_W[3 * NT_NUM_KEYS + i] ^ unpacked_W[13 * NT_NUM_KEYS + i], 1);
				ee = unpacked_es[i] + ROTATE(aa, 5) + (unpacked_bs[i] ^ cc ^ unpacked_ds[i]) + 0xCA62C1D6 + W11; bb = ROTATE(unpacked_bs[i], 30);
				if (ee != bin[4]) goto next_iteration;

				dd = unpacked_ds[i] + ROTATE(ee, 5) + (aa ^ bb ^ cc) + 0xCA62C1D6 + unpacked_W[12 * NT_NUM_KEYS + i]; aa = ROTATE(aa, 30);
				if (dd != bin[3]) goto next_iteration;

				W15 = ROTATE(unpacked_W[15 * NT_NUM_KEYS + i], 32 - 1); W15 ^= unpacked_W[12 * NT_NUM_KEYS + i] ^ unpacked_W[7 * NT_NUM_KEYS + i] ^ unpacked_W[1 * NT_NUM_KEYS + i];
				cc += ROTATE(dd, 5) + (ee ^ aa ^ bb) + 0xCA62C1D6 + ROTATE(unpacked_W[13 * NT_NUM_KEYS + i] ^ unpacked_W[10 * NT_NUM_KEYS + i] ^ unpacked_W[5 * NT_NUM_KEYS + i] ^ W15, 1); ee = ROTATE(ee, 30);
				if (cc != bin[2]) goto next_iteration;

				bb += (dd ^ ee ^ aa) + ROTATE(unpacked_W[14 * NT_NUM_KEYS + i] ^ W11 ^ unpacked_W[6 * NT_NUM_KEYS + i] ^ unpacked_W[0 * NT_NUM_KEYS + i], 1);
				if (bb != bin[1]) goto next_iteration;

				// Total match
				password_was_found(indx, "");

			next_iteration:
				indx = same_salt_next[indx];
			}
		}
	}

	_aligned_free(nt_buffer);
}
PRIVATE void ocl_gen_kernel_with_lenght_less_reg(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint output_size, DivisionParams div_param)
{
	char* nt_buffer[] = { "+nt_buffer0", "+nt_buffer1", "+nt_buffer2", "+nt_buffer3", "+nt_buffer4", "+nt_buffer5", "+nt_buffer6" };

	ocl_charset_load_buffer_be(source, key_lenght, &vector_size, div_param, nt_buffer);

	sprintf(source + strlen(source), "uint A,B,C,D,E,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");
	// Generate less repeated keys
	uint64_t max_work_item_index = num_diff_salts;
	int is_max_work_item_index_needed = TRUE;
	for (cl_uint i = 1; i < key_lenght; i++)
	{
		max_work_item_index *= num_char_in_charset;
		if (max_work_item_index > UINT32_MAX)
		{
			is_max_work_item_index_needed = FALSE;
			break;
		}
	}
	if (is_max_work_item_index_needed)// Only 'CALCULATED' work-items
		sprintf(source + strlen(source), "if(get_global_id(0)>=%uu) return;", (uint32_t)max_work_item_index);

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "nt_buffer0+=%uu;", is_charset_consecutive(charset) << 24u);

	// Eliminate the last 0x80
	if (key_lenght & 3)
		sprintf(source + strlen(source), "%s&=%uu;", nt_buffer[key_lenght / 4] + 1, (cl_uint)(0xffffffff << (32 - (key_lenght & 3) * 8)));

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(uint i=0;i<%uu;i++){", num_char_in_charset);

	// Fill Ws registers
	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "W0=nt_buffer0+(i<<24u);");
	else
		sprintf(source + strlen(source), "W0=nt_buffer0+(((uint)charset[i])<<24u);");

	nt_buffer[0] = "+W0";
	cl_uint i = 0;
	for (; i < key_lenght/4; i++)
		sprintf(source + strlen(source), "W%u=0%s;", i, nt_buffer[i]);

	// Union key - salt
	if (num_diff_salts == 1)
	{
		cl_uint salt_part_index = 0;
		if (key_lenght & 3)
		{
			sprintf(source + strlen(source), "W%u=%s|%uu;", i, nt_buffer[i] + 1, ((uint32_t*)salts_values)[(key_lenght & 3)*MAX_SIZE_SALT*num_diff_salts]);
			i++;
			salt_part_index++;
		}
		// Rest salt
		for (; salt_part_index < ((max_salt_len + (key_lenght & 3)) / 4 + 1); i++, salt_part_index++)
			sprintf(source + strlen(source), "W%u=%uu;", i, ((uint32_t*)salts_values)[(key_lenght & 3)*MAX_SIZE_SALT*num_diff_salts + salt_part_index]);
		// Zero values
		for (; i < 15; i++)
			sprintf(source + strlen(source), "W%u=0;", i);
		// Lenght
		sprintf(source + strlen(source), "W15=%uu;", (key_lenght + ((uint32_t*)salts_values)[MAX_SIZE_SALT * 4 * num_diff_salts]) << 3);
	}
	else
	{
		cl_uint salt_part_index = 0;
		if (key_lenght & 3)
		{
			sprintf(source + strlen(source), "W%u=%s|salt_values[%uu+salt_index*%uu];", i, nt_buffer[i] + 1, (key_lenght & 3)*MAX_SIZE_SALT*num_diff_salts, MAX_SIZE_SALT);
			i++;
			salt_part_index++;
		}
		// Rest salt
		for (; salt_part_index < ((max_salt_len + (key_lenght & 3)) / 4 + 1); i++, salt_part_index++)
			sprintf(source + strlen(source), "W%u=salt_values[%uu+salt_index*%uu];", i, (key_lenght & 3)*MAX_SIZE_SALT*num_diff_salts + salt_part_index, MAX_SIZE_SALT);
		// Zero values
		for (; i < 15; i++)
			sprintf(source + strlen(source), "W%u=0;", i);
		// Lenght
		sprintf(source + strlen(source), "W15=%uu+(salt_values[%uu+salt_index]<<3u);", key_lenght << 3, MAX_SIZE_SALT * 4 * num_diff_salts);
	}

	/* Round 1 */
	sprintf(source + strlen(source),
		"E=0x9fb498b3+W0;"
		"D=rotate(E,5u)+0x66b0cd0d+W1;"
		"C=rotate(D,5u)+(0x7bf36ae2^(E&0x22222222))+0xf33d5697+W2;E=rotate(E,30u);"
		"B=rotate(C,5u)+(0x59d148c0^(D&(E^0x59d148c0)))+0xd675e47b+W3;D=rotate(D,30u);"
		"A=rotate(B,5u)+bs(E,D,C)+0xb453c259+W4;C=rotate(C,30u);"

		"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W5;B=rotate(B,30u);"
		"D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W6;A=rotate(A,30u);"
		"C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W7;E=rotate(E,30u);"
		"B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W8;D=rotate(D,30u);"
		"A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W9;C=rotate(C,30u);"
		"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W10;B=rotate(B,30u);"
		"D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W11;A=rotate(A,30u);"
		"C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W12;E=rotate(E,30u);"
		"B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W13;D=rotate(D,30u);"
		"A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W14;C=rotate(C,30u);"
		"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W15;B=rotate(B,30u);");

	
	/* Round 2 */
	sprintf(source + strlen(source),
		"DCC2_R(0,13,8,2);D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W0;A=rotate(A,30u);"
		"DCC2_R(1,14,9,3);C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W1;E=rotate(E,30u);"
		"DCC2_R(2,15,10,4);B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W2;D=rotate(D,30u);"
		"DCC2_R(3,0,11,5);A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W3;C=rotate(C,30u);"

		"DCC2_R(4,1,12,6);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W4;B=rotate(B,30u);"
		"DCC2_R(5,2,13,7);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W5;A=rotate(A,30u);"
		"DCC2_R(6,3,14,8);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W6;E=rotate(E,30u);"
		"DCC2_R(7,4,15,9);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W7;D=rotate(D,30u);"
		"DCC2_R(8,5,0,10);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W8;C=rotate(C,30u);"
		"DCC2_R(9,6,1,11);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W9;B=rotate(B,30u);"
		"DCC2_R(10,7,2,12);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W10;A=rotate(A,30u);"
		"DCC2_R(11,8,3,13);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W11;E=rotate(E,30u);"
		"DCC2_R(12,9,4,14);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W12;D=rotate(D,30u);"
		"DCC2_R(13,10,5,15);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W13;C=rotate(C,30u);"
		"DCC2_R(14,11,6,0);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W14;B=rotate(B,30u);"
		"DCC2_R(15,12,7,1);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W15;A=rotate(A,30u);"
		"DCC2_R(0,13,8,2);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W0;E=rotate(E,30u);"
		"DCC2_R(1,14,9,3);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W1;D=rotate(D,30u);"
		"DCC2_R(2,15,10,4);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W2;C=rotate(C,30u);"
		"DCC2_R(3,0,11,5);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W3;B=rotate(B,30u);"
		"DCC2_R(4,1,12,6);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W4;A=rotate(A,30u);"
		"DCC2_R(5,2,13,7);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W5;E=rotate(E,30u);"
		"DCC2_R(6,3,14,8);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W6;D=rotate(D,30u);"
		"DCC2_R(7,4,15,9);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W7;C=rotate(C,30u);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"DCC2_R(8,5,0,10);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W8;B=rotate(B,30u);"
		"DCC2_R(9,6,1,11);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W9;A=rotate(A,30u);"
		"DCC2_R(10,7,2,12);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W10;E=rotate(E,30u);"
		"DCC2_R(11,8,3,13);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W11;D=rotate(D,30u);"
		"DCC2_R(12,9,4,14);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W12;C=rotate(C,30u);"
		"DCC2_R(13,10,5,15);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W13;B=rotate(B,30u);"
		"DCC2_R(14,11,6,0);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W14;A=rotate(A,30u);"
		"DCC2_R(15,12,7,1);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W15;E=rotate(E,30u);"
		"DCC2_R(0,13,8,2);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W0;D=rotate(D,30u);"
		"DCC2_R(1,14,9,3);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W1;C=rotate(C,30u);"
		"DCC2_R(2,15,10,4);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W2;B=rotate(B,30u);"
		"DCC2_R(3,0,11,5);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W3;A=rotate(A,30u);"
		"DCC2_R(4,1,12,6);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W4;E=rotate(E,30u);"
		"DCC2_R(5,2,13,7);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W5;D=rotate(D,30u);"
		"DCC2_R(6,3,14,8);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W6;C=rotate(C,30u);"
		"DCC2_R(7,4,15,9);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W7;B=rotate(B,30u);"
		"DCC2_R(8,5,0,10);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W8;A=rotate(A,30u);"
		"DCC2_R(9,6,1,11);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W9;E=rotate(E,30u);"
		"DCC2_R(10,7,2,12);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W10;D=rotate(D,30u);"
		"DCC2_R(11,8,3,13);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W11;C=rotate(C,30u);");

	/* Round 4 */
	sprintf(source + strlen(source),
		"DCC2_R(12,9,4,14);E+=rotate(A,5u)+(B^C^D)+CONST4+W12;B=rotate(B,30u);"
		"DCC2_R(13,10,5,15);D+=rotate(E,5u)+(A^B^C)+CONST4+W13;A=rotate(A,30u);"
		"DCC2_R(14,11,6,0);C+=rotate(D,5u)+(E^A^B)+CONST4+W14;E=rotate(E,30u);"
		"DCC2_R(15,12,7,1);B+=rotate(C,5u)+(D^E^A)+CONST4+W15;D=rotate(D,30u);"
		"DCC2_R(0,13,8,2);A+=rotate(B,5u)+(C^D^E)+CONST4+W0;C=rotate(C,30u);"
		"DCC2_R(1,14,9,3);E+=rotate(A,5u)+(B^C^D)+CONST4+W1;B=rotate(B,30u);"
		"DCC2_R(2,15,10,4);D+=rotate(E,5u)+(A^B^C)+CONST4+W2;A=rotate(A,30u);"
		"DCC2_R(3,0,11,5);C+=rotate(D,5u)+(E^A^B)+CONST4+W3;E=rotate(E,30u);"
		"DCC2_R(4,1,12,6);B+=rotate(C,5u)+(D^E^A)+CONST4+W4;D=rotate(D,30u);"
		"DCC2_R(5,2,13,7);A+=rotate(B,5u)+(C^D^E)+CONST4+W5;C=rotate(C,30u);"
		"DCC2_R(6,3,14,8);E+=rotate(A,5u)+(B^C^D)+CONST4+W6;B=rotate(B,30u);"
		"DCC2_R(7,4,15,9);D+=rotate(E,5u)+(A^B^C)+CONST4+W7;A=rotate(A,30u);"
		"DCC2_R(8,5,0,10);C+=rotate(D,5u)+(E^A^B)+CONST4+W8;E=rotate(E,30u);"
		"DCC2_R(9,6,1,11);B+=rotate(C,5u)+(D^E^A)+CONST4+W9;D=rotate(D,30u);"
		"DCC2_R(10,7,2,12);A+=rotate(B,5u)+(C^D^E)+CONST4+W10;"

		"DCC2_R(12,9,4,14);DCC2_R(15,12,7,1);A=rotate(A,30u)+W15;");

	// Find match
	if (num_passwords_loaded == 1)
	{
		cl_uint* bin = (cl_uint*)binary_values;
		sprintf(source + strlen(source),
				"if(A==%uu)"
				"{"
					"A=rotate(A-W15,2u);"
					"C=rotate(C,30u);"
					"W11=rotate(W11^W8^W3^W13,1u);"
					"E+=rotate(A,5u)+(B^C^D)+CONST4+W11;B=rotate(B,30u);"

					"D+=rotate(E,5u)+(A^B^C)+CONST4+W12;A=rotate(A,30u);"

					"W15=rotate(W15,31u);W15^=W12^W7^W1;"
					"C+=rotate(D,5u)+(E^A^B)+CONST4+rotate(W13^W10^W5^W15,1u);"

					"B+=(D^rotate(E,30u)^A)+rotate(W14^W11^W6^W0,1u);"

					"if(B==%uu&&C==%uu&&D==%uu&&E==%uu)"
					"{"
						"output[0]=1u;"
						"output[1]=key_index*NUM_CHAR_IN_CHARSET+i;"
						"output[2]=0;"
					"}"
				"}"
				, bin[0], bin[1], bin[2], bin[3], bin[4]);
	}
	else
	{
		if (num_diff_salts < num_passwords_loaded)
		{
			sprintf(source + strlen(source),
			// Search for a match 
			"indx=salt_indexs[salt_index];"
			
			"while(indx!=0xffffffff)"
			"{"
				"if(A==binary_values[indx])"
				"{"
					"uint aa=rotate(A-W15,2u);"
					"uint cc=rotate(C,30u);"
					"uint ww11=rotate(W11^W8^W3^W13,1u);"
					"uint ee=E+rotate(aa,5u)+(B^cc^D)+CONST4+ww11;uint bb=rotate(B,30u);"

					"uint dd=D+rotate(ee,5u)+(aa^bb^cc)+CONST4+W12;aa=rotate(aa,30u);"

					"uint ww15=rotate(W15,31u);ww15^=W12^W7^W1;"
					"cc+=rotate(dd,5u)+(ee^aa^bb)+CONST4+rotate(W13^W10^W5^ww15,1u);"

					"bb+=(dd^rotate(ee,30u)^aa)+rotate(W14^ww11^W6^W0,1u);"

					"if(bb==binary_values[indx+%uu]&&cc==binary_values[indx+%uu]&&dd==binary_values[indx+%uu]&&ee==binary_values[indx+%uu])"
					"{"
						"uint found=atomic_inc(output);"
						"if(found<%uu){"
							"output[2*found+1]=key_index*NUM_CHAR_IN_CHARSET+i;"
							"output[2*found+2]=indx;}"
					"}", num_passwords_loaded, 2*num_passwords_loaded, 3*num_passwords_loaded, 4*num_passwords_loaded, output_size);

strcat(source, "}"
				"indx=same_salt_next[indx];"
			"}");
		}
		else
		{
			sprintf(source + strlen(source),
				// Search for a match
				"indx=salt_index;"
				"if(A==binary_values[indx])"
				"{"
					"uint aa=rotate(A-W15,2u);"
					"uint cc=rotate(C,30u);"
					"uint ww11=rotate(W11^W8^W3^W13,1u);"
					"uint ee=E+rotate(aa,5u)+(B^cc^D)+CONST4+ww11;uint bb=rotate(B,30u);"

					"uint dd=D+rotate(ee,5u)+(aa^bb^cc)+CONST4+W12;aa=rotate(aa,30u);"

					"uint ww15=rotate(W15,31u);ww15^=W12^W7^W1;"
					"cc+=rotate(dd,5u)+(ee^aa^bb)+CONST4+rotate(W13^W10^W5^ww15,1u);"

					"bb+=(dd^rotate(ee,30u)^aa)+rotate(W14^ww11^W6^W0,1u);"

					"if(bb==binary_values[indx+%uu]&&cc==binary_values[indx+%uu]&&dd==binary_values[indx+%uu]&&ee==binary_values[indx+%uu])"
					"{"
						"uint found=atomic_inc(output);"
						"if(found<%uu){"
						"output[2*found+1]=key_index*NUM_CHAR_IN_CHARSET+i;"
						"output[2*found+2]=indx;}"
					"}"
				"}", num_passwords_loaded, 2 * num_passwords_loaded, 3 * num_passwords_loaded, 4 * num_passwords_loaded, output_size);
		}
	}

	strcat(source, "}}");
}
PRIVATE char* ocl_gen_charset_code(GPUDevice* gpu, cl_uint output_size)
{
	DivisionParams div_param = get_div_params(num_char_in_charset);
	char* source = (char*)malloc(1024 * 32 * __max(1, max_lenght + 1 - current_key_lenght));
	// Header
	ocl_write_ssha_header(source, gpu);

	sprintf(source + strlen(source), "\n#define NUM_CHAR_IN_CHARSET %uu\n", num_char_in_charset);

	strcat(source, "__constant uchar charset[]={");
	// Fill charset
	for (cl_uint i = 0; i < num_char_in_charset; i++)
		sprintf(source + strlen(source), "%s%uU", i ? "," : "", (cl_uint)charset[i]);
	strcat(source, "};\n");

	// By lenght
	for (cl_uint i = current_key_lenght; i < (max_lenght + 1); i++)
	{
		// Function definition
		sprintf(source + strlen(source), "\n__kernel void crypt%u(", i);

		cl_uint bits_by_char;
		cl_uint num_param_regs = get_number_of_32regs(num_char_in_charset, i - 1, &bits_by_char);

		for (cl_uint i = 0; i < num_param_regs; i++)
			sprintf(source + strlen(source), "uint current_key%u,", i);

		sprintf(source + strlen(source), "__global uint* restrict output,uint offset");

		if (num_passwords_loaded > 1)
		{
			strcat(source, ",const __global uint* restrict binary_values");

			if (num_diff_salts > 1)
				strcat(source, ",const __global uint* restrict salt_values");

			if (num_diff_salts < num_passwords_loaded)
				strcat(source, ",const __global uint* restrict salt_indexs,const __global uint* restrict same_salt_next");
		}
		// Begin function code
		sprintf(source + strlen(source), "){"
			"uint max_number=offset+get_global_id(0);");

		if (num_diff_salts > 1)
		{
			DivisionParams div_param = get_div_params(num_diff_salts);
			// Perform division
			if (div_param.magic)sprintf(source + strlen(source), "uint key_index=mul_hi(max_number+%iu,%uu)>>%uu;", (int)div_param.sum_one, div_param.magic, div_param.shift);// Normal division
			else				sprintf(source + strlen(source), "uint key_index=max_number>>%uu;", div_param.shift);// Power of two division

			sprintf(source + strlen(source), "uint salt_index=max_number-key_index*%uu; max_number=key_index;", num_diff_salts);
		}
		else
			sprintf(source + strlen(source), "uint key_index=max_number;");

		ocl_gen_kernel_with_lenght_less_reg(source + strlen(source), i, 1, output_size, div_param);
	}

	return source;
}
PRIVATE void ocl_protocol_charset_work(OpenCL_Param* param)
{
	cl_uchar buffer[MAX_KEY_LENGHT_SMALL + 2 * sizeof(cl_uint)];
	cl_uint num_found = 0;
	int is_consecutive = is_charset_consecutive(charset);
	// Params compresed
	cl_uint bits_by_char, chars_in_reg;
	_BitScanReverse(&bits_by_char, ceil_power_2(num_char_in_charset));
	chars_in_reg = 32 / bits_by_char;
	cl_uint max_j = 33 - bits_by_char;

	HS_SET_PRIORITY_GPU_THREAD;

	while (continue_attack && param->gen(buffer, param->param1, param->thread_id))
	{
		cl_uint key_lenght = ((cl_uint*)buffer)[8];
		cl_uint num_keys_filled = ((cl_uint*)buffer)[9];
		
		// Set registers params
		cl_uint num_param_regs = (key_lenght + chars_in_reg - 2) / chars_in_reg;
		cl_uint key_index = 1;
		for (cl_uint i = 0; i < num_param_regs; i++)
		{
			cl_uint key_param = buffer[key_index]; key_index++;

			for (cl_uint j = bits_by_char; j < max_j && key_index < key_lenght; j += bits_by_char, key_index++)
				key_param |= buffer[key_index] << j;

			pclSetKernelArg(param->kernels[key_lenght], i, sizeof(cl_uint), (void*)&key_param);
		}

		// TODO: Check if there is some problem
		cl_uint offset = 0;
		size_t num_work_items;
		cl_bool complete_processing = CL_FALSE;
		do
		{
			cl_uint posible_num_items = num_keys_filled*num_diff_salts - offset;

			pclSetKernelArg(param->kernels[key_lenght], num_param_regs + 1, sizeof(offset), (void*)&offset);

			if (posible_num_items > param->NUM_KEYS_OPENCL)
			{
				num_work_items = param->NUM_KEYS_OPENCL;
				offset += param->NUM_KEYS_OPENCL;
			}
			else
			{
				num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(posible_num_items, param->max_work_group_size);// Convert to multiple of work_group_size
				complete_processing = CL_TRUE;
			}
			pclEnqueueNDRangeKernel(param->queue, param->kernels[key_lenght], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		}
		while (!complete_processing);

		pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);
		// GPU found some passwords
		if (num_found)
			ocl_charset_process_found(param, &num_found, is_consecutive, buffer, key_lenght);

		report_keys_processed(num_keys_filled*num_char_in_charset);
	}

	release_opencl_param(param);
	finish_thread();
}
PRIVATE int ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	//                                                                             Max surpluss because OCL_MULTIPLE_WORKGROUP_SIZE
	cl_uint output_size = 2 * sizeof(cl_uint)* (num_passwords_loaded + ((cl_uint)gpu_devices[gpu_index].max_work_group_size)*num_char_in_charset);

	create_opencl_param(param, gpu_index, gen, output_size, FALSE);

	// Do not allow blank in GPU
	if (current_key_lenght == 0)
	{
		ocl_ssha_test_empty();
		current_key_lenght = 1;
		report_keys_processed(1);
	}

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= __max(1, 120 / num_char_in_charset);

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint) * __min(param->NUM_KEYS_OPENCL, (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size / (2 * 2 * sizeof(cl_uint))));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Create memory objects
#ifndef HS_OCL_CURRENT_KEY_AS_REGISTERS
	create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_ONLY, MAX_KEY_LENGHT, NULL);
#endif
	create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, sizeof(cl_uint) + output_size, NULL);

	if (num_passwords_loaded > 1)
	{
		create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);

		if (num_diff_salts > 1)
			create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY, sizeof(cl_uint)*(MAX_SIZE_SALT * 4 + 1)*num_diff_salts, NULL);

		if (num_diff_salts < num_passwords_loaded)
		{
			if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
			{
				create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
				create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
			}
			else
			{
				create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
				create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			}
		}
	}

	// Copy data to GPU
	unsigned char zero[MAX_KEY_LENGHT_SMALL];
	memset(zero, 0, MAX_KEY_LENGHT_SMALL);
#ifndef HS_OCL_CURRENT_KEY_AS_REGISTERS
	cl_write_buffer(param, GPU_CURRENT_KEY, MAX_KEY_LENGHT, zero);
#endif
	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), zero);
	if (num_passwords_loaded > 1)
	{
		// Facilitate cache
		cl_uint* bin = (cl_uint*)binary_values;
		cl_uint* my_binary_values = (cl_uint*)malloc(BINARY_SIZE * num_passwords_loaded);
		for (cl_uint i = 0; i < num_passwords_loaded; i++)
		{
			my_binary_values[i + 0 * num_passwords_loaded] = bin[5 * i + 0];
			my_binary_values[i + 1 * num_passwords_loaded] = bin[5 * i + 1];
			my_binary_values[i + 2 * num_passwords_loaded] = bin[5 * i + 2];
			my_binary_values[i + 3 * num_passwords_loaded] = bin[5 * i + 3];
			my_binary_values[i + 4 * num_passwords_loaded] = bin[5 * i + 4];
		}

		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE * num_passwords_loaded, my_binary_values);
		pclFinish(param->queue);
		free(my_binary_values);

		if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY) && num_diff_salts < num_passwords_loaded)
		{
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX], CL_FALSE, 0, 4 * num_passwords_loaded, salt_index, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, 4 * num_passwords_loaded, same_salt_next, 0, NULL, NULL);
		}
		if (num_diff_salts > 1)
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, sizeof(cl_uint)*(MAX_SIZE_SALT * 4 + 1)*num_diff_salts, salts_values, 0, NULL, NULL);
	}

	// Generate code
	char* source = ocl_gen_charset_code(&gpu_devices[gpu_index], output_size / 2 / sizeof(cl_uint));// Generate opencl code

	//size_t len = strlen(source);
	//{// Uncomment this to view opencl code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\ssha_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Crypt by length
	for (cl_uint i = current_key_lenght; i < (max_lenght + 1); i++)
	{
		char name_buffer[16];
		sprintf(name_buffer, "crypt%u", i);
		cl_int code = create_kernel(param, i, name_buffer);
		if (code != CL_SUCCESS)
		{
			release_opencl_param(param);
			return FALSE;
		}

		// Set OpenCL kernel params
		cl_uint bits_by_char;
		cl_uint num_param_regs = get_number_of_32regs(num_char_in_charset, i - 1, &bits_by_char);
		for (cl_uint j = 0; j < num_param_regs; j++)
			pclSetKernelArg(param->kernels[i], j, sizeof(cl_uint), (void*)zero);

		pclSetKernelArg(param->kernels[i], num_param_regs, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

		if (num_passwords_loaded > 1)
		{
			pclSetKernelArg(param->kernels[i], num_param_regs + 2, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
			if (num_diff_salts > 1)
				pclSetKernelArg(param->kernels[i], num_param_regs + 3, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);

			if (num_diff_salts < num_passwords_loaded)
			{
				pclSetKernelArg(param->kernels[i], num_param_regs + 4, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_INDEX]);
				pclSetKernelArg(param->kernels[i], num_param_regs + 5, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_SALT_NEXT]);
			}
		}
	}

	// Select best work_group
	cl_uint bits_by_char;
	cl_uint num_param_regs = get_number_of_32regs(num_char_in_charset, max_lenght - 1, &bits_by_char);
	pclSetKernelArg(param->kernels[max_lenght], num_param_regs + 1, sizeof(cl_uint), (void*)zero);

	ocl_calculate_best_work_group(param, param->kernels + max_lenght, UINT_MAX / num_char_in_charset, NULL, 0, CL_FALSE, CL_TRUE);
	param->param1 = __max(1, param->NUM_KEYS_OPENCL / num_diff_salts);

	pclFinish(param->queue);

	free(source);

	*gpu_crypt = ocl_protocol_charset_work;

	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_ssha(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint value_map_collission, void* salt_param, cl_uint prefered_vector_size)
{
	// Needed when use a rule with more than one param
	int found_multiplier = found_param_3 ? 3 : 2;
	char output_3[64];
	output_3[0] = 0;

	// Function definition
	sprintf(source + strlen(source), "\n__kernel void %s(const __global uint* keys,__global uint* restrict output, const __global uint* restrict binary_values, const __global uint* restrict salt_values, uint offset", kernel_name);

	if (num_diff_salts < num_passwords_loaded)
		strcat(source, ",const __global uint* restrict salt_indexs,const __global uint* restrict same_salt_next");

	if (aditional_param)
	{
		sprintf(source + strlen(source), ",uint param");
		*aditional_param = num_diff_salts < num_passwords_loaded ? 7 : 5;
	}

	// Begin function code
	sprintf(source + strlen(source), "){"
								"uint indx=offset+get_global_id(0);");

	if (num_diff_salts > 1)
	{
		DivisionParams div_param = get_div_params(num_diff_salts);
		// Perform division
		if (div_param.magic)sprintf(source + strlen(source), "uint key_index=mul_hi(indx+%iu,%uu)>>%uu;", (int)div_param.sum_one, div_param.magic, div_param.shift);// Normal division
		else				sprintf(source + strlen(source), "uint key_index=indx>>%uu;", div_param.shift);// Power of two division

		sprintf(source + strlen(source), "uint salt_index=indx-key_index*%uu; indx=key_index;", num_diff_salts);
	}
	else
		sprintf(source + strlen(source), "uint key_index=indx;"
										 "uint salt_index=0;");

	// Load the key
	sprintf(source + strlen(source), "uint A,B,C,D,E,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");
	if (found_param_3)
	{// Rules support
		char nt_buffer[16][16];
		char buffer_vector_size[16];

		memset(buffer_vector_size, 1, sizeof(buffer_vector_size));
		ocl_load(source, nt_buffer, buffer_vector_size, lenght, NUM_KEYS_OPENCL, 1);

		ocl_convert_2_big_endian(source, nt_buffer[0], "W0");
		ocl_convert_2_big_endian(source, nt_buffer[1], "W1");
		ocl_convert_2_big_endian(source, nt_buffer[2], "W2");
		ocl_convert_2_big_endian(source, nt_buffer[3], "W3");
		ocl_convert_2_big_endian(source, nt_buffer[4], "W4");
		ocl_convert_2_big_endian(source, nt_buffer[5], "W5");
		ocl_convert_2_big_endian(source, nt_buffer[6], "W6");

		cl_uint key_lenght = atoi(nt_buffer[7]+1)>>3;
		cl_uint i = key_lenght / 4;

		// Union key - salt
		if (num_diff_salts == 1)
		{
			cl_uint salt_part_index = 0;
			if (key_lenght & 3)
			{
				// Eliminate the last 0x80
				sprintf(source + strlen(source), "W%u&=%uu;", i, (cl_uint)(0xffffffff << (32 - (key_lenght & 3) * 8)));
				sprintf(source + strlen(source), "W%u|=%uu;", i,  ((uint32_t*)salts_values)[(key_lenght & 3)*MAX_SIZE_SALT*num_diff_salts]);
				i++;
				salt_part_index++;
			}
			// Rest salt
			for (; salt_part_index < ((max_salt_len + (key_lenght & 3)) / 4 + 1); i++, salt_part_index++)
				sprintf(source + strlen(source), "W%u=%uu;", i, ((uint32_t*)salts_values)[(key_lenght & 3)*MAX_SIZE_SALT*num_diff_salts + salt_part_index]);
			// Zero values
			for (; i < 15; i++)
				sprintf(source + strlen(source), "W%u=0;", i);
			// Lenght
			sprintf(source + strlen(source), "W15=%uu;", (key_lenght + ((uint32_t*)salts_values)[MAX_SIZE_SALT * 4 * num_diff_salts]) << 3);
		}
		else
		{
			cl_uint salt_part_index = 0;
			if (key_lenght & 3)
			{
				// Eliminate the last 0x80
				sprintf(source + strlen(source), "W%u&=%uu;", i, (cl_uint)(0xffffffff << (32 - (key_lenght & 3) * 8)));
				sprintf(source + strlen(source), "W%u|=salt_values[%uu+salt_index*%uu];", i, (key_lenght & 3)*MAX_SIZE_SALT*num_diff_salts, MAX_SIZE_SALT);
				i++;
				salt_part_index++;
			}
			// Rest salt
			for (; salt_part_index < ((max_salt_len + (key_lenght & 3)) / 4 + 1); i++, salt_part_index++)
				sprintf(source + strlen(source), "W%u=salt_values[%uu+salt_index*%uu];", i, (key_lenght & 3)*MAX_SIZE_SALT*num_diff_salts + salt_part_index, MAX_SIZE_SALT);
			// Zero values
			for (; i < 15; i++)
				sprintf(source + strlen(source), "W%u=0;", i);
			// Lenght
			sprintf(source + strlen(source), "W15=%uu+(salt_values[%uu+salt_index]<<3u);", key_lenght << 3, MAX_SIZE_SALT * 4 * num_diff_salts);
		}
	}
	else
		ocl_load(source, NULL, NULL, lenght, NUM_KEYS_OPENCL, 1);

	/* Round 1 */
	sprintf(source + strlen(source),
		"E=0x9fb498b3+W0;"
		"D=rotate(E,5u)+0x66b0cd0d+W1;"
		"C=rotate(D,5u)+(0x7bf36ae2^(E&0x22222222))+0xf33d5697+W2;E=rotate(E,30u);"
		"B=rotate(C,5u)+(0x59d148c0^(D&(E^0x59d148c0)))+0xd675e47b+W3;D=rotate(D,30u);"
		"A=rotate(B,5u)+bs(E,D,C)+0xb453c259+W4;C=rotate(C,30u);"

		"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W5;B=rotate(B,30u);"
		"D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W6;A=rotate(A,30u);"
		"C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W7;E=rotate(E,30u);"
		"B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W8;D=rotate(D,30u);"
		"A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W9;C=rotate(C,30u);"
		"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W10;B=rotate(B,30u);"
		"D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W11;A=rotate(A,30u);"
		"C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W12;E=rotate(E,30u);"
		"B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W13;D=rotate(D,30u);"
		"A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W14;C=rotate(C,30u);"
		"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W15;B=rotate(B,30u);");


	/* Round 2 */
	sprintf(source + strlen(source),
		"DCC2_R(0,13,8,2);D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W0;A=rotate(A,30u);"
		"DCC2_R(1,14,9,3);C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W1;E=rotate(E,30u);"
		"DCC2_R(2,15,10,4);B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W2;D=rotate(D,30u);"
		"DCC2_R(3,0,11,5);A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W3;C=rotate(C,30u);"

		"DCC2_R(4,1,12,6);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W4;B=rotate(B,30u);"
		"DCC2_R(5,2,13,7);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W5;A=rotate(A,30u);"
		"DCC2_R(6,3,14,8);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W6;E=rotate(E,30u);"
		"DCC2_R(7,4,15,9);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W7;D=rotate(D,30u);"
		"DCC2_R(8,5,0,10);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W8;C=rotate(C,30u);"
		"DCC2_R(9,6,1,11);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W9;B=rotate(B,30u);"
		"DCC2_R(10,7,2,12);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W10;A=rotate(A,30u);"
		"DCC2_R(11,8,3,13);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W11;E=rotate(E,30u);"
		"DCC2_R(12,9,4,14);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W12;D=rotate(D,30u);"
		"DCC2_R(13,10,5,15);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W13;C=rotate(C,30u);"
		"DCC2_R(14,11,6,0);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W14;B=rotate(B,30u);"
		"DCC2_R(15,12,7,1);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W15;A=rotate(A,30u);"
		"DCC2_R(0,13,8,2);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W0;E=rotate(E,30u);"
		"DCC2_R(1,14,9,3);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W1;D=rotate(D,30u);"
		"DCC2_R(2,15,10,4);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W2;C=rotate(C,30u);"
		"DCC2_R(3,0,11,5);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W3;B=rotate(B,30u);"
		"DCC2_R(4,1,12,6);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W4;A=rotate(A,30u);"
		"DCC2_R(5,2,13,7);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W5;E=rotate(E,30u);"
		"DCC2_R(6,3,14,8);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W6;D=rotate(D,30u);"
		"DCC2_R(7,4,15,9);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W7;C=rotate(C,30u);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"DCC2_R(8,5,0,10);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W8;B=rotate(B,30u);"
		"DCC2_R(9,6,1,11);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W9;A=rotate(A,30u);"
		"DCC2_R(10,7,2,12);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W10;E=rotate(E,30u);"
		"DCC2_R(11,8,3,13);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W11;D=rotate(D,30u);"
		"DCC2_R(12,9,4,14);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W12;C=rotate(C,30u);"
		"DCC2_R(13,10,5,15);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W13;B=rotate(B,30u);"
		"DCC2_R(14,11,6,0);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W14;A=rotate(A,30u);"
		"DCC2_R(15,12,7,1);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W15;E=rotate(E,30u);"
		"DCC2_R(0,13,8,2);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W0;D=rotate(D,30u);"
		"DCC2_R(1,14,9,3);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W1;C=rotate(C,30u);"
		"DCC2_R(2,15,10,4);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W2;B=rotate(B,30u);"
		"DCC2_R(3,0,11,5);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W3;A=rotate(A,30u);"
		"DCC2_R(4,1,12,6);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W4;E=rotate(E,30u);"
		"DCC2_R(5,2,13,7);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W5;D=rotate(D,30u);"
		"DCC2_R(6,3,14,8);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W6;C=rotate(C,30u);"
		"DCC2_R(7,4,15,9);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W7;B=rotate(B,30u);"
		"DCC2_R(8,5,0,10);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W8;A=rotate(A,30u);"
		"DCC2_R(9,6,1,11);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W9;E=rotate(E,30u);"
		"DCC2_R(10,7,2,12);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W10;D=rotate(D,30u);"
		"DCC2_R(11,8,3,13);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W11;C=rotate(C,30u);");

	/* Round 4 */
	sprintf(source + strlen(source),
		"DCC2_R(12,9,4,14);E+=rotate(A,5u)+(B^C^D)+CONST4+W12;B=rotate(B,30u);"
		"DCC2_R(13,10,5,15);D+=rotate(E,5u)+(A^B^C)+CONST4+W13;A=rotate(A,30u);"
		"DCC2_R(14,11,6,0);C+=rotate(D,5u)+(E^A^B)+CONST4+W14;E=rotate(E,30u);"
		"DCC2_R(15,12,7,1);B+=rotate(C,5u)+(D^E^A)+CONST4+W15;D=rotate(D,30u);"
		"DCC2_R(0,13,8,2);A+=rotate(B,5u)+(C^D^E)+CONST4+W0;C=rotate(C,30u);"
		"DCC2_R(1,14,9,3);E+=rotate(A,5u)+(B^C^D)+CONST4+W1;B=rotate(B,30u);"
		"DCC2_R(2,15,10,4);D+=rotate(E,5u)+(A^B^C)+CONST4+W2;A=rotate(A,30u);"
		"DCC2_R(3,0,11,5);C+=rotate(D,5u)+(E^A^B)+CONST4+W3;E=rotate(E,30u);"
		"DCC2_R(4,1,12,6);B+=rotate(C,5u)+(D^E^A)+CONST4+W4;D=rotate(D,30u);"
		"DCC2_R(5,2,13,7);A+=rotate(B,5u)+(C^D^E)+CONST4+W5;C=rotate(C,30u);"
		"DCC2_R(6,3,14,8);E+=rotate(A,5u)+(B^C^D)+CONST4+W6;B=rotate(B,30u);"
		"DCC2_R(7,4,15,9);D+=rotate(E,5u)+(A^B^C)+CONST4+W7;A=rotate(A,30u);"
		"DCC2_R(8,5,0,10);C+=rotate(D,5u)+(E^A^B)+CONST4+W8;E=rotate(E,30u);"
		"DCC2_R(9,6,1,11);B+=rotate(C,5u)+(D^E^A)+CONST4+W9;D=rotate(D,30u);"
		"DCC2_R(10,7,2,12);A+=rotate(B,5u)+(C^D^E)+CONST4+W10;"

		"DCC2_R(12,9,4,14);DCC2_R(15,12,7,1);A=rotate(A,30u)+W15;");

	// Match
	if (num_passwords_loaded == 1)
	{
		uint32_t* bin = (uint32_t*)binary_values;

		if (found_param_3)
			sprintf(output_3, "output[3u]=%s;", found_param_3);

		sprintf(source + strlen(source),
		"if(A==%uu)"
		"{"
			"A=rotate(A-W15,2u);"
			"C=rotate(C,30u);"
			"W11=rotate(W11^W8^W3^W13,1u);"
			"E+=rotate(A,5u)+(B^C^D)+CONST4+W11;B=rotate(B,30u);"
				
			"D+=rotate(E,5u)+(A^B^C)+CONST4+W12;A=rotate(A,30u);"
				
			"W15=rotate(W15,31u);W15^=W12^W7^W1;"
			"C+=rotate(D,5u)+(E^A^B)+CONST4+rotate(W13^W10^W5^W15,1u);"
				
			"B+=(D^rotate(E,30u)^A)+rotate(W14^W11^W6^W0,1u);"

			"if(B==%uu&&C==%uu&&D==%uu&&E==%uu)"
			"{"
				"output[0]=1u;"
				"output[1]=key_index;"
				"output[2]=0;"
				"%s"
			"}"
		"}"
		, bin[0], bin[1], bin[2], bin[3], bin[4], output_3);
	}
	else
	{
		if (found_param_3)
			sprintf(output_3, "output[3u*found+3u]=%s;", found_param_3);

		if (num_diff_salts < num_passwords_loaded)
		{
			sprintf(source + strlen(source),
				"indx=salt_indexs[salt_index];"

				"while(indx!=0xffffffff)"
				"{"
					"if(A==binary_values[indx])"
					"{"
						"uint aa=rotate(A-W15,2u);"
						"uint cc=rotate(C,30u);"
						"uint ww11=rotate(W11^W8^W3^W13,1u);"
						"uint ee=E+rotate(aa,5u)+(B^cc^D)+CONST4+ww11;uint bb=rotate(B,30u);"
							
						"uint dd=D+rotate(ee,5u)+(aa^bb^cc)+CONST4+W12;aa=rotate(aa,30u);"
							
						"uint ww15=rotate(W15,31u);ww15^=W12^W7^W1;"
						"cc+=rotate(dd,5u)+(ee^aa^bb)+CONST4+rotate(W13^W10^W5^ww15,1u);"
							
						"bb+=(dd^rotate(ee,30u)^aa)+rotate(W14^ww11^W6^W0,1u);"

						"if(bb==binary_values[indx+%uu]&&cc==binary_values[indx+%uu]&&dd==binary_values[indx+%uu]&&ee==binary_values[indx+%uu])"
						"{"
							"uint found=atomic_inc(output);"
							"output[%iu*found+1]=key_index;"
							"output[%iu*found+2]=indx;"
							"%s"
						"}", num_passwords_loaded, 2 * num_passwords_loaded, 3 * num_passwords_loaded, 4 * num_passwords_loaded, found_multiplier, found_multiplier, output_3);

	strcat(source, "}"
					"indx=same_salt_next[indx];"
				"}");
		}
		else
		{
			sprintf(source + strlen(source),
				"indx=salt_index;"

				"if(A==binary_values[indx])"
				"{"
					"uint aa=rotate(A-W15,2u);"
					"uint cc=rotate(C,30u);"
					"uint ww11=rotate(W11^W8^W3^W13,1u);"
					"uint ee=E+rotate(aa,5u)+(B^cc^D)+CONST4+ww11;uint bb=rotate(B,30u);"
							
					"uint dd=D+rotate(ee,5u)+(aa^bb^cc)+CONST4+W12;aa=rotate(aa,30u);"
							
					"uint ww15=rotate(W15,31u);ww15^=W12^W7^W1;"
					"cc+=rotate(dd,5u)+(ee^aa^bb)+CONST4+rotate(W13^W10^W5^ww15,1u);"
							
					"bb+=(dd^rotate(ee,30u)^aa)+rotate(W14^ww11^W6^W0,1u);"

					"if(bb==binary_values[indx+%uu]&&cc==binary_values[indx+%uu]&&dd==binary_values[indx+%uu]&&ee==binary_values[indx+%uu])"
					"{"
						"uint found=atomic_inc(output);"
						"output[%iu*found+1]=key_index;"
						"output[%iu*found+2]=indx;"
						"%s"
					"}"
				"}", num_passwords_loaded, 2 * num_passwords_loaded, 3 * num_passwords_loaded, 4 * num_passwords_loaded, found_multiplier, found_multiplier, output_3);
		}
	}

	if (ocl_end)	ocl_end(source);
	// End of kernel
	strcat(source, "}");
}
PRIVATE cl_uint ocl_load_ssha1(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size)
{
	// Total number of keys
	sprintf(source + strlen(source),
		"uint len=keys[indx+7*%uu];"
		"if(len>(27u<<4u))return;"
		"len>>=4u;", NUM_KEYS_OPENCL);

	strcat(source, "uint Ws[16];");

	sprintf(source + strlen(source),
		"uint i=0;"
		"for(;i<len/4;i++){"
			"uint tmp=rotate(keys[indx+i*%uu],16u);"
			"tmp=((tmp&0x00FF00FF)<<8u)+((tmp>>8u)&0x00FF00FF);"
			"Ws[i]=tmp;"
		"}", NUM_KEYS_OPENCL);

	sprintf(source + strlen(source),
		"uint salt_len=salt_values[%uu+salt_index];"
		"uint len3=len&3;"
		"uint j=len3*%uu+salt_index*%uu;"
		"uint size_salt=(salt_len+len3)/4+1+j;"
		"if(len3)"
		"{"
			"uint last_salt=rotate(keys[indx+i*%uu],16u);"
			"last_salt=((last_salt&0x00FF00FF)<<8u)+((last_salt>>8u)&0x00FF00FF);"
			"last_salt&=(0xffffffffu<<(32u-len3*8u));"// eliminate the last 0x80
			"Ws[i]=salt_values[j]|last_salt;"

			"i++;"
			"j++;"
		"}", MAX_SIZE_SALT * 4 * num_diff_salts, MAX_SIZE_SALT*num_diff_salts, MAX_SIZE_SALT, NUM_KEYS_OPENCL);

	sprintf(source + strlen(source),
		"for (;j<size_salt;j++,i++)"
			"Ws[i]=salt_values[j];"

		"for (;i<15;i++)"
			"Ws[i]=0;"

		"Ws[15]=(len+salt_len)<<3u;");

	for (cl_uint i = 0; i < 16; i++)
		sprintf(source + strlen(source), "W%u=Ws[%u];", i, i);

	return 1;
}
PRIVATE void ocl_work(OpenCL_Param* param)
{
	cl_uint num_found = 0;
	int num_keys_filled;

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	int result = param->gen(buffer, param->param1, param->thread_id);
	while (continue_attack && result)
	{
		cl_uint offset = 0;
		size_t num_work_items = kernel2common->process_buffer(buffer, result, param, &num_keys_filled);
		cl_bool complete_processing = CL_FALSE;
		do
		{
			cl_uint posible_num_items = num_keys_filled*num_diff_salts - offset;

			pclSetKernelArg(param->kernels[0], 4, sizeof(offset), (void*)&offset);

			if (posible_num_items > param->NUM_KEYS_OPENCL)
			{
				num_work_items = param->NUM_KEYS_OPENCL;
				offset += param->NUM_KEYS_OPENCL;
			}
			else
			{
				num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(posible_num_items, param->max_work_group_size);// Convert to multiple of work_group_size
				complete_processing = CL_TRUE;
			}
			pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		}
		while (!complete_processing);

		pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);

		// GPU found some passwords
		if (num_found)
			ocl_common_process_found(param, &num_found, kernel2common->get_key, buffer, num_work_items, num_keys_filled);

		report_keys_processed(num_keys_filled);

		// Generate keys
		result = param->gen(buffer, param->param1, param->thread_id);
	}

	free(buffer);
	release_opencl_param(param);

	finish_thread();
}
PRIVATE int ocl_protocol_common_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ssha_crypt, ocl_gen_processed_key* gen_processed_key, ocl_setup_proccessed_keys_params* setup_proccessed_keys_params, cl_uint keys_multipler)
{
	cl_uint output_size = 2 * sizeof(cl_uint) * num_passwords_loaded;

	create_opencl_param(param, gpu_index, gen, output_size, FALSE);

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= keys_multipler;

	while (param->NUM_KEYS_OPENCL >= gpu_devices[gpu_index].max_mem_alloc_size / 32)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint) * param->NUM_KEYS_OPENCL;
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	/// Generate code
	char* source = (char*)malloc(1024 * 32);

	// Write the definitions needed by the opencl implementation
	ocl_write_ssha_header(source, &gpu_devices[gpu_index]);
	// Kernel needed to convert from * to the common format
	gen_processed_key(source, param->NUM_KEYS_OPENCL);

	// Write the kernel
	ocl_gen_kernel_ssha(source, "ssha_crypt", ocl_load_ssha1, NULL, NULL, NULL, NTLM_MAX_KEY_LENGHT, param->NUM_KEYS_OPENCL, 0, NULL, 1);
	//{// Comment this to view code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	size_t len = strlen(source);
	//	fwrite(source, 1, len, code);
	//	fclose(code);
	//}

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Kernels
	cl_int code = create_kernel(param, KERNEL_PROCESS_KEY_INDEX, "process_key");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Generate kernels by lenght
	code = create_kernel(param, 0, "ssha_crypt");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Create memory objects
	create_opencl_mem(param, GPU_CURRENT_KEY  , CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL * param->NUM_KEYS_OPENCL, NULL);
	create_opencl_mem(param, GPU_OUTPUT       , CL_MEM_READ_WRITE, sizeof(cl_uint) + output_size, NULL);
	create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
	create_opencl_mem(param, GPU_SALT_VALUES  , CL_MEM_READ_ONLY, sizeof(cl_uint)*(MAX_SIZE_SALT * 4 + 1)*num_diff_salts, NULL);

	if (num_diff_salts < num_passwords_loaded)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
		}
		else
		{
			create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
	}
	setup_proccessed_keys_params(param, &gpu_devices[gpu_index]);

	// Set OpenCL kernel params
	pclSetKernelArg(param->kernels[0], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[0], 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);
	pclSetKernelArg(param->kernels[0], 2, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
	pclSetKernelArg(param->kernels[0], 3, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);
	if (num_diff_salts < num_passwords_loaded)
	{
		pclSetKernelArg(param->kernels[0], 5, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_INDEX]);
		pclSetKernelArg(param->kernels[0], 6, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_SALT_NEXT]);
	}

	// Copy data to GPU
	memset(source, 0, sizeof(cl_uint));
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, sizeof(cl_uint), source, 0, NULL, NULL);
	{
		// Facilitate cache
		cl_uint* bin = (cl_uint*)binary_values;
		cl_uint* my_binary_values = (cl_uint*)malloc(BINARY_SIZE * num_passwords_loaded);
		for (cl_uint i = 0; i < num_passwords_loaded; i++)
		{
			my_binary_values[i + 0 * num_passwords_loaded] = bin[5 * i + 0];
			my_binary_values[i + 1 * num_passwords_loaded] = bin[5 * i + 1];
			my_binary_values[i + 2 * num_passwords_loaded] = bin[5 * i + 2];
			my_binary_values[i + 3 * num_passwords_loaded] = bin[5 * i + 3];
			my_binary_values[i + 4 * num_passwords_loaded] = bin[5 * i + 4];
		}

		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE * num_passwords_loaded, my_binary_values);
		pclFinish(param->queue);
		free(my_binary_values);
	}

	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, sizeof(cl_uint)*(MAX_SIZE_SALT * 4 + 1)*num_diff_salts, salts_values, 0, NULL, NULL);

	if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY) && num_diff_salts < num_passwords_loaded)
	{
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX], CL_FALSE, 0, sizeof(cl_uint)* num_passwords_loaded, salt_index, 0, NULL, NULL);
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, sizeof(cl_uint)* num_passwords_loaded, same_salt_next, 0, NULL, NULL);
	}

	pclFinish(param->queue);
	free(source);

	// Find working workgroup
	cl_uint zero = 0;
	pclSetKernelArg(param->kernels[0], 4, sizeof(zero), (void*)&zero);

	cl_ulong duration = ocl_calculate_best_work_group(param, param->kernels, UINT32_MAX, NULL, 0, CL_FALSE, CL_FALSE);
	param->param1 = __max(1, param->NUM_KEYS_OPENCL / num_diff_salts);

	// Provide a good duration
	while (duration > (OCL_NORMAL_KERNEL_TIME * 4 / 3))
	{
		param->param1 /= 2;
		duration /= 2;
	}
	param->param1 = __max(1, param->param1);
	
	cl_uint used_num_diff_salts = num_diff_salts;
	while (duration < (OCL_NORMAL_KERNEL_TIME / 2) && used_num_diff_salts>=2)
	{
		param->param1 *= 2;
		duration *= 2;
		used_num_diff_salts /= 2;
	}

	*gpu_ssha_crypt = ocl_work;

	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	int r = ocl_protocol_common_init(param, gpu_index, gen, gpu_crypt, kernels2common[UTF8_INDEX_IN_KERNELS].gen_kernel, kernels2common[UTF8_INDEX_IN_KERNELS].setup_params, 2);
	param->additional_param = kernels2common + UTF8_INDEX_IN_KERNELS;
	return r;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	int r = ocl_protocol_common_init(param, gpu_index, gen, gpu_crypt, kernels2common[PHRASES_INDEX_IN_KERNELS].gen_kernel, kernels2common[PHRASES_INDEX_IN_KERNELS].setup_params, 8);
	param->additional_param = kernels2common + PHRASES_INDEX_IN_KERNELS;
	return r;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_write_ssha_header_rules(char* source, GPUDevice* gpu, cl_uint unused)
{
	ocl_write_ssha_header(source, gpu);
}
PRIVATE int ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	return ocl_rules_init_ssha(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, MAX_SIZE_SALT * 4 + 1, ocl_write_ssha_header_rules, ocl_gen_kernel_ssha, RULE_UTF8_LE_INDEX, 1);
}
#endif

Format ssha_format = {
	"SSHA",
	"Salted SHA1 format.",
	"{SSHA}",
	NTLM_MAX_KEY_LENGHT,
	BINARY_SIZE,
	SALT_SIZE,
	11,
	NULL,
	0,
	get_binary,
	binary2hex,
	DEFAULT_VALUE_MAP_INDEX,
	DEFAULT_VALUE_MAP_INDEX,
	is_valid,
	add_hash_from_line,
	optimize_hashes,
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