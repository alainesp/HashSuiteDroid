// This file is part of Hash Suite password cracker,
// Copyright (c) 2013-2015 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

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


int dcc_line_is_valid(char* user_name, char* dcc, char* unused, char* unused1);
sqlite3_int64 dcc_add_hash_from_line(ImportParam* param, char* user_name, char* dcc, int db_index);
PRIVATE int dcc2_line_is_valid(char* user_name, char* dcc, char* unused, char* unused1)
{
	if (user_name && !memcmp(user_name, "$DCC2$10240#", 12))
	{
		char* hex = strchr(user_name + 12, '#');
		int user_len = (int)(hex - user_name - 12);
		if (hex && user_len <= 19 && user_len >= 1 && valid_hex_string(hex + 1, 32))
			return TRUE;
	}
	return dcc_line_is_valid(user_name, dcc, unused, unused1);
}
PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* user_name, char* dcc, char* unused, char* unused1)
{
	if (user_name && !memcmp(user_name, "$DCC2$10240#", 12))
	{
		char* hex = strchr(user_name + 12, '#');
		int user_len = (int)(hex - user_name - 12);
		if (hex && user_len <= 19 && user_len >= 1 && valid_hex_string(hex + 1, 32))
		{
			hex[0] = 0;
			char user[20];
			strcpy(user, user_name + 12);
			hex[0] = ':';
			// Insert hash and account
			return insert_hash_account1(param, _strlwr(user), user_name + 12, DCC2_INDEX);
		}
	}
	return dcc_add_hash_from_line(param, user_name, dcc, DCC2_INDEX);
}

PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt_void)
{
	uint32_t* out = (uint32_t*)binary;
	uint32_t* salt = (uint32_t*)salt_void;
	uint32_t i = 0;
	uint32_t temp;
	uint32_t salt_lenght = 0;
	char ciphertext_buffer[64];

	//length=11 for save memory
	memset(salt, 0, SALT_SIZE);
	// Lowercase username
	ciphertext = _strlwr( strcpy(ciphertext_buffer, ciphertext) );
	// Get salt length
	for(; ciphertext[salt_lenght] != ':'; salt_lenght++);
	// Convert salt-----------------------------------------------------
	for(; i < salt_lenght/2; i++)
		salt[i] = ((uint32_t)ciphertext[2*i]) | ((uint32_t)ciphertext[2*i+1]) << 16;

	salt[i] = (salt_lenght%2) ? ((uint32_t)ciphertext[2*i]) | 0x800000 : 0x80;
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
PRIVATE void binary2hex(const void* binary, const uint32_t* salt, unsigned char* ciphertext)
{
	uint32_t salt_lenght = (salt[10] >> 4) - 8;
	// Convert to username
	for (uint32_t i = 0; i < salt_lenght / 2; i++)
	{
		ciphertext[2 * i + 0] = salt[i] & 0xFF;
		ciphertext[2 * i + 1] = (salt[i] >> 16) & 0xFF;
	}
	if (salt_lenght % 2)
		ciphertext[2 * (salt_lenght / 2)] = salt[salt_lenght / 2] & 0xFF;

	ciphertext[salt_lenght] = ':';

	binary_to_hex(binary, ciphertext + salt_lenght + 1, BINARY_SIZE / sizeof(uint32_t), FALSE);
}

void sha1_process_block_simd(uint32_t* state, uint32_t* W, uint32_t simd_with);
void sha1_process_block_hmac_sha1(const uint32_t state[5], uint32_t sha1_hash[5], uint32_t W[16]);
void hmac_sha1_init_simd(uint32_t* key, uint32_t* key_lenghts, uint32_t simd_with, uint32_t multiplier, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void dcc_salt_part_c_code(uint32_t* salt_buffer, uint32_t* crypt_result);
#ifndef HS_TESTING
PRIVATE
#endif
void dcc2_body_c_code(uint32_t* salt_buffer, uint32_t* crypt_result, uint32_t* sha1_hash, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W)
{
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

	a += INIT_A;
	b += INIT_B;
	c += INIT_C;
	d += INIT_D;

	//pbkdf2
	uint32_t salt_len = (salt_buffer[10] >> 3) - 16;
	SWAP_ENDIANNESS(a, a);
	SWAP_ENDIANNESS(b, b);
	SWAP_ENDIANNESS(c, c);
	SWAP_ENDIANNESS(d, d);

	sha1_hash[0] = a;
	sha1_hash[1] = b;
	sha1_hash[2] = c;
	sha1_hash[3] = d;
	uint32_t len = 4;
	hmac_sha1_init_simd(sha1_hash, &len, 1, 1, opad_state, ipad_state, W);

	memcpy(sha1_hash, ipad_state, 5 * sizeof(uint32_t));

	// Process the salt
	memcpy(W, salt_buffer, salt_len);
	memcpy(((unsigned char*)W) + salt_len, "\x0\x0\x0\x1\x80", 5);
	memset(((unsigned char*)W) + salt_len + 5, 0, 60 - (salt_len + 5));
	W[15] = (64 + salt_len + 4) << 3;
	swap_endianness_array(W, 14);
	sha1_process_block_simd(sha1_hash, W, 1);

	sha1_process_block_hmac_sha1(opad_state, sha1_hash, W);
	// Only copy first 16 bytes, since that is ALL this format uses
	memcpy(crypt_result + 8, sha1_hash, 4 * sizeof(uint32_t));

	for (uint32_t k = 1; k < 10240; k++)
	{
		sha1_process_block_hmac_sha1(ipad_state, sha1_hash, W);
		sha1_process_block_hmac_sha1(opad_state, sha1_hash, W);

		// Only XOR first 16 bytes, since that is ALL this format uses
		crypt_result[8 + 0] ^= sha1_hash[0];
		crypt_result[8 + 1] ^= sha1_hash[1];
		crypt_result[8 + 2] ^= sha1_hash[2];
		crypt_result[8 + 3] ^= sha1_hash[3];
	}
}
#ifndef _M_X64
void dcc_ntlm_part_c_code(uint32_t* nt_buffer, uint32_t* crypt_result);
PRIVATE void crypt_ntlm_protocol_c_code(CryptParam* param)
{
	uint32_t * nt_buffer = (uint32_t* )calloc(16*NT_NUM_KEYS, sizeof(uint32_t));
	unsigned char* key       = (unsigned char*)calloc(MAX_KEY_LENGHT_SMALL, sizeof(unsigned char));

	uint32_t crypt_result[12], sha1_hash[5], opad_state[5], ipad_state[5], W[16];

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(uint32_t i = 0; i < NT_NUM_KEYS; i++)
		{
			uint32_t* salt_buffer = (uint32_t*)salts_values;
			dcc_ntlm_part_c_code(nt_buffer+i, crypt_result);

			// For all salts
			for(uint32_t j = 0; continue_attack && j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_c_code(salt_buffer, crypt_result);
				dcc2_body_c_code(salt_buffer, crypt_result, sha1_hash, opad_state, ipad_state, W);

				// Search for a match
				uint32_t index = salt_index[j];

				// Partial match
				while(index != NO_ELEM)
				{
					uint32_t* bin = ((uint32_t*)binary_values) + index*4;

					// Total match
					if(crypt_result[8+0] == bin[0] && crypt_result[8+1] == bin[1] && crypt_result[8+2] == bin[2] && crypt_result[8+3] == bin[3])
						password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));
					
					index = same_salt_next[index];
				}
			}

			report_keys_processed(1);
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
#include "arch_simd.h"

//#ifdef HS_X86
#define LOAD_BIG_ENDIAN_V128(x) x = V128_OR(V128_SL(x, 16), V128_SR(x, 16)); x = V128_ADD(V128_SL(V128_AND(x, V128_CONST(0x00FF00FF)), 8), V128_AND(V128_SR(x, 8), V128_CONST(0x00FF00FF)));
//#endif

// Note: This code give errors in Neon
//#ifdef HS_ARM
//#define LOAD_BIG_ENDIAN_V128(x) vrev32q_u8(vreinterpretq_u8_u32(x))
//#endif

PRIVATE void dcc2_body_v128(V128_WORD* crypt_result, uint32_t* salt_buffer, int mul, int index)
{
	V128_WORD* sha1_hash = crypt_result + 12 * mul + 5 * index;
	V128_WORD* opad_state = sha1_hash + 5 * mul;
	V128_WORD* ipad_state = opad_state + 5 * mul;
	V128_WORD* W = ipad_state + 5 * mul + (16 - 5)*index;

	V128_WORD a = crypt_result[(8 + 0)*mul + index];
	V128_WORD b = crypt_result[(8 + 1)*mul + index];
	V128_WORD c = crypt_result[(8 + 2)*mul + index];
	V128_WORD d = crypt_result[(8 + 3)*mul + index];
	V128_WORD const_sse2 = V128_CONST(SQRT_3);

	d = V128_ADD(d, const_sse2); d = V128_ROTATE(d, 9);
	c = V128_4ADD(c, V128_3XOR(d, a, b), V128_CONST(salt_buffer[1]), const_sse2); c = V128_ROTATE(c, 11);
	b = V128_4ADD(b, V128_3XOR(c, d, a), V128_CONST(salt_buffer[9]), const_sse2); b = V128_ROTATE(b, 15);

	a = V128_4ADD(a, V128_3XOR(b, c, d), crypt_result[3 * mul + index], const_sse2); a = V128_ROTATE(a, 3);
	d = V128_4ADD(d, V128_3XOR(a, b, c), V128_CONST(salt_buffer[7]), const_sse2); d = V128_ROTATE(d, 9);
	c = V128_4ADD(c, V128_3XOR(d, a, b), V128_CONST(salt_buffer[3]), const_sse2); c = V128_ROTATE(c, 11);
	b = V128_3ADD(b, V128_3XOR(c, d, a), const_sse2); b = V128_ROTATE(b, 15);

	a = V128_ADD(a, V128_CONST(INIT_A));
	b = V128_ADD(b, V128_CONST(INIT_B));
	c = V128_ADD(c, V128_CONST(INIT_C));
	d = V128_ADD(d, V128_CONST(INIT_D));

	//pbkdf2
	uint32_t salt_len = (salt_buffer[10] >> 3) - 16;
	LOAD_BIG_ENDIAN_V128(a);
	LOAD_BIG_ENDIAN_V128(b);
	LOAD_BIG_ENDIAN_V128(c);
	LOAD_BIG_ENDIAN_V128(d);

	// ipad_state
	const_sse2 = V128_CONST(0x36363636);
	W[0] = V128_XOR(a, const_sse2);
	W[1] = V128_XOR(b, const_sse2);
	W[2] = V128_XOR(c, const_sse2);
	W[3] = V128_XOR(d, const_sse2);
	memset(W + 4, 0x36, (16 - 4)*sizeof(V128_WORD));

	ipad_state[0] = V128_CONST(INIT_A);
	ipad_state[1] = V128_CONST(INIT_B);
	ipad_state[2] = V128_CONST(INIT_C);
	ipad_state[3] = V128_CONST(INIT_D);
	ipad_state[4] = V128_CONST(INIT_E);
	sha1_process_block_simd((uint32_t*)ipad_state, (uint32_t*)W, 4);

	// opad_state
	const_sse2 = V128_CONST(0x5C5C5C5C);
	W[0] = V128_XOR(a, const_sse2);
	W[1] = V128_XOR(b, const_sse2);
	W[2] = V128_XOR(c, const_sse2);
	W[3] = V128_XOR(d, const_sse2);
	memset(W + 4, 0x5C, (16 - 4)*sizeof(V128_WORD));

	opad_state[0] = V128_CONST(INIT_A);
	opad_state[1] = V128_CONST(INIT_B);
	opad_state[2] = V128_CONST(INIT_C);
	opad_state[3] = V128_CONST(INIT_D);
	opad_state[4] = V128_CONST(INIT_E);
	sha1_process_block_simd((uint32_t*)opad_state, (uint32_t*)W, 4);

	memcpy(sha1_hash, ipad_state, 5 * sizeof(V128_WORD));

	// Process the salt
	memcpy(W, salt_buffer, salt_len);
	memcpy(((unsigned char*)W) + salt_len, "\x0\x0\x0\x1\x80", 5);
	memset(((unsigned char*)W) + salt_len + 5, 0, 60 - (salt_len + 5));
	W[14] = V128_CONST(0);
	W[15] = V128_CONST((64 + salt_len + 4) << 3);
	for (int k = 13; k >= 0; k--)
	{
		// Convert to BIG_ENDIAN
		uint32_t x = ROTATE(((uint32_t*)W)[k], 16U);
		x = ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
		W[k] = V128_CONST(x);
	}
	sha1_process_block_simd((uint32_t*)sha1_hash, (uint32_t*)W, 4);
}

#ifdef HS_X86
// Calculate W in each iteration
#undef DCC2_R
#define DCC2_R(w0, w1, w2, w3)	W[w0] = SSE2_ROTATE(SSE2_4XOR(W[w0], W[w1], W[w2], W[w3]), 1)

PUBLIC void sha1_process_sha1_sse2(const __m128i* state, __m128i* sha1_hash, __m128i* W)
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
void dcc_salt_part_sse2(uint32_t* salt_buffer, __m128i* crypt_result);

PRIVATE void crypt_ntlm_protocol_sse2(CryptParam* param)
{
	__m128i* nt_buffer = (__m128i*)_aligned_malloc(16*4*NT_NUM_KEYS, 16);
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT_SMALL, sizeof(unsigned char));
	__m128i* crypt_result = (__m128i*)_aligned_malloc(sizeof(__m128i)*(12+5+5+5+16), 16);

	__m128i* sha1_hash = crypt_result + 12;
	__m128i* opad_state = sha1_hash + 5;
	__m128i* ipad_state = opad_state + 5;
	__m128i* W = ipad_state + 5;

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(uint32_t i = 0; i < NT_NUM_KEYS/4; i++)
		{
			uint32_t* salt_buffer = (uint32_t*)salts_values;
			dcc_ntlm_part_sse2(nt_buffer+i, crypt_result);

			// For all salts
			for(uint32_t j = 0; continue_attack && j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_sse2(salt_buffer, crypt_result);
				
				dcc2_body_v128(crypt_result, salt_buffer, 1, 0);
				sha1_process_sha1_sse2(opad_state, sha1_hash, W);
				// Only copy first 4 elements, since that is ALL this format uses
				crypt_result[(8 + 0)*1 + 0] = sha1_hash[0];
				crypt_result[(8 + 1)*1 + 0] = sha1_hash[1];
				crypt_result[(8 + 2)*1 + 0] = sha1_hash[2];
				crypt_result[(8 + 3)*1 + 0] = sha1_hash[3];

				for(uint32_t k = 1; k < 10240; k++)
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
				for (uint32_t k = 0; k < 4; k++)
				{
					uint32_t index = salt_index[j];
					// Partial match
					while(index != NO_ELEM)
					{
						uint32_t* bin = ((uint32_t*)binary_values) + index*4;

						// Total match
						if(crypt_result[8+0].m128i_u32[k] == bin[0] && crypt_result[8+1].m128i_u32[k] == bin[1] && crypt_result[8+2].m128i_u32[k] == bin[2] && crypt_result[8+3].m128i_u32[k] == bin[3])
							password_was_found(index, ntlm2utf8_key((uint32_t*)nt_buffer, key, NT_NUM_KEYS, i*4+k));
					
						index = same_salt_next[index];
					}
				}
			}
			report_keys_processed(4);
		}
	}

	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);
	finish_thread();
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// V128 Implementation (AVX and Neon)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
void dcc_ntlm_part_avx(void* nt_buffer, void* crypt_result);
void dcc_salt_part_avx(void* salt_buffer, void* crypt_result);
void sha1_process_sha1_avx(const void* state, void* sha1_hash, void* W);

#define NT_NUM_KEYS_AVX 256
#define crypt_ntlm_protocol_v128 crypt_ntlm_protocol_avx
#define dcc_ntlm_part_v128 dcc_ntlm_part_avx
#define dcc_salt_part_v128 dcc_salt_part_avx
#define sha1_process_sha1_v128 sha1_process_sha1_avx
#endif

#ifdef HS_ARM
void dcc_ntlm_part_neon(void* nt_buffer, void* crypt_result);
void dcc_salt_part_neon13(void* salt_buffer, void* crypt_result);
void sha1_process_sha1_neon(const void* state, void* sha1_hash, void* W);

#define NT_NUM_KEYS_AVX 64
#define crypt_ntlm_protocol_v128 crypt_ntlm_protocol_neon
#define dcc_ntlm_part_v128 dcc_ntlm_part_neon
#define dcc_salt_part_v128 dcc_salt_part_neon13
#define sha1_process_sha1_v128 sha1_process_sha1_neon
#endif

PRIVATE void crypt_ntlm_protocol_v128(CryptParam* param)
{
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT_SMALL, sizeof(unsigned char));
	uint32_t* nt_buffer	= (uint32_t*)_aligned_malloc(16*4*NT_NUM_KEYS_AVX, 32);
	V128_WORD* crypt_result = (V128_WORD*)_aligned_malloc(sizeof(V128_WORD)* 2 * (12 + 5 + 5 + 5 + 16), 32);

	V128_WORD* sha1_hash = crypt_result + 24;
	V128_WORD* opad_state = sha1_hash + 10;
	V128_WORD* ipad_state = opad_state + 10;
	V128_WORD* W = ipad_state + 10;

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS_AVX);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS_AVX, param->thread_id))
	{
		for(uint32_t i = 0; i < NT_NUM_KEYS_AVX/8; i++)
		{
			uint32_t* salt_buffer = (uint32_t*)salts_values;
			dcc_ntlm_part_v128(nt_buffer + 8 * i, crypt_result);

			// For all salts
			for(uint32_t j = 0; continue_attack && j < num_diff_salts; j++, salt_buffer += 11)
			{
				dcc_salt_part_v128(salt_buffer, crypt_result);

				dcc2_body_v128(crypt_result, salt_buffer, 2, 0);
				dcc2_body_v128(crypt_result, salt_buffer, 2, 1);

				sha1_process_sha1_v128(opad_state, sha1_hash, W);
				// Only copy first 4 elements, since that is ALL this format uses
				crypt_result[(8 + 0)*2 + 0] = sha1_hash[0];
				crypt_result[(8 + 1)*2 + 0] = sha1_hash[1];
				crypt_result[(8 + 2)*2 + 0] = sha1_hash[2];
				crypt_result[(8 + 3)*2 + 0] = sha1_hash[3];

				crypt_result[(8 + 0)*2 + 1] = sha1_hash[5];
				crypt_result[(8 + 1)*2 + 1] = sha1_hash[6];
				crypt_result[(8 + 2)*2 + 1] = sha1_hash[7];
				crypt_result[(8 + 3)*2 + 1] = sha1_hash[8];

				for(uint32_t k = 1; k < 10240; k++)
				{
					sha1_process_sha1_v128(ipad_state, sha1_hash, W);
					sha1_process_sha1_v128(opad_state, sha1_hash, W);

					// Only XOR first 16 bytes, since that is ALL this format uses
					crypt_result[(8+0)*2+0] = V128_XOR(crypt_result[(8+0)*2+0], sha1_hash[0]);
					crypt_result[(8+1)*2+0] = V128_XOR(crypt_result[(8+1)*2+0], sha1_hash[1]);
					crypt_result[(8+2)*2+0] = V128_XOR(crypt_result[(8+2)*2+0], sha1_hash[2]);
					crypt_result[(8+3)*2+0] = V128_XOR(crypt_result[(8+3)*2+0], sha1_hash[3]);

					crypt_result[(8+0)*2+1] = V128_XOR(crypt_result[(8+0)*2+1], sha1_hash[5]);
					crypt_result[(8+1)*2+1] = V128_XOR(crypt_result[(8+1)*2+1], sha1_hash[6]);
					crypt_result[(8+2)*2+1] = V128_XOR(crypt_result[(8+2)*2+1], sha1_hash[7]);
					crypt_result[(8+3)*2+1] = V128_XOR(crypt_result[(8+3)*2+1], sha1_hash[8]);
				}

				for(uint32_t k = 0; k < 8; k++)
				{
					// Search for a match
					uint32_t index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						uint32_t* bin = ((uint32_t*)binary_values) + index * 4;
						uint32_t* crypt_bin = (uint32_t*)(crypt_result + 8 * 2);

						// Total match
						if(crypt_bin[k+8*0] == bin[0] && crypt_bin[k+8*1] == bin[1] && crypt_bin[k+8*2] == bin[2] && crypt_bin[k+8*3] == bin[3])
							password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS_AVX, 8*i+k));

						index = same_salt_next[index];
					}
				}
			}
			report_keys_processed(8);
		}
	}

	// Release resources
	free(key);
	_aligned_free(nt_buffer);
	_aligned_free(crypt_result);

	finish_thread();
}


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

PRIVATE void dcc2_body_avx2(__m256i* crypt_result, uint32_t* salt_buffer, int index)
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
	uint32_t salt_len = (salt_buffer[10] >> 3) - 16;
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
	sha1_process_block_simd( (uint32_t*)ipad_state, (uint32_t*)W, 8 );

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
	sha1_process_block_simd( (uint32_t*)opad_state, (uint32_t*)W, 8 );

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
		uint32_t x = ROTATE(((uint32_t*)W)[k], 16U);
		x = ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
		W[k] = _mm256_broadcastd_epi32(_mm_set1_epi32(x));
	}
	sha1_process_block_simd( (uint32_t*)sha1_hash, (uint32_t*)W, 8 );
}

PRIVATE void crypt_ntlm_protocol_avx2(CryptParam* param)
{
	unsigned char* key = (unsigned char*)calloc(MAX_KEY_LENGHT_SMALL, sizeof(unsigned char));
	uint32_t* nt_buffer = (uint32_t*)_aligned_malloc(16 * 4 * NT_NUM_KEYS_AVX, 32);
	__m256i* crypt_result = (__m256i*)_aligned_malloc(sizeof(__m256i)*2*(12+5+5+5+16), 32);

	__m256i* sha1_hash = crypt_result + 24;
	__m256i* opad_state = sha1_hash + 10;
	__m256i* ipad_state = opad_state + 10;
	__m256i* W = ipad_state + 10;

	memset(nt_buffer, 0, 16 * 4 * NT_NUM_KEYS_AVX);

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS_AVX, param->thread_id))
	{
		for(uint32_t i = 0; i < NT_NUM_KEYS_AVX/16; i++)
		{
			uint32_t* salt_buffer = (uint32_t*)salts_values;
			dcc_ntlm_part_avx2(nt_buffer+16*i, crypt_result);

			// For all salts
			for(uint32_t j = 0; continue_attack && j < num_diff_salts; j++, salt_buffer += 11)
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

				for(uint32_t k = 1; k < 10240; k++)
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

				for(uint32_t k = 0; k < 16; k++)
				{
					// Search for a match
					uint32_t index = salt_index[j];

					// Partial match
					while(index != NO_ELEM)
					{
						uint32_t* bin = ((uint32_t*)binary_values) + index * 4;
						uint32_t* crypt_bin = (uint32_t*)(crypt_result + 8 * 2);

						// Total match
						if(crypt_bin[k+16*0] == bin[0] && crypt_bin[k+16*1] == bin[1] && crypt_bin[k+16*2] == bin[2] && crypt_bin[k+16*3] == bin[3])
							password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS_AVX, 16*i+k));

						index = same_salt_next[index];
					}
				}
			}
			report_keys_processed(16);
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
// OpenCL Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT

#define KERNEL_INDEX_NTLM_PART					0
#define KERNEL_INDEX_DCC_PART					1
#define KERNEL_INDEX_DCC2_SHA1_OPAD				2
#define KERNEL_INDEX_DCC2_COMPARE_RESULT		3
#define KERNEL_INDEX_DCC2_SHA1_PAD_MASK			4
#define KERNEL_INDEX_SHA1_PROCESS_SALT			5
#define KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE		6
#define KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC	7

#define IPAD_STATE		0
#define OPAD_STATE		5
#define SHA1_HASH		10
#define CRYPT_RESULT	15

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_work_body(OpenCL_Param* param, int num_keys_filled, void* buffer, ocl_get_key* get_key)
{
	int64_t total_ks = num_diff_salts * 10239;
	size_t num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_keys_filled, param->max_work_group_size);
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_NTLM_PART], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
	int num_keys_reported = 0;

	for (cl_uint current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index++)
	{
		// Body
		pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC_PART], 3, sizeof(current_salt_index), (void*)&current_salt_index);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC_PART], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

		// IPAD STATE
		cl_uint state = IPAD_STATE;
		cl_uint flag = 0x36363636;
		pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 1, sizeof(state), (void*)&state);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 2, sizeof(flag), (void*)&flag);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		pclFinish(param->queue);

		// OPAD STATE
		state = OPAD_STATE;
		flag = 0x5C5C5C5C;
		pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 1, sizeof(state), (void*)&state);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 2, sizeof(flag), (void*)&flag);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

		// Salt
		pclSetKernelArg(param->kernels[KERNEL_INDEX_SHA1_PROCESS_SALT], 2, sizeof(current_salt_index), (void*)&current_salt_index);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_SHA1_PROCESS_SALT], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

		// Sha1 Opad
		pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

		// SHA1 cycle
		state = OCL_SLOW_GET_CYCLE_PARAM(param->param0);
		pclSetKernelArg(param->kernels[OCL_SLOW_GET_KERNEL_INDEX(param->param0)], 1, sizeof(state), (void*)&state);
		size_t cycle_num_work_items = num_work_items;
#ifndef HS_OCL_REDUCE_REGISTER_USE
		if (OCL_SLOW_GET_KERNEL_INDEX(param->param0) == KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC)
			cycle_num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_work_items / 2, param->max_work_group_size);
#endif
		for (cl_uint k = 0; k < 10239 / state; k++)
		{
			pclEnqueueNDRangeKernel(param->queue, param->kernels[OCL_SLOW_GET_KERNEL_INDEX(param->param0)], 1, NULL, &cycle_num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			pclFinish(param->queue);
			if (!continue_attack)
				break;

			// Report keys processed from time to time to maintain good Rate
			int64_t processed_ks = current_salt_index * 10239 + k*state;
			int num_keys_reported_add = (int)(num_keys_filled*processed_ks / total_ks) - num_keys_reported;
			if (num_keys_reported_add > 0)
			{
				num_keys_reported += num_keys_reported_add;
				report_keys_processed(num_keys_reported_add);
			}
		}
		if (continue_attack)
		{
			cl_uint num_found;
			state = OCL_SLOW_GET_CYCLE_PARAM(param->param0) - 1;
			pclSetKernelArg(param->kernels[OCL_SLOW_GET_KERNEL_INDEX(param->param0)], 1, sizeof(state), (void*)&state);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[OCL_SLOW_GET_KERNEL_INDEX(param->param0)], 1, NULL, &cycle_num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			// Compare results
			pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 1, sizeof(current_salt_index), (void*)&current_salt_index);
			pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

			// Find matches
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_found, 0, NULL, NULL);
			pclFinish(param->queue);

			// GPU found some passwords
			if (num_found)
				ocl_common_process_found(param, &num_found, get_key, buffer, num_work_items, num_keys_filled);
		}
	}

	if (continue_attack)
	{
		num_keys_filled -= num_keys_reported;
		if (num_keys_filled > 0)
			report_keys_processed(num_keys_filled);
	}
	else
		report_keys_processed(-num_keys_reported);
}
extern const char* sha1_array_body;
extern const char* sha1_process_sha1_body;
PRIVATE char* ocl_gen_kernels(GPUDevice* gpu, oclKernel2Common* ocl_kernel_provider, OpenCL_Param* param, int multiplier)
{
	// Generate code
	char* source = malloc(64 * 1024 * multiplier);
	source[0] = 0;
	// Header definitions
	//if(num_passwords_loaded > 1 )
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");

	sprintf(source+strlen(source), "#define bs(c,b,a) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
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
	
	//Initial values
	sprintf(source+strlen(source),
"#define INIT_A 0x67452301\n"
"#define INIT_B 0xefcdab89\n"
"#define INIT_C 0x98badcfe\n"
"#define INIT_D 0x10325476\n"
"#define INIT_E 0xC3D2E1F0\n"

"#define SQRT_2 0x5a827999\n"
"#define SQRT_3 0x6ed9eba1\n"
"#define CONST3 0x8F1BBCDC\n"
"#define CONST4 0xCA62C1D6\n"

"#define LOAD_BIG_ENDIAN(x) x=rotate(x,16U);x=((x&0x00FF00FF)<<8U)+((x>>8U)&0x00FF00FF);\n"

"#define IPAD_STATE		0\n"
"#define OPAD_STATE		5\n"
"#define SHA1_HASH		10\n"
"#define CRYPT_RESULT	15\n"
"#define GET_DATA(STATE,index) current_key[(STATE+index)*%uu+idx]\n"
"#define NUM_KEYS_OPENCL %uu\n"
, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL);

	sprintf(source+strlen(source),
	"#ifdef __ENDIAN_LITTLE__\n"
		//little-endian
		"#define GET_1(x) ((((x)<<8u)&0xff0000)+((x)&0xff))\n"
		"#define GET_2(x) ((((x)>>8u)&0xff0000)+(((x)>>16u)&0xff))\n"
	"#else\n"
		//big-endian
		"#define GET_1(x) ((((x)>>8u)&0xff0000)+(((x)>>24u)&0xff))\n"
		"#define GET_2(x) ((((x)<<16u)&0xff0000)+(((x)>>8u)&0xff))\n"
	"#endif\n");

	ocl_kernel_provider->gen_kernel(source, param->NUM_KEYS_OPENCL);

	sprintf(source+strlen(source),
	"\n#define DCC2_R(w0,w1,w2,w3)	W[w0]=rotate((W[w0]^W[w1]^W[w2]^W[w3]),1U)\n"
"__kernel void dcc2_sha1_pad_mask(__global uint* current_key,uint state,uint flag)"
"{"
		"uint idx=get_global_id(0);"
		"uint W[16];"

		"W[0]=GET_DATA(CRYPT_RESULT,0)^flag;"
		"W[1]=GET_DATA(CRYPT_RESULT,1)^flag;"
		"W[2]=GET_DATA(CRYPT_RESULT,2)^flag;"
		"W[3]=GET_DATA(CRYPT_RESULT,3)^flag;"
		"for(uint i=4;i<16;i++)"
			"W[i]=flag;"

		"uint A=INIT_A;"
		"uint B=INIT_B;"
		"uint C=INIT_C;"
		"uint D=INIT_D;"
		"uint E=INIT_E;"

		"%s"

		"GET_DATA(state,0)=INIT_A+A;"
		"GET_DATA(state,1)=INIT_B+B;"
		"GET_DATA(state,2)=INIT_C+C;"
		"GET_DATA(state,3)=INIT_D+D;"
		"GET_DATA(state,4)=INIT_E+E;"
"}", sha1_array_body);

	sprintf(source+strlen(source),
"\n__kernel void sha1_process_salt(__global uint* current_key,const __global uint* salt_values,uint current_salt_index)"
"{"
		"uint idx=get_global_id(0);"
		"uint W[16];"

		//memcpy(&sha1_hash, &ipad_state, 5*sizeof(uint32_t));
		"uint A=GET_DATA(IPAD_STATE,0);"
		"uint B=GET_DATA(IPAD_STATE,1);"
		"uint C=GET_DATA(IPAD_STATE,2);"
		"uint D=GET_DATA(IPAD_STATE,3);"
		"uint E=GET_DATA(IPAD_STATE,4);"

		"GET_DATA(SHA1_HASH,0)=A;"
		"GET_DATA(SHA1_HASH,1)=B;"
		"GET_DATA(SHA1_HASH,2)=C;"
		"GET_DATA(SHA1_HASH,3)=D;"
		"GET_DATA(SHA1_HASH,4)=E;"

		// Process the salt
		"uint salt_len=(salt_values[current_salt_index*11+10]>>3)-16;"
		"for(uint i=0;i<16;i++)"
			"W[i]=0;"
				
		//memcpy(W, salt_buffer, salt_len);
		"uint i=0;"
		"for(;i<salt_len/4;i++)"
			"W[i]=salt_values[current_salt_index*11+i];"

		//memcpy(((unsigned char*)W)+salt_len, "\x0\x0\x0\x1\x80", 5);
		"if((salt_len&3)==0)"
		"{"
			"W[i]=0x1000000;"
			"W[i+1]=0x80;"
		"}else{"
			"W[i]=salt_values[current_salt_index*11+i] & 0x0000FFFF;"
			"W[i+1]=0x800100;"
		"}"
				
		"W[15]=(64+salt_len+4)<<3;"
		"for(i=0;i<14;i++)"
		"{"
			"LOAD_BIG_ENDIAN(W[i]);"
		"}"

		"%s"

		"GET_DATA(SHA1_HASH,0)+=A;"
		"GET_DATA(SHA1_HASH,1)+=B;"
		"GET_DATA(SHA1_HASH,2)+=C;"
		"GET_DATA(SHA1_HASH,3)+=D;"
		"GET_DATA(SHA1_HASH,4)+=E;"
"}", sha1_array_body);


	// Function definition
sprintf(source+strlen(source), "\n__kernel void ntlm_part(__global uint* current_key,__global uint* ntlm_values)"
								"{"
									"uint idx=get_global_id(0);"
									"uint a,b,c,d,xx;"
									"uint nt_buffer[16];");

	// Convert the key into a nt_buffer
sprintf(source + strlen(source),
				"b=current_key[7u*%uU+idx]>>4;"
				"if(b>27u)return;"
				"for(xx=0;xx<(b/4+1);xx++)"
				"{"
					"a=current_key[idx+xx*%uu];"
					"nt_buffer[2*xx]=GET_1(a);"
					"nt_buffer[2*xx+1]=GET_2(a);"
				"}", param->NUM_KEYS_OPENCL*multiplier, param->NUM_KEYS_OPENCL*multiplier);
	// Fill with zeros
sprintf(source + strlen(source), "xx*=2;"
							"for(;xx<14;xx++)"
								"nt_buffer[xx]=0;"
							"nt_buffer[14]=b<<4;");

		/* Round 1 */
sprintf(source+strlen(source), 
		"a=0xFFFFFFFF+nt_buffer[0];a<<=3u;"
		"d=INIT_D+bs(INIT_C,INIT_B,a)+nt_buffer[1];d=rotate(d,7u);"
		"c=INIT_C+bs(INIT_B,a,d)+nt_buffer[2];c=rotate(c,11u);"
		"b=INIT_B+bs(a,d,c)+nt_buffer[3];b=rotate(b,19u);"

		"a+=bs(d,c,b)+nt_buffer[4];a=rotate(a,3u);"
		"d+=bs(c,b,a)+nt_buffer[5];d=rotate(d,7u);"
		"c+=bs(b,a,d)+nt_buffer[6];c=rotate(c,11u);"
		"b+=bs(a,d,c)+nt_buffer[7];b=rotate(b,19u);"

		"a+=bs(d,c,b)+nt_buffer[8];a=rotate(a,3u);"
		"d+=bs(c,b,a)+nt_buffer[9];d=rotate(d,7u);"
		"c+=bs(b,a,d)+nt_buffer[10];c=rotate(c,11u);"
		"b+=bs(a,d,c)+nt_buffer[11];b=rotate(b,19u);"

		"a+=bs(d,c,b)+nt_buffer[12];a=rotate(a,3u);"
		"d+=bs(c,b,a)+nt_buffer[13];d=rotate(d,7u);"
		"c+=bs(b,a,d)+nt_buffer[14];c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);");

		/* Round 2 */
sprintf(source+strlen(source),
		"a+=MAJ(b,c,d)+nt_buffer[0]+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+nt_buffer[4]+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+nt_buffer[8]+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+nt_buffer[12]+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+nt_buffer[1]+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+nt_buffer[5]+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+nt_buffer[9]+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+nt_buffer[13]+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+nt_buffer[2]+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+nt_buffer[6]+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+nt_buffer[10]+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+nt_buffer[14]+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+nt_buffer[3]+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+nt_buffer[7]+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+nt_buffer[11]+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+SQRT_2;b=rotate(b,13u);");

		/* Round 3 */
sprintf(source+strlen(source),
		"xx=c^b;"
		"a+=(d^xx)+nt_buffer[0]+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)+nt_buffer[8]+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)+nt_buffer[4]+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)+nt_buffer[12]+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)+nt_buffer[2]+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)+nt_buffer[10]+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)+nt_buffer[6]+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)+nt_buffer[14]+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)+nt_buffer[1]+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)+nt_buffer[9]+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)+nt_buffer[5]+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)+nt_buffer[13]+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)+nt_buffer[3]+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)+nt_buffer[11]+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)+nt_buffer[7]+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)+SQRT_3;b=rotate(b,15u);");

		// End key hashing
sprintf(source+strlen(source),	"ntlm_values[0*NUM_KEYS_OPENCL+idx]=a+%uU;"
								"ntlm_values[1*NUM_KEYS_OPENCL+idx]=b+%uU;"
								"ntlm_values[2*NUM_KEYS_OPENCL+idx]=c+%uU;"
								"ntlm_values[3*NUM_KEYS_OPENCL+idx]=d+%uU;"
						"}", 0x67452300/*INIT_A+0xFFFFFFFF*/, INIT_B+INIT_D, 0x3175B9FC/*INIT_C+INIT_C*/, INIT_D+INIT_B);

// Function definition
sprintf(source + strlen(source), "\n__kernel void dcc_part(__global uint* current_key,const __global uint* ntlm_values,const __global uint* salt_values,uint current_salt_index)"
	"{"
		"uint idx=get_global_id(0);"
		"uint a,b,c,d,xx;"
		
		"uint crypt_a=ntlm_values[0*NUM_KEYS_OPENCL+idx];"
		"uint crypt_b=ntlm_values[1*NUM_KEYS_OPENCL+idx];"
		"uint crypt_c=ntlm_values[2*NUM_KEYS_OPENCL+idx];"
		"uint crypt_d=ntlm_values[3*NUM_KEYS_OPENCL+idx];");

//Another MD4_crypt for the salt
strcat(source,	"a=rotate(crypt_a,3u);"
				"d=(INIT_C^(a&0x77777777))+crypt_b;d=rotate(d,7u);"
				"c=bs(INIT_B,a,d)+crypt_c;c=rotate(c,11u);"
				"b=bs(a,d,c)+crypt_d;b=rotate(b,19u);");

		/* Round 1 */
sprintf(source+strlen(source),
		"a+=bs(d,c,b)+salt_values[current_salt_index*11+0];a=rotate(a,3u);"
		"d+=bs(c,b,a)+salt_values[current_salt_index*11+1];d=rotate(d,7u);"
		"c+=bs(b,a,d)+salt_values[current_salt_index*11+2];c=rotate(c,11u);"
		"b+=bs(a,d,c)+salt_values[current_salt_index*11+3];b=rotate(b,19u);"

		"a+=bs(d,c,b)+salt_values[current_salt_index*11+4];a=rotate(a,3u);"
		"d+=bs(c,b,a)+salt_values[current_salt_index*11+5];d=rotate(d,7u);"
		"c+=bs(b,a,d)+salt_values[current_salt_index*11+6];c=rotate(c,11u);"
		"b+=bs(a,d,c)+salt_values[current_salt_index*11+7];b=rotate(b,19u);"

		"a+=bs(d,c,b)+salt_values[current_salt_index*11+8];a=rotate(a,3u);"
		"d+=bs(c,b,a)+salt_values[current_salt_index*11+9];d=rotate(d,7u);"
		"c+=bs(b,a,d)+salt_values[current_salt_index*11+10];c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);");

		/* Round 2 */
sprintf(source+strlen(source),
		"a+=MAJ(b,c,d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+salt_values[current_salt_index*11+0]+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+salt_values[current_salt_index*11+4]+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+salt_values[current_salt_index*11+8]+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_b+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+salt_values[current_salt_index*11+1]+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+salt_values[current_salt_index*11+5]+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+salt_values[current_salt_index*11+9]+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+salt_values[current_salt_index*11+2]+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+salt_values[current_salt_index*11+6]+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+salt_values[current_salt_index*11+10]+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)+crypt_d+%uU;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)+salt_values[current_salt_index*11+3]+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)+salt_values[current_salt_index*11+7]+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+SQRT_2;b=rotate(b,13u);"
		, SQRT_2-0xFFFFFFFF, SQRT_2-INIT_D, SQRT_2-INIT_C, SQRT_2-INIT_B);

		/* Round 3 */
sprintf(source+strlen(source),
		"xx=c^b;"
		"a+=(xx^d)+crypt_a+%uU;a=rotate(a,3u);"
		"d+=(a^xx)+salt_values[current_salt_index*11+4]+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)+salt_values[current_salt_index*11+0]+SQRT_3;c=rotate(c,11u);"
		"b+=(c^xx)+salt_values[current_salt_index*11+8]+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(xx^d)+crypt_c+%uU;a=rotate(a,3u);"
		"d+=(a^xx)+salt_values[current_salt_index*11+6]+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)+salt_values[current_salt_index*11+2]+SQRT_3;c=rotate(c,11u);"
		"b+=(c^xx)+salt_values[current_salt_index*11+10]+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(xx^d)+crypt_b+%uU;a=rotate(a,3u);"
		"d+=(a^xx)+salt_values[current_salt_index*11+5]+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)+salt_values[current_salt_index*11+1]+SQRT_3;c=rotate(c,11u);"
		"b+=(c^xx)+salt_values[current_salt_index*11+9]+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(xx^d)+crypt_d+%uU;a=rotate(a,3u);"
		"d+=(a^xx)+salt_values[current_salt_index*11+7]+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(xx^b)+salt_values[current_salt_index*11+3]+SQRT_3;c=rotate(c,11u);"
		"b+=(c^xx)+SQRT_3;b=rotate(b,15u);xx=c^b;"
													
		"a+=INIT_A;"
		"b+=INIT_B;"
		"c+=INIT_C;"
		"d+=INIT_D;"
		, SQRT_3-0xFFFFFFFF, SQRT_3-INIT_C, SQRT_3-INIT_D, SQRT_3-INIT_B);

sprintf(source+strlen(source),
		"LOAD_BIG_ENDIAN(a);"
		"LOAD_BIG_ENDIAN(b);"
		"LOAD_BIG_ENDIAN(c);"
		"LOAD_BIG_ENDIAN(d);"
		
		"GET_DATA(CRYPT_RESULT,0)=a;"
		"GET_DATA(CRYPT_RESULT,1)=b;"
		"GET_DATA(CRYPT_RESULT,2)=c;"
		"GET_DATA(CRYPT_RESULT,3)=d;"
	"}");

sprintf(source + strlen(source), "\n#undef DCC2_R\n"
	"#define DCC2_R(w0,w1,w2,w3)	(W ## w0)=rotate((W ## w0)^(W ## w1)^(W ## w2)^(W ## w3),1U)\n"
	"\n__kernel void dcc2_sha1_opad(__global uint* current_key)"
		"{"
				"uint W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;"
				"uint idx=get_global_id(0);"

				"W0=GET_DATA(SHA1_HASH,0);"
				"W1=GET_DATA(SHA1_HASH,1);"
				"W2=GET_DATA(SHA1_HASH,2);"
				"W3=GET_DATA(SHA1_HASH,3);"
				"W4=GET_DATA(SHA1_HASH,4);"

				"uint A=GET_DATA(OPAD_STATE,0);"
				"uint B=GET_DATA(OPAD_STATE,1);"
				"uint C=GET_DATA(OPAD_STATE,2);"
				"uint D=GET_DATA(OPAD_STATE,3);"
				"uint E=GET_DATA(OPAD_STATE,4);"

				"%s"

				"A+=GET_DATA(OPAD_STATE,0);"
				"B+=GET_DATA(OPAD_STATE,1);"
				"C+=GET_DATA(OPAD_STATE,2);"
				"D+=GET_DATA(OPAD_STATE,3);"
				"E+=GET_DATA(OPAD_STATE,4);"

				"GET_DATA(SHA1_HASH,0)=A;"
				"GET_DATA(SHA1_HASH,1)=B;"
				"GET_DATA(SHA1_HASH,2)=C;"
				"GET_DATA(SHA1_HASH,3)=D;"
				"GET_DATA(SHA1_HASH,4)=E;"

				"GET_DATA(CRYPT_RESULT,0)=A;"
				"GET_DATA(CRYPT_RESULT,1)=B;"
				"GET_DATA(CRYPT_RESULT,2)=C;"
				"GET_DATA(CRYPT_RESULT,3)=D;"
		"}", sha1_process_sha1_body);

sprintf(source + strlen(source), 
	"\n__kernel void pbkdf2_hmac_sha1_cycle(__global uint* current_key,uint iter_count)"
		"{"
				"uint W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;"
				"uint idx=get_global_id(0);"

				"W0=GET_DATA(SHA1_HASH,0);"
				"W1=GET_DATA(SHA1_HASH,1);"
				"W2=GET_DATA(SHA1_HASH,2);"
				"W3=GET_DATA(SHA1_HASH,3);"
				"W4=GET_DATA(SHA1_HASH,4);"

				"uint ipad_state0=GET_DATA(IPAD_STATE,0);"
				"uint ipad_state1=GET_DATA(IPAD_STATE,1);"
				"uint ipad_state2=GET_DATA(IPAD_STATE,2);"
				"uint ipad_state3=GET_DATA(IPAD_STATE,3);"
				"uint ipad_state4=GET_DATA(IPAD_STATE,4);"

				"uint opad_state0=GET_DATA(OPAD_STATE,0);"
				"uint opad_state1=GET_DATA(OPAD_STATE,1);"
				"uint opad_state2=GET_DATA(OPAD_STATE,2);"
				"uint opad_state3=GET_DATA(OPAD_STATE,3);"
				"uint opad_state4=GET_DATA(OPAD_STATE,4);"

				"uint result0=GET_DATA(CRYPT_RESULT,0);"
				"uint result1=GET_DATA(CRYPT_RESULT,1);"
				"uint result2=GET_DATA(CRYPT_RESULT,2);"
				"uint result3=GET_DATA(CRYPT_RESULT,3);"

				"for(uint i=0;i<iter_count;i++){"

					"uint A=ipad_state0;"
					"uint B=ipad_state1;"
					"uint C=ipad_state2;"
					"uint D=ipad_state3;"
					"uint E=ipad_state4;"

					"%s"

					"W0=ipad_state0+A;"
					"W1=ipad_state1+B;"
					"W2=ipad_state2+C;"
					"W3=ipad_state3+D;"
					"W4=ipad_state4+E;"

					"A=opad_state0;"
					"B=opad_state1;"
					"C=opad_state2;"
					"D=opad_state3;"
					"E=opad_state4;"

					"%s"

					"W0=opad_state0+A;"
					"W1=opad_state1+B;"
					"W2=opad_state2+C;"
					"W3=opad_state3+D;"
					"W4=opad_state4+E;"

					"result0^=W0;"
					"result1^=W1;"
					"result2^=W2;"
					"result3^=W3;"
				"}"

				"GET_DATA(SHA1_HASH,0)=W0;"
				"GET_DATA(SHA1_HASH,1)=W1;"
				"GET_DATA(SHA1_HASH,2)=W2;"
				"GET_DATA(SHA1_HASH,3)=W3;"
				"GET_DATA(SHA1_HASH,4)=W4;"

				"GET_DATA(CRYPT_RESULT,0)=result0;"
				"GET_DATA(CRYPT_RESULT,1)=result1;"
				"GET_DATA(CRYPT_RESULT,2)=result2;"
				"GET_DATA(CRYPT_RESULT,3)=result3;"
			"}\n", sha1_process_sha1_body, sha1_process_sha1_body);

#ifndef HS_OCL_REDUCE_REGISTER_USE
sprintf(source + strlen(source), 
	"\n#define  GET_DATA_VEC(STATE,index) vload2((STATE+index)*NUM_KEYS_OPENCL/2+idx,current_key)\n"
	"#define  SET_DATA_VEC(STATE,index,data) vstore2(data,(STATE+index)*NUM_KEYS_OPENCL/2+idx,current_key)\n"
	"__kernel void pbkdf2_hmac_sha1_cycle_vec(__global uint* current_key,uint iter_count)"
		"{"
				"uint2 W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;"
				"uint idx=get_global_id(0);"

				"W0=GET_DATA_VEC(SHA1_HASH,0);"
				"W1=GET_DATA_VEC(SHA1_HASH,1);"
				"W2=GET_DATA_VEC(SHA1_HASH,2);"
				"W3=GET_DATA_VEC(SHA1_HASH,3);"
				"W4=GET_DATA_VEC(SHA1_HASH,4);"

				"uint2 ipad_state0=GET_DATA_VEC(IPAD_STATE,0);"
				"uint2 ipad_state1=GET_DATA_VEC(IPAD_STATE,1);"
				"uint2 ipad_state2=GET_DATA_VEC(IPAD_STATE,2);"
				"uint2 ipad_state3=GET_DATA_VEC(IPAD_STATE,3);"
				"uint2 ipad_state4=GET_DATA_VEC(IPAD_STATE,4);"

				"uint2 opad_state0=GET_DATA_VEC(OPAD_STATE,0);"
				"uint2 opad_state1=GET_DATA_VEC(OPAD_STATE,1);"
				"uint2 opad_state2=GET_DATA_VEC(OPAD_STATE,2);"
				"uint2 opad_state3=GET_DATA_VEC(OPAD_STATE,3);"
				"uint2 opad_state4=GET_DATA_VEC(OPAD_STATE,4);"

				"uint2 result0=GET_DATA_VEC(CRYPT_RESULT,0);"
				"uint2 result1=GET_DATA_VEC(CRYPT_RESULT,1);"
				"uint2 result2=GET_DATA_VEC(CRYPT_RESULT,2);"
				"uint2 result3=GET_DATA_VEC(CRYPT_RESULT,3);"

				"for(uint i=0;i<iter_count;i++){"

					"uint2 A=ipad_state0;"
					"uint2 B=ipad_state1;"
					"uint2 C=ipad_state2;"
					"uint2 D=ipad_state3;"
					"uint2 E=ipad_state4;"

					"%s"

					"W0=ipad_state0+A;"
					"W1=ipad_state1+B;"
					"W2=ipad_state2+C;"
					"W3=ipad_state3+D;"
					"W4=ipad_state4+E;"

					"A=opad_state0;"
					"B=opad_state1;"
					"C=opad_state2;"
					"D=opad_state3;"
					"E=opad_state4;"

					"%s"

					"W0=opad_state0+A;"
					"W1=opad_state1+B;"
					"W2=opad_state2+C;"
					"W3=opad_state3+D;"
					"W4=opad_state4+E;"

					"result0^=W0;"
					"result1^=W1;"
					"result2^=W2;"
					"result3^=W3;"
				"}"

				"SET_DATA_VEC(SHA1_HASH,0,W0);"
				"SET_DATA_VEC(SHA1_HASH,1,W1);"
				"SET_DATA_VEC(SHA1_HASH,2,W2);"
				"SET_DATA_VEC(SHA1_HASH,3,W3);"
				"SET_DATA_VEC(SHA1_HASH,4,W4);"

				"SET_DATA_VEC(CRYPT_RESULT,0,result0);"
				"SET_DATA_VEC(CRYPT_RESULT,1,result1);"
				"SET_DATA_VEC(CRYPT_RESULT,2,result2);"
				"SET_DATA_VEC(CRYPT_RESULT,3,result3);"
			"}", sha1_process_sha1_body, sha1_process_sha1_body);
#endif

if (num_passwords_loaded == num_diff_salts)
sprintf(source + strlen(source), "\n__kernel void dcc2_compare_result(__global uint* current_key,uint salt_index,__global uint* output,const __global uint* binary_values)"
		"{"
				"uint idx=get_global_id(0);"
				"if(GET_DATA(CRYPT_RESULT,0)==binary_values[4*salt_index+0]&&GET_DATA(CRYPT_RESULT,1)==binary_values[4*salt_index+1]&&GET_DATA(CRYPT_RESULT,2)==binary_values[4*salt_index+2]&&GET_DATA(CRYPT_RESULT,3)==binary_values[4*salt_index+3])"
				"{"
						"uint found=atomic_inc(output);"
						"output[2*found+1]=idx;"
						"output[2*found+2]=salt_index;"
				"}"
		"}");
else
sprintf(source + strlen(source), "\n__kernel void dcc2_compare_result(__global uint* current_key,uint current_salt_index,__global uint* output,const __global uint* binary_values,const __global uint* salt_index,const __global uint* same_salt_next)"
		"{\n"
				"uint idx=get_global_id(0);"
				"uint index=salt_index[current_salt_index];"
				"while(index!=0xffffffff)"
				"{"
					"if(GET_DATA(CRYPT_RESULT,0)==binary_values[4*index+0]&&GET_DATA(CRYPT_RESULT,1)==binary_values[4*index+1]&&GET_DATA(CRYPT_RESULT,2)==binary_values[4*index+2]&&GET_DATA(CRYPT_RESULT,3)==binary_values[4*index+3])"
					"{"
							"uint found=atomic_inc(output);"
							"output[2*found+1]=idx;"
							"output[2*found+2]=index;"
					"}"
					"index=same_salt_next[index];"
				"}"
		"}");

	return source;
}
PRIVATE int ocl_protocol_common_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc2_crypt, oclKernel2Common* ocl_kernel_provider, int use_rules)
{
	// Only one hash
	// For Intel HD 4600 best DIVIDER=1-2
	//  1	3.32K
	//	2	3.32K
	//	4	3.28K
	//	8	2.91K
	//	16	2.42K
	//	32	2.33K
	// For AMD HD 7970 best DIVIDER=1-3
	//  1	116K
	//	2	115K
	//	4	114K
	//	8	111K
	//	16	110K
	//	32	105K
	//	64	90.5K
	// For Nvidia GTX 590 best DIVIDER=1-32
	//  1	26.2K
	//	2	26.1K
	//	4	26.2K
	//	8	26.1K
	//	16	26.2K
	//	32	26.2K
	//	64	25.1K
	//	128	14.3K
	if (!ocl_init_slow_hashes(param, gpu_index, gen, gpu_dcc2_crypt, ocl_kernel_provider, use_rules, 5 + 5 + 5 + 4, BINARY_SIZE, SALT_SIZE, ocl_gen_kernels, ocl_work_body, 2))
		return FALSE;

	// Crypt Kernels
	create_kernel(param, KERNEL_INDEX_NTLM_PART					, "ntlm_part");
	create_kernel(param, KERNEL_INDEX_DCC_PART					, "dcc_part");
	create_kernel(param, KERNEL_INDEX_DCC2_SHA1_OPAD			, "dcc2_sha1_opad");
	create_kernel(param, KERNEL_INDEX_DCC2_COMPARE_RESULT		, "dcc2_compare_result");
	create_kernel(param, KERNEL_INDEX_DCC2_SHA1_PAD_MASK		, "dcc2_sha1_pad_mask");
	create_kernel(param, KERNEL_INDEX_SHA1_PROCESS_SALT			, "sha1_process_salt");
	create_kernel(param, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE	, "pbkdf2_hmac_sha1_cycle");
#ifndef HS_OCL_REDUCE_REGISTER_USE
	create_kernel(param, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC, "pbkdf2_hmac_sha1_cycle_vec");
#endif
	
	create_opencl_mem(param, GPU_ORDERED_KEYS , CL_MEM_READ_WRITE, 4*sizeof(cl_uint)*param->NUM_KEYS_OPENCL, NULL);
	if (num_diff_salts < num_passwords_loaded)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			create_opencl_mem(param, GPU_SALT_INDEX    , CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
		}
		else
		{
			create_opencl_mem(param, GPU_SALT_INDEX    , CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
	}

	// Set OpenCL kernel params
	int big_buffer_index = use_rules ? GPU_RULE_SLOW_BUFFER : GPU_CURRENT_KEY;
	pclSetKernelArg(param->kernels[KERNEL_INDEX_NTLM_PART], 0, sizeof(cl_mem), (void*)&param->mems[use_rules ? GPU_RULE_SLOW_TRANSFORMED_KEYS : big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_NTLM_PART], 1, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);

	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC_PART], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC_PART], 1, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC_PART], 2, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);

	pclSetKernelArg(param->kernels[KERNEL_INDEX_SHA1_PROCESS_SALT], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_SHA1_PROCESS_SALT], 1, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);

	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_PAD_MASK]			, 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_SHA1_OPAD]				, 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE]		, 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
#ifndef HS_OCL_REDUCE_REGISTER_USE
	pclSetKernelArg(param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC] , 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
#endif

	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 0, sizeof(cl_mem), (void*)&param->mems[big_buffer_index]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 2, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 3, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
	if (num_diff_salts < num_passwords_loaded)
	{
		pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 4, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_INDEX]);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_DCC2_COMPARE_RESULT], 5, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_SALT_NEXT]);
	}
	
	if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY) && num_diff_salts < num_passwords_loaded)
	{
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX], CL_FALSE, 0, 4 * num_passwords_loaded, salt_index, 0, NULL, NULL);
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, 4 * num_passwords_loaded, same_salt_next, 0, NULL, NULL);
	}
	pclFinish(param->queue);

	// Select best params
	ocl_best_workgroup_pbkdf2(param, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC);

	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc2_crypt)
{
	// Do not allow blank in GPU
	if (current_key_lenght == 0)
	{
		current_key_lenght = 1;
		report_keys_processed(1);

		cl_uint crypt_result[12], sha1_hash[5], opad_state[5], ipad_state[5], W[16];
		cl_uint* salt_buffer = (cl_uint*)salts_values;

		for (cl_uint i = 0; i < num_diff_salts; i++, salt_buffer += 11)
		{
			crypt_result[4] = 0x067eb187;
			crypt_result[5] = 0x66ce2570;
			crypt_result[6] = 0x9e29f7ff;
			crypt_result[7] = 0x7456a070;

			crypt_result[0] = 0xe0cfd631;
			crypt_result[1] = 0x31e96ad1;
			crypt_result[2] = 0xd7593cb7;
			crypt_result[3] = 0xc089c0e0;

			dcc_salt_part_c_code(salt_buffer, crypt_result);
			dcc2_body_c_code(salt_buffer, crypt_result, sha1_hash, opad_state, ipad_state, W);

			// Search for a match
			cl_uint index = salt_index[i];

			// Partial match
			while (index != NO_ELEM)
			{
				cl_uint* bin = ((cl_uint*)binary_values) + index * 4;

				// Total match
				if (crypt_result[8 + 0] == bin[0] && crypt_result[8 + 1] == bin[1] && crypt_result[8 + 2] == bin[2] && crypt_result[8 + 3] == bin[3])
					password_was_found(index, "");

				index = same_salt_next[index];
			}
		}
	}
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_dcc2_crypt, kernels2common + CHARSET_INDEX_IN_KERNELS, FALSE);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc2_crypt)
{
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_dcc2_crypt, kernels2common + PHRASES_INDEX_IN_KERNELS, FALSE);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc2_crypt)
{
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_dcc2_crypt, kernels2common + UTF8_INDEX_IN_KERNELS, FALSE);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
extern int provider_index;

PRIVATE int ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_dcc2_crypt)
{
	int i, kernel2common_index;

	// Find a compatible generate_key_funtion function for a given key_provider
	for (i = 0; i < LENGHT(key_providers[provider_index].impls); i++)
		for (kernel2common_index = 0; kernel2common_index < (int)num_kernels2common; kernel2common_index++)
			if (key_providers[provider_index].impls[i].protocol == kernels2common[kernel2common_index].protocol)
			{
				gen = key_providers[provider_index].impls[i].generate;
				goto out;
			}
out:
	return ocl_protocol_common_init(param, gpu_device_index, gen, gpu_dcc2_crypt, kernels2common + kernel2common_index, TRUE);
}
#endif

Format dcc2_format = {
	"DCC2"/*"MSCASH2"*/,
	"Domain Cache Credentials 2 (also know as MSCASH2).",
	"$DCC2$10240#",
	PLAINTEXT_LENGTH,
	BINARY_SIZE,
	SALT_SIZE,
	4,
	NULL,
	0,
	get_binary,
	binary2hex,
	DEFAULT_VALUE_MAP_INDEX,
	DEFAULT_VALUE_MAP_INDEX,
	dcc2_line_is_valid,
	add_hash_from_line,
	NULL,
#ifdef _M_X64
	{{CPU_CAP_AVX2, PROTOCOL_NTLM, crypt_ntlm_protocol_avx2}, {CPU_CAP_AVX, PROTOCOL_NTLM, crypt_ntlm_protocol_avx}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}},
#else
	#ifdef HS_ARM
		{{CPU_CAP_NEON, PROTOCOL_NTLM, crypt_ntlm_protocol_neon}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}},
	#else
		{{CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}},
	#endif
#endif

#ifdef HS_OPENCL_SUPPORT
	{{PROTOCOL_CHARSET_OCL_NO_ALIGNED, ocl_protocol_charset_init}, {PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init}, {PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init}, {PROTOCOL_UTF8, ocl_protocol_utf8_init}}
#endif
};
