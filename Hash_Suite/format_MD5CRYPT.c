// This file is part of Hash Suite password cracker,
// Copyright (c) 2016-2020 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

//Initial values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define BINARY_SIZE			16
#define SALT_SIZE           12
#define MD5_MAX_KEY_LENGHT	15

typedef struct {
	uint8_t salt[8];
	uint8_t saltlen;
	uint8_t prefix;		/** 0 when $1$, 1 when $apr1$ or 2 for {smd5} which uses no prefix. **/
	uint8_t prefix_len;
	uint8_t unused;
} crypt_md5_salt;

PRIVATE char* prefixs[] = {"$1$", "$apr1$", ""};

PRIVATE int is_valid(char* user_name, char* ciphertext, char* unused, char* unused1)
{
	if (user_name && ciphertext)
	{
		if (strncmp(ciphertext, "$1$", 3))
		{
			if(strncmp(ciphertext, "$apr1$", 6) && strncmp(ciphertext, "{smd5}", 6))
				return FALSE;

			ciphertext += 3;
		}

		char *pos = strchr(ciphertext + 3, '$');

		if (!pos || pos > &ciphertext[11])
			return FALSE;

		if (!valid_base64_string(pos + 1, 22))
			return FALSE;

		if (base64_to_num[*(pos + 22)] & 0x3C)
			return FALSE;

		return TRUE;
	}

	return FALSE;
}

PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* user_name, char* ciphertext, char* unused, char* unused1)
{
	if (user_name && ciphertext)
	{
		char* all_ciphertext = ciphertext;
		if (strncmp(ciphertext, "$1$", 3))
		{
			if (strncmp(ciphertext, "$apr1$", 6) && strncmp(ciphertext, "{smd5}", 6))
				return -1;

			ciphertext += 3;
		}

		char* pos = strchr(ciphertext + 3, '$');

		if (!pos || pos > &ciphertext[11])
			return -1;

		if (!valid_base64_string(pos + 1, 22))
			return -1;

		if (base64_to_num[*(pos + 22)] & 0x3C)
			return -1;

		return insert_hash_account1(param, user_name, all_ciphertext, MD5CRYPT_INDEX);
	}

	return -1;
}
#define TO_BINARY(b1, b2, b3) \
	value = \
		 (uint32_t)base64_to_num[pos[0]] | \
		((uint32_t)base64_to_num[pos[1]] << 6) | \
		((uint32_t)base64_to_num[pos[2]] << 12) | \
		((uint32_t)base64_to_num[pos[3]] << 18); \
	pos += 4; \
	out[b1] = value >> 16; \
	out[b2] = value >> 8; \
	out[b3] = value;
PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	// Binary
	unsigned char* out = (unsigned char*)binary;
	uint32_t value;

	const char* pos = ciphertext + 3;
	if (!strncmp(ciphertext, "$apr1$", 6) || !strncmp(ciphertext, "{smd5}", 6))
		pos = ciphertext + 6;

	while (*pos++ != '$');

	TO_BINARY(0, 6, 12);
	TO_BINARY(1, 7, 13);
	TO_BINARY(2, 8, 14);
	TO_BINARY(3, 9, 15);
	TO_BINARY(4, 10, 5);
	out[11] = ((uint32_t)base64_to_num[pos[0]]) | ((uint32_t)base64_to_num[pos[1]] << 6);

	// Salt
	crypt_md5_salt* out_salt = (crypt_md5_salt*)salt;
	out_salt->unused = 0;

	if (!strncmp(ciphertext, "$apr1$", 6))
	{
		out_salt->prefix = 1;
		out_salt->prefix_len = 6;
		pos = ciphertext + 6;
	}
	else if (!strncmp(ciphertext, "{smd5}", 6))
	{
		out_salt->prefix = 2;
		out_salt->prefix_len = 0;
		pos = ciphertext + 6;
	}
	else
	{
		out_salt->prefix = 0;
		out_salt->prefix_len = 3;
		pos = ciphertext + 3;
	}

	memset(out_salt->salt, 0, 8);
	for (out_salt->saltlen = 0; *pos != '$' && out_salt->saltlen < 8; out_salt->saltlen++)
		out_salt->salt[out_salt->saltlen] = *pos++;

	return ((uint32_t*)out)[0];
}
PRIVATE char* prefixs_show[] = { "$1$", "$apr1$", "{smd5}" };
#define TO_BASE64(b1, b2, b3) \
	value = out[b3] | (out[b2] << 8) | (out[b1] << 16);\
	\
	pos[0] = itoa64[(value    ) & 63];\
	pos[1] = itoa64[(value>>6 ) & 63];\
	pos[2] = itoa64[(value>>12) & 63];\
	pos[3] = itoa64[(value>>18) & 63];\
	pos += 4;
PRIVATE void binary2hex(const void* binary, const uint8_t* salt, unsigned char* ciphertext)
{
	// Salt
	crypt_md5_salt* out_salt = (crypt_md5_salt*)salt;

	sprintf((char*)ciphertext, "%s", prefixs_show[out_salt->prefix]);
	strncat(ciphertext, out_salt->salt, out_salt->saltlen);
	strcat(ciphertext, "$");

	// Binary
	char* pos = ciphertext + strlen(ciphertext);
	unsigned char* out = (unsigned char*)binary;
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

typedef void copy_pattern_same_size_func(void* pattern, const void* state);
PRIVATE uint8_t g[] = { 0, 7, 3, 5, 3, 7, 1, 6, 3, 5, 3, 7, 1, 7, 2, 5, 3, 7, 1, 7, 3, 4, 3, 7, 1, 7, 3, 5, 2, 7, 1, 7, 3, 5, 3, 6, 1, 7, 3, 5, 3, 7 };
PRIVATE void crypt_utf8_coalesc_protocol_body(CryptParam* param, process_block_asm_func* kernel_asm, uint32_t keys_in_parallel, copy_pattern_same_size_func* copy_asm[])
{
	uint32_t* buffer = (uint32_t*)_aligned_malloc((8 + 16*8 + 4) * sizeof(uint32_t) * keys_in_parallel + 64, 32);
	uint32_t* md5_buffer = buffer + 8 * keys_in_parallel;
	uint32_t* state = buffer + (8 + 16 * 8) * keys_in_parallel;
	uint8_t* simple_buffer = (uint8_t*)(state + 4 * keys_in_parallel);

	unsigned char key[MAX_KEY_LENGHT_SMALL];
	memset(buffer, 0, (8 + 16 * 8 + 4) * sizeof(uint32_t) * keys_in_parallel + 64);

	while (continue_attack && param->gen(buffer, keys_in_parallel, param->thread_id))
	{
		// Only accept valid keys
		for (uint32_t i = 7 * keys_in_parallel; i < (8*keys_in_parallel); i++)
			if (buffer[i] > (MD5_MAX_KEY_LENGHT << 3))
			{
				buffer[i] = MD5_MAX_KEY_LENGHT << 3;
				// Clear overflown length
				uint32_t key_index = i - 4 * keys_in_parallel;
				buffer[key_index] = (buffer[key_index] & 0x00FFFFFF) | (0x80 << 24);// pos=3
				buffer[key_index + 1*keys_in_parallel] = 0;// pos=4
				buffer[key_index + 2*keys_in_parallel] = 0;// pos=5
				buffer[key_index + 3*keys_in_parallel] = 0;// pos=6
			}

		for (uint32_t current_salt_index = 0; current_salt_index < num_diff_salts; current_salt_index++)
		{
			crypt_md5_salt salt = ((crypt_md5_salt*)salts_values)[current_salt_index];

			// First digest
			for (uint32_t i = 0; i < keys_in_parallel; i++)
			{
				memset(simple_buffer, 0, 64);
				utf8_coalesc2utf8_key(buffer, simple_buffer, keys_in_parallel, i);
				uint32_t len = (uint32_t)strlen(simple_buffer);
				
				memcpy(simple_buffer + len, salt.salt, salt.saltlen);
				memcpy(simple_buffer + len + salt.saltlen, simple_buffer, len);
				simple_buffer[2 * len + salt.saltlen] = 0x80;
				((uint32_t*)simple_buffer)[14] = (2 * len + salt.saltlen) << 3;

				for (uint32_t j = 0; j < 15; j++)
					md5_buffer[j*keys_in_parallel + i] = ((uint32_t*)simple_buffer)[j];
			}
			kernel_asm(state, md5_buffer);

			// Second digest
			for (uint32_t i = 0; i < keys_in_parallel; i++)
			{
				memset(simple_buffer, 0, 64);
				utf8_coalesc2utf8_key(buffer, simple_buffer, keys_in_parallel, i);
				uint32_t len = (uint32_t)strlen(simple_buffer);
				uint32_t buffer_len = len;
				memcpy(simple_buffer + buffer_len, prefixs[salt.prefix], strlen(prefixs[salt.prefix])); buffer_len += (uint32_t)strlen(prefixs[salt.prefix]);
				memcpy(simple_buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
				// Consider len < 16
				buffer_len += len;
				for (int j = 0, copy_len = len; j < 4 && copy_len > 0; j++, copy_len -= 4)
					memcpy(simple_buffer + buffer_len - copy_len, state+j*keys_in_parallel + i, __min(4, copy_len));

				for (uint32_t j = len; j > 0; j >>= 1, buffer_len++)
					simple_buffer[buffer_len] = (j & 1) ? 0 : simple_buffer[0];

				simple_buffer[buffer_len] = 0x80;
				((uint32_t*)simple_buffer)[14] = buffer_len << 3;

				for (uint32_t j = 0; j < 15; j++)
					md5_buffer[j*keys_in_parallel + i] = ((uint32_t*)simple_buffer)[j];
			}
			kernel_asm(state, md5_buffer);

			// Patterns--------------------------------------------------------------------
			memset(md5_buffer, 0, 16 * 8 * sizeof(uint32_t) * keys_in_parallel);
			//pattern[0]=alt pass
			memcpy(md5_buffer + 4 * keys_in_parallel, buffer, 16 * keys_in_parallel);
			for (uint32_t i = 0; i < keys_in_parallel; i++)
			{
				utf8_coalesc2utf8_key(buffer, key, keys_in_parallel, i);
				uint32_t md5_len = buffer[7 * keys_in_parallel + i];
				uint32_t len = md5_len >> 3;

				md5_buffer[(16 * 0 + 14) * keys_in_parallel + i] =   md5_len + (16 << 3);
				md5_buffer[(16 * 1 + 14) * keys_in_parallel + i] = 2*md5_len + (16 << 3);
				md5_buffer[(16 * 2 + 14) * keys_in_parallel + i] =   md5_len + ((16 + salt.saltlen) << 3);
				md5_buffer[(16 * 3 + 14) * keys_in_parallel + i] = 2*md5_len + ((16 + salt.saltlen) << 3);
				md5_buffer[(16 * 4 + 14) * keys_in_parallel + i] =   md5_len + (16 << 3);
				md5_buffer[(16 * 5 + 14) * keys_in_parallel + i] = 2*md5_len + (16 << 3);
				md5_buffer[(16 * 6 + 14) * keys_in_parallel + i] =   md5_len + ((16 + salt.saltlen) << 3);
				md5_buffer[(16 * 7 + 14) * keys_in_parallel + i] = 2*md5_len + ((16 + salt.saltlen) << 3);

				//pattern[1]=alt pass pass
				memset(simple_buffer, 0, 64-8-16);
				memcpy(simple_buffer, key, len);
				memcpy(simple_buffer + len, key, len);
				simple_buffer[2 * len] = 0x80;

				for (uint32_t j = 4; j < 14; j++)
					md5_buffer[(16 * 1 + j) * keys_in_parallel + i] = ((uint32_t*)simple_buffer)[j-4];
				//pattern[2]=alt salt pass
				memset(simple_buffer, 0, 64-8-16);

				memcpy(simple_buffer, salt.salt, salt.saltlen);
				memcpy(simple_buffer + salt.saltlen, key, len);
				simple_buffer[salt.saltlen+len] = 0x80;

				for (uint32_t j = 4; j < 14; j++)
					md5_buffer[(16 * 2 + j) * keys_in_parallel + i] = ((uint32_t*)simple_buffer)[j-4];
				//pattern[3]=alt salt pass pass
				memset(simple_buffer, 0, 64 - 8 - 16);

				memcpy(simple_buffer, salt.salt, salt.saltlen);
				memcpy(simple_buffer + salt.saltlen, key, len);
				memcpy(simple_buffer + salt.saltlen + len, key, len);
				simple_buffer[salt.saltlen + 2*len] = 0x80;

				for (uint32_t j = 4; j < 14; j++)
					md5_buffer[(16 * 3 + j) * keys_in_parallel + i] = ((uint32_t*)simple_buffer)[j-4];
				//pattern[6]=pass salt alt
				memcpy(simple_buffer, key, len);
				memcpy(simple_buffer + len, salt.salt, salt.saltlen);

				for (uint32_t j = 0; j < (len + salt.saltlen+3)/4; j++)
					md5_buffer[(16 * 6 + j) * keys_in_parallel + i] = ((uint32_t*)simple_buffer)[j];
				//pattern[7]=pass salt pass alt
				memcpy(simple_buffer, key, len);
				memcpy(simple_buffer + len, salt.salt, salt.saltlen);
				memcpy(simple_buffer + len + salt.saltlen, key, len);

				for (uint32_t j = 0; j < (2*len + salt.saltlen + 3) / 4; j++)
					md5_buffer[(16 * 7 + j) * keys_in_parallel + i] = ((uint32_t*)simple_buffer)[j];
			}
			//pattern[4]=pass alt
			memcpy(md5_buffer + 16*4 * keys_in_parallel, buffer, 16 * keys_in_parallel);
			//pattern[5]=pass pass alt
			memcpy(md5_buffer + 16 * 5 * keys_in_parallel, md5_buffer + (16 * 1 + 4) * keys_in_parallel, 16 * 2 * keys_in_parallel);
			// end patterns------------------------------------------------------------------

			uint32_t same_lenght = buffer[7 * keys_in_parallel];
			for (uint32_t i = 1; i < keys_in_parallel; i++)
				if (same_lenght != buffer[7 * keys_in_parallel + i])
				{
					same_lenght = NO_ELEM;
					break;
				}
			// Big cycle
			for (uint32_t k = 0, g_index = 0; k < 1000; k++, g_index++)
			{
				uint32_t* pattern_buffer = md5_buffer + 16 * keys_in_parallel*g[g_index];
				if (k & 1)// Copy at end
				{
					if (same_lenght == NO_ELEM)// Keys with different lenghts
					{
						for (uint32_t i = 0; i < keys_in_parallel; i++)
						{
							uint32_t len = (pattern_buffer[14 * keys_in_parallel + i] >> 3) - 16;
							uint32_t len3 = 8 * (len & 3);
							len = len / 4 * keys_in_parallel + i;

							if (len3)
							{
								uint32_t buffer_value = pattern_buffer[len] & (0xffffff >> (24 - len3));
								for (uint32_t j = 0; j < 4; j++, len += keys_in_parallel)
								{
									uint32_t state_value = state[j*keys_in_parallel + i];
									pattern_buffer[len] = buffer_value | (state_value << len3);
									buffer_value = state_value >> (32 - len3);
								}
								pattern_buffer[len] = buffer_value | (0x80 << len3);
							}
							else
							{
								for (uint32_t j = 0; j < 4; j++, len += keys_in_parallel)
									pattern_buffer[len] = state[j*keys_in_parallel + i];
								pattern_buffer[len] = 0x80;
							}
						}
					}
					else// All keys had same length
					{
						uint32_t len = (pattern_buffer[14 * keys_in_parallel] >> 3) - 16;
						uint32_t len3 = len & 3;
						len /= 4;

						if (len3)// Note: Use 3 versions of functions because register shifts are incredible expensive
							copy_asm[len3-1](pattern_buffer + len * keys_in_parallel, state);
						else
						{
							memcpy(pattern_buffer + len * keys_in_parallel, state, 16 * keys_in_parallel);
							for (uint32_t i = 0; i < keys_in_parallel; i++)
								pattern_buffer[(len + 4) * keys_in_parallel + i] = 0x80;
						}
					}
				}
				else// Copy at beginning
					memcpy(pattern_buffer, state, 16 * keys_in_parallel);

				kernel_asm(state, pattern_buffer);

				if (g_index == 41)
					g_index = -1;
			}
			
			// Search for a match
			uint32_t indx = salt_index[current_salt_index];

			while (indx != NO_ELEM)
			{
				uint32_t* bin = ((uint32_t*)binary_values) + indx * 4;

				for (uint32_t i = 0; i < keys_in_parallel; i++)
					// Total match
					if (bin[0] == state[i] && bin[1] == state[keys_in_parallel + i] && bin[2] == state[2 * keys_in_parallel + i] && bin[3] == state[3 * keys_in_parallel + i])
						password_was_found(indx, utf8_coalesc2utf8_key(buffer, key, keys_in_parallel, i));

				indx = same_salt_next[indx];
			}
		}

		report_keys_processed(keys_in_parallel);
	}

	_aligned_free(buffer);

	finish_thread();
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// C code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void md5_process_block(uint32_t* state, const void* block);
PRIVATE void md5_one_block_c_code(uint32_t* state, const void* block)
{
	state[0] = INIT_A;
	state[1] = INIT_B;
	state[2] = INIT_C;
	state[3] = INIT_D;
	md5_process_block(state, block);
}
#ifndef _M_X64
PRIVATE void copy_pattern_c_code_1(uint32_t* pattern, const uint32_t* state)
{
	uint32_t buffer_value = pattern[0] & 0xff;
	for (uint32_t j = 0; j < 4; j++, pattern++)
	{
		uint32_t state_value = state[j];
		pattern[0] = buffer_value | (state_value << 8);
		buffer_value = state_value >> 24;
	}
	pattern[0] = buffer_value | 0x8000;
}
PRIVATE void copy_pattern_c_code_2(uint32_t* pattern, const uint32_t* state)
{
	uint32_t buffer_value = pattern[0] & 0xffff;
	for (uint32_t j = 0; j < 4; j++, pattern++)
	{
		uint32_t state_value = state[j];
		pattern[0] = buffer_value | (state_value << 16);
		buffer_value = state_value >> 16;
	}
	pattern[0] = buffer_value | 0x800000;
}
PRIVATE void copy_pattern_c_code_3(uint32_t* pattern, const uint32_t* state)
{
	uint32_t buffer_value = pattern[0] & 0xffffff;
	for (uint32_t j = 0; j < 4; j++, pattern++)
	{
		uint32_t state_value = state[j];
		pattern[0] = buffer_value | (state_value << 24);
		buffer_value = state_value >> 8;
	}
	pattern[0] = buffer_value | 0x80000000;
}
PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_c_code[] = { copy_pattern_c_code_1, copy_pattern_c_code_2, copy_pattern_c_code_3 };
	crypt_utf8_coalesc_protocol_body(param, md5_one_block_c_code, 1, copy_pattern_c_code);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include "arch_simd.h"

#ifdef HS_X86
PRIVATE void md5_one_block_sse2(SSE2_WORD* state, const SSE2_WORD* block)
{
	/* Round 1 */
	SSE2_WORD a = SSE2_ADD(block[0], SSE2_CONST(0xd76aa477)); a = SSE2_ADD(SSE2_ROTATE(a, 7), SSE2_CONST(INIT_B));
	SSE2_WORD d = SSE2_3ADD(SSE2_XOR(SSE2_CONST(INIT_C), SSE2_AND(a, SSE2_CONST(0x77777777))), block[1 ], SSE2_CONST(0xf8fa0bcc)); d = SSE2_ADD(SSE2_ROTATE(d, 12), a);
	SSE2_WORD c = SSE2_3ADD(SSE2_XOR(SSE2_CONST(INIT_B), SSE2_AND(d, SSE2_XOR(a, SSE2_CONST(INIT_B)))), block[2 ], SSE2_CONST(0xbcdb4dd9)); c = SSE2_ADD(SSE2_ROTATE(c, 17), d);
	SSE2_WORD b = SSE2_3ADD(SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a))), block[3 ], SSE2_CONST(0xb18b7a77)); b = SSE2_ADD(SSE2_ROTATE(b, 22), c);

	a = SSE2_4ADD(a, SSE2_XOR(d, SSE2_AND(b, SSE2_XOR(c, d))), block[4 ], SSE2_CONST(0xf57c0faf)); a = SSE2_ADD(SSE2_ROTATE(a, 7), b);
	d = SSE2_4ADD(d, SSE2_XOR(c, SSE2_AND(a, SSE2_XOR(b, c))), block[5 ], SSE2_CONST(0x4787c62a)); d = SSE2_ADD(SSE2_ROTATE(d, 12), a);
	c = SSE2_4ADD(c, SSE2_XOR(b, SSE2_AND(d, SSE2_XOR(a, b))), block[6 ], SSE2_CONST(0xa8304613)); c = SSE2_ADD(SSE2_ROTATE(c, 17), d);
	b = SSE2_4ADD(b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a))), block[7 ], SSE2_CONST(0xfd469501)); b = SSE2_ADD(SSE2_ROTATE(b, 22), c);

	a = SSE2_4ADD(a, SSE2_XOR(d, SSE2_AND(b, SSE2_XOR(c, d))), block[8 ], SSE2_CONST(0x698098d8)); a = SSE2_ADD(SSE2_ROTATE(a, 7), b);
	d = SSE2_4ADD(d, SSE2_XOR(c, SSE2_AND(a, SSE2_XOR(b, c))), block[9 ], SSE2_CONST(0x8b44f7af)); d = SSE2_ADD(SSE2_ROTATE(d, 12), a);
	c = SSE2_4ADD(c, SSE2_XOR(b, SSE2_AND(d, SSE2_XOR(a, b))), block[10], SSE2_CONST(0xffff5bb1)); c = SSE2_ADD(SSE2_ROTATE(c, 17), d);
	b = SSE2_4ADD(b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a))), block[11], SSE2_CONST(0x895cd7be)); b = SSE2_ADD(SSE2_ROTATE(b, 22), c);

	a = SSE2_4ADD(a, SSE2_XOR(d, SSE2_AND(b, SSE2_XOR(c, d))), block[12], SSE2_CONST(0x6b901122)); a = SSE2_ADD(SSE2_ROTATE(a, 7), b);
	d = SSE2_4ADD(d, SSE2_XOR(c, SSE2_AND(a, SSE2_XOR(b, c))), block[13], SSE2_CONST(0xfd987193)); d = SSE2_ADD(SSE2_ROTATE(d, 12), a);
	c = SSE2_4ADD(c, SSE2_XOR(b, SSE2_AND(d, SSE2_XOR(a, b))), block[14], SSE2_CONST(0xa679438e)); c = SSE2_ADD(SSE2_ROTATE(c, 17), d);
	b = SSE2_3ADD(b, SSE2_XOR(a, SSE2_AND(c, SSE2_XOR(d, a)))           , SSE2_CONST(0x49b40821)); b = SSE2_ADD(SSE2_ROTATE(b, 22), c);

	/* Round 2 */
	a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_AND(d, SSE2_XOR(b, c))), block[1 ], SSE2_CONST(0xf61e2562)); a = SSE2_ADD(SSE2_ROTATE(a, 5), b);
	d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_AND(c, SSE2_XOR(a, b))), block[6 ], SSE2_CONST(0xc040b340)); d = SSE2_ADD(SSE2_ROTATE(d, 9), a);
	c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_AND(b, SSE2_XOR(d, a))), block[11], SSE2_CONST(0x265e5a51)); c = SSE2_ADD(SSE2_ROTATE(c, 14), d);
	b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_AND(a, SSE2_XOR(c, d))), block[0 ], SSE2_CONST(0xe9b6c7aa)); b = SSE2_ADD(SSE2_ROTATE(b, 20), c);

	a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_AND(d, SSE2_XOR(b, c))), block[5 ], SSE2_CONST(0xd62f105d)); a = SSE2_ADD(SSE2_ROTATE(a, 5), b);
	d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_AND(c, SSE2_XOR(a, b))), block[10], SSE2_CONST(0x02441453)); d = SSE2_ADD(SSE2_ROTATE(d, 9), a);
	c = SSE2_3ADD(c, SSE2_XOR(a, SSE2_AND(b, SSE2_XOR(d, a)))           , SSE2_CONST(0xd8a1e681)); c = SSE2_ADD(SSE2_ROTATE(c, 14), d);
	b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_AND(a, SSE2_XOR(c, d))), block[4 ], SSE2_CONST(0xe7d3fbc8)); b = SSE2_ADD(SSE2_ROTATE(b, 20), c);

	a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_AND(d, SSE2_XOR(b, c))), block[9 ], SSE2_CONST(0x21e1cde6)); a = SSE2_ADD(SSE2_ROTATE(a, 5), b);
	d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_AND(c, SSE2_XOR(a, b))), block[14], SSE2_CONST(0xc33707d6)); d = SSE2_ADD(SSE2_ROTATE(d, 9), a);
	c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_AND(b, SSE2_XOR(d, a))), block[3 ], SSE2_CONST(0xf4d50d87)); c = SSE2_ADD(SSE2_ROTATE(c, 14), d);
	b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_AND(a, SSE2_XOR(c, d))), block[8 ], SSE2_CONST(0x455a14ed)); b = SSE2_ADD(SSE2_ROTATE(b, 20), c);

	a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_AND(d, SSE2_XOR(b, c))), block[13], SSE2_CONST(0xa9e3e905)); a = SSE2_ADD(SSE2_ROTATE(a, 5), b);
	d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_AND(c, SSE2_XOR(a, b))), block[2 ], SSE2_CONST(0xfcefa3f8)); d = SSE2_ADD(SSE2_ROTATE(d, 9), a);
	c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_AND(b, SSE2_XOR(d, a))), block[7 ], SSE2_CONST(0x676f02d9)); c = SSE2_ADD(SSE2_ROTATE(c, 14), d);
	b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_AND(a, SSE2_XOR(c, d))), block[12], SSE2_CONST(0x8d2a4c8a)); b = SSE2_ADD(SSE2_ROTATE(b, 20), c);

	/* Round 3 */
	SSE2_WORD xx = SSE2_XOR(b, c);
	a = SSE2_4ADD(a, SSE2_XOR(xx, d), block[5 ], SSE2_CONST(0xfffa3942)); a = SSE2_ADD(SSE2_ROTATE(a, 4), b);
	d = SSE2_4ADD(d, SSE2_XOR(a, xx), block[8 ], SSE2_CONST(0x8771f681)); d = SSE2_ADD(SSE2_ROTATE(d, 11), a); xx = SSE2_XOR(d, a);
	c = SSE2_4ADD(c, SSE2_XOR(xx, b), block[11], SSE2_CONST(0x6d9d6122)); c = SSE2_ADD(SSE2_ROTATE(c, 16), d);
	b = SSE2_4ADD(b, SSE2_XOR(c, xx), block[14], SSE2_CONST(0xfde5380c)); b = SSE2_ADD(SSE2_ROTATE(b, 23), c); xx = SSE2_XOR(b, c);

	a = SSE2_4ADD(a, SSE2_XOR(xx, d), block[1 ], SSE2_CONST(0xa4beea44)); a = SSE2_ADD(SSE2_ROTATE(a, 4), b);
	d = SSE2_4ADD(d, SSE2_XOR(a, xx), block[4 ], SSE2_CONST(0x4bdecfa9)); d = SSE2_ADD(SSE2_ROTATE(d, 11), a); xx = SSE2_XOR(d, a);
	c = SSE2_4ADD(c, SSE2_XOR(xx, b), block[7 ], SSE2_CONST(0xf6bb4b60)); c = SSE2_ADD(SSE2_ROTATE(c, 16), d);
	b = SSE2_4ADD(b, SSE2_XOR(c, xx), block[10], SSE2_CONST(0xbebfbc70)); b = SSE2_ADD(SSE2_ROTATE(b, 23), c); xx = SSE2_XOR(b, c);

	a = SSE2_4ADD(a, SSE2_XOR(xx, d), block[13], SSE2_CONST(0x289b7ec6)); a = SSE2_ADD(SSE2_ROTATE(a, 4), b);
	d = SSE2_4ADD(d, SSE2_XOR(a, xx), block[0 ], SSE2_CONST(0xeaa127fa)); d = SSE2_ADD(SSE2_ROTATE(d, 11), a); xx = SSE2_XOR(d, a);
	c = SSE2_4ADD(c, SSE2_XOR(xx, b), block[3 ], SSE2_CONST(0xd4ef3085)); c = SSE2_ADD(SSE2_ROTATE(c, 16), d);
	b = SSE2_4ADD(b, SSE2_XOR(c, xx), block[6 ], SSE2_CONST(0x04881d05)); b = SSE2_ADD(SSE2_ROTATE(b, 23), c); xx = SSE2_XOR(b, c);

	a = SSE2_4ADD(a, SSE2_XOR(xx, d), block[9 ], SSE2_CONST(0xd9d4d039)); a = SSE2_ADD(SSE2_ROTATE(a, 4), b);
	d = SSE2_4ADD(d, SSE2_XOR(a, xx), block[12], SSE2_CONST(0xe6db99e5)); d = SSE2_ADD(SSE2_ROTATE(d, 11), a); xx = SSE2_XOR(d, a);
	c = SSE2_3ADD(c, SSE2_XOR(xx, b)           , SSE2_CONST(0x1fa27cf8)); c = SSE2_ADD(SSE2_ROTATE(c, 16), d);
	b = SSE2_4ADD(b, SSE2_XOR(c, xx), block[2 ], SSE2_CONST(0xc4ac5665)); b = SSE2_ADD(SSE2_ROTATE(b, 23), c);

	/* Round 4 */
	a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_OR(b, SSE2_NOT(d))), block[0 ], SSE2_CONST(0xf4292244)); a = SSE2_ADD(SSE2_ROTATE(a, 6), b);
	d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_OR(a, SSE2_NOT(c))), block[7 ], SSE2_CONST(0x432aff97)); d = SSE2_ADD(SSE2_ROTATE(d, 10), a);
	c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_OR(d, SSE2_NOT(b))), block[14], SSE2_CONST(0xab9423a7)); c = SSE2_ADD(SSE2_ROTATE(c, 15), d);
	b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_OR(c, SSE2_NOT(a))), block[5 ], SSE2_CONST(0xfc93a039)); b = SSE2_ADD(SSE2_ROTATE(b, 21), c);

	a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_OR(b, SSE2_NOT(d))), block[12], SSE2_CONST(0x655b59c3)); a = SSE2_ADD(SSE2_ROTATE(a, 6), b);
	d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_OR(a, SSE2_NOT(c))), block[3 ], SSE2_CONST(0x8f0ccc92)); d = SSE2_ADD(SSE2_ROTATE(d, 10), a);
	c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_OR(d, SSE2_NOT(b))), block[10], SSE2_CONST(0xffeff47d)); c = SSE2_ADD(SSE2_ROTATE(c, 15), d);
	b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_OR(c, SSE2_NOT(a))), block[1 ], SSE2_CONST(0x85845dd1)); b = SSE2_ADD(SSE2_ROTATE(b, 21), c);

	a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_OR(b, SSE2_NOT(d))), block[8 ], SSE2_CONST(0x6fa87e4f)); a = SSE2_ADD(SSE2_ROTATE(a, 6), b);
	d = SSE2_3ADD(d, SSE2_XOR(b, SSE2_OR(a, SSE2_NOT(c)))           , SSE2_CONST(0xfe2ce6e0)); d = SSE2_ADD(SSE2_ROTATE(d, 10), a);
	c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_OR(d, SSE2_NOT(b))), block[6 ], SSE2_CONST(0xa3014314)); c = SSE2_ADD(SSE2_ROTATE(c, 15), d);
	b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_OR(c, SSE2_NOT(a))), block[13], SSE2_CONST(0x4e0811a1)); b = SSE2_ADD(SSE2_ROTATE(b, 21), c);

	a = SSE2_4ADD(a, SSE2_XOR(c, SSE2_OR(b, SSE2_NOT(d))), block[4 ], SSE2_CONST(0xf7537e82)); a = SSE2_ADD(SSE2_ROTATE(a, 6), b);
	d = SSE2_4ADD(d, SSE2_XOR(b, SSE2_OR(a, SSE2_NOT(c))), block[11], SSE2_CONST(0xbd3af235)); d = SSE2_ADD(SSE2_ROTATE(d, 10), a);
	c = SSE2_4ADD(c, SSE2_XOR(a, SSE2_OR(d, SSE2_NOT(b))), block[2 ], SSE2_CONST(0x2ad7d2bb)); c = SSE2_ADD(SSE2_ROTATE(c, 15), d);
	b = SSE2_4ADD(b, SSE2_XOR(d, SSE2_OR(c, SSE2_NOT(a))), block[9 ], SSE2_CONST(0xeb86d391)); b = SSE2_ADD(SSE2_ROTATE(b, 21), c);

	state[0] = SSE2_ADD(a, SSE2_CONST(INIT_A));
	state[1] = SSE2_ADD(b, SSE2_CONST(INIT_B));
	state[2] = SSE2_ADD(c, SSE2_CONST(INIT_C));
	state[3] = SSE2_ADD(d, SSE2_CONST(INIT_D));
}
PRIVATE void copy_pattern_sse2_1(V128_WORD* pattern, const V128_WORD* state)
{
	V128_WORD buffer_value = V128_AND(V128_LOAD(pattern), V128_CONST(0xff));
	for (uint32_t j = 0; j < 4; j++, pattern++)
	{
		V128_WORD state_value = V128_LOAD(state + j);
		V128_STORE(pattern, V128_OR(buffer_value, V128_SL(state_value, 8)));
		buffer_value = V128_SR(state_value, 24);
	}
	V128_STORE(pattern, V128_OR(buffer_value, V128_CONST(0x8000)));
}
PRIVATE void copy_pattern_sse2_2(V128_WORD* pattern, const V128_WORD* state)
{
	V128_WORD buffer_value = V128_AND(V128_LOAD(pattern), V128_CONST(0xffff));
	for (uint32_t j = 0; j < 4; j++, pattern++)
	{
		V128_WORD state_value = V128_LOAD(state + j);
		V128_STORE(pattern, V128_OR(buffer_value, V128_SL(state_value, 16)));
		buffer_value = V128_SR(state_value, 16);
	}
	V128_STORE(pattern, V128_OR(buffer_value, V128_CONST(0x800000)));
}
PRIVATE void copy_pattern_sse2_3(V128_WORD* pattern, const V128_WORD* state)
{
	V128_WORD buffer_value = V128_AND(V128_LOAD(pattern), V128_CONST(0xffffff));
	for (uint32_t j = 0; j < 4; j++, pattern++)
	{
		V128_WORD state_value = V128_LOAD(state + j);
		V128_STORE(pattern, V128_OR(buffer_value, V128_SL(state_value, 24)));
		buffer_value = V128_SR(state_value, 8);
	}
	V128_STORE(pattern, V128_OR(buffer_value, V128_CONST(0x80000000)));
}
PRIVATE void crypt_utf8_coalesc_protocol_sse2(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_sse2[] = { copy_pattern_sse2_1, copy_pattern_sse2_2, copy_pattern_sse2_3 };
	crypt_utf8_coalesc_protocol_body(param, md5_one_block_sse2, 4, copy_pattern_sse2);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// V128 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void copy_pattern_v128_1(V128_WORD* pattern, const V128_WORD* state)
{
	V128_WORD buffer_value0 = V128_AND(V128_LOAD(pattern + 0), V128_CONST(0xff));
	V128_WORD buffer_value1 = V128_AND(V128_LOAD(pattern + 1), V128_CONST(0xff));
	for (uint32_t j = 0; j < 8; j += 2, pattern += 2)
	{
		V128_WORD state_value0 = V128_LOAD(state + j + 0);
		V128_WORD state_value1 = V128_LOAD(state + j + 1);
		V128_STORE(pattern + 0, V128_OR(buffer_value0, V128_SL(state_value0, 8)));
		V128_STORE(pattern + 1, V128_OR(buffer_value1, V128_SL(state_value1, 8)));
		buffer_value0 = V128_SR(state_value0, 24);
		buffer_value1 = V128_SR(state_value1, 24);
	}
	V128_STORE(pattern + 0, V128_OR(buffer_value0, V128_CONST(0x8000)));
	V128_STORE(pattern + 1, V128_OR(buffer_value1, V128_CONST(0x8000)));
}
PRIVATE void copy_pattern_v128_2(V128_WORD* pattern, const V128_WORD* state)
{
	V128_WORD buffer_value0 = V128_AND(V128_LOAD(pattern + 0), V128_CONST(0xffff));
	V128_WORD buffer_value1 = V128_AND(V128_LOAD(pattern + 1), V128_CONST(0xffff));
	for (uint32_t j = 0; j < 8; j += 2, pattern += 2)
	{
		V128_WORD state_value0 = V128_LOAD(state + j + 0);
		V128_WORD state_value1 = V128_LOAD(state + j + 1);
		V128_STORE(pattern + 0, V128_OR(buffer_value0, V128_SL(state_value0, 16)));
		V128_STORE(pattern + 1, V128_OR(buffer_value1, V128_SL(state_value1, 16)));
		buffer_value0 = V128_SR(state_value0, 16);
		buffer_value1 = V128_SR(state_value1, 16);
	}
	V128_STORE(pattern + 0, V128_OR(buffer_value0, V128_CONST(0x800000)));
	V128_STORE(pattern + 1, V128_OR(buffer_value1, V128_CONST(0x800000)));
}
PRIVATE void copy_pattern_v128_3(V128_WORD* pattern, const V128_WORD* state)
{
	V128_WORD buffer_value0 = V128_AND(V128_LOAD(pattern + 0), V128_CONST(0xffffff));
	V128_WORD buffer_value1 = V128_AND(V128_LOAD(pattern + 1), V128_CONST(0xffffff));
	for (uint32_t j = 0; j < 8; j += 2, pattern += 2)
	{
		V128_WORD state_value0 = V128_LOAD(state + j + 0);
		V128_WORD state_value1 = V128_LOAD(state + j + 1);
		V128_STORE(pattern + 0, V128_OR(buffer_value0, V128_SL(state_value0, 24)));
		V128_STORE(pattern + 1, V128_OR(buffer_value1, V128_SL(state_value1, 24)));
		buffer_value0 = V128_SR(state_value0, 8);
		buffer_value1 = V128_SR(state_value1, 8);
	}
	V128_STORE(pattern + 0, V128_OR(buffer_value0, V128_CONST(0x80000000)));
	V128_STORE(pattern + 1, V128_OR(buffer_value1, V128_CONST(0x80000000)));
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void md5_one_block_avx(void* state, const void* block);
PRIVATE void crypt_utf8_coalesc_protocol_avx(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_v128[] = { copy_pattern_v128_1, copy_pattern_v128_2, copy_pattern_v128_3 };
	crypt_utf8_coalesc_protocol_body(param, md5_one_block_avx, 8, copy_pattern_v128);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include "arch_avx2.h"

void md5_one_block_avx2(void* state, const void* block);
PRIVATE void copy_pattern_avx2_1(AVX2_WORD* pattern, const AVX2_WORD* state)
{
	AVX2_WORD buffer_value0 = AVX2_AND(AVX2_LOAD(pattern + 0), AVX2_CONST(0xff));
	AVX2_WORD buffer_value1 = AVX2_AND(AVX2_LOAD(pattern + 1), AVX2_CONST(0xff));
	for (uint32_t j = 0; j < 8; j+=2, pattern+=2)
	{
		AVX2_WORD state_value0 = AVX2_LOAD(state + j + 0);
		AVX2_WORD state_value1 = AVX2_LOAD(state + j + 1);
		AVX2_STORE(pattern + 0, AVX2_OR(buffer_value0, AVX2_SL(state_value0, 8)));
		AVX2_STORE(pattern + 1, AVX2_OR(buffer_value1, AVX2_SL(state_value1, 8)));
		buffer_value0 = AVX2_SR(state_value0, 24);
		buffer_value1 = AVX2_SR(state_value1, 24);
	}
	AVX2_STORE(pattern + 0, AVX2_OR(buffer_value0, AVX2_CONST(0x8000)));
	AVX2_STORE(pattern + 1, AVX2_OR(buffer_value1, AVX2_CONST(0x8000)));
}
PRIVATE void copy_pattern_avx2_2(AVX2_WORD* pattern, const AVX2_WORD* state)
{
	AVX2_WORD buffer_value0 = AVX2_AND(AVX2_LOAD(pattern + 0), AVX2_CONST(0xffff));
	AVX2_WORD buffer_value1 = AVX2_AND(AVX2_LOAD(pattern + 1), AVX2_CONST(0xffff));
	for (uint32_t j = 0; j < 8; j += 2, pattern += 2)
	{
		AVX2_WORD state_value0 = AVX2_LOAD(state + j + 0);
		AVX2_WORD state_value1 = AVX2_LOAD(state + j + 1);
		AVX2_STORE(pattern + 0, AVX2_OR(buffer_value0, AVX2_SL(state_value0, 16)));
		AVX2_STORE(pattern + 1, AVX2_OR(buffer_value1, AVX2_SL(state_value1, 16)));
		buffer_value0 = AVX2_SR(state_value0, 16);
		buffer_value1 = AVX2_SR(state_value1, 16);
	}
	AVX2_STORE(pattern + 0, AVX2_OR(buffer_value0, AVX2_CONST(0x800000)));
	AVX2_STORE(pattern + 1, AVX2_OR(buffer_value1, AVX2_CONST(0x800000)));
}
PRIVATE void copy_pattern_avx2_3(AVX2_WORD* pattern, const AVX2_WORD* state)
{
	AVX2_WORD buffer_value0 = AVX2_AND(AVX2_LOAD(pattern + 0), AVX2_CONST(0xffffff));
	AVX2_WORD buffer_value1 = AVX2_AND(AVX2_LOAD(pattern + 1), AVX2_CONST(0xffffff));
	for (uint32_t j = 0; j < 8; j += 2, pattern += 2)
	{
		AVX2_WORD state_value0 = AVX2_LOAD(state + j + 0);
		AVX2_WORD state_value1 = AVX2_LOAD(state + j + 1);
		AVX2_STORE(pattern + 0, AVX2_OR(buffer_value0, AVX2_SL(state_value0, 24)));
		AVX2_STORE(pattern + 1, AVX2_OR(buffer_value1, AVX2_SL(state_value1, 24)));
		buffer_value0 = AVX2_SR(state_value0, 8);
		buffer_value1 = AVX2_SR(state_value1, 8);
	}
	AVX2_STORE(pattern + 0, AVX2_OR(buffer_value0, AVX2_CONST(0x80000000)));
	AVX2_STORE(pattern + 1, AVX2_OR(buffer_value1, AVX2_CONST(0x80000000)));
}
PRIVATE void crypt_utf8_coalesc_protocol_avx2(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_avx2[] = { copy_pattern_avx2_1, copy_pattern_avx2_2, copy_pattern_avx2_3 };
	crypt_utf8_coalesc_protocol_body(param, md5_one_block_avx2, 16, copy_pattern_avx2);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Neon code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM
void md5_one_block_neon(void* state, const void* block);
PRIVATE void crypt_utf8_coalesc_protocol_neon(CryptParam* param)
{
	copy_pattern_same_size_func* copy_pattern_v128[] = { copy_pattern_v128_1, copy_pattern_v128_2, copy_pattern_v128_3 };
	crypt_utf8_coalesc_protocol_body(param, md5_one_block_neon, 8, copy_pattern_v128);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT

PRIVATE const char* md5_body =
	/* Round 1 */
	"a=0xd76aa477+block[0];a=rotate(a,7u)+INIT_B;"
	"d=(INIT_C^(a&0x77777777))+block[1]+0xf8fa0bcc;d=rotate(d,12u)+a;"
	"c=bs(INIT_B,a,d)+block[2]+0xbcdb4dd9;c=rotate(c,17u)+d;"
	"b=bs(a,d,c)+block[3]+0xb18b7a77;b=rotate(b,22u)+c;"

	"a+=bs(d,c,b)+block[4 ]+0xf57c0faf;a=rotate(a,7u )+b;"
	"d+=bs(c,b,a)+block[5 ]+0x4787c62a;d=rotate(d,12u)+a;"
	"c+=bs(b,a,d)+block[6 ]+0xa8304613;c=rotate(c,17u)+d;"
	"b+=bs(a,d,c)+block[7 ]+0xfd469501;b=rotate(b,22u)+c;"

	"a+=bs(d,c,b)+block[8 ]+0x698098d8;a=rotate(a,7u )+b;"
	"d+=bs(c,b,a)+block[9 ]+0x8b44f7af;d=rotate(d,12u)+a;"
	"c+=bs(b,a,d)+block[10]+0xffff5bb1;c=rotate(c,17u)+d;"
	"b+=bs(a,d,c)+block[11]+0x895cd7be;b=rotate(b,22u)+c;"

	"a+=bs(d,c,b)+block[12]+0x6b901122;a=rotate(a,7u )+b;"
	"d+=bs(c,b,a)+block[13]+0xfd987193;d=rotate(d,12u)+a;"
	"c+=bs(b,a,d)+block[14]+0xa679438e;c=rotate(c,17u)+d;"
	"b+=bs(a,d,c)          +0x49b40821;b=rotate(b,22u)+c;"

	/* Round 2 */
	"a+=bs(c,b,d)+block[1 ]+0xf61e2562;a=rotate(a,5u )+b;"
	"d+=bs(b,a,c)+block[6 ]+0xc040b340;d=rotate(d,9u )+a;"
	"c+=bs(a,d,b)+block[11]+0x265e5a51;c=rotate(c,14u)+d;"
	"b+=bs(d,c,a)+block[0 ]+0xe9b6c7aa;b=rotate(b,20u)+c;"

	"a+=bs(c,b,d)+block[5 ]+0xd62f105d;a=rotate(a,5u )+b;"
	"d+=bs(b,a,c)+block[10]+0x02441453;d=rotate(d,9u )+a;"
	"c+=bs(a,d,b)          +0xd8a1e681;c=rotate(c,14u)+d;"
	"b+=bs(d,c,a)+block[4 ]+0xe7d3fbc8;b=rotate(b,20u)+c;"

	"a+=bs(c,b,d)+block[9 ]+0x21e1cde6;a=rotate(a,5u )+b;"
	"d+=bs(b,a,c)+block[14]+0xc33707d6;d=rotate(d,9u )+a;"
	"c+=bs(a,d,b)+block[3 ]+0xf4d50d87;c=rotate(c,14u)+d;"
	"b+=bs(d,c,a)+block[8 ]+0x455a14ed;b=rotate(b,20u)+c;"

	"a+=bs(c,b,d)+block[13]+0xa9e3e905;a=rotate(a,5u )+b;"
	"d+=bs(b,a,c)+block[2 ]+0xfcefa3f8;d=rotate(d,9u )+a;"
	"c+=bs(a,d,b)+block[7 ]+0x676f02d9;c=rotate(c,14u)+d;"
	"b+=bs(d,c,a)+block[12]+0x8d2a4c8a;b=rotate(b,20u)+c;"

	/*Round 3 */
	"a+=(b^c ^d)+block[5 ]+0xfffa3942;a=rotate(a,4u )+b;"
	"d+=(a^b ^c)+block[8 ]+0x8771f681;d=rotate(d,11u)+a;"
	"c+=(d^a ^b)+block[11]+0x6d9d6122;c=rotate(c,16u)+d;"
	"b+=(c^d ^a)+block[14]+0xfde5380c;b=rotate(b,23u)+c;"

	"a+=(b^c ^d)+block[1 ]+0xa4beea44;a=rotate(a,4u )+b;"
	"d+=(a^b ^c)+block[4 ]+0x4bdecfa9;d=rotate(d,11u)+a;"
	"c+=(d^a ^b)+block[7 ]+0xf6bb4b60;c=rotate(c,16u)+d;"
	"b+=(c^d ^a)+block[10]+0xbebfbc70;b=rotate(b,23u)+c;"

	"a+=(b^c ^d)+block[13]+0x289b7ec6;a=rotate(a,4u )+b;"
	"d+=(a^b ^c)+block[0 ]+0xeaa127fa;d=rotate(d,11u)+a;"
	"c+=(d^a ^b)+block[3 ]+0xd4ef3085;c=rotate(c,16u)+d;"
	"b+=(c^d ^a)+block[6 ]+0x04881d05;b=rotate(b,23u)+c;"

	"a+=(b^c ^d)+block[9 ]+0xd9d4d039;a=rotate(a,4u )+b;"
	"d+=(a^b ^c)+block[12]+0xe6db99e5;d=rotate(d,11u)+a;"
	"c+=(d^a ^b)          +0x1fa27cf8;c=rotate(c,16u)+d;"
	"b+=(c^d ^a)+block[2 ]+0xc4ac5665;b=rotate(b,23u)+c;"

	/* Round 4 */
	"a+=I(c,b,d)+block[0 ]+0xf4292244;a=rotate(a,6u )+b;"
	"d+=I(b,a,c)+block[7 ]+0x432aff97;d=rotate(d,10u)+a;"
	"c+=I(a,d,b)+block[14]+0xab9423a7;c=rotate(c,15u)+d;"
	"b+=I(d,c,a)+block[5 ]+0xfc93a039;b=rotate(b,21u)+c;"

	"a+=I(c,b,d)+block[12]+0x655b59c3;a=rotate(a,6u )+b;"
	"d+=I(b,a,c)+block[3 ]+0x8f0ccc92;d=rotate(d,10u)+a;"
	"c+=I(a,d,b)+block[10]+0xffeff47d;c=rotate(c,15u)+d;"
	"b+=I(d,c,a)+block[1 ]+0x85845dd1;b=rotate(b,21u)+c;"

	"a+=I(c,b,d)+block[8 ]+0x6fa87e4f;a=rotate(a,6u )+b;"
	"d+=I(b,a,c)          +0xfe2ce6e0;d=rotate(d,10u)+a;"
	"c+=I(a,d,b)+block[6 ]+0xa3014314;c=rotate(c,15u)+d;"
	"b+=I(d,c,a)+block[13]+0x4e0811a1;b=rotate(b,21u)+c;"

	"a+=I(c,b,d)+block[4 ]+0xf7537e82;a=rotate(a,6u )+b;"
	"d+=I(b,a,c)+block[11]+0xbd3af235;d=rotate(d,10u)+a;"
	"c+=I(a,d,b)+block[2 ]+0x2ad7d2bb;c=rotate(c,15u)+d;"
	"b+=I(d,c,a)+block[9 ]+0xeb86d391;b=rotate(b,21u)+c;"

	"a+=INIT_A;"
	"b+=INIT_B;"
	"c+=INIT_C;"
	"d+=INIT_D;";

#define KERNEL_INDEX_INIT_PART			16
#define KERNEL_INDEX_MD5_CYCLE			17
#define KERNEL_INDEX_COMPARE_RESULT		18

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_work_body(OpenCL_Param* param, cl_uint lenght, cl_uint gpu_max_num_keys, cl_uint gpu_base_pos, cl_uint offset, size_t num_work_items)
{
	cl_uint num_found;

	// Init
	pclSetKernelArg(param->kernels[KERNEL_INDEX_INIT_PART], 3, sizeof(cl_uint), &gpu_base_pos);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_INIT_PART], 4, sizeof(cl_uint), &lenght);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_INIT_PART], 5, sizeof(cl_uint), &offset);
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_INIT_PART], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

	// MD5 cycle
	int md5_kernel_index = KERNEL_INDEX_MD5_CYCLE;
	int param_index = 5;
	if (param->param0)// Optimized case
	{
		md5_kernel_index = lenght;
		param_index = 3;
	}
	else// Generic case
	{
		pclSetKernelArg(param->kernels[KERNEL_INDEX_MD5_CYCLE], 3, sizeof(cl_uint), &gpu_base_pos);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_MD5_CYCLE], 4, sizeof(cl_uint), &lenght);
		param_index = 5;
	}

	pclSetKernelArg(param->kernels[md5_kernel_index], param_index, sizeof(cl_uint), &offset);
	pclEnqueueNDRangeKernel(param->queue, param->kernels[md5_kernel_index], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

	// Compare results
	pclSetKernelArg(param->kernels[KERNEL_INDEX_COMPARE_RESULT], 3, sizeof(cl_uint), &offset);
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_COMPARE_RESULT], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

	// Find matches
	pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);

	// GPU found some passwords
	if (num_found)
		ocl_slow_ordered_found(param, &num_found, gpu_max_num_keys, gpu_base_pos, lenght);
}
PRIVATE void ocl_gen_md5body_by_lenght(char* source, OpenCL_Param* param, cl_uint lenght)
{
	cl_uint gpu_pos_ordered_by_len[MD5_MAX_KEY_LENGHT + 1];
	char* blocks[] = { "+block0", "+block1", "+block2", "+block3", "+block4", "+block5", "+block6", "+block7", "+block8", "+block9", "+block10", "+block11", "+block12", "+block13" };

	// Size in uint
	for (cl_uint i = 0, j = 32; i <= MD5_MAX_KEY_LENGHT; i++)
	{
		gpu_pos_ordered_by_len[i] = j;
		j += (i + 3) / 4 * param->param1 * 2;
	}

	sprintf(source + strlen(source),
		"\n__kernel void md5crypt_cycle%u(__global uint* current_key,__global uint* current_data,__global uint* salts, uint offset)"
		"{"
			"uint idx=offset+get_global_id(0);", lenght);

	if (num_diff_salts == 1)
		sprintf(source + strlen(source), 
			"uint salt0=%uu;"
			"uint salt1=%uu;", ((uint32_t*)salts_values)[0], ((uint32_t*)salts_values)[1]);
	else
	{
		DivisionParams div_param = get_div_params(num_diff_salts);
		// Perform division
		if (div_param.magic)sprintf(source + strlen(source), "uint div=mul_hi(idx+%iu,%uu)>>%uu;", (int)div_param.sum_one, div_param.magic, div_param.shift);// Normal division
		else				sprintf(source + strlen(source), "uint div=idx>>%uu;", div_param.shift);// Power of two division

		sprintf(source + strlen(source), 
			"uint salt_index=3u*(idx-div*%uu);"
			"idx=div;"
			
			"uint salt0=salts[salt_index];"
			"uint salt1=salts[salt_index+1u];"
			, num_diff_salts);
	}

	sprintf(source + strlen(source), "uint a,b,c,d,block14;");

	// Handle block vars used
	cl_uint max_num_blocks = (2 * lenght + 24) / 4 + 1;
	for (cl_uint i = 0; i < max_num_blocks; i++)
		sprintf(source + strlen(source), "uint block%u=0;", i);
	for (cl_uint i = max_num_blocks; i < 14; i++)
		blocks[i] = "";

	// Load key
	for (cl_uint i = 0; i < (lenght + 3) / 4; i++)
		sprintf(source + strlen(source), "uint key%u=current_key[idx+%uu];", i, i * param->param1 * 2 + gpu_pos_ordered_by_len[lenght]);
	// Eliminate last 0x80
	if (lenght & 3)
		sprintf(source + strlen(source), "key%u&=%uu;", lenght/4, 0xffffff >> (24 - 8 * (lenght & 3)));

	sprintf(source + strlen(source),
			"a=GET_MD5_DATA(0);"
			"b=GET_MD5_DATA(1);"
			"c=GET_MD5_DATA(2);"
			"d=GET_MD5_DATA(3);"

			"for(uint i=0u;i<1000u;i++)"
			"{"
				"uint g_value=(i&1u)<<2u;"
				// Convert %3 and %7 tests converted to MULTIPLICATION_INVERSE and comparison: "Hackers Delight 2nd" Chapter 10-17
				"g_value|=((i*0xAAAAAAABu)>=0x55555555u)?2u:0u;"
				"g_value|=((i*0xB6DB6DB7u)>=0x24924924u)?1u:0u;"

				"switch(g_value)"
				"{");
	
	if (lenght & 3)
	{
		//pattern[0]=alt pass------------------------------------------
		sprintf(source + strlen(source),
					"case 0: block0=a;block1=b;block2=c;block3=d;");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i+4, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=key%u|%uu;"
						"block14=%uu;", lenght / 4 + 4, lenght / 4, 0x80<<(8*(lenght&3)), (16 + lenght) << 3);
		// Put zeros
		for (cl_uint i = lenght / 4 + 5; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[1]=alt pass pass------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 1: block0=a;block1=b;block2=c;block3=d;");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i+4, i);
		// End key-Begin key
		sprintf(source + strlen(source),
						"block%u=key%u|(key0<<%uu);", lenght/4+4, lenght/4, 8*(lenght&3));
		// Copy key again
		for (cl_uint i = 1; i < (lenght+3)/4; i++)
			sprintf(source + strlen(source),
						"block%u=bytealign(key%u,key%u,%uu);", lenght/4+4+i, i, i-1, 4-(lenght&3));
		// End data
		if ((lenght & 3) == 1) sprintf(source + strlen(source),
						"block%u|=0x800000u;", 2 * lenght / 4 + 4);
		if ((lenght & 3) == 2) sprintf(source + strlen(source),
						"block%u=0x80u;", 2 * lenght / 4 + 4);
		if ((lenght & 3) == 3) sprintf(source + strlen(source),
						"block%u=0x800000u|(key%u>>8u);", 2 * lenght / 4 + 4, lenght/4);
		// Lenght
		sprintf(source + strlen(source),
						"block14=%uu;", (16+2*lenght)<<3);
		// Put zeros
		for (cl_uint i = 2 * lenght / 4 + 5; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[2]=alt salt pass-------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 2: block0=a;block1=b;block2=c;block3=d;block4=salt0;block5=salt1;");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i+6, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=key%u|%uu;"
						"block14=%uu;", lenght / 4 + 6, lenght / 4, 0x80<<(8*(lenght&3)), (16 + 8 + lenght) << 3);
		// Put zeros
		for (cl_uint i = lenght / 4 + 7; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[3]=alt salt pass pass--------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 3: block0=a;block1=b;block2=c;block3=d;block4=salt0;block5=salt1;");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i+6, i);
		// End key-Begin key
		sprintf(source + strlen(source),
						"block%u=key%u|(key0<<%uu);", lenght/4+6, lenght/4, 8*(lenght&3));
		// Copy key again
		for (cl_uint i = 1; i < (lenght+3)/4; i++)
			sprintf(source + strlen(source),
						"block%u=bytealign(key%u,key%u,%uu);", lenght/4+6+i, i, i-1, 4-(lenght&3));
		// End data
		if ((lenght & 3) == 1) sprintf(source + strlen(source),
						"block%u|=0x800000u;", 2 * lenght / 4 + 6);
		if ((lenght & 3) == 2) sprintf(source + strlen(source),
						"block%u=0x80u;", 2 * lenght / 4 + 6);
		if ((lenght & 3) == 3) sprintf(source + strlen(source),
						"block%u=0x800000u|(key%u>>8u);", 2 * lenght / 4 + 6, lenght/4);
		// Lenght
		sprintf(source + strlen(source),
						"block14=%uu;", (16+8+2*lenght)<<3);
		//pattern[4]=pass alt------------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 4:");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=key%u|(a<<%uu);"
						"block%u=bytealign(b,a,%uu);"
						"block%u=bytealign(c,b,%uu);"
						"block%u=bytealign(d,c,%uu);"
						"block%u=(d>>%uu)|%uu;"
						"block14=%uu;"
						, lenght / 4, lenght / 4, 8*(lenght&3)
						, lenght / 4 + 1, 4-(lenght&3)
						, lenght / 4 + 2, 4-(lenght&3)
						, lenght / 4 + 3, 4-(lenght&3)
						, lenght / 4 + 4, 32 - 8 * (lenght & 3), 0x80<<(8 * (lenght & 3))
						, (16 + lenght) << 3);
		// Put zeros
		for (cl_uint i = lenght / 4 + 5; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[5]=pass pass alt-------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 5:");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i, i);
		// End key-Begin key
		sprintf(source + strlen(source),
						"block%u=key%u|(key0<<%uu);", lenght/4, lenght/4, 8*(lenght&3));
		// Copy key again
		for (cl_uint i = 1; i < (lenght+3)/4; i++)
			sprintf(source + strlen(source),
						"block%u=bytealign(key%u,key%u,%uu);", lenght/4+i, i, i-1, 4-(lenght&3));
		// End data
		if ((lenght & 3) == 1) sprintf(source + strlen(source),
						"block%u|=(a<<16u);"
						"block%u=bytealign(b,a,2u);"
						"block%u=bytealign(c,b,2u);"
						"block%u=bytealign(d,c,2u);"
						"block%u=(d>>16u)|0x800000u;"
						, 2 * lenght / 4 + 0
						, 2 * lenght / 4 + 1
						, 2 * lenght / 4 + 2
						, 2 * lenght / 4 + 3
						, 2 * lenght / 4 + 4);
		if ((lenght & 3) == 2) sprintf(source + strlen(source),
						"block%u=a;"
						"block%u=b;"
						"block%u=c;"
						"block%u=d;"
						"block%u=0x80u;"
						, 2 * lenght / 4 + 0
						, 2 * lenght / 4 + 1
						, 2 * lenght / 4 + 2
						, 2 * lenght / 4 + 3
						, 2 * lenght / 4 + 4);
		if ((lenght & 3) == 3) sprintf(source + strlen(source),
						"block%u=(key%u>>8u)|(a<<16u);"
						"block%u=bytealign(b,a,2u);"
						"block%u=bytealign(c,b,2u);"
						"block%u=bytealign(d,c,2u);"
						"block%u=(d>>16u)|0x800000u;"
						, 2 * lenght / 4 + 0, lenght / 4
						, 2 * lenght / 4 + 1
						, 2 * lenght / 4 + 2
						, 2 * lenght / 4 + 3
						, 2 * lenght / 4 + 4);
		// Lenght
		sprintf(source + strlen(source),
						"block14=%uu;", (16+2*lenght)<<3);
		// Put zeros
		for (cl_uint i = 2 * lenght / 4 + 5; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[6]=pass salt alt-------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 6:");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=key%u|(salt0<<%uu);"
						"block%u=bytealign(salt1,salt0,%uu);"
						"block%u=bytealign(a,salt1,%uu);"
						"block%u=bytealign(b,a,%uu);"
						"block%u=bytealign(c,b,%uu);"
						"block%u=bytealign(d,c,%uu);"
						"block%u=(d>>%uu)|%uu;"
						"block14=%uu;"
						, lenght / 4, lenght / 4, 8*(lenght&3)
						, lenght / 4 + 1, 4-(lenght&3)
						, lenght / 4 + 2, 4-(lenght&3)
						, lenght / 4 + 3, 4-(lenght&3)
						, lenght / 4 + 4, 4-(lenght&3)
						, lenght / 4 + 5, 4-(lenght&3)
						, lenght / 4 + 6, 32 - 8 * (lenght & 3), 0x80<<(8 * (lenght & 3))
						, (16 + 8 + lenght) << 3);
		// Put zeros
		for (cl_uint i = lenght / 4 + 7; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[7]=pass salt pass alt--------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 7:");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i, i);
		// End key-Begin key
		sprintf(source + strlen(source),
						"block%u=key%u|(salt0<<%uu);"
						"block%u=bytealign(salt1,salt0,%uu);"
						"block%u=bytealign(key0,salt1,%uu);"
						, lenght / 4, lenght / 4, 8 * (lenght & 3)
						, lenght / 4 + 1, 4-(lenght&3)
						, lenght / 4 + 2, 4-(lenght&3));
		// Copy key again
		for (cl_uint i = 1; i < (lenght+3)/4; i++)
			sprintf(source + strlen(source),
						"block%u=bytealign(key%u,key%u,%uu);", lenght/4+2+i, i, i-1, 4-(lenght&3));
		// End data
		if ((lenght & 3) == 1) sprintf(source + strlen(source),
						"block%u|=(a<<16u);"
						"block%u=bytealign(b,a,2u);"
						"block%u=bytealign(c,b,2u);"
						"block%u=bytealign(d,c,2u);"
						"block%u=(d>>16u)|0x800000u;"
						, 2 * lenght / 4 + 0+2
						, 2 * lenght / 4 + 1+2
						, 2 * lenght / 4 + 2+2
						, 2 * lenght / 4 + 3+2
						, 2 * lenght / 4 + 4+2);
		if ((lenght & 3) == 2) sprintf(source + strlen(source),
						"block%u=a;"
						"block%u=b;"
						"block%u=c;"
						"block%u=d;"
						"block%u=0x80u;"
						, 2 * lenght / 4 + 0 + 2
						, 2 * lenght / 4 + 1 + 2
						, 2 * lenght / 4 + 2 + 2
						, 2 * lenght / 4 + 3 + 2
						, 2 * lenght / 4 + 4 + 2);
		if ((lenght & 3) == 3) sprintf(source + strlen(source),
						"block%u=(key%u>>8u)|(a<<16u);"
						"block%u=bytealign(b,a,2u);"
						"block%u=bytealign(c,b,2u);"
						"block%u=bytealign(d,c,2u);"
						"block%u=(d>>16u)|0x800000u;"
						, 2 * lenght / 4 + 0 + 2, lenght / 4
						, 2 * lenght / 4 + 1 + 2
						, 2 * lenght / 4 + 2 + 2
						, 2 * lenght / 4 + 3 + 2
						, 2 * lenght / 4 + 4 + 2);
		// Lenght
		sprintf(source + strlen(source),
						"block14=%uu;", (16+8+2*lenght)<<3);
	}
	else
	{
		//pattern[0]=alt pass------------------------------------------
		sprintf(source + strlen(source),
					"case 0: block0=a;block1=b;block2=c;block3=d;");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i+4, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=0x80u;"
						"block14=%uu;", lenght / 4 + 4, (16+lenght)<<3);
		// Put zeros
		for (cl_uint i = lenght / 4 + 5; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[1]=alt pass pass--------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 1: block0=a;block1=b;block2=c;block3=d;");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;"
						"block%u=key%u;", i + 4, i, i + 4 + lenght / 4, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=0x80u;"
						"block14=%uu;", 2 * lenght / 4 + 4, (16+2*lenght)<<3);
		// Put zeros
		for (cl_uint i = 2*lenght / 4 + 5; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[2]=alt salt pass-------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 2: block0=a;block1=b;block2=c;block3=d;block4=salt0;block5=salt1;");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i+6, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=0x80u;"
						"block14=%uu;", lenght / 4 + 6, (16+8+lenght)<<3);
		// Put zeros
		for (cl_uint i = lenght / 4 + 7; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[3]=alt salt pass pass---------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 3: block0=a;block1=b;block2=c;block3=d;block4=salt0;block5=salt1;");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;"
						"block%u=key%u;", i + 6, i, i + 6 + lenght / 4, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=0x80u;"
						"block14=%uu;", 2*lenght / 4 + 6, (16+8+2*lenght)<<3);
		//pattern[4]=pass alt-------------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 4:");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=a; block%u=b;  block%u=c;  block%u=d;  block%u=0x80u;  block14=%uu;"
						, lenght/4, lenght/4+1, lenght/4+2, lenght/4+3, lenght/4+4, (16 + lenght) << 3);
		// Put zeros
		for (cl_uint i = lenght / 4 + 5; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[5]=pass pass alt--------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 5:");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;"
						"block%u=key%u;", i, i, lenght / 4 + i, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=a; block%u=b;  block%u=c;  block%u=d;  block%u=0x80u;  block14=%uu;"
						, 2*lenght/4, 2*lenght/4+1, 2*lenght/4+2, 2*lenght/4+3, 2*lenght/4+4, (16 + 2*lenght) << 3);
		// Put zeros
		for (cl_uint i = 2*lenght / 4 + 5; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[6]=pass salt alt--------------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 6:");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;", i, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=salt0; block%u=salt1; block%u=a; block%u=b;  block%u=c;  block%u=d;  block%u=0x80u;  block14=%uu;"
						, lenght/4,     lenght/4+1,   lenght/4+2, lenght/4+3, lenght/4+4, lenght/4+5, lenght/4+6, (16 + 8 + lenght) << 3);
		// Put zeros
		for (cl_uint i = lenght / 4 + 7; i < max_num_blocks; i++)
			sprintf(source + strlen(source),
						"block%u=0;", i);
		//pattern[7]=pass salt pass alt---------------------------------
		sprintf(source + strlen(source),
					"break;"
					"case 7:");
		// Copy key
		for (cl_uint i = 0; i < lenght/4; i++)
			sprintf(source + strlen(source),
						"block%u=key%u;"
						"block%u=key%u;", i, i, lenght / 4+2+i, i);
		// End data
		sprintf(source + strlen(source),
						"block%u=salt0; block%u=salt1;  block%u=a;   block%u=b;    block%u=c;    block%u=d;   block%u=0x80u;  block14=%uu;"
						, lenght/4,     lenght/4+1,   2*lenght/4+2, 2*lenght/4+3, 2*lenght/4+4, 2*lenght/4+5, 2*lenght/4+6, (16 + 8 + 2*lenght) << 3);
	}
	sprintf(source + strlen(source),
					"break;"
				"}");

	// MD5 body
	sprintf(source + strlen(source),
				/* Round 1 */
				"a=0xd76aa477+block0;a=rotate(a,7u)+INIT_B;"
				"d=(INIT_C^(a&0x77777777))+block1+0xf8fa0bcc;d=rotate(d,12u)+a;"
				"c=bs(INIT_B,a,d)+block2+0xbcdb4dd9;c=rotate(c,17u)+d;"
				"b=bs(a,d,c)+block3+0xb18b7a77;b=rotate(b,22u)+c;"

				"a+=bs(d,c,b)+block4+0xf57c0faf;a=rotate(a,7u)+b;"
				"d+=bs(c,b,a)+block5+0x4787c62a;d=rotate(d,12u)+a;"
				"c+=bs(b,a,d)+block6+0xa8304613;c=rotate(c,17u)+d;"
				"b+=bs(a,d,c)%s+0xfd469501;b=rotate(b,22u)+c;"

				"a+=bs(d,c,b)%s+0x698098d8;a=rotate(a,7u)+b;"
				"d+=bs(c,b,a)%s+0x8b44f7af;d=rotate(d,12u)+a;"
				"c+=bs(b,a,d)%s+0xffff5bb1;c=rotate(c,17u)+d;"
				"b+=bs(a,d,c)%s+0x895cd7be;b=rotate(b,22u)+c;"

				"a+=bs(d,c,b)%s+0x6b901122;a=rotate(a,7u)+b;"
				"d+=bs(c,b,a)%s+0xfd987193;d=rotate(d,12u)+a;"
				"c+=bs(b,a,d)+block14+0xa679438e;c=rotate(c,17u)+d;"
				"b+=bs(a,d,c)+0x49b40821;b=rotate(b,22u)+c;"
				, blocks[7], blocks[8], blocks[9], blocks[10], blocks[11], blocks[12], blocks[13]);
	/* Round 2 */
	sprintf(source + strlen(source),
				"a+=bs(c,b,d)+block1+0xf61e2562;a=rotate(a,5u)+b;"
				"d+=bs(b,a,c)+block6+0xc040b340;d=rotate(d,9u)+a;"
				"c+=bs(a,d,b)%s+0x265e5a51;c=rotate(c,14u)+d;"
				"b+=bs(d,c,a)+block0+0xe9b6c7aa;b=rotate(b,20u)+c;"

				"a+=bs(c,b,d)+block5+0xd62f105d;a=rotate(a,5u)+b;"
				"d+=bs(b,a,c)%s+0x02441453;d=rotate(d,9u)+a;"
				"c+=bs(a,d,b)+0xd8a1e681;c=rotate(c,14u)+d;"
				"b+=bs(d,c,a)+block4+0xe7d3fbc8;b=rotate(b,20u)+c;"

				"a+=bs(c,b,d)%s+0x21e1cde6;a=rotate(a,5u)+b;"
				"d+=bs(b,a,c)+block14+0xc33707d6;d=rotate(d,9u)+a;"
				"c+=bs(a,d,b)+block3 +0xf4d50d87;c=rotate(c,14u)+d;"
				"b+=bs(d,c,a)%s+0x455a14ed;b=rotate(b,20u)+c;"

				"a+=bs(c,b,d)%s+0xa9e3e905;a=rotate(a,5u)+b;"
				"d+=bs(b,a,c)+block2+0xfcefa3f8;d=rotate(d,9u)+a;"
				"c+=bs(a,d,b)%s+0x676f02d9;c=rotate(c,14u)+d;"
				"b+=bs(d,c,a)%s+0x8d2a4c8a;b=rotate(b,20u)+c;"
				, blocks[11], blocks[10], blocks[9], blocks[8], blocks[13], blocks[7], blocks[12]);
	/*Round 3 */
	sprintf(source + strlen(source),
				"uint xx=b^c;"
				"a+=(xx^d)+block5+0xfffa3942;a=rotate(a,4u)+b;"
				"d+=(a^xx)%s+0x8771f681;d=rotate(d,11u)+a;xx=d^a;"
				"c+=(xx^b)%s+0x6d9d6122;c=rotate(c,16u)+d;"
				"b+=(c^xx)+block14+0xfde5380c;b=rotate(b,23u)+c;xx=b^c;"

				"a+=(xx^d)+block1+0xa4beea44;a=rotate(a,4u)+b;"
				"d+=(a^xx)+block4+0x4bdecfa9;d=rotate(d,11u)+a;xx=d^a;"
				"c+=(xx^b)%s+0xf6bb4b60;c=rotate(c,16u)+d;"
				"b+=(c^xx)%s+0xbebfbc70;b=rotate(b,23u)+c;xx=b^c;"

				"a+=(xx^d)%s+0x289b7ec6;a=rotate(a,4u)+b;"
				"d+=(a^xx)+block0+0xeaa127fa;d=rotate(d,11u)+a;xx=d^a;"
				"c+=(xx^b)+block3+0xd4ef3085;c=rotate(c,16u)+d;"
				"b+=(c^xx)+block6+0x04881d05;b=rotate(b,23u)+c;xx=b^c;"

				"a+=(xx^d)%s+0xd9d4d039;a=rotate(a,4u)+b;"
				"d+=(a^xx)%s+0xe6db99e5;d=rotate(d,11u)+a;xx=d^a;"
				"c+=(xx^b)+0x1fa27cf8;c=rotate(c,16u)+d;"
				"b+=(c^xx)+block2+0xc4ac5665;b=rotate(b,23u)+c;"
				, blocks[8], blocks[11], blocks[7], blocks[10], blocks[13], blocks[9], blocks[12]);
	/* Round 4 */
	sprintf(source + strlen(source),
				"a+=I(c,b,d)+block0+0xf4292244;a=rotate(a,6u)+b;"
				"d+=I(b,a,c)%s+0x432aff97;d=rotate(d,10u)+a;"
				"c+=I(a,d,b)+block14+0xab9423a7;c=rotate(c,15u)+d;"
				"b+=I(d,c,a)+block5 +0xfc93a039;b=rotate(b,21u)+c;"

				"a+=I(c,b,d)%s+0x655b59c3;a=rotate(a,6u)+b;"
				"d+=I(b,a,c)+block3+0x8f0ccc92;d=rotate(d,10u)+a;"
				"c+=I(a,d,b)%s+0xffeff47d;c=rotate(c,15u)+d;"
				"b+=I(d,c,a)+block1+0x85845dd1;b=rotate(b,21u)+c;"

				"a+=I(c,b,d)%s+0x6fa87e4f;a=rotate(a,6u)+b;"
				"d+=I(b,a,c)+0xfe2ce6e0;d=rotate(d,10u)+a;"
				"c+=I(a,d,b)+block6+0xa3014314;c=rotate(c,15u)+d;"
				"b+=I(d,c,a)%s+0x4e0811a1;b=rotate(b,21u)+c;"

				"a+=I(c,b,d)+block4+0xf7537e82;a=rotate(a,6u)+b;"
				"d+=I(b,a,c)%s+0xbd3af235;d=rotate(d,10u)+a;"
				"c+=I(a,d,b)+block2+0x2ad7d2bb;c=rotate(c,15u)+d;"
				"b+=I(d,c,a)%s+0xeb86d391;b=rotate(b,21u)+c;"
				, blocks[7], blocks[12], blocks[10], blocks[8], blocks[13], blocks[11], blocks[9]);

	sprintf(source + strlen(source),
				"a+=INIT_A;"
				"b+=INIT_B;"
				"c+=INIT_C;"
				"d+=INIT_D;"
			"}"

			"GET_MD5_DATA(0)=a;"
			"GET_MD5_DATA(1)=b;"
			"GET_MD5_DATA(2)=c;"
			"GET_MD5_DATA(3)=d;"
		"}\n");
}
PRIVATE char* ocl_gen_kernels(GPUDevice* gpu, OpenCL_Param* param, int use_rules)
{
	// Generate code
	char* source = malloc(32 * 1024 * (1 + use_rules + MD5_MAX_KEY_LENGHT + 1));
	source[0] = 0;
	// Header definitions
	//if(num_passwords_loaded > 1 )
	strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");
	if (gpu->flags & GPU_FLAG_SUPPORT_AMD_OPS)
		strcat(source, "#pragma OPENCL EXTENSION cl_amd_media_ops : enable\n");

	sprintf(source + strlen(source), "#define bytealign(high,low,shift) (%s)\n", (gpu->flags & GPU_FLAG_SUPPORT_AMD_OPS) ? "amd_bytealign(high,low,shift)" : "((high<<(32u-shift*8u))|(low>>(shift*8u)))");
	// MD5 bit functions
	sprintf(source + strlen(source), "#define bs(c,b,a) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bitselect((c),(b),(a))" : "((c)^((a)&((b)^(c))))");
	sprintf(source + strlen(source), "#define I(y,x,z)  (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "(bitselect(0xffffffffU,(x),(z))^(y))" : "((y)^((x)|~(z)))");

	//Initial values
	sprintf(source + strlen(source),
		"#define INIT_A 0x67452301\n"
		"#define INIT_B 0xefcdab89\n"
		"#define INIT_C 0x98badcfe\n"
		"#define INIT_D 0x10325476\n"

		"#define GET_MD5_DATA(index) current_data[(%uu+index)*%uu+get_global_id(0)]\n"
		, use_rules ? 8 : 0, param->NUM_KEYS_OPENCL);

	sprintf(source + strlen(source), "\n#define PUTCHAR(buf, index, val) (buf)[(index)>>2u] = ((buf)[(index)>>2u] & ~(0xffU << (((index) & 3u) << 3u))) + ((val) << (((index) & 3u) << 3u))\n");
	// Prefixes
	sprintf(source + strlen(source), "\n__constant uint prefixs[]={0x243124,0,0x72706124,0x2431,0,0};");

	// Helpers
	sprintf(source + strlen(source), "\ninline void update_buffer(uint block[15],uint* data,uint data_len)"
		"{"
			"uint buffer_len=block[14];"
			"uint len3=8u*(buffer_len&3u);"
			"if(len3)"
			"{"
				"uint block_value=block[buffer_len/4] & (0xffffffu >> (24u - len3));"

				"for(uint i=0;i<((data_len+3)/4);i++){"
					"uint data_value = data[i];"
					"block[buffer_len/4 + i]= block_value | (data_value << len3);"
					"block_value=data_value>>(32u-len3);"
				"}"
				"block[buffer_len/4+((data_len+3)/4)]=block_value;"
			"}else{"
				"for(uint i=0;i<((data_len+3)/4);i++)"
					"block[buffer_len/4 + i]= data[i];"
			"}"
			"block[14]+=data_len;"
		"}");
	sprintf(source + strlen(source), "\ninline void update_buffer_global(uint block[15],__global uint* data, uint data_len)"
		"{"
			"uint buffer_len=block[14];"
			"uint len3=8u*(buffer_len&3u);"
			"if(len3)"
			"{"
				"uint block_value=block[buffer_len/4] & (0xffffffu >> (24u - len3));"

				"for(uint i=0;i<((data_len+3)/4);i++){"
					"uint data_value = data[i];"
					"block[buffer_len/4 + i]= block_value | (data_value << len3);"
					"block_value=data_value>>(32u-len3);"
				"}"
				"block[buffer_len/4+((data_len+3)/4)]=block_value;"
			"}else{"
				"for(uint i=0;i<((data_len+3)/4);i++)"
					"block[buffer_len/4 + i]= data[i];"
			"}"
			"block[14]+=data_len;"
		"}");
	sprintf(source + strlen(source), "\ninline void update_buffer_constant(uint block[15],__constant uint* data, uint data_len)"
		"{"
			"uint buffer_len=block[14];"
			"uint len3=8u*(buffer_len&3u);"
			"if(len3)"
			"{"
				"uint block_value=block[buffer_len/4] & (0xffffffu >> (24u - len3));"

				"for(uint i=0;i<((data_len+3)/4);i++){"
					"uint data_value = data[i];"
					"block[buffer_len/4 + i]= block_value | (data_value << len3);"
					"block_value=data_value>>(32u-len3);"
				"}"
				"block[buffer_len/4+((data_len+3)/4)]=block_value;"
			"}else{"
				"for(uint i=0;i<((data_len+3)/4);i++)"
					"block[buffer_len/4 + i]= data[i];"
			"}"
			"block[14]+=data_len;"
		"}");

	// Function definition
	sprintf(source + strlen(source),
		"\n__kernel void init_part(__global uint* current_key,__global uint* current_data,__global uint* salts, uint base_len, uint len, uint offset)"
		"{"
			"uint idx=offset+get_global_id(0);");

	if (num_diff_salts == 1)
		sprintf(source + strlen(source), "uint salt_index=0;");
	else
	{
		DivisionParams div_param = get_div_params(num_diff_salts);
		// Perform division
		if (div_param.magic)sprintf(source + strlen(source), "uint div=mul_hi(idx+%iu,%uu)>>%uu;", (int)div_param.sum_one, div_param.magic, div_param.shift);// Normal division
		else				sprintf(source + strlen(source), "uint div=idx>>%uu;", div_param.shift);// Power of two division

		sprintf(source + strlen(source),"uint salt_index=idx-div*%uu; idx=div;", num_diff_salts);
	}

	sprintf(source + strlen(source),
			"uint a,b,c,d;"
			"uint block[15];"

			// 1st digest
			"if(len>15u)return;"

			"for(uint i=0;i<((len+3u)/4u);i++)"
				"block[i]=current_key[idx+i*%uu+base_len];"
			"block[14] = len;", param->param1*2);
	
	sprintf(source + strlen(source),
			// Copy salt
			"update_buffer_global(block, salts+3u*salt_index, salts[3u*salt_index+2u] & 0xff);"
			// Copy key
			"update_buffer(block, block, len);"
			// End buffer
			"uint buffer_len=block[14];"
			"uint len3=8u*(buffer_len&3u);"

			"uint block_value=block[buffer_len/4] & (0xffffffu >> (24u - len3));"
			"block[buffer_len/4]=block_value | (0x80 << len3);"

			"for(uint i=buffer_len/4+1;i<14;i++)"
				"block[i]=0;"
			"block[14]=buffer_len<<3u;"

			// MD5 hash
			"%s", md5_body);

			// 2nd digest
	sprintf(source + strlen(source),
			"block[14] = len;"
			// Copy salt prefixs
			"update_buffer_constant(block, prefixs+2*((salts[3u*salt_index+2u]>>8u)&0xff), salts[3u*salt_index+2u] >> 16u);"
			// Copy salt
			"update_buffer_global(block, salts+3u*salt_index, salts[3u*salt_index+2u] & 0xff);"
			// Copy md5_state
			"block[10]=a;"
			"block[11]=b;"
			"block[12]=c;"
			"block[13]=d;"
			"update_buffer(block, block+10, len);"
			// End buffer
			"buffer_len=block[14];"
			// Key lenght dependand
			"for (uint i = len; i > 0u; i >>= 1u, buffer_len++)"
			"{"
				"uchar val = (i & 1u) ? 0 : (block[0] & 0xffu);"
				"PUTCHAR(block, buffer_len, val);"
			"}"

			"len3=8u*(buffer_len&3u);"

			"block_value=block[buffer_len/4] & (0xffffffu >> (24u - len3));"
			"block[buffer_len/4]=block_value | (0x80 << len3);"

			"for(uint i=buffer_len/4+1;i<14;i++)"
				"block[i]=0;"
			"block[14]=buffer_len<<3u;"

			// MD5 hash
			"%s", md5_body);

	sprintf(source + strlen(source), 
			"GET_MD5_DATA(0)=a;"
			"GET_MD5_DATA(1)=b;"
			"GET_MD5_DATA(2)=c;"
			"GET_MD5_DATA(3)=d;"
		"}");

	sprintf(source + strlen(source),
		"\n__kernel void md5crypt_cycle(__global uint* current_key,__global uint* current_data,__global uint* salts, uint base_len, uint len, uint offset)"
		"{"
			"uint idx=offset+get_global_id(0);");

	if (num_diff_salts == 1)
		sprintf(source + strlen(source), "uint salt_index=0;");
	else
	{
		DivisionParams div_param = get_div_params(num_diff_salts);
		// Perform division
		if (div_param.magic)sprintf(source + strlen(source), "uint div=mul_hi(idx+%iu,%uu)>>%uu;", (int)div_param.sum_one, div_param.magic, div_param.shift);// Normal division
		else				sprintf(source + strlen(source), "uint div=idx>>%uu;", div_param.shift);// Power of two division

		sprintf(source + strlen(source), "uint salt_index=idx-div*%uu; idx=div;", num_diff_salts);
	}
	sprintf(source + strlen(source),
		"uint salt0=salts[3u*salt_index];"
		"uint salt1=salts[3u*salt_index+1u];"
		"uint salt_size=salts[3u*salt_index+2u] & 0xff;");


	sprintf(source + strlen(source),
			"uint a,b,c,d;"
			"uint block[15];"
			"uint key0,key1,key2,key3;"

			"if(len>15u)return;"

			"key0=( len  ) ? current_key[idx       +base_len] : 0;"
			"key1=(len>4 ) ? current_key[idx+1u*%uu+base_len] : 0;"
			"key2=(len>8 ) ? current_key[idx+2u*%uu+base_len] : 0;"
			"key3=(len>12) ? current_key[idx+3u*%uu+base_len] : 0;"

			"a = GET_MD5_DATA(0);"
			"b = GET_MD5_DATA(1);"
			"c = GET_MD5_DATA(2);"
			"d = GET_MD5_DATA(3);"

			"for(uint i=0u;i<1000u;i++)"
			"{"
				"if (i & 1u)"
				"{"
					"block[0]=key0;"
					"block[1]=key1;"
					"block[2]=key2;"
					"block[3]=key3;"
					"block[14]=len;"
				"}else{"
					"block[0]=a;"
					"block[1]=b;"
					"block[2]=c;"
					"block[3]=d;"
					"block[14]=16u;"
				"}"
				"if (i %% 3u)"
				"{"
					"block[12]=salt0;"
					"block[13]=salt1;"
					"update_buffer(block, block+12, salt_size);"
				"}"
				"if (i %% 7u)"
				"{"
					"block[10]=key0;"
					"block[11]=key1;"
					"block[12]=key2;"
					"block[13]=key3;"
					"update_buffer(block, block+10, len);"
				"}"
				"if (i & 1u)"
				"{"
					"block[10]=a;"
					"block[11]=b;"
					"block[12]=c;"
					"block[13]=d;"
					"update_buffer(block, block+10, 16u);"
				"}else{"
					"block[10]=key0;"
					"block[11]=key1;"
					"block[12]=key2;"
					"block[13]=key3;"
					"update_buffer(block, block+10, len);"
				"}"
				
				 // End buffer
				"uint buffer_len=block[14];"
				"uint len3=8u*(buffer_len&3u);"

				"uint block_value=block[buffer_len/4] & (0xffffffu >> (24u - len3));"
				"block[buffer_len/4]=block_value | (0x80 << len3);"

				"for(uint i=buffer_len/4+1;i<14;i++)"
					"block[i]=0;"
				"block[14]=buffer_len<<3u;"

				"%s"
			"}"

			"GET_MD5_DATA(0)=a;"
			"GET_MD5_DATA(1)=b;"
			"GET_MD5_DATA(2)=c;"
			"GET_MD5_DATA(3)=d;"
		"}\n", param->param1 * 2, param->param1 * 2, param->param1 * 2, md5_body);

	if (num_passwords_loaded == num_diff_salts)
	{
		sprintf(source + strlen(source), "\n__kernel void compare_result(__global uint* current_data,__global uint* output,const __global uint* bin, uint offset)"
		"{"
			"uint idx=offset+get_global_id(0);");

		if (num_diff_salts == 1)
			sprintf(source + strlen(source), "uint salt_index=0;");
		else
		{
			DivisionParams div_param = get_div_params(num_diff_salts);
			// Perform division
			if (div_param.magic)sprintf(source + strlen(source), "uint div=mul_hi(idx+%iu,%uu)>>%uu;", (int)div_param.sum_one, div_param.magic, div_param.shift);// Normal division
			else				sprintf(source + strlen(source), "uint div=idx>>%uu;", div_param.shift);// Power of two division

			sprintf(source + strlen(source), "uint salt_index=idx-div*%uu; idx=div;", num_diff_salts);
		}
		sprintf(source + strlen(source),
			"if(GET_MD5_DATA(0)==bin[4u*salt_index+0]&&GET_MD5_DATA(1)==bin[4u*salt_index+1u]&&GET_MD5_DATA(2)==bin[4u*salt_index+2u]&&GET_MD5_DATA(3)==bin[4u*salt_index+3u])"
			"{"
				"uint found=atomic_inc(output);"
				"output[2*found+1]=idx;"
				"output[2*found+2]=salt_index;"
			"}"
		"}");
	}
	else
	{
		sprintf(source + strlen(source), "\n__kernel void compare_result(__global uint* current_data,__global uint* output,const __global uint* bin, uint offset,const __global uint* salt_index,const __global uint* same_salt_next)"
		"{"
			"uint idx=offset+get_global_id(0);");

		DivisionParams div_param = get_div_params(num_diff_salts);
		// Perform division
		if (div_param.magic)sprintf(source + strlen(source), "uint div=mul_hi(idx+%iu,%uu)>>%uu;", (int)div_param.sum_one, div_param.magic, div_param.shift);// Normal division
		else				sprintf(source + strlen(source), "uint div=idx>>%uu;", div_param.shift);// Power of two division

		sprintf(source + strlen(source), "uint current_salt_index=idx-div*%uu; idx=div;", num_diff_salts);

		sprintf(source + strlen(source),
			"uint index=salt_index[current_salt_index];"
			"while(index!=0xffffffff)"
			"{"
				"if(GET_MD5_DATA(0)==bin[4u*index]&&GET_MD5_DATA(1)==bin[4u*index+1u]&&GET_MD5_DATA(2)==bin[4u*index+2u]&&GET_MD5_DATA(3)==bin[4u*index+3u])"
				"{"
					"uint found=atomic_inc(output);"
					"output[2*found+1]=idx;"
					"output[2*found+2]=index;"
				"}"
				"index=same_salt_next[index];"
			"}"
		"}");
	}

	// Generate specific code for each lenght
	for (cl_uint i = 0; i <= MD5_MAX_KEY_LENGHT; i++)
		ocl_gen_md5body_by_lenght(source + strlen(source), param, i);

	//size_t len = strlen(source);
	return source;
}
PRIVATE int ocl_protocol_common_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, oclKernel2Common* ocl_kernel_provider, int use_rules)
{
	// Check if we can use optimize version
	cl_bool all_salt_lenght_8 = CL_TRUE;
	for (cl_uint i = 0; i < num_diff_salts; i++)
		if (((crypt_md5_salt*)salts_values)[i].saltlen != 8)
		{
			all_salt_lenght_8 = CL_FALSE;
			break;
		}
	// Only one hash
	// For Intel HD 4600 best DIVIDER=1-2
	//  1	128K
	//	2	121K
	//	4	104K
	//	8	77.5K
	//	16	62.4K
	//	32	32.0K
	// For AMD HD 7970 best DIVIDER=1-4
	//  1	4.80M
	//	2	4.69M
	//	4	4.50M
	//	8	4.15M
	//	16	3.62M
	//	32	3.09M
	// For Nvidia GTX 970 best DIVIDER=1-4
	//  1	5.71M
	//	2	5.64M
	//	4	5.56M
	//	8	4.57M
	//	16	3.36M
	//	32	3.10M

	// For AMD HD 7970
	// oclHashcat: 2.46M
	// Theoretical: 5.24M
	// HS by len : 4.50M
	if (!ocl_init_slow_hashes_ordered(param, gpu_index, gen, gpu_crypt, ocl_kernel_provider, use_rules, (use_rules ? 8 : 0) + 4, BINARY_SIZE, SALT_SIZE, ocl_gen_kernels, ocl_work_body, 
		all_salt_lenght_8 ? 2 : 4, MD5_MAX_KEY_LENGHT, FALSE))
		return FALSE;
	// Now With Intel HD 4600 y wordlist_small.lst: 7m:42s
	// New--------------------------------------->: 1m:38s

	// Crypt Kernels
	cl_int code;
	param->kernels[KERNEL_INDEX_INIT_PART] = pclCreateKernel(param->additional_program, "init_part", &code);
	param->kernels[KERNEL_INDEX_MD5_CYCLE] = pclCreateKernel(param->additional_program, "md5crypt_cycle", &code);
	param->kernels[KERNEL_INDEX_COMPARE_RESULT] = pclCreateKernel(param->additional_program, "compare_result", &code);

	if (num_diff_salts < num_passwords_loaded)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint) * num_passwords_loaded, salt_index);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint) * num_passwords_loaded, same_salt_next);
		}
		else
		{
			create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
	}

	// Set OpenCL kernel params
	//__kernel void init_part(__global uint* current_key,__global uint* current_data,__global uint* salts, uint base_len, uint len, uint offset)
	pclSetKernelArg(param->kernels[KERNEL_INDEX_INIT_PART], 0, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_INIT_PART], 1, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_INIT_PART], 2, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);

	//__kernel void md5crypt_cycle(__global uint* current_key,__global uint* current_data,__global uint* salts, uint base_len, uint len, uint offset)
	pclSetKernelArg(param->kernels[KERNEL_INDEX_MD5_CYCLE], 0, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_MD5_CYCLE], 1, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_MD5_CYCLE], 2, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);

	//__kernel void compare_result(__global uint* current_data,__global uint* output,const __global uint* bin, uint offset,const __global uint* salt_index,const __global uint* same_salt_next)
	pclSetKernelArg(param->kernels[KERNEL_INDEX_COMPARE_RESULT], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_COMPARE_RESULT], 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_COMPARE_RESULT], 2, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
	if (num_diff_salts < num_passwords_loaded)
	{
		pclSetKernelArg(param->kernels[KERNEL_INDEX_COMPARE_RESULT], 4, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_INDEX]);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_COMPARE_RESULT], 5, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_SALT_NEXT]);
	}

	if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY) && num_diff_salts < num_passwords_loaded)
	{
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX], CL_FALSE, 0, 4 * num_passwords_loaded, salt_index, 0, NULL, NULL);
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, 4 * num_passwords_loaded, same_salt_next, 0, NULL, NULL);
	}
	pclFinish(param->queue);

	// Create the kernels by lenght
	for (cl_uint i = 0; i <= MD5_MAX_KEY_LENGHT; i++)
	{
		char name[32];
		sprintf(name, "md5crypt_cycle%u", i);
		param->kernels[i] = pclCreateKernel(param->additional_program, name, &code);

		//__kernel void md5crypt_cycle%u(__global uint* current_key, __global uint* current_data, __global uint* salts, uint i, uint max_i, uint offset)
		pclSetKernelArg(param->kernels[i], 0, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);
		pclSetKernelArg(param->kernels[i], 1, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
		pclSetKernelArg(param->kernels[i], 2, sizeof(cl_mem), (void*)&param->mems[GPU_SALT_VALUES]);
	}

	param->param0 = all_salt_lenght_8;
	cl_uint zero = 0;
	if (param->param0)
	{
		pclSetKernelArg(param->kernels[15], 3, sizeof(zero), &zero);
		ocl_calculate_best_work_group(param, param->kernels + 15, 0, NULL, 0, FALSE, CL_FALSE);
	}
	else
	{
		// Select best params
		//                                                0                             1                      2             3           4         5        
		//__kernel void md5crypt_cycle(__global uint* current_key,__global uint* current_data,__global uint* salts, uint base_len, uint len, uint offset)
		pclSetKernelArg(param->kernels[KERNEL_INDEX_MD5_CYCLE], 3, sizeof(zero), &zero);
		pclSetKernelArg(param->kernels[KERNEL_INDEX_MD5_CYCLE], 5, sizeof(zero), &zero);
		zero = 15;
		pclSetKernelArg(param->kernels[KERNEL_INDEX_MD5_CYCLE], 4, sizeof(zero), &zero);

		ocl_calculate_best_work_group(param, param->kernels + KERNEL_INDEX_MD5_CYCLE, 0, NULL, 0, FALSE, CL_FALSE);
	}

	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_check_empty()
{
	uint32_t md5_state[4];
	uint8_t buffer[64];

	for (uint32_t current_salt_index = 0; current_salt_index < num_diff_salts; current_salt_index++)
	{
		crypt_md5_salt salt = ((crypt_md5_salt*)salts_values)[current_salt_index];

		// 1st digest
		memset(buffer, 0, sizeof(buffer));
		memcpy(buffer, salt.salt, salt.saltlen);
		buffer[salt.saltlen] = 0x80;
		((uint32_t*)buffer)[14] = salt.saltlen << 3;
		md5_one_block_c_code(md5_state, buffer);

		// 2nd digest
		memset(buffer, 0, sizeof(buffer));
		uint32_t buffer_len = 0;
		memcpy(buffer + buffer_len, prefixs[salt.prefix], strlen(prefixs[salt.prefix])); buffer_len += (uint32_t)strlen(prefixs[salt.prefix]);
		memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
		buffer[buffer_len] = 0x80;
		((uint32_t*)buffer)[14] = buffer_len << 3;
		md5_one_block_c_code(md5_state, buffer);

		// Big cycle
		for (int i = 0; i < 1000; i++)
		{
			memset(buffer, 0, sizeof(buffer));
			buffer_len = 0;

			if (!(i & 1))
			{
				memcpy(buffer + buffer_len, md5_state, 16); buffer_len += 16;
			}
			if (i % 3)
			{
				memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
			}
			if (i & 1)
			{
				memcpy(buffer + buffer_len, md5_state, 16); buffer_len += 16;
			}

			buffer[buffer_len] = 0x80;
			((uint32_t*)buffer)[14] = buffer_len << 3;
			md5_one_block_c_code(md5_state, buffer);
		}

		// Search for a match
		uint32_t indx = salt_index[current_salt_index];

		while (indx != NO_ELEM)
		{
			// Total match
			if (!memcmp(md5_state, ((uint32_t*)binary_values) + indx*4, 16))
				password_was_found(indx, "");

			indx = same_salt_next[indx];
		}
	}
}
PRIVATE int ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	// Do not allow blank in GPU
	if (current_key_lenght == 0)
	{
		ocl_check_empty();

		current_key_lenght = 1;
		report_keys_processed(1);
	}
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_crypt, kernels2common + CHARSET_INDEX_IN_KERNELS, FALSE);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_crypt, kernels2common + PHRASES_INDEX_IN_KERNELS, FALSE);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	return ocl_protocol_common_init(param, gpu_index, gen, gpu_crypt, kernels2common + UTF8_INDEX_IN_KERNELS, FALSE);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
extern int provider_index;

PRIVATE int ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_device_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	int i, kernel2common_index;

	// Find a compatible generate_key_funtion function for a given key_provider
	for (i = 0; i < LENGTH(key_providers[provider_index].impls); i++)
		for (kernel2common_index = 0; kernel2common_index < (int)num_kernels2common; kernel2common_index++)
			if (key_providers[provider_index].impls[i].protocol == kernels2common[kernel2common_index].protocol)
			{
				gen = key_providers[provider_index].impls[i].generate;
				goto out;
			}
out:
	return ocl_protocol_common_init(param, gpu_device_index, gen, gpu_crypt, kernels2common + kernel2common_index, TRUE);
}
#endif

Format md5crypt_format = {
	"MD5CRYPT",
	"FreeBSD-style MD5-based crypt(3).",
	"",
	MD5_MAX_KEY_LENGHT,
	BINARY_SIZE,
	SALT_SIZE,
	12,
	NULL,
	0,
	get_binary,
	binary2hex,
	DEFAULT_VALUE_MAP_INDEX,
	DEFAULT_VALUE_MAP_INDEX,
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
	{ { PROTOCOL_CHARSET_OCL_NO_ALIGNED, ocl_protocol_charset_init }, { PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init }, { PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init }, { PROTOCOL_UTF8, ocl_protocol_utf8_init } }
#endif
};