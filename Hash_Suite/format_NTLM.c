// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2015 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

//Initial values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

#define BINARY_SIZE			16
#define NTLM_MAX_KEY_LENGHT	27

PRIVATE int is_valid(char* user_name, char* rid, char* lm, char* ntlm)
{
	if (user_name && rid && lm && ntlm)
	{
		// If is empty password and load from fgdump->convert
		if (!strcmp(lm, "NO PASSWORD*********************") && !strcmp(ntlm, "NO PASSWORD*********************"))
			return TRUE;
		// Need at least a valid ntlm
		if (valid_hex_string(ntlm, 32))
			return TRUE;
	}
	// Format-> username:ntlm_hash
	else if (user_name && rid && valid_hex_string(rid, 32))
		return TRUE;
	else if (user_name && valid_hex_string(user_name, 32))
		return TRUE;

	return FALSE;
}

PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* user_name, char* rid, char* lm, char* ntlm)
{
	char lm_part[17];
	// All values to zero
	lm_part[16] = 0;// Null terminate it
	sqlite3_int64 account_id = -1;

	if (user_name && rid && lm && ntlm)
	{
		// If is empty password and load from fgdump->convert
		if (!strcmp(lm, "NO PASSWORD*********************") && !strcmp(ntlm, "NO PASSWORD*********************"))
		{
			strcpy(lm, "AAD3B435B51404EEAAD3B435B51404EE");
			strcpy(ntlm, "31D6CFE0D16AE931B73C59D7E0C089C0");
		}
		// Need at least a valid ntlm
		if (valid_hex_string(ntlm, 32))
		{
			// Insert hash ntlm and tagged account
			account_id = insert_hash_account1(param, user_name, _strupr(ntlm), NTLM_INDEX);

			if (valid_hex_string(_strupr(lm), 32) && (strcmp(lm, "AAD3B435B51404EEAAD3B435B51404EE") || !strcmp(ntlm, "31D6CFE0D16AE931B73C59D7E0C089C0")))
			{
				// Insert hash lm
				strncpy(lm_part, lm, 16);
				sqlite3_int64 hash_id = insert_hash_if_necesary(lm_part, LM_INDEX, param->result.formats_stat + LM_INDEX);

				strncpy(lm_part, lm + 16, 16);
				sqlite3_int64 hash_id2 = insert_hash_if_necesary(lm_part, LM_INDEX, param->result.formats_stat + LM_INDEX);

				// Insert account lm
				sqlite3_reset(insert_account_lm);
				sqlite3_bind_int64(insert_account_lm, 1, account_id);
				sqlite3_bind_int64(insert_account_lm, 2, hash_id);
				sqlite3_bind_int64(insert_account_lm, 3, hash_id2);
				sqlite3_step(insert_account_lm);

				num_user_by_formats1[LM_INDEX]++;
			}
			else
				param->result.formats_stat[LM_INDEX].num_hash_disable++;
		}
	}
	// Format-> username:ntlm_hash
	else if (user_name && rid && valid_hex_string(rid, 32))
	{
		// Insert hash ntlm and tagged account
		account_id = insert_hash_account1(param, user_name, _strupr(rid), NTLM_INDEX);
	}
	// Format-> ntlm_hash
	else if (user_name && valid_hex_string(user_name, 32))
	{
		// Insert hash ntlm and tagged account
		account_id = insert_hash_account1(param, NULL, _strupr(user_name), NTLM_INDEX);
	}

	return account_id;
}
#define VALUE_MAP_INDEX0 1
#define VALUE_MAP_INDEX1 0
PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	uint32_t* out = (uint32_t*)binary;
	uint32_t i = 0;
	uint32_t temp;

	for (; i < 4; i++)
	{
 		temp  = (hex_to_num[ciphertext[i*8+0]])<<4;
 		temp |= (hex_to_num[ciphertext[i*8+1]]);
		
		temp |= (hex_to_num[ciphertext[i*8+2]])<<12;
		temp |= (hex_to_num[ciphertext[i*8+3]])<<8;
		
		temp |= (hex_to_num[ciphertext[i*8+4]])<<20;
		temp |= (hex_to_num[ciphertext[i*8+5]])<<16;
		
		temp |= (hex_to_num[ciphertext[i*8+6]])<<28;
		temp |= (hex_to_num[ciphertext[i*8+7]])<<24;
		
		out[i] = temp;
	}

	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;
	
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3 + (out[2] ^ out[3] ^ out[0]);

	out[2] = (out[2] >> 11) | (out[2] << 21);
	out[2] -= SQRT_3 + (out[3] ^ out[1] ^ out[0]);

	out[3] = (out[3] >> 9) | (out[3] << 23);
	out[3] -= SQRT_3;

	out[0] = (out[0] >> 3) | (out[0] << 29);
	out[0] -= SQRT_3;
	
	return out[VALUE_MAP_INDEX0];
}

PRIVATE void binary2hex(const void* binary, const void* salt, unsigned char* ciphertext)
{
	uint32_t bin[BINARY_SIZE / sizeof(uint32_t)];
	memcpy(bin, binary, BINARY_SIZE);

	bin[0] = ROTATE32(bin[0] + SQRT_3, 3);
	bin[3] = ROTATE32(bin[3] + SQRT_3, 9);

	bin[2] += SQRT_3 + (bin[3] ^ bin[1] ^ bin[0]);
	bin[2] = ROTATE32(bin[2], 11);
	
	bin[1] += SQRT_3 + (bin[2] ^ bin[3] ^ bin[0]);
	bin[1] = ROTATE32(bin[1], 15);

	bin[0] += INIT_A;
	bin[1] += INIT_B;
	bin[2] += INIT_C;
	bin[3] += INIT_D;

	binary_to_hex(bin, ciphertext, BINARY_SIZE/sizeof(uint32_t), TRUE);
}

#ifdef HS_ARM
	#define NT_NUM_KEYS		    128
#endif

#ifdef HS_X86
	#define NT_NUM_KEYS		    256
#endif

PRIVATE uint32_t compare_elem(uint32_t i, uint32_t cbg_table_pos, uint32_t* nt_buffer)
{
	if(cbg_table_pos == NO_ELEM) return FALSE;

	uint32_t* bin = ((uint32_t*)binary_values) + cbg_table_pos * 4;

	uint32_t* unpacked_as = (uint32_t*)(nt_buffer + 16 * NT_NUM_KEYS);
	uint32_t* unpacked_bs = (uint32_t*)(nt_buffer + 16 * NT_NUM_KEYS + 1 * NT_NUM_KEYS);
	uint32_t* unpacked_cs = (uint32_t*)(nt_buffer + 16 * NT_NUM_KEYS + 2 * NT_NUM_KEYS);
	uint32_t* unpacked_ds = (uint32_t*)(nt_buffer + 16 * NT_NUM_KEYS + 3 * NT_NUM_KEYS);

	if (unpacked_bs[i] != bin[1] || unpacked_as[i] != bin[0]) return FALSE;
	uint32_t aa = unpacked_as[i] + SQRT_3; aa = ROTATE(aa, 3);

	uint32_t dd = unpacked_ds[i] + (aa ^ unpacked_bs[i] ^ unpacked_cs[i]) + nt_buffer[11 * NT_NUM_KEYS + i];
	if (dd != bin[3])  return FALSE;

	uint32_t cc = unpacked_cs[i] + nt_buffer[7 * NT_NUM_KEYS + i];
	if (cc != bin[2])  return FALSE;

	return TRUE;
}

PRIVATE void crypt_ntlm_protocol_body(CryptParam* param, crypt_kernel_asm_func* crypt_ntlm_kernel_asm)
{
	uint32_t* nt_buffer = (uint32_t*)_aligned_malloc(16 * 4 * NT_NUM_KEYS + 4 * 4 * NT_NUM_KEYS, 64);

	uint32_t* unpacked_as = (uint32_t*)(nt_buffer + 16*NT_NUM_KEYS);
	uint32_t* unpacked_bs = (uint32_t*)(nt_buffer + 16*NT_NUM_KEYS + 1*NT_NUM_KEYS);

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_ntlm_kernel_asm(nt_buffer);

		for (uint32_t i = 0; i < NT_NUM_KEYS; i++)
		{
			uint32_t up_b = unpacked_bs[i];
			uint32_t up_a = unpacked_as[i];

			uint32_t pos = up_b & cbg_mask;
			uint_fast16_t data = cbg_filter[pos];
			if (((data ^ up_a) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], nt_buffer))
				password_was_found(cbg_table[pos], ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match

			// 2nd pos
			if (data & 0b110)
			{
				pos += data & 0b1 ? -1 : 1;
				uint_fast16_t hash = cbg_filter[pos];
				if (((hash ^ up_a) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], nt_buffer))
					password_was_found(cbg_table[pos], ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match

				// Unluky bucket
				if (data & 0b10)
				{
					pos = up_a & cbg_mask;
					data = cbg_filter[pos];
					if (((data ^ up_b) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], nt_buffer))
						password_was_found(cbg_table[pos], ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match

					// 2nd pos
					pos += data & 0b1 ? -1 : 1;
					hash = cbg_filter[pos];
					if (((hash ^ up_b) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], nt_buffer))
						password_was_found(cbg_table[pos], ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match
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
PRIVATE void crypt_ntlm_kernel_c(uint32_t* nt_buffer)
{
	for (int i = 0; i < NT_NUM_KEYS; i++)
	{
		/* Round 1 */
		uint32_t a = 0xFFFFFFFF + nt_buffer[0 * NT_NUM_KEYS + i]; a = ROTATE(a, 3);
		uint32_t d = INIT_D + (INIT_C ^ (a & 0x77777777)) + nt_buffer[1 * NT_NUM_KEYS + i]; d = ROTATE(d, 7);
		uint32_t c = INIT_C + (INIT_B ^ (d & (a ^ INIT_B))) + nt_buffer[2 * NT_NUM_KEYS + i]; c = ROTATE(c, 11);
		uint32_t b = INIT_B + (a ^ (c & (d ^ a))) + nt_buffer[3 * NT_NUM_KEYS + i]; b = ROTATE(b, 19);

		a += (d ^ (b & (c ^ d))) + nt_buffer[4 * NT_NUM_KEYS + i]; a = ROTATE(a, 3);
		d += (c ^ (a & (b ^ c))) + nt_buffer[5 * NT_NUM_KEYS + i]; d = ROTATE(d, 7);
		c += (b ^ (d & (a ^ b))) + nt_buffer[6 * NT_NUM_KEYS + i]; c = ROTATE(c, 11);
		b += (a ^ (c & (d ^ a))) + nt_buffer[7 * NT_NUM_KEYS + i]; b = ROTATE(b, 19);

		a += (d ^ (b & (c ^ d))) + nt_buffer[8 * NT_NUM_KEYS + i]; a = ROTATE(a, 3);
		d += (c ^ (a & (b ^ c))) + nt_buffer[9 * NT_NUM_KEYS + i]; d = ROTATE(d, 7);
		c += (b ^ (d & (a ^ b))) + nt_buffer[10 * NT_NUM_KEYS + i]; c = ROTATE(c, 11);
		b += (a ^ (c & (d ^ a))) + nt_buffer[11 * NT_NUM_KEYS + i]; b = ROTATE(b, 19);

		a += (d ^ (b & (c ^ d))) + nt_buffer[12 * NT_NUM_KEYS + i]; a = ROTATE(a, 3);
		d += (c ^ (a & (b ^ c))) + nt_buffer[13 * NT_NUM_KEYS + i]; d = ROTATE(d, 7);
		c += (b ^ (d & (a ^ b))) + nt_buffer[14 * NT_NUM_KEYS + i]; c = ROTATE(c, 11);
		b += (a ^ (c & (d ^ a))); b = ROTATE(b, 19);

		/* Round 2 */
		a += ((b & (c | d)) | (c & d)) + nt_buffer[0 * NT_NUM_KEYS + i] + SQRT_2; a = ROTATE(a, 3);
		d += ((a & (b | c)) | (b & c)) + nt_buffer[4 * NT_NUM_KEYS + i] + SQRT_2; d = ROTATE(d, 5);
		c += ((d & (a | b)) | (a & b)) + nt_buffer[8 * NT_NUM_KEYS + i] + SQRT_2; c = ROTATE(c, 9);
		b += ((c & (d | a)) | (d & a)) + nt_buffer[12 * NT_NUM_KEYS + i] + SQRT_2; b = ROTATE(b, 13);

		a += ((b & (c | d)) | (c & d)) + nt_buffer[1 * NT_NUM_KEYS + i] + SQRT_2; a = ROTATE(a, 3);
		d += ((a & (b | c)) | (b & c)) + nt_buffer[5 * NT_NUM_KEYS + i] + SQRT_2; d = ROTATE(d, 5);
		c += ((d & (a | b)) | (a & b)) + nt_buffer[9 * NT_NUM_KEYS + i] + SQRT_2; c = ROTATE(c, 9);
		b += ((c & (d | a)) | (d & a)) + nt_buffer[13 * NT_NUM_KEYS + i] + SQRT_2; b = ROTATE(b, 13);

		a += ((b & (c | d)) | (c & d)) + nt_buffer[2 * NT_NUM_KEYS + i] + SQRT_2; a = ROTATE(a, 3);
		d += ((a & (b | c)) | (b & c)) + nt_buffer[6 * NT_NUM_KEYS + i] + SQRT_2; d = ROTATE(d, 5);
		c += ((d & (a | b)) | (a & b)) + nt_buffer[10 * NT_NUM_KEYS + i] + SQRT_2; c = ROTATE(c, 9);
		b += ((c & (d | a)) | (d & a)) + nt_buffer[14 * NT_NUM_KEYS + i] + SQRT_2; b = ROTATE(b, 13);

		a += ((b & (c | d)) | (c & d)) + nt_buffer[3 * NT_NUM_KEYS + i] + SQRT_2; a = ROTATE(a, 3);
		d += ((a & (b | c)) | (b & c)) + nt_buffer[7 * NT_NUM_KEYS + i] + SQRT_2; d = ROTATE(d, 5);
		c += ((d & (a | b)) | (a & b)) + nt_buffer[11 * NT_NUM_KEYS + i] + SQRT_2; c = ROTATE(c, 9);
		b += ((c & (d | a)) | (d & a)) + SQRT_2; b = ROTATE(b, 13);

		/* Round 3 */
		a += (d ^ c ^ b) + nt_buffer[0 * NT_NUM_KEYS + i] + SQRT_3; a = ROTATE(a, 3);
		d += (c ^ b ^ a) + nt_buffer[8 * NT_NUM_KEYS + i] + SQRT_3; d = ROTATE(d, 9);
		c += (b ^ a ^ d) + nt_buffer[4 * NT_NUM_KEYS + i] + SQRT_3; c = ROTATE(c, 11);
		b += (a ^ d ^ c) + nt_buffer[12 * NT_NUM_KEYS + i] + SQRT_3; b = ROTATE(b, 15);

		a += (d ^ c ^ b) + nt_buffer[2 * NT_NUM_KEYS + i] + SQRT_3; a = ROTATE(a, 3);
		d += (c ^ b ^ a) + nt_buffer[10 * NT_NUM_KEYS + i] + SQRT_3; d = ROTATE(d, 9);
		c += (b ^ a ^ d) + nt_buffer[6 * NT_NUM_KEYS + i] + SQRT_3; c = ROTATE(c, 11);
		b += (a ^ d ^ c) + nt_buffer[14 * NT_NUM_KEYS + i] + SQRT_3; b = ROTATE(b, 15);

		a += (d ^ c ^ b) + nt_buffer[1 * NT_NUM_KEYS + i] + SQRT_3; a = ROTATE(a, 3);
		d += (c ^ b ^ a) + nt_buffer[9 * NT_NUM_KEYS + i] + SQRT_3; d = ROTATE(d, 9);
		c += (b ^ a ^ d) + nt_buffer[5 * NT_NUM_KEYS + i] + SQRT_3; c = ROTATE(c, 11);
		b += (a ^ d ^ c) + nt_buffer[13* NT_NUM_KEYS + i] + SQRT_3; b = ROTATE(b, 15);

		a += (b ^ d ^ c) + nt_buffer[3 * NT_NUM_KEYS + i];

		nt_buffer[16 * NT_NUM_KEYS + i] = a;
		nt_buffer[16 * NT_NUM_KEYS + 1 * NT_NUM_KEYS + i] = b;
		nt_buffer[16 * NT_NUM_KEYS + 2 * NT_NUM_KEYS + i] = c;
		nt_buffer[16 * NT_NUM_KEYS + 3 * NT_NUM_KEYS + i] = d;
	}
}
PRIVATE void crypt_ntlm_protocol_c_code(CryptParam* param)
{
	crypt_ntlm_protocol_body(param, crypt_ntlm_kernel_c);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Neon code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM
void crypt_ntlm_neon_kernel_asm(uint32_t* buffer);
PRIVATE void crypt_ntlm_protocol_neon(CryptParam* param)
{
	crypt_ntlm_protocol_body(param, crypt_ntlm_neon_kernel_asm);
}

#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef _M_X64
void crypt_ntlm_avx_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_ntlm_protocol_avx(CryptParam* param)
{
	crypt_ntlm_protocol_body(param, crypt_ntlm_avx_kernel_asm);
}
#endif
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef _M_X64
void crypt_ntlm_avx2_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_ntlm_protocol_avx2(CryptParam* param)
{
	crypt_ntlm_protocol_body(param, crypt_ntlm_avx2_kernel_asm);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
void crypt_ntlm_sse2_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_ntlm_protocol_sse2(CryptParam* param)
{
	crypt_ntlm_protocol_body(param, crypt_ntlm_sse2_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_write_ntlm_header(char* source, GPUDevice* gpu, cl_uint ntlm_size_bit_table1)
{
	source[0] = 0;
	// Header definitions
	if(num_passwords_loaded > 1 )
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
	// Minor optimization
#ifdef __ANDROID__
	if (num_passwords_loaded == 1)
		sprintf(source + strlen(source), "#define MAJ(c,d,b) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
	else
		sprintf(source + strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
#else
	if (gpu->vendor == OCL_VENDOR_AMD && gpu->vector_int_size >= 4)
	{
		if (num_passwords_loaded == 1)
			sprintf(source + strlen(source), "#define MAJ(c,d,b) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
		else
			sprintf(source + strlen(source), "#define MAJ(b,d,c) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
	}
	else if (gpu->vendor == OCL_VENDOR_INTEL && num_passwords_loaded == 1)
		sprintf(source + strlen(source), "#define MAJ(d,c,b) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
	else
		sprintf(source + strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
#endif
#endif
	
	//Initial values
	sprintf(source+strlen(source),
"#define INIT_A 0x67452301\n"
"#define INIT_B 0xefcdab89\n"
"#define INIT_C 0x98badcfe\n"
"#define INIT_D 0x10325476\n"

"#define SQRT_2 0x5a827999\n"
"#define SQRT_3 0x6ed9eba1\n");

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
}
PRIVATE void ocl_gen_kernel_with_lenght_onehash(char* source, cl_uint key_lenght, cl_uint vector_size, char** nt_buffer, char** str_comp)
{
	uint32_t a = ((uint32_t*)binary_values)[0];
	uint32_t b = ((uint32_t*)binary_values)[1];

	uint32_t max_char_in_charset = 0;
	for (uint32_t i = 0; i < num_char_in_charset; i++)
		if (max_char_in_charset < charset[i])
			max_char_in_charset = charset[i];

	strcat(source, "uint a1,b1,c1,d1,xx;");

	if (max_char_in_charset <= 127 && key_lenght >= 4)
		sprintf(source+strlen(source), 
			"a1=rotate(nt_buffer0%s,3u);"
			"d1=INIT_D+(INIT_C^(a1&0x77777777))%s;d1=rotate(d1,7u);"
			"uint val_d=d1&0xFFFC07FF;"
			, str_comp[0], nt_buffer[1]);
	
	//if(key_lenght == 14) c -= 14<<4;
	//if(key_lenght <= 14) d -= (a ^ b ^ c);
	a += SQRT_3; a = ROTATE(a, 3);

	//if(key_lenght > 14)
	{
		sprintf(source+strlen(source), "c1=%uu-%s;", ((uint32_t*)binary_values)[2], key_lenght >= 14 ? (nt_buffer[7]+1) : "0");
		sprintf(source+strlen(source), "d1=%uu-((%uu^c1)%s);", ((uint32_t*)binary_values)[3], a^b, nt_buffer[11]);
	}

	a = ROTATE(a, 29); a -= SQRT_3;
	b = ROTATE(b, 32-15); b -= SQRT_3;
	/* Round 3 */
	sprintf(source+strlen(source),
		"xx=d1^c1;"
		"a1=%uu-((xx^%uu)%s);"

		"b1=%uu-((a1^xx)%s);xx=b1^a1;"
		"c1=rotate(c1,21u);c1-=(xx^d1)%s+SQRT_3;"
		"d1=rotate(d1,23u);d1-=(c1^xx)%s+SQRT_3;xx=d1^c1;"
		"a1=rotate(a1,29u);a1-=(xx^b1)%s+SQRT_3;"

		"b1=rotate(b1,17u);b1-=(a1^xx)+%uu;xx=b1^a1;"
		"c1=rotate(c1,21u);c1-=(xx^d1)%s+SQRT_3;"
		"d1=rotate(d1,23u);d1-=(c1^xx)%s+SQRT_3;xx=d1^c1;"
		"a1=rotate(a1,29u);a1-=(xx^b1)%s+SQRT_3;"

		"b1=rotate(b1,17u);b1-=(a1^xx)%s+SQRT_3;xx=b1^a1;"
		"c1=rotate(c1,21u);c1-=(xx^d1)%s+SQRT_3;"
		"d1=rotate(d1,23u);d1-=(c1^xx)%s+SQRT_3;"
		"a1=rotate(a1,29u);a1-=(d1^c1^b1)+SQRT_3;"

		"b1=rotate(b1,19u);b1-=SQRT_2;"
		"uint c1_rot=rotate(c1,23u);c1_rot-=SQRT_2;"
		"uint d1_rot=rotate(d1,27u);d1_rot-=SQRT_2;"
		, a, ((uint32_t*)binary_values)[1], nt_buffer[3], b, nt_buffer[13]
		, nt_buffer[5], nt_buffer[9], nt_buffer[1], (key_lenght<<4)+SQRT_3, nt_buffer[6]
		, nt_buffer[10], nt_buffer[2], nt_buffer[12], nt_buffer[4], nt_buffer[8]);

	if(key_lenght > 2) strcat(source, "nt_buffer1+=SQRT_2;");
	if(key_lenght > 4) strcat(source, "nt_buffer2+=SQRT_2;");
	if(key_lenght > 6) strcat(source, "nt_buffer3+=SQRT_2;");
	if(key_lenght > 8) strcat(source, "nt_buffer4+=SQRT_2;");

	if( is_charset_consecutive(charset) )
		for (uint32_t i = 0; i < vector_size; i++)
			sprintf(source + strlen(source), "nt_buffer0%s|=%iU;", str_comp[i], is_charset_consecutive(charset) - vector_size + i);

	// Begin cycle changing first character
	sprintf(source+strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if( is_charset_consecutive(charset) )
		sprintf(source+strlen(source), "nt_buffer0+=%uU;", vector_size);
	else
		for (uint32_t i = 0; i < vector_size; i++)
			sprintf(source+strlen(source), "nt_buffer0%s^=charset[NUM_CHAR_IN_CHARSET+i+%uU];", str_comp[i], i);

			/* Round 2 */
sprintf(source+strlen(source), 
			"a=a1-nt_buffer0;"

			"b=b1-MAJ(c1,d1,a);"
			"c=c1_rot-(MAJ(d1,a,b)%s);"
			"d=d1_rot-(MAJ(a,b,c)%s);"
			"a=rotate(a,29u);a-=MAJ(b,c,d)%s%s;"

			"b=rotate(b,19u);b-=MAJ(c,d,a)+%uu;"
			"c=rotate(c,23u);c-=MAJ(d,a,b)%s+SQRT_2;"
			"d=rotate(d,27u);d-=MAJ(a,b,c)%s+SQRT_2;"
			"a=rotate(a,29u);a-=MAJ(b,c,d)%s%s;"

			"b=rotate(b,19u);b-=MAJ(c,d,a)%s+SQRT_2;"
			"c=rotate(c,23u);c-=MAJ(d,a,b)%s+SQRT_2;"
			"d=rotate(d,27u);d-=MAJ(a,b,c)%s+SQRT_2;"
			"a=rotate(a,29u);a-=MAJ(b,c,d)%s%s;"

			"b=rotate(b,19u);b-=MAJ(c,d,a)%s+SQRT_2;"
			"c=rotate(c,23u);c-=MAJ(d,a,b)%s+SQRT_2;"
			"d=rotate(d,27u);d-=MAJ(a,b,c)%s%s;"
			"a=rotate(a,29u);a-=MAJ(b,c,d)%s+SQRT_2;"
			, nt_buffer[11], nt_buffer[7], nt_buffer[3], key_lenght>6?"":"+SQRT_2", (key_lenght<<4)+SQRT_2, nt_buffer[10], nt_buffer[6], nt_buffer[2], key_lenght>4?"":"+SQRT_2"
			, nt_buffer[13], nt_buffer[9], nt_buffer[5], nt_buffer[1], key_lenght>2?"":"+SQRT_2", nt_buffer[12] , nt_buffer[8] , nt_buffer[4], key_lenght>8?"":"+SQRT_2", nt_buffer[0]);

			/* Round 1 */
sprintf(source+strlen(source), 
			"b=rotate(b,13u);b-=bs(a,d,c);"
			"c=rotate(c,21u);c-=bs(b,a,d)+%uu;"
			"d=rotate(d,25u);d-=bs(c,b,a)%s;"
			"a=rotate(a,29u);a-=bs(d,c,b)%s;"

			"b=rotate(b,13u);b-=bs(a,d,c)%s;"
			"c=rotate(c,21u);c-=bs(b,a,d)%s;"
			"d=rotate(d,25u);d-=bs(c,b,a)%s;"
			"a=rotate(a,29u);a-=bs(d,c,b)%s;"

			"b=rotate(b,13u);b-=bs(a,d,c)%s;"
			"c=rotate(c,21u);c-=bs(b,a,d)%s;"
			"d=rotate(d,25u);d-=bs(c,b,a)%s;"
			, key_lenght << 4, nt_buffer[13], nt_buffer[12], nt_buffer[11], nt_buffer[10], 
			nt_buffer[9], nt_buffer[8], nt_buffer[7], nt_buffer[6], nt_buffer[5]);


	if (max_char_in_charset <= 127 && key_lenght >= 4)
	{
		for (uint32_t comp = 0; comp < vector_size; comp++)
		{
			sprintf(source+strlen(source),
			"if((d%s&0xFFFC07FF)==val_d)"
			"{"
				"a%s=rotate(a%s,29u);a%s-=bs(d%s,c%s,b%s)%s%s;"
				"b%s=rotate(b%s,13u);b%s-=bs(a%s,d%s,c%s)%s%s;"
				"if(b%s==INIT_B)"
				"{"
					"c%s=rotate(c%s,21u);c%s-=bs(b%s,a%s,d%s)%s%s;"
					"d%s=rotate(d%s,25u);d%s-=bs(c%s,b%s,a%s)%s%s;"
					"a%s=rotate(a%s,29u);a%s-=%s%s;"

					"if(c%s==INIT_C&&d%s==INIT_D&&a%s==0xFFFFFFFF)"
					"{"
						"output[0]=1;"
						"output[1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
						"output[2]=0;"
					"}"
				"}"
			"}",
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],nt_buffer[4], key_lenght<=8?"":"-SQRT_2",
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3], key_lenght<=6?"":"-SQRT_2",
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],nt_buffer[2], key_lenght<=4?"":"-SQRT_2",
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[1], key_lenght<=2?"":"-SQRT_2",
			str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[0]  , str_comp[comp],
			str_comp[comp], str_comp[comp], str_comp[comp], comp);
		}
	}
	else
	{
		sprintf(source+strlen(source), 
			"a=rotate(a,29u);a-=bs(d,c,b)%s%s;"
			"b=rotate(b,13u);b-=bs(a,d,c)%s%s;"
			, nt_buffer[4], key_lenght <= 8 ? "" : "-SQRT_2", nt_buffer[3], key_lenght <= 6 ? "" : "-SQRT_2");

		for (uint32_t comp = 0; comp < vector_size; comp++)
			sprintf(source+strlen(source),
			"if(b%s==INIT_B)"
			"{"
				"c%s=rotate(c%s,21u);c%s-=bs(b%s,a%s,d%s)%s%s;"
				"d%s=rotate(d%s,25u);d%s-=bs(c%s,b%s,a%s)%s%s;"
				"a%s=rotate(a%s,29u);a%s-=%s%s;"

				"if(c%s==INIT_C&&d%s==INIT_D&&a%s==0xFFFFFFFF)"
				"{"
					"output[0]=1;"
					"output[1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
					"output[2]=0;"
				"}"
			"}",
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],nt_buffer[2], key_lenght<=4?"":"-SQRT_2",
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[1], key_lenght<=2?"":"-SQRT_2",
			str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[0]  , str_comp[comp],
			str_comp[comp], str_comp[comp], str_comp[comp], comp);
	}

	strcat(source, "}}");
}
PRIVATE void ocl_gen_kernel_with_lenght(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table2, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission2, cl_uint workgroup)
{
	cl_uint i;
	char* nt_buffer[] = {"+nt_buffer0" , "+nt_buffer1" , "+nt_buffer2" , "+nt_buffer3" , 
						 "+nt_buffer4" , "+nt_buffer5" , "+nt_buffer6" , "+nt_buffer7" , 
						 "+nt_buffer8" , "+nt_buffer9" , "+nt_buffer10", "+nt_buffer11", 
						 "+nt_buffer12", "+nt_buffer13"};
	char buffer[16];
	buffer[0] = 0;
	if (vector_size > 1)	sprintf(buffer, "%u", vector_size);

	// Begin function code
	sprintf(source+strlen(source),	"uint%s a,b,c,d,nt_buffer0=0;uint indx;", buffer);
	// Generate less repeated keys
	uint64_t max_work_item_index = 1;
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

	// Prefetch in local memory
	//if ((ntlm_size_bit_table/32+1) <= 1024 && num_passwords_loaded > 1)
	//{
	//	sprintf(source + strlen(source), "local uint lbit_table[%i];", ntlm_size_bit_table/32+1);
	//	// Copy from global to local
	//	sprintf(source + strlen(source), "for(uint i=get_local_id(0); i < %uu; i+=get_local_size(0))"
	//										"lbit_table[i]=bit_table[i];"
	//									"barrier(CLK_LOCAL_MEM_FENCE);", ntlm_size_bit_table/32+1);
	//}

#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
	cl_uint bits_by_char;
	_BitScanReverse(&bits_by_char, ceil_power_2(num_char_in_charset));
	cl_uint chars_in_reg = 32 / bits_by_char;
#endif
	
	for(i = 0; i < key_lenght/2; i++)
		for (cl_uint j = 0; j < 2; j++)
			if (i || j)
			{
				cl_uint key_index = 2 * i + j;
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
					sprintf(source + strlen(source), "nt_buffer%u+=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<16u;", i);
				else
					sprintf(source + strlen(source), "uint nt_buffer%u=charset[max_number-NUM_CHAR_IN_CHARSET*indx];", i);

				sprintf(source + strlen(source), "max_number=indx;");
			}

	if(key_lenght == 1)
		sprintf(source+strlen(source), "nt_buffer0=0x800000;");
	else if(key_lenght & 1)
	{
		cl_uint key_index = key_lenght - 1;
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
		key_index--;
		sprintf(source + strlen(source), "max_number+=(current_key%i>>%uu)&%uu;", key_index / chars_in_reg, (key_index%chars_in_reg)*bits_by_char, ceil_power_2(num_char_in_charset) - 1);
#else
		sprintf(source+strlen(source), "max_number+=current_key[%i];", key_index);
#endif
		// Perform division
		if(div_param.magic)	sprintf(source+strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
		else				sprintf(source+strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

		sprintf(source+strlen(source), "uint nt_buffer%u=((uint)(charset[max_number-NUM_CHAR_IN_CHARSET*indx]))+0x800000;", i);
	}
	else
		nt_buffer[i] = "+0x80";

	for (i = key_lenght / 2 + 1; i < 14; i++)
		nt_buffer[i] = "";

	// Generate optimized code for particular case of only one hash
	if(num_passwords_loaded==1)
	{
		ocl_gen_kernel_with_lenght_onehash(source+strlen(source), key_lenght, vector_size, nt_buffer, str_comp);
		return;
	}

	// Small optimization
	if( is_charset_consecutive(charset) )
		for (i = 0; i < vector_size; i++)
			sprintf(source+strlen(source), "nt_buffer0%s|=%iU;", str_comp[i], is_charset_consecutive(charset)-vector_size+i);

	if(key_lenght > 2) sprintf(source+strlen(source), "nt_buffer1+=INIT_D;");
	if(key_lenght > 4) sprintf(source+strlen(source), "nt_buffer2+=INIT_C;");

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if( is_charset_consecutive(charset) )
		sprintf(source+strlen(source), "nt_buffer0+=%uU;", vector_size);
	else
		for (i = 0; i < vector_size; i++)
			sprintf(source+strlen(source), "nt_buffer0%s^=charset[NUM_CHAR_IN_CHARSET+i+%uU];", str_comp[i], i);

		/* Round 1 */
sprintf(source+strlen(source), 
		"a=0xffffffff+nt_buffer0;a<<=3u;"
		"d=%sbs(INIT_C,INIT_B,a)%s;d=rotate(d,7u);"
		"c=%sbs(INIT_B,a,d)%s;c=rotate(c,11u);"
		"b=INIT_B+bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)+%uu;c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);"
		, key_lenght > 2 ? "" : "INIT_D+", nt_buffer[1], key_lenght > 4 ? "" : "INIT_C+", nt_buffer[2], nt_buffer[3]
		, nt_buffer[4] , nt_buffer[5] , nt_buffer[6], nt_buffer[7], nt_buffer[8], nt_buffer[9], nt_buffer[10], nt_buffer[11], nt_buffer[12], nt_buffer[13]
		, key_lenght << 4);

		/* Round 2 */
		sprintf(source+strlen(source), 
		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s%s;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s%s;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+%uu;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)+SQRT_2;b=rotate(b,13u);"
		, nt_buffer[0], nt_buffer[4], nt_buffer[8] , nt_buffer[12]
		, nt_buffer[1], key_lenght > 2 ? "+0x4A502523" : "+SQRT_2", nt_buffer[5], nt_buffer[9], nt_buffer[13]
		, nt_buffer[2], key_lenght > 4 ? "+0xC1C79C9B" : "+SQRT_2", nt_buffer[6], nt_buffer[10], (key_lenght<<4)+SQRT_2
		, nt_buffer[3]											  , nt_buffer[7], nt_buffer[11]);

		/* Round 3 */
		sprintf(source + strlen(source),
			"uint%s xx=c^b;"
			"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
			"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
			"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
			"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

			"a+=(d^xx)%s%s;a=rotate(a,3u);"
			"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
			"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
			"b+=(xx^c)+%uu;b=rotate(b,15u);xx=c^b;"

			"a+=(d^xx)%s%s;a=rotate(a,3u);"
			, buffer
			, nt_buffer[0], nt_buffer[8], nt_buffer[4], nt_buffer[12]
			, nt_buffer[2], key_lenght > 4 ? "+0xD61F0EA3" : "+SQRT_3", nt_buffer[10], nt_buffer[6], (key_lenght << 4) + SQRT_3
			, nt_buffer[1], key_lenght > 2 ? "+0x5EA7972B" : "+SQRT_3");

		if (key_lenght <= 13 && max_lenght <= 13)
		{ 
			sprintf(source+strlen(source), "d+=(xx^a);a+=0%s;", nt_buffer[3]);

			// Find match
			sprintf(source + strlen(source), "xx=d&%uu;uint fdata;", cbg_mask);

			for (cl_uint comp = 0; comp < vector_size; comp++)
			{
				sprintf(source + strlen(source),
					"fdata=(uint)(cbg_filter[xx%s]);"

					"if(((fdata^a%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"

							"uint da=rotate(d%s+SQRT_3,9u)^(a%s-(0%s));"
							"c%s+=(b%s^da)%s+SQRT_3;c%s=rotate(c%s,11u);"
							"b%s+=(da^c%s);"

							"if(b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
								"uint found=atomic_inc(output);"
								"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
									"output[2*found+2]=indx;}"
							"}"
							// TODO: Reverse c,b to their last value for the unlikely case of 2 hashes with same a,d
							// TODO: if (value_map_collission1) do_smothing
						"}"
					"}"
					, str_comp[comp]
					, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
					, str_comp[comp], str_comp[comp], nt_buffer[3]
					, str_comp[comp], str_comp[comp], nt_buffer[5], str_comp[comp], str_comp[comp]
					, str_comp[comp], str_comp[comp]
					, str_comp[comp], str_comp[comp]
					, output_size, comp);
				
				if(cbg_count_moved)
					sprintf(source + strlen(source),
						"if(fdata&4){"// Is second
							"xx%s+=fdata&1?-1:1;"
							"if(((((uint)cbg_filter[xx%s])^a%s)&0xFFF8)==0){"
								"indx=cbg_table[xx%s];"
								"if(indx!=0xffffffff&&d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"

									"uint da=rotate(d%s+SQRT_3,9u)^(a%s-(0%s));"
									"c%s+=(b%s^da)%s+SQRT_3;c%s=rotate(c%s,11u);"
									"b%s+=(da^c%s);"

									"if(b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
										"uint found=atomic_inc(output);"
										"if(found<%uu){"
											"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
											"output[2*found+2]=indx;}"
									"}"
								"}"
							"}"
						"}"
						, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
						, str_comp[comp], str_comp[comp], nt_buffer[3]
						, str_comp[comp], str_comp[comp], nt_buffer[5], str_comp[comp], str_comp[comp]
						, str_comp[comp], str_comp[comp]
						, str_comp[comp], str_comp[comp]
						, output_size, comp);

				if(cbg_count_unlucky)
				{
					sprintf(source + strlen(source),
						"if(fdata&2){"// Is unlucky
							"xx%s=a%s&%uu;"
							"fdata=(uint)(cbg_filter[xx%s]);"
							"if(((fdata^d%s)&0xFFF8)==0){"
								"indx=cbg_table[xx%s];"
								"if(indx!=0xffffffff&&d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"

									"uint da=rotate(d%s+SQRT_3,9u)^(a%s-(0%s));"
									"c%s+=(b%s^da)%s+SQRT_3;c%s=rotate(c%s,11u);"
									"b%s+=(da^c%s);"

									"if(b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
										"uint found=atomic_inc(output);"
										"if(found<%uu){"
											"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
											"output[2*found+2]=indx;}"
									"}"
								"}"
							"}"
						, str_comp[comp], str_comp[comp], cbg_mask
						, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
						, str_comp[comp], str_comp[comp], nt_buffer[3]
						, str_comp[comp], str_comp[comp], nt_buffer[5], str_comp[comp], str_comp[comp]
						, str_comp[comp], str_comp[comp]
						, str_comp[comp], str_comp[comp]
						, output_size, comp);

					sprintf(source + strlen(source),
							"if(fdata&4){"// Is second
								"xx%s+=fdata&1?-1:1;"
								"if(((((uint)cbg_filter[xx%s])^d%s)&0xFFF8)==0){"
									"indx=cbg_table[xx%s];"
									"if(indx!=0xffffffff&&d%s==binary_values[indx*4u+3u]&&a%s==binary_values[indx*4u]){"

										"uint da=rotate(d%s+SQRT_3,9u)^(a%s-(0%s));"
										"c%s+=(b%s^da)%s+SQRT_3;c%s=rotate(c%s,11u);"
										"b%s+=(da^c%s);"

										"if(b%s==binary_values[indx*4u+1u]&&c%s==binary_values[indx*4u+2u]){"
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
						, str_comp[comp], str_comp[comp], nt_buffer[3]
						, str_comp[comp], str_comp[comp], nt_buffer[5], str_comp[comp], str_comp[comp]
						, str_comp[comp], str_comp[comp]
						, str_comp[comp], str_comp[comp]
						, output_size, comp);
				}
			}
		}
		else
		{
		sprintf(source+strlen(source), 
				"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
				"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
				"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);"
				"a+=(d^c^b)%s;"
				, nt_buffer[9] , nt_buffer[5], nt_buffer[13], nt_buffer[3]);

			// Find match
			sprintf(source + strlen(source), "xx=b&%uu;uint fdata;", cbg_mask);

			for (cl_uint comp = 0; comp < vector_size; comp++)
			{
				sprintf(source + strlen(source),
					"fdata=(uint)(cbg_filter[xx%s]);"

					"if(((fdata^a%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
							"d%s+=(rotate(a%s+SQRT_3,3u)^b%s^c%s)%s;"
							"c%s+=0%s;"

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
					, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11]
					, str_comp[comp], nt_buffer[7]
					, str_comp[comp], str_comp[comp]
					, output_size, comp);
				
				sprintf(source + strlen(source),
					"if(fdata&4){"// Is second
						"xx%s+=fdata&1?-1:1;"
						"if(((((uint)cbg_filter[xx%s])^a%s)&0xFFF8)==0){"
							"indx=cbg_table[xx%s];"
							"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
								"d%s+=(rotate(a%s+SQRT_3,3u)^b%s^c%s)%s;"
								"c%s+=0%s;"

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
					, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11]
					, str_comp[comp], nt_buffer[7]
					, str_comp[comp], str_comp[comp]
					, output_size, comp);

				sprintf(source + strlen(source),
					"if(fdata&2){"// Is unlucky
						"xx%s=a%s&%uu;"
						"fdata=(uint)(cbg_filter[xx%s]);"
						"if(((fdata^b%s)&0xFFF8)==0){"
							"indx=cbg_table[xx%s];"
							"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
								"d%s+=(rotate(a%s+SQRT_3,3u)^b%s^c%s)%s;"
								"c%s+=0%s;"

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
					, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11]
					, str_comp[comp], nt_buffer[7]
					, str_comp[comp], str_comp[comp]
					, output_size, comp);

				sprintf(source + strlen(source),
						"if(fdata&4){"// Is second
							"xx%s+=fdata&1?-1:1;"
							"if(((((uint)cbg_filter[xx%s])^b%s)&0xFFF8)==0){"
								"indx=cbg_table[xx%s];"
								"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
									"d%s+=(rotate(a%s+SQRT_3,3u)^b%s^c%s)%s;"
									"c%s+=0%s;"

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
					, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11]
					, str_comp[comp], nt_buffer[7]
					, str_comp[comp], str_comp[comp]
					, output_size, comp);
			}
		}

	strcat(source, "}}");
}

PRIVATE int ocl_protocol_charset_init(OpenCL_Param* result, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	int r = TRUE;
	if (num_passwords_loaded > 1 && max_lenght <= 13)
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
			// c += nt_buffer[7 * NT_NUM_KEYS + i];
			// d += (a ^ b ^ c) + nt_buffer[11 * NT_NUM_KEYS + i];
			bin[3] -= (ROTATE(bin[0] + SQRT_3, 3) ^ bin[1] ^ bin[2]);
			// a += (b ^ c ^ d) + nt_buffer[3 * NT_NUM_KEYS + i];
			bin[0] -= (bin[1] ^ bin[2] ^ bin[3]);

			bin[1] = ROTATE(bin[1], 32 - 15) - SQRT_3;
			bin[3] = ROTATE(bin[3], 32 -  9) - SQRT_3;
		}
		// Initialize table map
		build_cbg_table(NTLM_INDEX, 3, 0);

		cl_bool has_unified_memory = gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY;
		GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_HAD_UNIFIED_MEMORY);

		cl_uint ntlm_empy_hash[] = { 0x5e5bde24, 0xc08c4545, 0xb69f1f41, 0xbb1da021 };
		r = ocl_charset_init(result, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_ntlm_header, ocl_gen_kernel_with_lenght, ntlm_empy_hash, FALSE, 1);

		// Change values back
		if (has_unified_memory)
			gpu_devices[gpu_index].flags |= GPU_FLAG_HAD_UNIFIED_MEMORY;

		bin = (cl_uint*)binary_values;
		// Reverse binary_values modification
		for (cl_uint current_index = 0; current_index < num_passwords_loaded; current_index++, bin += 4)
		{
			bin[3] = ROTATE(bin[3] + SQRT_3, 9);
			bin[1] = ROTATE(bin[1] + SQRT_3, 15);

			bin[0] += (bin[1] ^ bin[2] ^ bin[3]);
			bin[3] += (ROTATE(bin[0] + SQRT_3, 3) ^ bin[1] ^ bin[2]);
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
		cl_uint ntlm_empy_hash[] = { 0xa0576ac5, 0x187317b3, 0xb69f1f41, 0xc67e4015 };
		r = ocl_charset_init(result, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_ntlm_header, ocl_gen_kernel_with_lenght, ntlm_empy_hash, FALSE, 1);
	}

	return r;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_ntlm_common(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL
	, cl_uint prefered_vector_size, char* kernel_params)
{
	char nt_buffer[16][16];
	char buffer_vector_size[16];
	// Needed when use a rule with more than one param
	int found_multiplier = found_param_3 ? 3 : 2;
	char output_3[64];
	output_3[0] = 0;

	// NTLM Function definition
	sprintf(source + strlen(source), "\n__kernel void %s(const __global uint* keys,__global uint* restrict output%s", kernel_name, kernel_params);

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
		"a=0xffffffff%s;a<<=3u;"
		"d=INIT_D+bs(INIT_C,INIT_B,a)%s;d=rotate(d,7u);"
		"c=INIT_C+bs(INIT_B,a,d)%s;c=rotate(c,11u);"
		"b=INIT_B+bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);"
		, nt_buffer[0], nt_buffer[1], nt_buffer[2], nt_buffer[3], nt_buffer[4], nt_buffer[5], nt_buffer[6], nt_buffer[7]
		, nt_buffer[8], nt_buffer[9], nt_buffer[10], nt_buffer[11], nt_buffer[12], nt_buffer[13], nt_buffer[14]);

	/* Round 2 */
	sprintf(source + strlen(source),
		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)  +SQRT_2;b=rotate(b,13u);"
		, nt_buffer[0], nt_buffer[4], nt_buffer[8], nt_buffer[12], nt_buffer[1], nt_buffer[5], nt_buffer[9], nt_buffer[13]
		, nt_buffer[2], nt_buffer[6], nt_buffer[10], nt_buffer[14], nt_buffer[3], nt_buffer[7], nt_buffer[11]);

	/* Round 3 */
	sprintf(source + strlen(source),
		"xx=c^b;"
		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s;"
		, nt_buffer[0], nt_buffer[8], nt_buffer[4], nt_buffer[12], nt_buffer[2], nt_buffer[10]
		, nt_buffer[6], nt_buffer[14], nt_buffer[1], nt_buffer[9], nt_buffer[5], nt_buffer[13]);


	// Match
	char* str_comp[] = { ".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf" };
	if (vector_size == 1) str_comp[0] = "";

	if (num_passwords_loaded == 1)
	{
		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			if (found_param_3)
				sprintf(output_3, "output[3u]=%s+%uu;", found_param_3, comp);

			sprintf(source + strlen(source),
			"if(b%s==%uu)"
			"{"
				"b%s+=SQRT_3;b%s=rotate(b%s,15u);"
				 
				"a%s+=(b%s^c%s^d%s)%s%s;"
				"d%s+=(rotate(a%s+SQRT_3,3u)^b%s^c%s)%s%s;"
				"c%s+=0%s%s;"
				"if(a%s==%uu&&d%s==%uu&&c%s==%uu)"
				"{"
					"output[0]=1;"
					"output[1]=get_global_id(0);"
					"output[2]=0;"
					"%s"
				"}"
			"}"
			, str_comp[comp], ROTATE(((cl_uint*)binary_values)[1], 32 - 15) - SQRT_3
			, str_comp[comp], str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3 ], buffer_vector_size[3 ] == 1 ? "" : str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11], buffer_vector_size[11] == 1 ? "" : str_comp[comp]
			, str_comp[comp], nt_buffer[7 ], buffer_vector_size[7 ] == 1 ? "" : str_comp[comp]

			, str_comp[comp], ((cl_uint*)binary_values)[0], str_comp[comp], ((cl_uint*)binary_values)[3], str_comp[comp], ((cl_uint*)binary_values)[2]
			, output_3);
		}
	}
	else
	{
		sprintf(source + strlen(source),
			"b+=SQRT_3;b=rotate(b,15u);"
			"a+=(d^c^b)%s;"
			, nt_buffer[3]);

		// Find match
		sprintf(source + strlen(source), "xx=b&%uu;uint fdata;", cbg_mask);

		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			if (found_param_3)
				sprintf(output_3, "output[3u*found+3u]=%s+%uu;", found_param_3, comp);

			sprintf(source + strlen(source),
				"fdata=(uint)(cbg_filter[xx%s]);"

				"if(((fdata^a%s)&0xFFF8)==0){"
					"indx=cbg_table[xx%s];"
					"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
						"d%s+=(rotate(a%s+SQRT_3,3u)^b%s^c%s)%s;"
						"c%s+=0%s;"

						"if(d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u]){"
							"uint found=atomic_inc(output);"
							"output[%i*found+1]=get_global_id(0);"
							"output[%i*found+2]=indx;"
							"%s"
						"}"
						// TODO: Reverse c,d to their last value for the unlikely case of 2 hashes with same a,b
						// TODO: if (value_map_collission1) do_smothing
					"}"
				"}"
				, str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11]
				, str_comp[comp], nt_buffer[7]
				, str_comp[comp], str_comp[comp]
				, found_multiplier, found_multiplier, output_3);
				
			sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx%s+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx%s])^a%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
							"d%s+=(rotate(a%s+SQRT_3,3u)^b%s^c%s)%s;"
							"c%s+=0%s;"

							"if(d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u]){"
								"uint found=atomic_inc(output);"
								"output[%i*found+1]=get_global_id(0);"
								"output[%i*found+2]=indx;"
								"%s"
							"}"
						"}"
					"}"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11]
				, str_comp[comp], nt_buffer[7]
				, str_comp[comp], str_comp[comp]
				, found_multiplier, found_multiplier, output_3);

			sprintf(source + strlen(source),
				"if(fdata&2){"// Is unlucky
					"xx%s=a%s&%uu;"
					"fdata=(uint)(cbg_filter[xx%s]);"
					"if(((fdata^b%s)&0xFFF8)==0){"
						"indx=cbg_table[xx%s];"
						"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
							"d%s+=(rotate(a%s+SQRT_3,3u)^b%s^c%s)%s;"
							"c%s+=0%s;"

							"if(d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u]){"
								"uint found=atomic_inc(output);"
								"output[%i*found+1]=get_global_id(0);"
								"output[%i*found+2]=indx;"
								"%s"
							"}"
						"}"
					"}"
				, str_comp[comp], str_comp[comp], cbg_mask
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11]
				, str_comp[comp], nt_buffer[7]
				, str_comp[comp], str_comp[comp]
				, found_multiplier, found_multiplier, output_3);

			sprintf(source + strlen(source),
					"if(fdata&4){"// Is second
						"xx%s+=fdata&1?-1:1;"
						"if(((((uint)cbg_filter[xx%s])^b%s)&0xFFF8)==0){"
							"indx=cbg_table[xx%s];"
							"if(indx!=0xffffffff&&b%s==binary_values[indx*4u+1u]&&a%s==binary_values[indx*4u]){"
								"d%s+=(rotate(a%s+SQRT_3,3u)^b%s^c%s)%s;"
								"c%s+=0%s;"

								"if(d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u]){"
									"uint found=atomic_inc(output);"
									"output[%i*found+1]=get_global_id(0);"
									"output[%i*found+2]=indx;"
									"%s"
								"}"
							"}"
						"}"
					"}"
				"}"
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp]
				, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11]
				, str_comp[comp], nt_buffer[7]
				, str_comp[comp], str_comp[comp]
				, found_multiplier, found_multiplier, output_3);
		}
	}

	if (ocl_end)	ocl_end(source);
	// End of kernel
	strcat(source, "}");
}

PRIVATE void ocl_gen_kernel_ntlm(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint value_map_collission, void* salt_param, cl_uint prefered_vector_size)
{
	ocl_gen_kernel_ntlm_common(source, kernel_name, ocl_load, ocl_end, found_param_3, aditional_param, lenght, NUM_KEYS_OPENCL, prefered_vector_size, "");
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UTF8
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
#ifdef __ANDROID__
	return ocl_common_init(param, gpu_index, gen, gpu_ntlm_crypt, BINARY_SIZE, ocl_write_ntlm_header, ocl_gen_kernel_ntlm, kernels2common + UTF8_INDEX_IN_KERNELS, 32, ocl_rule_simple_copy_unicode);
#else
	return ocl_common_init(param, gpu_index, gen, gpu_ntlm_crypt, BINARY_SIZE, ocl_write_ntlm_header, ocl_gen_kernel_ntlm, kernels2common + UTF8_INDEX_IN_KERNELS, 4/*consider 2 for Nvidia*/, ocl_rule_simple_copy_unicode);
#endif
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
extern uint32_t num_words;

PRIVATE void ocl_load_phrase_unicode(char* source, char nt_buffer[16][16], cl_uint lenght, cl_uint size_new_word)
{
	strcpy(nt_buffer[0], "+nt_buffer0");
	strcpy(nt_buffer[1], "+nt_buffer1");
	strcpy(nt_buffer[2], "+nt_buffer2");
	strcpy(nt_buffer[3], "+nt_buffer3");
	strcpy(nt_buffer[4], "+nt_buffer4");
	strcpy(nt_buffer[5], "+nt_buffer5");
	strcpy(nt_buffer[6], "+nt_buffer6");
	strcpy(nt_buffer[7], "+nt_buffer7");
	strcpy(nt_buffer[8], "+nt_buffer8");
	strcpy(nt_buffer[9], "+nt_buffer9");
	strcpy(nt_buffer[10], "+nt_buffer10");
	strcpy(nt_buffer[11], "+nt_buffer11");
	strcpy(nt_buffer[12], "+nt_buffer12");
	strcpy(nt_buffer[13], "+nt_buffer13");
	strcpy(nt_buffer[14], "+total_len");

	// Define the kernel to process the keys from phrases into a "fast-to-use" format
	sprintf(source + strlen(source),
							"uint max_number=get_global_id(0);"
							"uint i,out_idx=0;");

	for (cl_uint i = 0; i < 14; i++)
		sprintf(source + strlen(source), "uint nt_buffer%u=0;", i);

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
							"uint val0,val1;"
							// Body part of the string to copy
							"for(i=0;i<len/4;i++)"
							"{"
								"uint qword_copy=keys[word_pos_j+i];"
								"REG_ASSIGN(out_idx,qword_copy);"
								"out_idx+=2;"
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
									"out_idx+=2;"
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
										"out_idx+=2;"
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
						"total_len<<=4u;");
}
PRIVATE char* ocl_gen_kernel_phrases(char* kernel_name, cl_uint value_map_collission1, GPUDevice* gpu, cl_uint ntlm_size_bit_table1, cl_uint size_new_word)
{
	char* source = (char*)malloc(1024 * 16);

	ocl_write_ntlm_header(source, gpu, /*ntlm_size_bit_table*/0);

	sprintf(source + strlen(source),
		"#define REG_ASSIGN(index,val) "

		"val0=GET_1(val);"
		"val1=GET_2(val);"

		"switch(index)"
		"{"
			"case 0:"
				"nt_buffer0=val0;"
				"nt_buffer1=val1;"
			"break;"
			"case 2:"
				"nt_buffer2=val0;"
				"nt_buffer3=val1;"
			"break;"
			"case 4:"
				"nt_buffer4=val0;"
				"nt_buffer5=val1;"
			"break;"
			"case 6:"
				"nt_buffer6=val0;"
				"nt_buffer7=val1;"
			"break;"
			"case 8:"
				"nt_buffer8=val0;"
				"nt_buffer9=val1;"
			"break;"
			"case 10:"
				"nt_buffer10=val0;"
				"nt_buffer11=val1;"
			"break;"
			"case 12:"
				"nt_buffer12=val0;"
				"nt_buffer13=val1;"
			"break;"
		"}\n");

	char nt_buffer[16][16];
	// NTLM Function definition
	sprintf(source + strlen(source), "\n__kernel void %s(const __global uint* restrict keys,__global uint* restrict output", kernel_name);

	if (num_passwords_loaded > 1)
		strcat(source, ",const __global uint* restrict cbg_table,const __global uint* restrict binary_values,const __global ushort* restrict cbg_filter");

	// Begin function code
	sprintf(source + strlen(source), "){");

	// Convert the key into a nt_buffer
	ocl_load_phrase_unicode(source, nt_buffer, max_lenght, size_new_word);

	sprintf(source + strlen(source), "uint a,b,c,d,xx,indx;");

	/* Round 1 */
	sprintf(source + strlen(source),
		"a=0xffffffff%s;a<<=3u;"
		"d=INIT_D+bs(INIT_C,INIT_B,a)%s;d=rotate(d,7u);"
		"c=INIT_C+bs(INIT_B,a,d)%s;c=rotate(c,11u);"
		"b=INIT_B+bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c)%s;b=rotate(b,19u);"

		"a+=bs(d,c,b)%s;a=rotate(a,3u);"
		"d+=bs(c,b,a)%s;d=rotate(d,7u);"
		"c+=bs(b,a,d)%s;c=rotate(c,11u);"
		"b+=bs(a,d,c);b=rotate(b,19u);"
		, nt_buffer[0], nt_buffer[1], nt_buffer[2], nt_buffer[3], nt_buffer[4], nt_buffer[5], nt_buffer[6], nt_buffer[7]
		, nt_buffer[8], nt_buffer[9], nt_buffer[10], nt_buffer[11], nt_buffer[12], nt_buffer[13], nt_buffer[14]);

	/* Round 2 */
	sprintf(source + strlen(source),
		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)%s+SQRT_2;b=rotate(b,13u);"

		"a+=MAJ(b,c,d)%s+SQRT_2;a=rotate(a,3u);"
		"d+=MAJ(a,b,c)%s+SQRT_2;d=rotate(d,5u);"
		"c+=MAJ(d,a,b)%s+SQRT_2;c=rotate(c,9u);"
		"b+=MAJ(c,d,a)  +SQRT_2;b=rotate(b,13u);"
		, nt_buffer[0], nt_buffer[4], nt_buffer[8], nt_buffer[12], nt_buffer[1], nt_buffer[5], nt_buffer[9], nt_buffer[13]
		, nt_buffer[2], nt_buffer[6], nt_buffer[10], nt_buffer[14], nt_buffer[3], nt_buffer[7], nt_buffer[11]);

	/* Round 3 */
	sprintf(source + strlen(source),
		"xx=c^b;"
		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s+SQRT_3;b=rotate(b,15u);xx=c^b;"

		"a+=(d^xx)%s+SQRT_3;a=rotate(a,3u);"
		"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
		"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
		"b+=(xx^c)%s;"
		, nt_buffer[0], nt_buffer[8], nt_buffer[4], nt_buffer[12], nt_buffer[2], nt_buffer[10]
		, nt_buffer[6], nt_buffer[14], nt_buffer[1], nt_buffer[9], nt_buffer[5], nt_buffer[13]);


	// Match
	if (num_passwords_loaded == 1)
	{
		sprintf(source + strlen(source),
			"if(b==%uu)"
			"{"
				"b+=SQRT_3;b=rotate(b,15u);"
				 
				"a+=(b^c^d)%s;"
				"d+=(rotate(a+SQRT_3,3u)^b^c)%s;"
				"c+=%s;"
				"if(a==%uu&&d==%uu&&c==%uu)"
				"{"
					"output[0]=1;"
					"output[1]=get_global_id(0);"
					"output[2]=0;"
				"}"
			"}"
			, ROTATE(((cl_uint*)binary_values)[1], 32-15) - SQRT_3
			, nt_buffer[3 ]
			, nt_buffer[11]
			, nt_buffer[7 ]
			, ((cl_uint*)binary_values)[0], ((cl_uint*)binary_values)[3], ((cl_uint*)binary_values)[2]);
	}
	else
	{
		sprintf(source + strlen(source),
			"b+=SQRT_3;b=rotate(b,15u);"
			"a+=(d^c^b)%s;"
			, nt_buffer[3]);

		// Find match
		sprintf(source + strlen(source), "xx=b&%uu;uint fdata;", cbg_mask);
		
		sprintf(source + strlen(source),
			"fdata=(uint)(cbg_filter[xx]);"

			"if(((fdata^a)&0xFFF8)==0){"
				"indx=cbg_table[xx];"
				"if(indx!=0xffffffff&&b==binary_values[indx*4u+1u]&&a==binary_values[indx*4u]){"
					"d+=(rotate(a+SQRT_3,3u)^b^c)%s;"
					"c+=0%s;"

					"if(d==binary_values[indx*4u+3u]&&c==binary_values[indx*4u+2u]){"
						"uint found=atomic_inc(output);"
						"output[2*found+1]=get_global_id(0);"
						"output[2*found+2]=indx;"
					"}"
					// TODO: Reverse c,d to their last value for the unlikely case of 2 hashes with same a,b
					// TODO: if (value_map_collission1) do_smothing
				"}"
			"}"
			, nt_buffer[11], nt_buffer[7]);
				
		sprintf(source + strlen(source),
			"if(fdata&4){"// Is second
				"xx+=fdata&1?-1:1;"
				"if(((((uint)cbg_filter[xx])^a)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&b==binary_values[indx*4u+1u]&&a==binary_values[indx*4u]){"
						"d+=(rotate(a+SQRT_3,3u)^b^c)%s;"
						"c+=0%s;"

						"if(d==binary_values[indx*4u+3u]&&c==binary_values[indx*4u+2u]){"
							"uint found=atomic_inc(output);"
							"output[2*found+1]=get_global_id(0);"
							"output[2*found+2]=indx;"
						"}"
					"}"
				"}"
			"}"
			, nt_buffer[11], nt_buffer[7]);

		sprintf(source + strlen(source),
			"if(fdata&2){"// Is unlucky
				"xx=a&%uu;"
				"fdata=(uint)(cbg_filter[xx]);"
				"if(((fdata^b)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&b==binary_values[indx*4u+1u]&&a==binary_values[indx*4u]){"
						"d+=(rotate(a+SQRT_3,3u)^b^c)%s;"
						"c+=0%s;"

						"if(d==binary_values[indx*4u+3u]&&c==binary_values[indx*4u+2u]){"
							"uint found=atomic_inc(output);"
							"output[2*found+1]=get_global_id(0);"
							"output[2*found+2]=indx;"
						"}"
					"}"
				"}"
			, cbg_mask, nt_buffer[11], nt_buffer[7]);

		sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx])^b)&0xFFF8)==0){"
						"indx=cbg_table[xx];"
						"if(indx!=0xffffffff&&b==binary_values[indx*4u+1u]&&a==binary_values[indx*4u]){"
							"d+=(rotate(a+SQRT_3,3u)^b^c)%s;"
							"c+=0%s;"

							"if(d==binary_values[indx*4u+3u]&&c==binary_values[indx*4u+2u]){"
								"uint found=atomic_inc(output);"
								"output[2*found+1]=get_global_id(0);"
								"output[2*found+2]=indx;"
							"}"
						"}"
					"}"
				"}"
			"}"
			, nt_buffer[11], nt_buffer[7]);
	}

	// End of kernel
	strcat(source, "}");

	return source;
}

PRIVATE int ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	// Teoretical: 7.87G	AMD Radeon HD 7970
	// Baseline  : 1.74G
	// Now------>: 3.50G
	return ocl_phrases_init(param, gpu_index, gen, gpu_ntlm_crypt, BINARY_SIZE, ocl_gen_kernel_phrases, 128);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	return ocl_rules_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_ntlm_header, ocl_gen_kernel_ntlm, RULE_UNICODE_INDEX, 1);
}
#endif

Format ntlm_format = {
	"NTLM",
	"MD4 based.",
	"",
	NTLM_MAX_KEY_LENGHT,
	BINARY_SIZE,
	0,
	2,
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
	{{CPU_CAP_AVX2, PROTOCOL_NTLM, crypt_ntlm_protocol_avx2}, {CPU_CAP_AVX, PROTOCOL_NTLM, crypt_ntlm_protocol_avx}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}},
#else
	#ifdef HS_ARM
		{{CPU_CAP_NEON, PROTOCOL_NTLM, crypt_ntlm_protocol_neon}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}},
	#else
		{{CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_SSE2, PROTOCOL_NTLM, crypt_ntlm_protocol_sse2}, {CPU_CAP_C_CODE, PROTOCOL_NTLM, crypt_ntlm_protocol_c_code}},
	#endif
#endif
	#ifdef HS_OPENCL_SUPPORT
		{{PROTOCOL_CHARSET_OCL, ocl_protocol_charset_init}, {PROTOCOL_PHRASES_OPENCL, ocl_protocol_phrases_init}, {PROTOCOL_RULES_OPENCL, ocl_protocol_rules_init}, {PROTOCOL_UTF8, ocl_protocol_utf8_init}}
	#endif
};
