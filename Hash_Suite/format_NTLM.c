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

	return FALSE;
}

PRIVATE void add_hash_from_line(ImportParam* param, char* user_name, char* rid, char* lm, char* ntlm, sqlite3_int64 tag_id)
{
	char lm_part[17];
	// All values to zero
	lm_part[16] = 0;// Null terminate it

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
			sqlite3_int64 account_id = insert_hash_account(param, user_name, _strupr(ntlm), NTLM_INDEX, tag_id);

			if (valid_hex_string(_strupr(lm), 32) && (strcmp(lm, "AAD3B435B51404EEAAD3B435B51404EE") || !strcmp(ntlm, "31D6CFE0D16AE931B73C59D7E0C089C0")))
			{
				// Insert hash lm
				strncpy(lm_part, lm, 16);
				sqlite3_int64 hash_id = insert_hash_if_necesary(lm_part, formats[LM_INDEX].db_id, param->result.formats_stat + LM_INDEX);

				strncpy(lm_part, lm + 16, 16);
				sqlite3_int64 hash_id2 = insert_hash_if_necesary(lm_part, formats[LM_INDEX].db_id, param->result.formats_stat + LM_INDEX);

				// Insert account lm
				sqlite3_reset(insert_account_lm);
				sqlite3_bind_int64(insert_account_lm, 1, account_id);
				sqlite3_bind_int64(insert_account_lm, 2, hash_id);
				sqlite3_bind_int64(insert_account_lm, 3, hash_id2);
				sqlite3_step(insert_account_lm);

				num_user_by_formats[LM_INDEX]++;
			}
			else
				param->result.formats_stat[LM_INDEX].num_hash_disable++;
		}
	}
}

PRIVATE unsigned int get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	unsigned int* out = (unsigned int*)binary;
	unsigned int i = 0;
	unsigned int temp;

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
	out[1]  = (out[1] >> 15) | (out[1] << 17);
	out[1] -= SQRT_3;
	
	return out[1];
}

#ifdef HS_ARM
	#define NT_NUM_KEYS		    128
#endif

#ifdef HS_X86
	#define NT_NUM_KEYS		    256
#endif

PRIVATE void crypt_ntlm_protocol_body(CryptParam* param, crypt_kernel_asm_func* crypt_ntlm_kernel_asm)
{
	unsigned int* nt_buffer = (unsigned int*)_aligned_malloc(16 * 4 * NT_NUM_KEYS + 5 * 4 * NT_NUM_KEYS, 32);

	unsigned int* unpacked_as = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS);
	unsigned int* unpacked_bs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 1*NT_NUM_KEYS);
	unsigned int* unpacked_cs = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 2*NT_NUM_KEYS);
	unsigned int* unpacked_ds = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 3*NT_NUM_KEYS);
	unsigned int* indexs	  = (unsigned int*)(nt_buffer + 16*NT_NUM_KEYS + 4*NT_NUM_KEYS);

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, 16*4*NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_ntlm_kernel_asm(nt_buffer, bit_table, size_bit_table);

		for (unsigned int i = 0; i < NT_NUM_KEYS; i++)
			if(indexs[i])
			{
				unsigned int indx = table[unpacked_bs[i] & size_table];
				// Partial match
				while(indx != NO_ELEM)
				{
					unsigned int aa, bb, cc, dd;
					unsigned int* bin = ((unsigned int*)binary_values) + indx*4;

					if(unpacked_bs[i] != bin[1]) goto next_iteration;
					bb = unpacked_bs[i] + SQRT_3; bb = rotate(bb , 15);

					aa = unpacked_as[i] + (bb ^ unpacked_cs[i] ^ unpacked_ds[i]) + nt_buffer[3*NT_NUM_KEYS+i] + SQRT_3; aa = rotate(aa , 3 );
					if(aa != bin[0]) goto next_iteration;

					dd = unpacked_ds[i] + (aa ^ bb ^ unpacked_cs[i]) + nt_buffer[11*NT_NUM_KEYS+i] + SQRT_3; dd = rotate(dd , 9 );
					if(dd != bin[3]) goto next_iteration;

					cc = unpacked_cs[i] + (dd ^ aa ^ bb) + nt_buffer[7*NT_NUM_KEYS+i] + SQRT_3; cc = rotate(cc , 11);	
					if(cc != bin[2]) goto next_iteration;

					// Total match
					password_was_found(indx, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

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
PRIVATE void crypt_ntlm_protocol_c_code(CryptParam* param)
{
	unsigned int nt_buffer[15*NT_NUM_KEYS];
	unsigned int a, b, c, d, index;

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, sizeof(nt_buffer));
	memset(key, 0, sizeof(key));

	while(continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		for(int i = 0; i < NT_NUM_KEYS; i++)
		{
			/* Round 1 */
			a = 		0xFFFFFFFF					 + nt_buffer[0*NT_NUM_KEYS+i]; a=rotate(a, 3);
			d = INIT_D+(INIT_C ^ (a & 0x77777777))   + nt_buffer[1*NT_NUM_KEYS+i]; d=rotate(d, 7);
			c = INIT_C+(INIT_B ^ (d & (a ^ INIT_B))) + nt_buffer[2*NT_NUM_KEYS+i]; c=rotate(c, 11);
			b = INIT_B + (a ^ (c & (d ^ a)))		 + nt_buffer[3*NT_NUM_KEYS+i]; b=rotate(b, 19);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer[4*NT_NUM_KEYS+i] ; a = rotate(a , 3 );
			d += (c ^ (a & (b ^ c)))  +  nt_buffer[5*NT_NUM_KEYS+i] ; d = rotate(d , 7 );
			c += (b ^ (d & (a ^ b)))  +  nt_buffer[6*NT_NUM_KEYS+i] ; c = rotate(c , 11);
			b += (a ^ (c & (d ^ a)))  +  nt_buffer[7*NT_NUM_KEYS+i] ; b = rotate(b , 19);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer[8*NT_NUM_KEYS+i] ; a = rotate(a , 3 );
			d += (c ^ (a & (b ^ c)))  +  nt_buffer[9*NT_NUM_KEYS+i] ; d = rotate(d , 7 );
			c += (b ^ (d & (a ^ b)))  +  nt_buffer[10*NT_NUM_KEYS+i]; c = rotate(c , 11);
			b += (a ^ (c & (d ^ a)))  +  nt_buffer[11*NT_NUM_KEYS+i]; b = rotate(b , 19);

			a += (d ^ (b & (c ^ d)))  +  nt_buffer[12*NT_NUM_KEYS+i] ; a = rotate(a , 3 );
			d += (c ^ (a & (b ^ c)))  +  nt_buffer[13*NT_NUM_KEYS+i] ; d = rotate(d , 7 );
			c += (b ^ (d & (a ^ b)))  +  nt_buffer[14*NT_NUM_KEYS+i] ; c = rotate(c , 11);
			b += (a ^ (c & (d ^ a)))								 ; b = rotate(b , 19);

			/* Round 2 */
			a += ((b & (c | d)) | (c & d)) + nt_buffer[0*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 );
			d += ((a & (b | c)) | (b & c)) + nt_buffer[4*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 );
			c += ((d & (a | b)) | (a & b)) + nt_buffer[8*NT_NUM_KEYS+i] + SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a)) + nt_buffer[12*NT_NUM_KEYS+i]+ SQRT_2; b = rotate(b , 13);

			a += ((b & (c | d)) | (c & d)) + nt_buffer[1*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 );
			d += ((a & (b | c)) | (b & c)) + nt_buffer[5*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 );
			c += ((d & (a | b)) | (a & b)) + nt_buffer[9*NT_NUM_KEYS+i] + SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a)) + nt_buffer[13*NT_NUM_KEYS+i]+ SQRT_2; b = rotate(b , 13);

			a += ((b & (c | d)) | (c & d)) + nt_buffer[2*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 );
			d += ((a & (b | c)) | (b & c)) + nt_buffer[6*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 );
			c += ((d & (a | b)) | (a & b)) + nt_buffer[10*NT_NUM_KEYS+i]+ SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a)) + nt_buffer[14*NT_NUM_KEYS+i]+ SQRT_2; b = rotate(b , 13);

			a += ((b & (c | d)) | (c & d)) + nt_buffer[3*NT_NUM_KEYS+i] + SQRT_2; a = rotate(a , 3 );
			d += ((a & (b | c)) | (b & c)) + nt_buffer[7*NT_NUM_KEYS+i] + SQRT_2; d = rotate(d , 5 );
			c += ((d & (a | b)) | (a & b)) + nt_buffer[11*NT_NUM_KEYS+i]+ SQRT_2; c = rotate(c , 9 );
			b += ((c & (d | a)) | (d & a))								+ SQRT_2; b = rotate(b , 13);

			/* Round 3 */
			a += (d ^ c ^ b) + nt_buffer[0*NT_NUM_KEYS+i]  + SQRT_3; a = rotate(a , 3 );
			d += (c ^ b ^ a) + nt_buffer[8*NT_NUM_KEYS+i]  + SQRT_3; d = rotate(d , 9 );
			c += (b ^ a ^ d) + nt_buffer[4*NT_NUM_KEYS+i]  + SQRT_3; c = rotate(c , 11);
			b += (a ^ d ^ c) + nt_buffer[12*NT_NUM_KEYS+i] + SQRT_3; b = rotate(b , 15);

			a += (d ^ c ^ b) + nt_buffer[2*NT_NUM_KEYS+i]  + SQRT_3; a = rotate(a , 3 );
			d += (c ^ b ^ a) + nt_buffer[10*NT_NUM_KEYS+i] + SQRT_3; d = rotate(d , 9 );
			c += (b ^ a ^ d) + nt_buffer[6 * NT_NUM_KEYS + i] + SQRT_3; c = rotate(c, 11);
			b += (a ^ d ^ c) + nt_buffer[14 * NT_NUM_KEYS + i] + SQRT_3; b = rotate(b, 15);

			a += (d ^ c ^ b) + nt_buffer[1 * NT_NUM_KEYS + i] + SQRT_3; a = rotate(a, 3);
			d += (c ^ b ^ a) + nt_buffer[9 * NT_NUM_KEYS + i] + SQRT_3; d = rotate(d, 9);
			c += (b ^ a ^ d) + nt_buffer[5 * NT_NUM_KEYS + i] + SQRT_3; c = rotate(c, 11);
			b += (a ^ d ^ c) + nt_buffer[13 * NT_NUM_KEYS + i];

			// Search for a match
			index = table[b & size_table];

			// Partial match
			while (index != NO_ELEM)
			{
				unsigned int aa, bb, cc, dd;
				unsigned int* bin = ((unsigned int*)binary_values) + index * 4;

				if (b != bin[1]) goto next_iteration;
				bb = b + SQRT_3; bb = rotate(bb, 15);

				aa = a + (bb ^ c ^ d) + nt_buffer[3 * NT_NUM_KEYS + i] + SQRT_3; aa = rotate(aa, 3);
				if (aa != bin[0]) goto next_iteration;

				dd = d + (aa ^ bb ^ c) + nt_buffer[11 * NT_NUM_KEYS + i] + SQRT_3; dd = rotate(dd, 9);
				if (dd != bin[3]) goto next_iteration;

				cc = c + (dd ^ aa ^ bb) + nt_buffer[7 * NT_NUM_KEYS + i] + SQRT_3; cc = rotate(cc, 11);
				if (cc != bin[2]) goto next_iteration;

				// Total match
				password_was_found(index, ntlm2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));

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
void crypt_ntlm_neon_kernel_asm(unsigned int* buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_ntlm_protocol_neon(CryptParam* param)
{
	crypt_ntlm_protocol_body(param, crypt_ntlm_neon_kernel_asm);
}

#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef _M_X64
void crypt_ntlm_avx_kernel_asm(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_ntlm_protocol_avx(CryptParam* param)
{
	crypt_ntlm_protocol_body(param, crypt_ntlm_avx_kernel_asm);
}
#endif
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef _M_X64
void crypt_ntlm_avx2_kernel_asm(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
PRIVATE void crypt_ntlm_protocol_avx2(CryptParam* param)
{
	crypt_ntlm_protocol_body(param, crypt_ntlm_avx2_kernel_asm);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 Implementation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
void crypt_ntlm_sse2_kernel_asm(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
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
PRIVATE void ocl_write_ntlm_header(char* source, GPUDevice* gpu, cl_uint ntlm_size_bit_table)
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
	sprintf(source + strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
#endif
	
	//Initial values
	sprintf(source+strlen(source),
"#define INIT_A 0x67452301\n"
"#define INIT_B 0xefcdab89\n"
"#define INIT_C 0x98badcfe\n"
"#define INIT_D 0x10325476\n"

"#define SQRT_2 0x5a827999\n"
"#define SQRT_3 0x6ed9eba1\n");

	if(num_passwords_loaded > 1 )
		sprintf(source+strlen(source),
"#define SIZE_TABLE %uu\n"
"#define SIZE_BIT_TABLE %uu\n", size_table, ntlm_size_bit_table);

	sprintf(source+strlen(source),
	"#ifdef __ENDIAN_LITTLE__\n"
		//little-endian
		"#define GET_1(x) ((((x)<<8)&0xff0000)+((x)&0xff))\n"
		"#define GET_2(x) ((((x)>>8)&0xff0000)+(((x)>>16)&0xff))\n"
	"#else\n"
		//big-endian
		"#define GET_1(x) ((((x)>>8)&0xff0000)+(((x)>>24)&0xff))\n"
		"#define GET_2(x) ((((x)<<16)&0xff0000)+(((x)>>8)&0xff))\n"
	"#endif\n");
}
PRIVATE void ocl_gen_kernel_with_lenght_onehash(char* source, cl_uint key_lenght, cl_uint vector_size, char** nt_buffer, char** str_comp)
{
	cl_uint a = ((unsigned int*)binary_values)[0];
	cl_uint b = ((unsigned int*)binary_values)[1];
	cl_uint c = ((unsigned int*)binary_values)[2];
	cl_uint d = ((unsigned int*)binary_values)[3];

	unsigned int max_char_in_charset = 0;
	for (unsigned int i = 0; i < num_char_in_charset; i++)
		if (max_char_in_charset < charset[i])
			max_char_in_charset = charset[i];

	strcat(source, "uint a1,b1,c1,d1,xx;");

	if (max_char_in_charset <= 127 && key_lenght >= 4)
		sprintf(source+strlen(source), 
			"a1=rotate(nt_buffer0%s,3u);"
			"d1=INIT_D+(INIT_C^(a1&0x77777777))%s;d1=rotate(d1,7u);"
			"uint val_d=d1&0xFFFC07FF;"
			, str_comp[0], nt_buffer[1]);
	

	b += SQRT_3; b = rotate(b, 15);
	// Reverse
	c = rotate(c, 21u);	c -= (d ^ a ^ b) + SQRT_3;
	d = rotate(d, 23u);	d -= SQRT_3;
	
	//if(key_lenght == 14) c -= 14<<4;
	//if(key_lenght <= 14) d -= (a ^ b ^ c);

	//if(key_lenght > 14)
	{
		sprintf(source+strlen(source), "c1=%uu-%s;", c, key_lenght >= 14 ? (nt_buffer[7]+1) : "0");
		sprintf(source+strlen(source), "d1=%uu-((%uu^c1)%s);", d, a^b, nt_buffer[11]);
	}

	a = rotate(a, 29); a -= SQRT_3;
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
		, a, b, nt_buffer[3], ((unsigned int*)binary_values)[1], nt_buffer[13]
		, nt_buffer[5], nt_buffer[9], nt_buffer[1], (key_lenght<<4)+SQRT_3, nt_buffer[6]
		, nt_buffer[10], nt_buffer[2], nt_buffer[12], nt_buffer[4], nt_buffer[8]);

	if(key_lenght > 2) strcat(source, "nt_buffer1+=SQRT_2;");
	if(key_lenght > 4) strcat(source, "nt_buffer2+=SQRT_2;");
	if(key_lenght > 6) strcat(source, "nt_buffer3+=SQRT_2;");
	if(key_lenght > 8) strcat(source, "nt_buffer4+=SQRT_2;");

	if( is_charset_consecutive(charset) )
		for (unsigned int i = 0; i < vector_size; i++)
			sprintf(source + strlen(source), "nt_buffer0%s|=%iU;", str_comp[i], is_charset_consecutive(charset) - vector_size + i);

	// Begin cycle changing first character
	sprintf(source+strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if( is_charset_consecutive(charset) )
		sprintf(source+strlen(source), "nt_buffer0+=%uU;", vector_size);
	else
		for (unsigned int i = 0; i < vector_size; i++)
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
		for (unsigned int comp = 0; comp < vector_size; comp++)
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

		for (unsigned int comp = 0; comp < vector_size; comp++)
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
PRIVATE void ocl_gen_kernel_with_lenght(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission, cl_uint workgroup)
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
			sprintf(source + strlen(source), "a+=0%s;", nt_buffer[3]);

			// Find match
			sprintf(source + strlen(source),
					"xx=a&SIZE_BIT_TABLE;"
					"uint%s bit_table_val=xx>>5u;"
					"xx&=31u;", buffer);

			for (cl_uint comp = 0; comp < vector_size; comp++)
				sprintf(source + strlen(source),
					"bit_table_val%s=bit_table[bit_table_val%s];", str_comp[comp], str_comp[comp]);

			strcat(source, "bit_table_val=(bit_table_val>>xx)&1u;");

			for (cl_uint comp = 0; comp < vector_size; comp++)
			{
				sprintf(source+strlen(source), 
					"if(bit_table_val%s)"
					"{"
						"indx=table[(a%s)&SIZE_TABLE];"

						"while(indx!=0xffffffff)"
						//"if(indx!=0xffffffff)"
						"{"
							"if(a%s==binary_values[indx*4u])"
							"{"
								"a%s-=0%s;"

								"d%s+=(a%s^b%s^c%s)+SQRT_3;d%s=rotate(d%s,9u);"
								"c%s+=(d%s^a%s^b%s)%s+SQRT_3;c%s=rotate(c%s,11u);"
								"b%s+=(a%s^d%s^c%s);"

								"if(b%s==binary_values[indx*4u+1u]&&d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u])"
								"{"
									"uint found=atomic_inc(output);"
									"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
									"output[2*found+2]=indx;}"
								"}",
							str_comp[comp],
							str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3],
							str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
							str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[5 ], str_comp[comp], str_comp[comp],
							str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
							str_comp[comp], str_comp[comp], str_comp[comp], output_size, comp);

				// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same b
				if (value_map_collission)
					sprintf(source + strlen(source),
								"b%s-=(a%s^d%s^c%s);"
								"c%s=rotate(c%s,32u-11u);c%s-=(d%s^a%s^b%s)%s+SQRT_3;"
								"d%s=rotate(d%s,32u-9u );d%s-=(a%s^b%s^c%s)+SQRT_3;"
								"a%s+=0%s;",
								str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
								str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[5],
								str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp],
								str_comp[comp], nt_buffer[3]);
			strcat(source,  "}"
							"indx=same_hash_next[indx];"
						"}"
					"}");
			}
		}
		else
		{
		sprintf(source+strlen(source), 
				"d+=(xx^a)%s+SQRT_3;d=rotate(d,9u);xx=a^d;"
				"c+=(b^xx)%s+SQRT_3;c=rotate(c,11u);"
				"b+=(xx^c)%s;"
				, nt_buffer[9] , nt_buffer[5], nt_buffer[13]);

			// Find match
			sprintf(source + strlen(source),
						"xx=b&SIZE_BIT_TABLE;"
						"uint%s bit_table_val=xx>>5u;"
						"xx&=31u;", buffer);

			for (cl_uint comp = 0; comp < vector_size; comp++)
				sprintf(source + strlen(source),
					"bit_table_val%s=bit_table[bit_table_val%s];", str_comp[comp], str_comp[comp]);

			strcat(source, "bit_table_val=(bit_table_val>>xx)&1u;");

			for (cl_uint comp = 0; comp < vector_size; comp++)
			{
				sprintf(source+strlen(source), 
					"if(bit_table_val%s)"
					"{"
						"indx=table[(b%s)&SIZE_TABLE];"

						"while(indx!=0xffffffff)"
						//"if(indx!=0xffffffff)"
						"{"
							"if(b%s==binary_values[indx*4u+1u])"
							"{"
								"b%s+=SQRT_3;b%s=rotate(b%s,15u);"

								"a%s+=(b%s^c%s^d%s)%s+SQRT_3;a%s=rotate(a%s,3u);"
								"d%s+=(a%s^b%s^c%s)%s+SQRT_3;d%s=rotate(d%s,9u);"
								"c%s+=(d%s^a%s^b%s)%s+SQRT_3;c%s=rotate(c%s,11u);"
								"if(a%s==binary_values[indx*4u]&&d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u])"
								"{"
									"uint found=atomic_inc(output);"
									"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+(i+%uu)%%NUM_CHAR_IN_CHARSET;"
									"output[2*found+2]=indx;}"
								"}",
				str_comp[comp],
				str_comp[comp], str_comp[comp], str_comp[comp], 
				str_comp[comp], str_comp[comp],
				str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3],
				str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11],
				str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[7], 
				str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], output_size, comp);

				// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same b
				if (value_map_collission)
					sprintf(source + strlen(source),
								"c%s=rotate(c%s,21u);c%s-=(d%s^a%s^b%s)%s+SQRT_3;"
								"d%s=rotate(d%s,23u);d%s-=(a%s^b%s^c%s)%s+SQRT_3;"
								"a%s=rotate(a%s,29u);a%s-=(b%s^c%s^d%s)%s+SQRT_3;"
								"b%s=rotate(b%s,17u);b%s-=SQRT_3;",
								str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[7],
								str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11],
								str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3],
								str_comp[comp], str_comp[comp], str_comp[comp]);
			strcat(source,  "}"
							"indx=same_hash_next[indx];"
						"}"
					"}");
			}
		}

	strcat(source, "}}");
}

PRIVATE void ocl_protocol_charset_init(OpenCL_Param* result, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	if (num_passwords_loaded > 1 && max_lenght <= 13)
	{
		cl_uint* old_table = table;
		cl_uint* old_bit_table = bit_table;
		cl_uint* old_same_hash_next = same_hash_next;
		void* old_bins = malloc(BINARY_SIZE*num_passwords_loaded);

		table = (cl_uint*)_aligned_malloc(sizeof(cl_uint)* (size_table + 1), 4096);
		bit_table = (cl_uint*)_aligned_malloc((size_bit_table / 32 + 1) * sizeof(cl_uint), 4096);
		same_hash_next = (cl_uint*)_aligned_malloc(sizeof(cl_uint)* num_passwords_loaded, 4096);

		// Initialize table map
		memcpy(old_bins, binary_values, BINARY_SIZE*num_passwords_loaded);
		memset(bit_table, 0, (size_bit_table / 32 + 1) * sizeof(cl_uint));
		memset(table, 0xff, sizeof(cl_uint)* (size_table + 1));
		memset(same_hash_next, 0xff, sizeof(cl_uint)* num_passwords_loaded);

		// Reverse last steps
		cl_uint* bin = (cl_uint*)binary_values;
		for (cl_uint current_index = 0; current_index < num_passwords_loaded; current_index++, bin += 4)
		{
			bin[1] = rotate(bin[1] + SQRT_3, 15);

			// c += (d ^ a ^ b) + nt_buffer[7 * NT_NUM_KEYS + i] + SQRT_3; c = rotate(c, 11);
			bin[2] = rotate(bin[2], 32-11);
			bin[2] -= (bin[3] ^ bin[0] ^ bin[1]) + SQRT_3;
			// d += (a ^ b ^ c) + nt_buffer[11 * NT_NUM_KEYS + i] + SQRT_3; d = rotate(d, 9);
			bin[3] = rotate(bin[3], 32 - 9);
			bin[3] -= (bin[0] ^ bin[1] ^ bin[2]) + SQRT_3;
			// a += (b ^ c ^ d) + nt_buffer[3 * NT_NUM_KEYS + i] + SQRT_3; a = rotate(a, 3);
			bin[0] = rotate(bin[0], 32 - 3);
			bin[0] -= (bin[1] ^ bin[2] ^ bin[3]) + SQRT_3;

			bin[1] = rotate(bin[1], 32 - 15) - SQRT_3;

			// Calculate bit_table, table and other data
			cl_uint value_map = bin[0];
			bit_table[(value_map & size_bit_table) >> 5] |= 1 << ((value_map & size_bit_table) & 31);
			// Put the password in the table map
			if (table[value_map & size_table] == NO_ELEM)
			{
				table[value_map & size_table] = current_index;
			}
			else
			{
				cl_uint last_index = table[value_map & size_table];
				while (same_hash_next[last_index] != NO_ELEM)
					last_index = same_hash_next[last_index];

				same_hash_next[last_index] = current_index;
			}
		}

		cl_bool has_unified_memory = gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY;
		GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_HAD_UNIFIED_MEMORY);

		cl_uint ntlm_empy_hash[] = { 0x5e5bde24, 0xc08c4545, 0xb69f1f41, 0xef178453 };
		ocl_charset_init(result, gpu_index, gen, gpu_crypt, BINARY_SIZE, 0, ocl_write_ntlm_header, ocl_gen_kernel_with_lenght, ntlm_empy_hash, FALSE, 1);

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
		cl_uint ntlm_empy_hash[] = {0x798ab330, 0xc08c4545, 0x3e9e5fb9, 0xb0576c6a};
		ocl_charset_init(result, gpu_index, gen, gpu_crypt, BINARY_SIZE, 1, ocl_write_ntlm_header, ocl_gen_kernel_with_lenght, ntlm_empy_hash, FALSE, 1);
	}
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_ntlm(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint value_map_collission, void* salt_param, cl_uint prefered_vector_size)
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
		"b+=(xx^c)%s;\n"
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
				 
				"a%s+=(b%s^c%s^d%s)%s%s+SQRT_3;a%s=rotate(a%s,3u);"
				"d%s+=(a%s^b%s^c%s)%s%s+SQRT_3;d%s=rotate(d%s,9u);\n"
				"c%s+=(d%s^a%s^b%s)%s%s+SQRT_3;c%s=rotate(c%s,11u);"
				"if(a%s==%uu&&d%s==%uu&&c%s==%uu)"
				"{"
					"output[0]=1;"
					"output[1]=get_global_id(0);"
					"output[2]=0;"
					"%s"
				"}"
			"}"
			, str_comp[comp], ((cl_uint*)binary_values)[1]
			, str_comp[comp], str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3 ], buffer_vector_size[3 ] == 1 ? "" : str_comp[comp], str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11], buffer_vector_size[11] == 1 ? "" : str_comp[comp], str_comp[comp], str_comp[comp]
			, str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[7 ], buffer_vector_size[7 ] == 1 ? "" : str_comp[comp], str_comp[comp], str_comp[comp]
			, str_comp[comp], ((cl_uint*)binary_values)[0], str_comp[comp], ((cl_uint*)binary_values)[3], str_comp[comp], ((cl_uint*)binary_values)[2]
			, output_3);
		}
	}
	else
	{
		//"indx=b & SIZE_BIT_TABLE;"
		//"if((bit_table[indx>>5]>>(indx&31))&1)"
	sprintf(source + strlen(source),
				"xx=b&SIZE_BIT_TABLE;"
				"uint%s bit_table_val=xx>>5u;"
				"xx&=31u;", buffer);

		for (cl_uint comp = 0; comp < vector_size; comp++)
			sprintf(source + strlen(source),
				"bit_table_val%s=bit_table[bit_table_val%s];", str_comp[comp], str_comp[comp]);

		strcat(source, "bit_table_val=(bit_table_val>>xx)&1u;\n");

		for (cl_uint comp = 0; comp < vector_size; comp++)
		{
			if (found_param_3)
				sprintf(output_3, "output[3u*found+3u]=%s+%uu;", found_param_3, comp);

			sprintf(source+strlen(source), 
				"if(bit_table_val%s)"
				"{"
					"indx=table[(b%s)&SIZE_TABLE];"

					"while(indx!=0xffffffff)"
					//"if(indx!=0xffffffff)"
					"{"
						"if(b%s==binary_values[indx*4u+1u])\n"
						"{"
							"b%s+=SQRT_3;b%s=rotate(b%s,15u);"

							"a%s+=(b%s^c%s^d%s)%s%s+SQRT_3;a%s=rotate(a%s,3u);"
							"d%s+=(a%s^b%s^c%s)%s%s+SQRT_3;d%s=rotate(d%s,9u);"
							"c%s+=(d%s^a%s^b%s)%s%s+SQRT_3;c%s=rotate(c%s,11u);\n"
							"if(a%s==binary_values[indx*4u]&&d%s==binary_values[indx*4u+3u]&&c%s==binary_values[indx*4u+2u])"
							"{"
								"uint found=atomic_inc(output);"
								"output[%i*found+1]=get_global_id(0);"
								"output[%i*found+2]=indx;"
								"%s"
							"}",
			str_comp[comp],
			str_comp[comp], str_comp[comp], str_comp[comp], 
			str_comp[comp], str_comp[comp],
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3], buffer_vector_size[3] == 1 ? "" : str_comp[comp],
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11], buffer_vector_size[11] == 1 ? "" : str_comp[comp],
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[7], buffer_vector_size[7] == 1 ? "" : str_comp[comp], 
			str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], found_multiplier, found_multiplier, output_3);

			// Reverse a,b,c,d to their last value for the unlikely case of 2 hashes with same b
			if (value_map_collission)
				sprintf(source + strlen(source),
							"c%s=rotate(c%s,21u);c%s-=(d%s^a%s^b%s)%s%s+SQRT_3;"
							"d%s=rotate(d%s,23u);d%s-=(a%s^b%s^c%s)%s%s+SQRT_3;"
							"a%s=rotate(a%s,29u);a%s-=(b%s^c%s^d%s)%s%s+SQRT_3;"
							"b%s=rotate(b%s,17u);b%s-=SQRT_3;",
							str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[7], buffer_vector_size[7] == 1 ? "" : str_comp[comp],
							str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[11], buffer_vector_size[11] == 1 ? "" : str_comp[comp],
							str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], str_comp[comp], nt_buffer[3], buffer_vector_size[3] == 1 ? "" : str_comp[comp],
							str_comp[comp], str_comp[comp], str_comp[comp]);
		strcat(source,  "}"
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
PRIVATE void ocl_protocol_utf8_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
#ifdef ANDROID
	ocl_common_init(param, gpu_index, gen, gpu_ntlm_crypt, BINARY_SIZE, 1, ocl_write_ntlm_header, ocl_gen_kernel_ntlm, kernels2common + UTF8_INDEX_IN_KERNELS, 32, ocl_rule_simple_copy_unicode);
#else
	ocl_common_init(param, gpu_index, gen, gpu_ntlm_crypt, BINARY_SIZE, 1, ocl_write_ntlm_header, ocl_gen_kernel_ntlm, kernels2common + UTF8_INDEX_IN_KERNELS, 4/*consider 2 for Nvidia*/, ocl_rule_simple_copy_unicode);
#endif
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_ntlm_crypt)
{
	ocl_common_init(param, gpu_index, gen, gpu_ntlm_crypt, BINARY_SIZE, 1, ocl_write_ntlm_header, ocl_gen_kernel_ntlm, kernels2common + PHRASES_INDEX_IN_KERNELS, 64/*consider 32 for Nvidia*/, ocl_rule_simple_copy_unicode);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	ocl_rules_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, 1, ocl_write_ntlm_header, ocl_gen_kernel_ntlm, RULE_UNICODE_INDEX, 1);
}
#endif

PRIVATE int bench_values[] = {1,10,100,1000,10000,65536,100000,1000000};
Format ntlm_format = {
	"NTLM",
	"MD4 based.",
	NTLM_MAX_KEY_LENGHT,
	BINARY_SIZE,
	0,
	2,
	bench_values,
	LENGHT(bench_values),
	get_binary,
	is_valid,
	add_hash_from_line,
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
