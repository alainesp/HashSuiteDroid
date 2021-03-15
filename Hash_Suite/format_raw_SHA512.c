// This file is part of Hash Suite password cracker,
// Copyright (c) 2015-2018 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

//Initial values
#define INIT_A  0x6A09E667F3BCC908ULL
#define INIT_B  0xBB67AE8584CAA73BULL
#define INIT_C  0x3C6EF372FE94F82BULL
#define INIT_D  0xA54FF53A5F1D36F1ULL
#define INIT_E  0x510E527FADE682D1ULL
#define INIT_F  0x9B05688C2B3E6C1FULL
#define INIT_G  0x1F83D9ABFB41BD6BULL
#define INIT_H  0x5BE0CD19137E2179ULL


#define BINARY_SIZE			64
#define NTLM_MAX_KEY_LENGHT	27

#undef ROTATE
#define ROTATE ROTATE64

#define R_E(x) (ROTATE(x,50) ^ ROTATE(x,46) ^ ROTATE(x,23))
#define R_A(x) (ROTATE(x,36) ^ ROTATE(x,30) ^ ROTATE(x,25))
#define R0(x)  (ROTATE(x,63) ^ ROTATE(x,56) ^ ((x)>>7))
#define R1(x)  (ROTATE(x,45) ^ ROTATE(x,3 ) ^ ((x)>>6))

PRIVATE int is_valid(char* user_name, char* sha512, char* unused, char* unused1)
{
	if (user_name)
	{
		char* hash = sha512 ? sha512 : user_name;

		if (valid_hex_string(hash, BINARY_SIZE*2) || (!memcmp(hash, "$SHA512$", 8) && valid_hex_string(hash+8, BINARY_SIZE*2)))
			return TRUE;
	}

	return FALSE;
}

PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* user_name, char* sha512, char* unused, char* unused1)
{
	if (user_name)
	{
		char* hash = sha512 ? sha512 : user_name;
		char* user = sha512 ? user_name : NULL;

		if (valid_hex_string(hash, BINARY_SIZE*2))
			return insert_hash_account1(param, user, _strupr(hash), SHA512_INDEX);

		if (!memcmp(hash, "$SHA512$", 8) && valid_hex_string(hash+8, BINARY_SIZE*2))
			return insert_hash_account1(param, user, _strupr(hash+8), SHA512_INDEX);
	}

	return -1;
}
#define VALUE_MAP_INDEX0 0
#define VALUE_MAP_INDEX1 1
PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	uint64_t* out = (uint64_t*)binary;

	for (uint32_t i = 0; i < 8; i++)
	{
		uint64_t temp = ((uint64_t)hex_to_num[ciphertext[i * 16 + 0]]) << 60;
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 1]]) << 56;
									   
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 2]]) << 52;
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 3]]) << 48;
										   
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 4]]) << 44;
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 5]]) << 40;
										   
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 6]]) << 36;
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 7]]) << 32;
		// Low dword
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 8]]) << 28;
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 9]]) << 24;
					   
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 10]]) << 20;
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 11]]) << 16;
					   
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 12]]) << 12;
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 13]]) << 8;
						   
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 14]]) << 4;
		temp |= ((uint64_t)hex_to_num[ciphertext[i * 16 + 15]]) << 0;

		out[i] = temp;
	}

	// Reverse
	out[0] -= INIT_A;
	out[1] -= INIT_B;
	out[2] -= INIT_C;
	out[3] -= INIT_D;
	out[4] -= INIT_E;
	out[5] -= INIT_F;
	out[6] -= INIT_G;
	out[7] -= INIT_H;

	//A += R_A(B) + ((B & C) | (D & (B | C)));										E += A;			A += R_E(F) + (H ^ (F & (G ^ H))) + 0x6C44198C4A475817ULL;
	out[0] -= R_A(out[1]) + ((out[1] & out[2]) | (out[3] & (out[1] | out[2]))); out[4] -= out[0]; out[0] -= R_E(out[5]) + (out[7] ^ (out[5] & (out[6] ^ out[7]))) + 0x6C44198C4A475817ULL;

	//B += R_A(C) + ((C & D) | (E & (C | D)));                                   F += B;            B    +=   R_E(G)    + 0xBEF9A3F7
	out[1] -= R_A(out[2]) + ((out[2] & out[3]) | (out[4] & (out[2] | out[3]))); out[5] -= out[1]; out[1] -= R_E(out[6]) + 0x5FCB6FAB3AD6FAECULL;

	// C += R_A(D) + ((D & E) | (F & (D | E)));
	out[2] -= R_A(out[3]) + ((out[3] & out[4]) | (out[5] & (out[3] | out[4])));

	// G += C;                         D += R_A(E) + ((E & F) | (G & (E | F)));
	uint64_t G = out[6] - out[2]; out[3] -= R_A(out[4]) + ((out[4] & out[5]) | (G & (out[4] | out[5])));

	// H += D;                        E += R_A(F) + ((F & G) | (H & (F | G)));
	uint64_t H = out[7] - out[3]; out[4] -= R_A(out[5]) + ((out[5] & G) | (H & (out[5] | G)));

	// F += R_A(G)
	out[5] -= R_A(G);

	// A += E;
	out[0] -= out[4];

	return (uint32_t)(out[0] & UINT_MAX);
}
PRIVATE void binary2hex(const void* binary, const void* salt, unsigned char* ciphertext)
{
	uint64_t bin[BINARY_SIZE / sizeof(uint64_t)];
	memcpy(bin, binary, BINARY_SIZE);

	// A += E;
	bin[0] += bin[4];
	// F += R_A(G)
	uint64_t G = bin[6] - bin[2];
	bin[5] += R_A(G);
	// H += D;                        E += R_A(F) + ((F & G) | (H & (F | G)));
	uint64_t H = bin[7] - bin[3]; bin[4] += R_A(bin[5]) + ((bin[5] & G) | (H & (bin[5] | G)));
	// G += C;                         D += R_A(E) + ((E & F) | (G & (E | F)));
	bin[3] += R_A(bin[4]) + ((bin[4] & bin[5]) | (G & (bin[4] | bin[5])));
	// C += R_A(D) + ((D & E) | (F & (D | E)));
	bin[2] += R_A(bin[3]) + ((bin[3] & bin[4]) | (bin[5] & (bin[3] | bin[4])));
	//B += R_A(C) + ((C & D) | (E & (C | D)));                                   F += B;            B    +=   R_E(G)    + 0xBEF9A3F7
	bin[1] += R_E(bin[6]) + 0x5FCB6FAB3AD6FAECULL; bin[5] += bin[1]; bin[1] += R_A(bin[2]) + ((bin[2] & bin[3]) | (bin[4] & (bin[2] | bin[3])));
	//A += R_A(B) + ((B & C) | (D & (B | C)));										E += A;			A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC67178F2;
	bin[0] += R_E(bin[5]) + (bin[7] ^ (bin[5] & (bin[6] ^ bin[7]))) + 0x6C44198C4A475817ULL; bin[4] += bin[0]; bin[0] += R_A(bin[1]) + ((bin[1] & bin[2]) | (bin[3] & (bin[1] | bin[2])));

	// Reverse
	bin[0] = ROTATE(bin[0] + INIT_A, 32);
	bin[1] = ROTATE(bin[1] + INIT_B, 32);
	bin[2] = ROTATE(bin[2] + INIT_C, 32);
	bin[3] = ROTATE(bin[3] + INIT_D, 32);
	bin[4] = ROTATE(bin[4] + INIT_E, 32);
	bin[5] = ROTATE(bin[5] + INIT_F, 32);
	bin[6] = ROTATE(bin[6] + INIT_G, 32);
	bin[7] = ROTATE(bin[7] + INIT_H, 32);


	binary_to_hex((const uint32_t*)bin, ciphertext, BINARY_SIZE / sizeof(uint32_t), FALSE);
}

#ifdef HS_ARM
	#define NT_NUM_KEYS		    128
#endif

#ifdef HS_X86
	#define NT_NUM_KEYS		    256
#endif

PRIVATE HS_ALIGN(16) uint64_t K64[] = {
	0x954d6b38bcfcddf5ULL, 0x954d6b38bcfcddf5ULL,
	0x90bb1e3d1f312338ULL, 0x90bb1e3d1f312338ULL,
	0x50c6645c178ba74eULL, 0x50c6645c178ba74eULL,
	0x3ac42e252f705e8dULL, 0x3ac42e252f705e8dULL,
	0x3956C25BF348B538ULL, 0x3956C25BF348B538ULL,
	0x59F111F1B605D019ULL, 0x59F111F1B605D019ULL,
	0x923F82A4AF194F9BULL, 0x923F82A4AF194F9BULL,
	0xAB1C5ED5DA6D8118ULL, 0xAB1C5ED5DA6D8118ULL,
	0xD807AA98A3030242ULL, 0xD807AA98A3030242ULL,
	0x12835B0145706FBEULL, 0x12835B0145706FBEULL,
	0x243185BE4EE4B28CULL, 0x243185BE4EE4B28CULL,
	0x550C7DC3D5FFB4E2ULL, 0x550C7DC3D5FFB4E2ULL,
	0x72BE5D74F27B896FULL, 0x72BE5D74F27B896FULL,
	0x80DEB1FE3B1696B1ULL, 0x80DEB1FE3B1696B1ULL,
	0x9BDC06A725C71235ULL, 0x9BDC06A725C71235ULL,
	0xC19BF174CF692694ULL, 0xC19BF174CF692694ULL,

	0xE49B69C19EF14AD2ULL, 0xE49B69C19EF14AD2ULL,
	0xEFBE4786384F25E3ULL, 0xEFBE4786384F25E3ULL,
	0x0FC19DC68B8CD5B5ULL, 0x0FC19DC68B8CD5B5ULL,
	0x240CA1CC77AC9C65ULL, 0x240CA1CC77AC9C65ULL,
	0x2DE92C6F592B0275ULL, 0x2DE92C6F592B0275ULL,
	0x4A7484AA6EA6E483ULL, 0x4A7484AA6EA6E483ULL,
	0x5CB0A9DCBD41FBD4ULL, 0x5CB0A9DCBD41FBD4ULL,
	0x76F988DA831153B5ULL, 0x76F988DA831153B5ULL,
	0x983E5152EE66DFABULL, 0x983E5152EE66DFABULL,
	0xA831C66D2DB43210ULL, 0xA831C66D2DB43210ULL,
	0xB00327C898FB213FULL, 0xB00327C898FB213FULL,
	0xBF597FC7BEEF0EE4ULL, 0xBF597FC7BEEF0EE4ULL,
	0xC6E00BF33DA88FC2ULL, 0xC6E00BF33DA88FC2ULL,
	0xD5A79147930AA725ULL, 0xD5A79147930AA725ULL,
	0x06CA6351E003826FULL, 0x06CA6351E003826FULL,
	0x142929670A0E6E70ULL, 0x142929670A0E6E70ULL,
						 
	0x27B70A8546D22FFCULL, 0x27B70A8546D22FFCULL,
	0x2E1B21385C26C926ULL, 0x2E1B21385C26C926ULL,
	0x4D2C6DFC5AC42AEDULL, 0x4D2C6DFC5AC42AEDULL,
	0x53380D139D95B3DFULL, 0x53380D139D95B3DFULL,
	0x650A73548BAF63DEULL, 0x650A73548BAF63DEULL,
	0x766A0ABB3C77B2A8ULL, 0x766A0ABB3C77B2A8ULL,
	0x81C2C92E47EDAEE6ULL, 0x81C2C92E47EDAEE6ULL,
	0x92722C851482353BULL, 0x92722C851482353BULL,
	0xA2BFE8A14CF10364ULL, 0xA2BFE8A14CF10364ULL,
	0xA81A664BBC423001ULL, 0xA81A664BBC423001ULL,
	0xC24B8B70D0F89791ULL, 0xC24B8B70D0F89791ULL,
	0xC76C51A30654BE30ULL, 0xC76C51A30654BE30ULL,
	0xD192E819D6EF5218ULL, 0xD192E819D6EF5218ULL,
	0xD69906245565A910ULL, 0xD69906245565A910ULL,
	0xF40E35855771202AULL, 0xF40E35855771202AULL,
	0x106AA07032BBD1B8ULL, 0x106AA07032BBD1B8ULL,
						
	0x19A4C116B8D2D0C8ULL, 0x19A4C116B8D2D0C8ULL,
	0x1E376C085141AB53ULL, 0x1E376C085141AB53ULL,
	0x2748774CDF8EEB99ULL, 0x2748774CDF8EEB99ULL,
	0x34B0BCB5E19B48A8ULL, 0x34B0BCB5E19B48A8ULL,
	0x391C0CB3C5C95A63ULL, 0x391C0CB3C5C95A63ULL,
	0x4ED8AA4AE3418ACBULL, 0x4ED8AA4AE3418ACBULL,
	0x5B9CCA4F7763E373ULL, 0x5B9CCA4F7763E373ULL,
	0x682E6FF3D6B2B8A3ULL, 0x682E6FF3D6B2B8A3ULL,
	0x748F82EE5DEFB2FCULL, 0x748F82EE5DEFB2FCULL,
	0x78A5636F43172F60ULL, 0x78A5636F43172F60ULL,
	0x84C87814A1F0AB72ULL, 0x84C87814A1F0AB72ULL,
	0x8CC702081A6439ECULL, 0x8CC702081A6439ECULL,
	0x90BEFFFA23631E28ULL, 0x90BEFFFA23631E28ULL,
	0xA4506CEBDE82BDE9ULL, 0xA4506CEBDE82BDE9ULL,
	0xBEF9A3F7B2C67915ULL, 0xBEF9A3F7B2C67915ULL,
	0xC67178F2E372532BULL, 0xC67178F2E372532BULL,
						 
	0xCA273ECEEA26619CULL, 0xCA273ECEEA26619CULL,
	0xD186B8C721C0C207ULL, 0xD186B8C721C0C207ULL,
	0xEADA7DD6CDE0EB1EULL, 0xEADA7DD6CDE0EB1EULL,
	0xF57D4F7FEE6ED178ULL, 0xF57D4F7FEE6ED178ULL,
	0x06F067AA72176FBAULL, 0x06F067AA72176FBAULL,
	0x0A637DC5A2C898A6ULL, 0x0A637DC5A2C898A6ULL,
	0x113F9804BEF90DAEULL, 0x113F9804BEF90DAEULL,
	0x1B710B35131C471BULL, 0x1B710B35131C471BULL,

	INIT_A, INIT_A,
	INIT_E, INIT_E,
	INIT_F, INIT_F,
	0x621b337bbdb8419cULL, 0x621b337bbdb8419cULL,
	INIT_C, INIT_C,
	INIT_B, INIT_B
};

#ifdef __ANDROID__
	typedef void crypt_kernel_asm_sha512_func(uint32_t* nt_buffer, void* sha512_consts);
#else
	#define crypt_kernel_asm_sha512_func crypt_kernel_asm_func
#endif

PRIVATE uint32_t compare_elem(uint32_t i, uint32_t cbg_table_pos, uint64_t* unpacked_W)
{
	if (cbg_table_pos == NO_ELEM) return FALSE;

	uint64_t* bin = ((uint64_t*)binary_values) + cbg_table_pos * 8;

	uint64_t* unpacked_as = unpacked_W + 4 * NT_NUM_KEYS;
	uint64_t* unpacked_bs = unpacked_W + 6 * NT_NUM_KEYS;
	uint64_t* unpacked_cs = unpacked_W + 16 * NT_NUM_KEYS;
	uint64_t* unpacked_ds = unpacked_cs + NT_NUM_KEYS;
	uint64_t* unpacked_es = unpacked_ds + NT_NUM_KEYS;
	uint64_t* unpacked_fs = unpacked_es + NT_NUM_KEYS;
	uint64_t* unpacked_gs = unpacked_fs + NT_NUM_KEYS;
	uint64_t* unpacked_hs = unpacked_gs + NT_NUM_KEYS;

	uint64_t aa = unpacked_as[i], bb, cc, dd, ee, ff, gg, hh, W10, W12, W14;
	uint64_t* W = unpacked_W + i;

	if (aa != bin[0]) return FALSE;
	// W-> 0,1,2 ,4, 6
	aa -= W[0  * NT_NUM_KEYS];
	W10 = W[10 * NT_NUM_KEYS] + R1(W[8 * NT_NUM_KEYS])+ W[3 * NT_NUM_KEYS] + R0(W[11 * NT_NUM_KEYS]);
	W12 = W[12 * NT_NUM_KEYS] + R1(W10)               + W[5 * NT_NUM_KEYS] + R0(W[13 * NT_NUM_KEYS]);
	W14 = W[14 * NT_NUM_KEYS] + R1(W12)               + W[7 * NT_NUM_KEYS] + R0(W[15 * NT_NUM_KEYS]);

	bb = unpacked_bs[i];
	cc = unpacked_cs[i];
	dd = unpacked_ds[i];
	ee = unpacked_es[i];
	ff = unpacked_fs[i];
	gg = unpacked_gs[i];
	hh = unpacked_hs[i];

	hh += R_E(ee) + (gg ^ (ee & (ff ^ gg))) + 0x28DB77F523047D84ULL + W[8 * NT_NUM_KEYS]; dd += hh; hh += R_A(aa) + ((aa & bb) | (cc & (aa | bb)));
	gg += R_E(dd) + (ff ^ (dd & (ee ^ ff))) + 0x32CAAB7B40C72493ULL + W[9 * NT_NUM_KEYS]; cc += gg; gg += R_A(hh) + ((hh & aa) | (bb & (hh | aa)));
	ff += R_E(cc) + (ee ^ (cc & (dd ^ ee))) + 0x3C9EBE0A15C9BEBCULL + W10               ; bb += ff; ff +=           ((gg & hh) | (aa & (gg | hh)));
	ee += R_E(bb) + (dd ^ (bb & (cc ^ dd))) + 0x431D67C49C100D4CULL + W[2 * NT_NUM_KEYS]; aa += ee;
	dd += R_E(aa) + (cc ^ (aa & (bb ^ cc))) + 0x4CC5D4BECB3E42B6ULL + W12               ; hh += dd;
	cc += R_E(hh) + (bb ^ (hh & (aa ^ bb))) + 0x597F299CFC657E2AULL + W[1 * NT_NUM_KEYS]; gg += cc;
	bb +=           (aa ^ (gg & (hh ^ aa)))                         + W14 ;

	if (bb != bin[1] || cc != bin[2] || dd != bin[3] || ee != bin[4] || ff != bin[5] || gg != bin[6] || hh != bin[7])
		return FALSE;

	return TRUE;
}

PRIVATE void crypt_utf8_coalesc_protocol_body(CryptParam* param, crypt_kernel_asm_sha512_func* crypt_kernel_asm)
{
	uint64_t* nt_buffer = (uint64_t*)_aligned_malloc((4+16+6) * sizeof(uint64_t) * NT_NUM_KEYS, 64);

	uint64_t* unpacked_W  = nt_buffer   + 4  * NT_NUM_KEYS;
	uint64_t* unpacked_as = unpacked_W  + 4  * NT_NUM_KEYS;

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, 4 * sizeof(uint64_t)* NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while (continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
#ifdef __ANDROID__
		crypt_kernel_asm((uint32_t*)nt_buffer, K64);
#else
		crypt_kernel_asm((uint32_t*)nt_buffer);
#endif

		for (uint32_t i = 0; i < NT_NUM_KEYS; i++)
		{
			uint32_t up0 = (uint32_t)(unpacked_as[i]);
			uint32_t up1 = (uint32_t)(unpacked_as[i] >> 32);

			uint32_t pos = up0 & cbg_mask;
			uint_fast16_t data = cbg_filter[pos];
			if (((data ^ up1) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], unpacked_W))
				password_was_found(cbg_table[pos], utf8_coalesc2utf8_key((uint32_t*)nt_buffer, key, NT_NUM_KEYS, i));// Total match

			// 2nd pos
			if (data & 0b110)
			{
				pos += data & 0b1 ? -1 : 1;
				uint_fast16_t hash = cbg_filter[pos];
				if (((hash ^ up1) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], unpacked_W))
					password_was_found(cbg_table[pos], utf8_coalesc2utf8_key((uint32_t*)nt_buffer, key, NT_NUM_KEYS, i));// Total match

				// Unluky bucket
				if (data & 0b10)
				{
					pos = up1 & cbg_mask;
					data = cbg_filter[pos];
					if (((data ^ up0) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], unpacked_W))
						password_was_found(cbg_table[pos], utf8_coalesc2utf8_key((uint32_t*)nt_buffer, key, NT_NUM_KEYS, i));// Total match

					// 2nd pos
					pos += data & 0b1 ? -1 : 1;
					hash = cbg_filter[pos];
					if (((hash ^ up0) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], unpacked_W))
						password_was_found(cbg_table[pos], utf8_coalesc2utf8_key((uint32_t*)nt_buffer, key, NT_NUM_KEYS, i));// Total match
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
#ifdef __ANDROID__
PRIVATE void crypt_kernel_c_code(uint32_t* nt_buffer, void* sha512_consts)
#else
PRIVATE void crypt_kernel_c_code(uint32_t* nt_buffer)
#endif
{
	uint64_t A, B, C, D, E, F, G, H;
	uint64_t* W = ((uint64_t*)nt_buffer) + 4 * NT_NUM_KEYS;
	uint32_t tmp0, tmp1;

	for (int jj = 0; jj < NT_NUM_KEYS; jj++, nt_buffer++, W++)
	{
		tmp0 = _byteswap_ulong(nt_buffer[0 * NT_NUM_KEYS]);
		tmp1 = _byteswap_ulong(nt_buffer[1 * NT_NUM_KEYS]);
		W[0 * NT_NUM_KEYS] = (((uint64_t)tmp0) << 32) + tmp1;
		tmp0 = _byteswap_ulong(nt_buffer[2 * NT_NUM_KEYS]);
		tmp1 = _byteswap_ulong(nt_buffer[3 * NT_NUM_KEYS]);
		W[1 * NT_NUM_KEYS] = (((uint64_t)tmp0) << 32) + tmp1;
		tmp0 = _byteswap_ulong(nt_buffer[4 * NT_NUM_KEYS]);
		tmp1 = _byteswap_ulong(nt_buffer[5 * NT_NUM_KEYS]);
		W[2 * NT_NUM_KEYS] = (((uint64_t)tmp0) << 32) + tmp1;

		tmp0 = _byteswap_ulong(nt_buffer[6 * NT_NUM_KEYS]);
		W[3 * NT_NUM_KEYS] = ((uint64_t)tmp0) << 32;
		W[15 * NT_NUM_KEYS] = nt_buffer[7 * NT_NUM_KEYS];

		A = INIT_A; E = INIT_E; F = INIT_F;

		/* Rounds */
		H = 0x954d6b38bcfcddf5ULL + W[0 * NT_NUM_KEYS]; D = 0x621b337bbdb8419cULL + H;
		G  = R_E(D) + (F ^ (D & (E ^ F))) + 0x90bb1e3d1f312338ULL + W[ 1 * NT_NUM_KEYS]; C=INIT_C+G; G += R_A(H) + ((H & A) | (INIT_B & (H | A)));
		F  = R_E(C) + (E ^ (C & (D ^ E))) + 0x50c6645c178ba74eULL + W[ 2 * NT_NUM_KEYS]; B=INIT_B+F; F += R_A(G) + ((G & H) | (A & (G | H)));
		E  = R_E(B) + (D ^ (B & (C ^ D))) + 0x3ac42e252f705e8dULL + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		D += R_E(A) + (C ^ (A & (B ^ C))) + 0x3956C25BF348B538ULL                      ; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		C += R_E(H) + (B ^ (H & (A ^ B))) + 0x59F111F1B605D019ULL                      ; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		B += R_E(G) + (A ^ (G & (H ^ A))) + 0x923F82A4AF194F9BULL                      ; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		A += R_E(F) + (H ^ (F & (G ^ H))) + 0xAB1C5ED5DA6D8118ULL                      ; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		H += R_E(E) + (G ^ (E & (F ^ G))) + 0xD807AA98A3030242ULL                      ; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		G += R_E(D) + (F ^ (D & (E ^ F))) + 0x12835B0145706FBEULL                      ; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		F += R_E(C) + (E ^ (C & (D ^ E))) + 0x243185BE4EE4B28CULL                      ; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		E += R_E(B) + (D ^ (B & (C ^ D))) + 0x550C7DC3D5FFB4E2ULL                      ; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		D += R_E(A) + (C ^ (A & (B ^ C))) + 0x72BE5D74F27B896FULL                      ; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		C += R_E(H) + (B ^ (H & (A ^ B))) + 0x80DEB1FE3B1696B1ULL                      ; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		B += R_E(G) + (A ^ (G & (H ^ A))) + 0x9BDC06A725C71235ULL                      ; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC19BF174CF692694ULL + W[15 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));

		W[ 0 * NT_NUM_KEYS] +=					                               R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xE49B69C19EF14AD2ULL + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS])                       + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xEFBE4786384F25E3ULL + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS])                       + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x0FC19DC68B8CD5B5ULL + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS])                                                ; E += R_E(B) + (D ^ (B & (C ^ D))) + 0x240CA1CC77AC9C65ULL + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS]  = R1(W[2  * NT_NUM_KEYS])                                                ; D += R_E(A) + (C ^ (A & (B ^ C))) + 0x2DE92C6F592B0275ULL + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS]  = R1(W[3  * NT_NUM_KEYS])                                                ; C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4A7484AA6EA6E483ULL + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS]  = R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS]                          ; B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5CB0A9DCBD41FBD4ULL + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS]  = R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS]                          ; A += R_E(F) + (H ^ (F & (G ^ H))) + 0x76F988DA831153B5ULL + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS]  = R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS]                          ; H += R_E(E) + (G ^ (E & (F ^ G))) + 0x983E5152EE66DFABULL + W[ 8 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 9 * NT_NUM_KEYS]  = R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS]                          ; G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA831C66D2DB43210ULL + W[ 9 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[10 * NT_NUM_KEYS]  = R1(W[8  * NT_NUM_KEYS]) + W[3  * NT_NUM_KEYS]                          ; F += R_E(C) + (E ^ (C & (D ^ E))) + 0xB00327C898FB213FULL + W[10 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[11 * NT_NUM_KEYS]  = R1(W[9  * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS]                          ; E += R_E(B) + (D ^ (B & (C ^ D))) + 0xBF597FC7BEEF0EE4ULL + W[11 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[12 * NT_NUM_KEYS]  = R1(W[10 * NT_NUM_KEYS]) + W[5  * NT_NUM_KEYS]                          ; D += R_E(A) + (C ^ (A & (B ^ C))) + 0xC6E00BF33DA88FC2ULL + W[12 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[13 * NT_NUM_KEYS]  = R1(W[11 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS]                          ; C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD5A79147930AA725ULL + W[13 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[14 * NT_NUM_KEYS]  = R1(W[12 * NT_NUM_KEYS]) + W[7  * NT_NUM_KEYS] + R0(W[15 * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x06CA6351E003826FULL + W[14 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[15 * NT_NUM_KEYS] += R1(W[13 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x142929670A0E6E70ULL + W[15 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																    																						  
		W[ 0 * NT_NUM_KEYS] += R1(W[14 * NT_NUM_KEYS]) + W[9  * NT_NUM_KEYS] + R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x27B70A8546D22FFCULL + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS]) + W[10 * NT_NUM_KEYS] + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x2E1B21385C26C926ULL + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS]) + W[11 * NT_NUM_KEYS] + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x4D2C6DFC5AC42AEDULL + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS]) + W[12 * NT_NUM_KEYS] + R0(W[4  * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x53380D139D95B3DFULL + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS] += R1(W[2  * NT_NUM_KEYS]) + W[13 * NT_NUM_KEYS] + R0(W[5  * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x650A73548BAF63DEULL + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS] += R1(W[3  * NT_NUM_KEYS]) + W[14 * NT_NUM_KEYS] + R0(W[6  * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x766A0ABB3C77B2A8ULL + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS] += R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS] + R0(W[7  * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x81C2C92E47EDAEE6ULL + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS] += R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS] + R0(W[8  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x92722C851482353BULL + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS] += R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS] + R0(W[9  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xA2BFE8A14CF10364ULL + W[ 8 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 9 * NT_NUM_KEYS] += R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS] + R0(W[10 * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA81A664BBC423001ULL + W[ 9 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[10 * NT_NUM_KEYS] += R1(W[8  * NT_NUM_KEYS]) + W[3  * NT_NUM_KEYS] + R0(W[11 * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0xC24B8B70D0F89791ULL + W[10 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[11 * NT_NUM_KEYS] += R1(W[9  * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS] + R0(W[12 * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0xC76C51A30654BE30ULL + W[11 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[12 * NT_NUM_KEYS] += R1(W[10 * NT_NUM_KEYS]) + W[5  * NT_NUM_KEYS] + R0(W[13 * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0xD192E819D6EF5218ULL + W[12 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[13 * NT_NUM_KEYS] += R1(W[11 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS] + R0(W[14 * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD69906245565A910ULL + W[13 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[14 * NT_NUM_KEYS] += R1(W[12 * NT_NUM_KEYS]) + W[7  * NT_NUM_KEYS] + R0(W[15 * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0xF40E35855771202AULL + W[14 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[15 * NT_NUM_KEYS] += R1(W[13 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x106AA07032BBD1B8ULL + W[15 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		
		W[ 0 * NT_NUM_KEYS] += R1(W[14 * NT_NUM_KEYS]) + W[9  * NT_NUM_KEYS] + R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x19A4C116B8D2D0C8ULL + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS]) + W[10 * NT_NUM_KEYS] + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x1E376C085141AB53ULL + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS]) + W[11 * NT_NUM_KEYS] + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x2748774CDF8EEB99ULL + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS]) + W[12 * NT_NUM_KEYS] + R0(W[4  * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x34B0BCB5E19B48A8ULL + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS] += R1(W[2  * NT_NUM_KEYS]) + W[13 * NT_NUM_KEYS] + R0(W[5  * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x391C0CB3C5C95A63ULL + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS] += R1(W[3  * NT_NUM_KEYS]) + W[14 * NT_NUM_KEYS] + R0(W[6  * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4ED8AA4AE3418ACBULL + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS] += R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS] + R0(W[7  * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5B9CCA4F7763E373ULL + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS] += R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS] + R0(W[8  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x682E6FF3D6B2B8A3ULL + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS] += R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS] + R0(W[9  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x748F82EE5DEFB2FCULL + W[ 8 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 9 * NT_NUM_KEYS] += R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS] + R0(W[10 * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x78A5636F43172F60ULL + W[ 9 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[10 * NT_NUM_KEYS] += R1(W[8  * NT_NUM_KEYS]) + W[3  * NT_NUM_KEYS] + R0(W[11 * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x84C87814A1F0AB72ULL + W[10 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[11 * NT_NUM_KEYS] += R1(W[9  * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS] + R0(W[12 * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x8CC702081A6439ECULL + W[11 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[12 * NT_NUM_KEYS] += R1(W[10 * NT_NUM_KEYS]) + W[5  * NT_NUM_KEYS] + R0(W[13 * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x90BEFFFA23631E28ULL + W[12 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[13 * NT_NUM_KEYS] += R1(W[11 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS] + R0(W[14 * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xA4506CEBDE82BDE9ULL + W[13 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[14 * NT_NUM_KEYS] += R1(W[12 * NT_NUM_KEYS]) + W[7  * NT_NUM_KEYS] + R0(W[15 * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0xBEF9A3F7B2C67915ULL + W[14 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[15 * NT_NUM_KEYS] += R1(W[13 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC67178F2E372532BULL + W[15 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																																							  
		W[ 0 * NT_NUM_KEYS] += R1(W[14 * NT_NUM_KEYS]) + W[9  * NT_NUM_KEYS] + R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xCA273ECEEA26619CULL + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS]) + W[10 * NT_NUM_KEYS] + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xD186B8C721C0C207ULL + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS]) + W[11 * NT_NUM_KEYS] + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0xEADA7DD6CDE0EB1EULL + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS]) + W[12 * NT_NUM_KEYS] + R0(W[4  * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0xF57D4F7FEE6ED178ULL + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS] += R1(W[2  * NT_NUM_KEYS]) + W[13 * NT_NUM_KEYS] + R0(W[5  * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x06F067AA72176FBAULL + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS] += R1(W[3  * NT_NUM_KEYS]) + W[14 * NT_NUM_KEYS] + R0(W[6  * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x0A637DC5A2C898A6ULL + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS] += R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS] + R0(W[7  * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x113F9804BEF90DAEULL + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS] += R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS] + R0(W[8  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x1B710B35131C471BULL + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS] += R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS] + R0(W[9  * NT_NUM_KEYS]);
		W[ 9 * NT_NUM_KEYS] += R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS] + R0(W[10 * NT_NUM_KEYS]);
		W[2 * NT_NUM_KEYS] = W[11 * NT_NUM_KEYS] + R1(W[9  * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS] + R0(W[12 * NT_NUM_KEYS]);
		W[1 * NT_NUM_KEYS] = W[13 * NT_NUM_KEYS] + R1(W[2 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS] + R0(W[14 * NT_NUM_KEYS]);
		W[0 * NT_NUM_KEYS] = W[15 * NT_NUM_KEYS] + R1(W[1 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += W[0 * NT_NUM_KEYS]; 

		W[4  * NT_NUM_KEYS] = A;
		W[6  * NT_NUM_KEYS] = B;
		W[16 * NT_NUM_KEYS] = C;
		W[17 * NT_NUM_KEYS] = D;
		W[18 * NT_NUM_KEYS] = E;
		W[19 * NT_NUM_KEYS] = F;
		W[20 * NT_NUM_KEYS] = G;
		W[21 * NT_NUM_KEYS] = H;
	}
}
PRIVATE void crypt_utf8_coalesc_protocol_c_code(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_kernel_c_code);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Neon code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_ARM

void crypt_sha512_neon_kernel_asm(uint32_t* nt_buffer, void* sha512_consts);
PRIVATE void crypt_utf8_coalesc_protocol_neon(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_sha512_neon_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include "arch_simd.h"

#define SHA512_NUM		(NT_NUM_KEYS/2)
#define SWAP_ENDIANNESS_SSE2(x,data) x = SSE2_ROTATE(data, 16); x = SSE2_ADD(SSE2_SL(SSE2_AND(x, mask), 8), SSE2_AND(SSE2_SR(x, 8), mask));

#undef R_E
#undef R_A
#undef R0
#undef R1
#define R_E(x) SSE2_3XOR(SSE2_ROTATE64(x,50), SSE2_ROTATE64(x,46), SSE2_ROTATE64(x,23))
#define R_A(x) SSE2_3XOR(SSE2_ROTATE64(x,36), SSE2_ROTATE64(x,30), SSE2_ROTATE64(x,25))
#define R0(x)  SSE2_3XOR(SSE2_ROTATE64(x,63), SSE2_ROTATE64(x,56), SSE2_SR64(x,7))
#define R1(x)  SSE2_3XOR(SSE2_ROTATE64(x,45), SSE2_ROTATE64(x,3 ), SSE2_SR64(x,6))

PRIVATE void crypt_kernel_sse2(uint32_t* nt_bufferu)
{
	SSE2_WORD* W = (SSE2_WORD*)(nt_bufferu + 8 * NT_NUM_KEYS);
	SSE2_WORD mask = SSE2_CONST(0x00FF00FF);
	SSE2_WORD A, B, C, D, E, F, G, H;
	SSE2_WORD t0, t1, t2, t3, t4, t5, t6, len;
	SSE2_WORD* K = (SSE2_WORD*)K64;

	for (int i = 0; i < SHA512_NUM; i++, W++)
	{
		uint32_t _2i = 2 * (i & 1);
		uint32_t _2i1 = _2i + 1;
		if (_2i == 0)
		{
			SSE2_WORD* nt_buffer = (SSE2_WORD*)nt_bufferu;

			SWAP_ENDIANNESS_SSE2(t0, nt_buffer[0 * NT_NUM_KEYS / 4]);
			SWAP_ENDIANNESS_SSE2(t1, nt_buffer[1 * NT_NUM_KEYS / 4]);

			SWAP_ENDIANNESS_SSE2(t2, nt_buffer[2 * NT_NUM_KEYS / 4]);
			SWAP_ENDIANNESS_SSE2(t3, nt_buffer[3 * NT_NUM_KEYS / 4]);

			SWAP_ENDIANNESS_SSE2(t4, nt_buffer[4 * NT_NUM_KEYS / 4]);
			SWAP_ENDIANNESS_SSE2(t5, nt_buffer[5 * NT_NUM_KEYS / 4]);

			SWAP_ENDIANNESS_SSE2(t6, nt_buffer[6 * NT_NUM_KEYS / 4]);
			len = nt_buffer[7 * NT_NUM_KEYS / 4];

			nt_bufferu += 4;
		}

		W[0 * SHA512_NUM].m128i_u64[0] = (((uint64_t)t0.m128i_u32[_2i ])<<32) + t1.m128i_u32[_2i ];
		W[0 * SHA512_NUM].m128i_u64[1] = (((uint64_t)t0.m128i_u32[_2i1])<<32) + t1.m128i_u32[_2i1];

		W[1 * SHA512_NUM].m128i_u64[0] = (((uint64_t)t2.m128i_u32[_2i ])<<32) + t3.m128i_u32[_2i ];
		W[1 * SHA512_NUM].m128i_u64[1] = (((uint64_t)t2.m128i_u32[_2i1])<<32) + t3.m128i_u32[_2i1];

		W[2 * SHA512_NUM].m128i_u64[0] = (((uint64_t)t4.m128i_u32[_2i ])<<32) + t5.m128i_u32[_2i ];
		W[2 * SHA512_NUM].m128i_u64[1] = (((uint64_t)t4.m128i_u32[_2i1])<<32) + t5.m128i_u32[_2i1];

		W[3 * SHA512_NUM].m128i_u64[0] = ((uint64_t)t6.m128i_u32[_2i ])<<32;
		W[3 * SHA512_NUM].m128i_u64[1] = ((uint64_t)t6.m128i_u32[_2i1])<<32;
		W[15* SHA512_NUM].m128i_u64[0] = len.m128i_u32[_2i ];
		W[15* SHA512_NUM].m128i_u64[1] = len.m128i_u32[_2i1];
		
		/* Rounds */
		A = K[72]; E = K[73]; F = K[74];

		H = SSE2_ADD64(K[0], W[0 * SHA512_NUM]); D = SSE2_ADD64(K[75], H);
		G = SSE2_4ADD64(   R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), K[1 ], W[ 1 * SHA512_NUM]); C = SSE2_ADD64(K[76],G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(K[77], SSE2_OR(H, A))));
		F = SSE2_4ADD64(   R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), K[2 ], W[ 2 * SHA512_NUM]); B = SSE2_ADD64(K[77],F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		E = SSE2_4ADD64(   R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), K[3 ], W[ 3 * SHA512_NUM]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		D = SSE2_4ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), K[4 ]                    ); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		C = SSE2_4ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), K[5 ]                    ); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		B = SSE2_4ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), K[6 ]                    ); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		A = SSE2_4ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), K[7 ]                    ); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		H = SSE2_4ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), K[8 ]                    ); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		G = SSE2_4ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), K[9 ]                    ); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		F = SSE2_4ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), K[10]                    ); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		E = SSE2_4ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), K[11]                    ); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		D = SSE2_4ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), K[12]                    ); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		C = SSE2_4ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), K[13]                    ); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		B = SSE2_4ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), K[14]                    ); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), K[15], W[15 * SHA512_NUM]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));

		W[ 0 * SHA512_NUM] = SSE2_ADD64 (W[ 0 * SHA512_NUM], 					                         R0(W[1  * SHA512_NUM])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), K[16], W[ 0 * SHA512_NUM]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA512_NUM] = SSE2_3ADD64(W[ 1 * SHA512_NUM], R1(W[15 * SHA512_NUM])                    , R0(W[2  * SHA512_NUM])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), K[17], W[ 1 * SHA512_NUM]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA512_NUM] = SSE2_3ADD64(W[ 2 * SHA512_NUM], R1(W[0  * SHA512_NUM])                    , R0(W[3  * SHA512_NUM])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), K[18], W[ 2 * SHA512_NUM]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA512_NUM] = SSE2_ADD64 (W[ 3 * SHA512_NUM], R1(W[1  * SHA512_NUM])                                            ); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), K[19], W[ 3 * SHA512_NUM]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA512_NUM] =                                 R1(W[2  * SHA512_NUM])                                             ; D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), K[20], W[ 4 * SHA512_NUM]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA512_NUM] =                                 R1(W[3  * SHA512_NUM])                                             ; C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), K[21], W[ 5 * SHA512_NUM]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA512_NUM] = SSE2_ADD64(                     R1(W[4  * SHA512_NUM]), W[15 * SHA512_NUM]                        ); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), K[22], W[ 6 * SHA512_NUM]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA512_NUM] = SSE2_ADD64(                     R1(W[5  * SHA512_NUM]), W[0  * SHA512_NUM]                        ); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), K[23], W[ 7 * SHA512_NUM]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA512_NUM] = SSE2_ADD64(                     R1(W[6  * SHA512_NUM]), W[1  * SHA512_NUM]                        ); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), K[24], W[ 8 * SHA512_NUM]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 9 * SHA512_NUM] = SSE2_ADD64(                     R1(W[7  * SHA512_NUM]), W[2  * SHA512_NUM]                        ); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), K[25], W[ 9 * SHA512_NUM]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[10 * SHA512_NUM] = SSE2_ADD64(                     R1(W[8  * SHA512_NUM]), W[3  * SHA512_NUM]                        ); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), K[26], W[10 * SHA512_NUM]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[11 * SHA512_NUM] = SSE2_ADD64(                     R1(W[9  * SHA512_NUM]), W[4  * SHA512_NUM]                        ); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), K[27], W[11 * SHA512_NUM]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[12 * SHA512_NUM] = SSE2_ADD64(                     R1(W[10 * SHA512_NUM]), W[5  * SHA512_NUM]                        ); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), K[28], W[12 * SHA512_NUM]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[13 * SHA512_NUM] = SSE2_ADD64(                     R1(W[11 * SHA512_NUM]), W[6  * SHA512_NUM]                        ); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), K[29], W[13 * SHA512_NUM]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[14 * SHA512_NUM] = SSE2_3ADD64(                    R1(W[12 * SHA512_NUM]), W[7  * SHA512_NUM], R0(W[15 * SHA512_NUM])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), K[30], W[14 * SHA512_NUM]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[15 * SHA512_NUM] = SSE2_4ADD64(W[15 * SHA512_NUM], R1(W[13 * SHA512_NUM]), W[8  * SHA512_NUM], R0(W[0  * SHA512_NUM])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), K[31], W[15 * SHA512_NUM]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
																														 	  			
		W[ 0 * SHA512_NUM] = SSE2_4ADD64(W[ 0 * SHA512_NUM], R1(W[14 * SHA512_NUM]), W[9  * SHA512_NUM], R0(W[1  * SHA512_NUM])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), K[32], W[ 0 * SHA512_NUM]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA512_NUM] = SSE2_4ADD64(W[ 1 * SHA512_NUM], R1(W[15 * SHA512_NUM]), W[10 * SHA512_NUM], R0(W[2  * SHA512_NUM])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), K[33], W[ 1 * SHA512_NUM]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA512_NUM] = SSE2_4ADD64(W[ 2 * SHA512_NUM], R1(W[0  * SHA512_NUM]), W[11 * SHA512_NUM], R0(W[3  * SHA512_NUM])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), K[34], W[ 2 * SHA512_NUM]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA512_NUM] = SSE2_4ADD64(W[ 3 * SHA512_NUM], R1(W[1  * SHA512_NUM]), W[12 * SHA512_NUM], R0(W[4  * SHA512_NUM])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), K[35], W[ 3 * SHA512_NUM]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA512_NUM] = SSE2_4ADD64(W[ 4 * SHA512_NUM], R1(W[2  * SHA512_NUM]), W[13 * SHA512_NUM], R0(W[5  * SHA512_NUM])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), K[36], W[ 4 * SHA512_NUM]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA512_NUM] = SSE2_4ADD64(W[ 5 * SHA512_NUM], R1(W[3  * SHA512_NUM]), W[14 * SHA512_NUM], R0(W[6  * SHA512_NUM])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), K[37], W[ 5 * SHA512_NUM]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA512_NUM] = SSE2_4ADD64(W[ 6 * SHA512_NUM], R1(W[4  * SHA512_NUM]), W[15 * SHA512_NUM], R0(W[7  * SHA512_NUM])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), K[38], W[ 6 * SHA512_NUM]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA512_NUM] = SSE2_4ADD64(W[ 7 * SHA512_NUM], R1(W[5  * SHA512_NUM]), W[0  * SHA512_NUM], R0(W[8  * SHA512_NUM])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), K[39], W[ 7 * SHA512_NUM]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA512_NUM] = SSE2_4ADD64(W[ 8 * SHA512_NUM], R1(W[6  * SHA512_NUM]), W[1  * SHA512_NUM], R0(W[9  * SHA512_NUM])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), K[40], W[ 8 * SHA512_NUM]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 9 * SHA512_NUM] = SSE2_4ADD64(W[ 9 * SHA512_NUM], R1(W[7  * SHA512_NUM]), W[2  * SHA512_NUM], R0(W[10 * SHA512_NUM])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), K[41], W[ 9 * SHA512_NUM]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[10 * SHA512_NUM] = SSE2_4ADD64(W[10 * SHA512_NUM], R1(W[8  * SHA512_NUM]), W[3  * SHA512_NUM], R0(W[11 * SHA512_NUM])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), K[42], W[10 * SHA512_NUM]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[11 * SHA512_NUM] = SSE2_4ADD64(W[11 * SHA512_NUM], R1(W[9  * SHA512_NUM]), W[4  * SHA512_NUM], R0(W[12 * SHA512_NUM])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), K[43], W[11 * SHA512_NUM]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[12 * SHA512_NUM] = SSE2_4ADD64(W[12 * SHA512_NUM], R1(W[10 * SHA512_NUM]), W[5  * SHA512_NUM], R0(W[13 * SHA512_NUM])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), K[44], W[12 * SHA512_NUM]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[13 * SHA512_NUM] = SSE2_4ADD64(W[13 * SHA512_NUM], R1(W[11 * SHA512_NUM]), W[6  * SHA512_NUM], R0(W[14 * SHA512_NUM])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), K[45], W[13 * SHA512_NUM]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[14 * SHA512_NUM] = SSE2_4ADD64(W[14 * SHA512_NUM], R1(W[12 * SHA512_NUM]), W[7  * SHA512_NUM], R0(W[15 * SHA512_NUM])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), K[46], W[14 * SHA512_NUM]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[15 * SHA512_NUM] = SSE2_4ADD64(W[15 * SHA512_NUM], R1(W[13 * SHA512_NUM]), W[8  * SHA512_NUM], R0(W[0  * SHA512_NUM])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), K[47], W[15 * SHA512_NUM]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
			   										   							  														
		W[ 0 * SHA512_NUM] = SSE2_4ADD64(W[ 0 * SHA512_NUM], R1(W[14 * SHA512_NUM]), W[9  * SHA512_NUM], R0(W[1  * SHA512_NUM])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), K[48], W[ 0 * SHA512_NUM]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA512_NUM] = SSE2_4ADD64(W[ 1 * SHA512_NUM], R1(W[15 * SHA512_NUM]), W[10 * SHA512_NUM], R0(W[2  * SHA512_NUM])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), K[49], W[ 1 * SHA512_NUM]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA512_NUM] = SSE2_4ADD64(W[ 2 * SHA512_NUM], R1(W[0  * SHA512_NUM]), W[11 * SHA512_NUM], R0(W[3  * SHA512_NUM])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), K[50], W[ 2 * SHA512_NUM]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA512_NUM] = SSE2_4ADD64(W[ 3 * SHA512_NUM], R1(W[1  * SHA512_NUM]), W[12 * SHA512_NUM], R0(W[4  * SHA512_NUM])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), K[51], W[ 3 * SHA512_NUM]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA512_NUM] = SSE2_4ADD64(W[ 4 * SHA512_NUM], R1(W[2  * SHA512_NUM]), W[13 * SHA512_NUM], R0(W[5  * SHA512_NUM])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), K[52], W[ 4 * SHA512_NUM]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA512_NUM] = SSE2_4ADD64(W[ 5 * SHA512_NUM], R1(W[3  * SHA512_NUM]), W[14 * SHA512_NUM], R0(W[6  * SHA512_NUM])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), K[53], W[ 5 * SHA512_NUM]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA512_NUM] = SSE2_4ADD64(W[ 6 * SHA512_NUM], R1(W[4  * SHA512_NUM]), W[15 * SHA512_NUM], R0(W[7  * SHA512_NUM])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), K[54], W[ 6 * SHA512_NUM]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA512_NUM] = SSE2_4ADD64(W[ 7 * SHA512_NUM], R1(W[5  * SHA512_NUM]), W[0  * SHA512_NUM], R0(W[8  * SHA512_NUM])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), K[55], W[ 7 * SHA512_NUM]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA512_NUM] = SSE2_4ADD64(W[ 8 * SHA512_NUM], R1(W[6  * SHA512_NUM]), W[1  * SHA512_NUM], R0(W[9  * SHA512_NUM])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), K[56], W[ 8 * SHA512_NUM]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 9 * SHA512_NUM] = SSE2_4ADD64(W[ 9 * SHA512_NUM], R1(W[7  * SHA512_NUM]), W[2  * SHA512_NUM], R0(W[10 * SHA512_NUM])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), K[57], W[ 9 * SHA512_NUM]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[10 * SHA512_NUM] = SSE2_4ADD64(W[10 * SHA512_NUM], R1(W[8  * SHA512_NUM]), W[3  * SHA512_NUM], R0(W[11 * SHA512_NUM])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), K[58], W[10 * SHA512_NUM]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[11 * SHA512_NUM] = SSE2_4ADD64(W[11 * SHA512_NUM], R1(W[9  * SHA512_NUM]), W[4  * SHA512_NUM], R0(W[12 * SHA512_NUM])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), K[59], W[11 * SHA512_NUM]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[12 * SHA512_NUM] = SSE2_4ADD64(W[12 * SHA512_NUM], R1(W[10 * SHA512_NUM]), W[5  * SHA512_NUM], R0(W[13 * SHA512_NUM])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), K[60], W[12 * SHA512_NUM]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[13 * SHA512_NUM] = SSE2_4ADD64(W[13 * SHA512_NUM], R1(W[11 * SHA512_NUM]), W[6  * SHA512_NUM], R0(W[14 * SHA512_NUM])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), K[61], W[13 * SHA512_NUM]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[14 * SHA512_NUM] = SSE2_4ADD64(W[14 * SHA512_NUM], R1(W[12 * SHA512_NUM]), W[7  * SHA512_NUM], R0(W[15 * SHA512_NUM])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), K[62], W[14 * SHA512_NUM]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[15 * SHA512_NUM] = SSE2_4ADD64(W[15 * SHA512_NUM], R1(W[13 * SHA512_NUM]), W[8  * SHA512_NUM], R0(W[0  * SHA512_NUM])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), K[63], W[15 * SHA512_NUM]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
														   					 		   													
		W[ 0 * SHA512_NUM] = SSE2_4ADD64(W[ 0 * SHA512_NUM], R1(W[14 * SHA512_NUM]), W[9  * SHA512_NUM], R0(W[1  * SHA512_NUM])); H = SSE2_5ADD64(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), K[64], W[ 0 * SHA512_NUM]); D = SSE2_ADD64(D, H); H = SSE2_3ADD64(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA512_NUM] = SSE2_4ADD64(W[ 1 * SHA512_NUM], R1(W[15 * SHA512_NUM]), W[10 * SHA512_NUM], R0(W[2  * SHA512_NUM])); G = SSE2_5ADD64(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), K[65], W[ 1 * SHA512_NUM]); C = SSE2_ADD64(C, G); G = SSE2_3ADD64(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA512_NUM] = SSE2_4ADD64(W[ 2 * SHA512_NUM], R1(W[0  * SHA512_NUM]), W[11 * SHA512_NUM], R0(W[3  * SHA512_NUM])); F = SSE2_5ADD64(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), K[66], W[ 2 * SHA512_NUM]); B = SSE2_ADD64(B, F); F = SSE2_3ADD64(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA512_NUM] = SSE2_4ADD64(W[ 3 * SHA512_NUM], R1(W[1  * SHA512_NUM]), W[12 * SHA512_NUM], R0(W[4  * SHA512_NUM])); E = SSE2_5ADD64(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), K[67], W[ 3 * SHA512_NUM]); A = SSE2_ADD64(A, E); E = SSE2_3ADD64(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA512_NUM] = SSE2_4ADD64(W[ 4 * SHA512_NUM], R1(W[2  * SHA512_NUM]), W[13 * SHA512_NUM], R0(W[5  * SHA512_NUM])); D = SSE2_5ADD64(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), K[68], W[ 4 * SHA512_NUM]); H = SSE2_ADD64(H, D); D = SSE2_3ADD64(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA512_NUM] = SSE2_4ADD64(W[ 5 * SHA512_NUM], R1(W[3  * SHA512_NUM]), W[14 * SHA512_NUM], R0(W[6  * SHA512_NUM])); C = SSE2_5ADD64(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), K[69], W[ 5 * SHA512_NUM]); G = SSE2_ADD64(G, C); C = SSE2_3ADD64(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA512_NUM] = SSE2_4ADD64(W[ 6 * SHA512_NUM], R1(W[4  * SHA512_NUM]), W[15 * SHA512_NUM], R0(W[7  * SHA512_NUM])); B = SSE2_5ADD64(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), K[70], W[ 6 * SHA512_NUM]); F = SSE2_ADD64(F, B); B = SSE2_3ADD64(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA512_NUM] = SSE2_4ADD64(W[ 7 * SHA512_NUM], R1(W[5  * SHA512_NUM]), W[0  * SHA512_NUM], R0(W[8  * SHA512_NUM])); A = SSE2_5ADD64(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), K[71], W[ 7 * SHA512_NUM]); E = SSE2_ADD64(E, A); A = SSE2_3ADD64(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA512_NUM] = SSE2_4ADD64(W[ 8 * SHA512_NUM], R1(W[6  * SHA512_NUM]), W[1  * SHA512_NUM], R0(W[9  * SHA512_NUM]));
		W[ 9 * SHA512_NUM] = SSE2_4ADD64(W[ 9 * SHA512_NUM], R1(W[7  * SHA512_NUM]), W[2  * SHA512_NUM], R0(W[10 * SHA512_NUM]));
		W[2 * SHA512_NUM] = SSE2_4ADD64(W[11 * SHA512_NUM], R1(W[9 * SHA512_NUM]), W[4 * SHA512_NUM], R0(W[12 * SHA512_NUM]));
		W[1 * SHA512_NUM] = SSE2_4ADD64(W[13 * SHA512_NUM], R1(W[2 * SHA512_NUM]), W[6 * SHA512_NUM], R0(W[14 * SHA512_NUM]));
		W[0 * SHA512_NUM] = SSE2_4ADD64(W[15 * SHA512_NUM], R1(W[1 * SHA512_NUM]), W[8 * SHA512_NUM], R0(W[0  * SHA512_NUM])); A = SSE2_ADD64(A, W[0 * SHA512_NUM]); 

		W[4  * SHA512_NUM] = A;
		W[6  * SHA512_NUM] = B;
		W[16 * SHA512_NUM] = C;
		W[17 * SHA512_NUM] = D;
		W[18 * SHA512_NUM] = E;
		W[19 * SHA512_NUM] = F;
		W[20 * SHA512_NUM] = G;
		W[21 * SHA512_NUM] = H;
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

void crypt_sha512_avx_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_utf8_coalesc_protocol_avx(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_sha512_avx_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void crypt_sha512_avx2_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_utf8_coalesc_protocol_avx2(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_sha512_avx2_kernel_asm);
}
#endif

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementations
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Number of SHA256-SHA512 32bits instruction
//---------------------------------------------------------------------------------------------------------------------------
// Step		W0 += R1(W14) + W9 + R0(W1);H += R_E(E) + bs(G,F,E) + 0x19A4C116B8D2D0C8UL + W0; D += H;H += R_A(A) + MAJ(A,B,C);
// SHA256	   1    9     1    1   9      1   11    1  1        1                      1       1      1   11    1  2=53
// SHA512	   4    20    4    4   20     4   22    4  2        4                      4       4      4   22    4  4=130
//---------------------------------------------------------------------------------------------------------------------------
// SHA256/SHA512=2.45
#ifdef HS_OPENCL_SUPPORT
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
#undef R1
#undef R0
#define R0(x)  (ROTATE(x,63) ^ ROTATE(x,56) ^ ((x)>>7))
#define R1(x)  (ROTATE(x,45) ^ ROTATE(x,3 ) ^ ((x)>>6))
PRIVATE void ocl_write_sha512_header_ulong(char* source, GPUDevice* gpu, cl_uint ntlm_size_bit_table1)
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
	
	// Definitions
	sprintf(source + strlen(source), 
		"#define R_E(x) (rotate(x,50UL)^rotate(x,46UL)^rotate(x,23UL))\n"
		"#define R_A(x) (rotate(x,36UL)^rotate(x,30UL)^rotate(x,25UL))\n"
		"#define R0(x) (rotate(x,63UL)^rotate(x,56UL)^((x)>>7UL))\n"
		"#define R1(x) (rotate(x,45UL)^rotate(x,3UL)^((x)>>6UL))\n");
}
PRIVATE void ocl_write_sha512_header_uint2(char* source, GPUDevice* gpu, cl_uint ntlm_size_bit_table1)
{
	source[0] = 0;
	// Header definitions
	if (num_passwords_loaded > 1)
		strcat(source, "#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable\n");
	if (gpu->flags & GPU_FLAG_SUPPORT_AMD_OPS)
		strcat(source, "#pragma OPENCL EXTENSION cl_amd_media_ops : enable\n");

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
	// Minor optimization
	if (gpu->vendor == OCL_VENDOR_AMD && gpu->vector_int_size >= 4)
		sprintf(source + strlen(source), "#define MAJ(c,b,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
	else
		sprintf(source + strlen(source), "#define MAJ(b,c,d) (%s)\n", (gpu->flags & GPU_FLAG_NATIVE_BITSELECT) ? "bs(c,b,d^c)" : "(b&(c|d))|(c&d)");
#endif
	
	// Definitions
	sprintf(source + strlen(source),
#ifdef __ANDROID__
		"#define SUB(r,a0,a1) t.s1=a0.s0<a1.s0;r=a0-a1;r.s1-=t.s1;\n"//4 32bits op
		"#define ADD(r,a0,a1) r=a0+a1;r.s1+=r.s0<a1.s0;\n"//4 32bits op
		"#define ADD_CONST(r,a,const1,const0) r.s0=a.s0+const0;r.s1=a.s1+const1;r.s1+=r.s0<const0;\n"//4 32bits op
#else
		"#define SUB(r,a0,a1) r=as_uint2(as_ulong(a0)-as_ulong(a1));\n"//4 32bits op
		"#define ADD(r,a0,a1) r=as_uint2(as_ulong(a0)+as_ulong(a1));\n"//4 32bits op
		"#define ADD_CONST(r,a,const1,const0) r=as_uint2(as_ulong(a)+((((ulong)const1)<<32)+const0));\n"//4 32bits op
#endif

		// "H+=R_E(E)+bs(G,F,E)+0xE49B69C19EF14AD2UL+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"#define STEP_1ST(h,e,g,f,const1,const0,w,d) R_E(t,e);ADD(h,h,t);t=bs(g,f,e);ADD(h,h,t);ADD_CONST(h,h,const1,const0);ADD(h,h,w);ADD(d,d,h);\n"
		"#define STEP(h,e,g,f,const1,const0,w,d,a,b,c) STEP_1ST(h,e,g,f,const1,const0,w,d);R_A(t,a);ADD(h,h,t);t=MAJ(a,b,c);ADD(h,h,t);\n"
		//"W0+=R1(W1)+W2+R0(W3)
		"#define WR(w0,w1,w2,w3) ADD(w0,w0,w2);R1(t,w1);ADD(w0,w0,t);R0(t,w3);ADD(w0,w0,t);\n");

	if (gpu->flags & GPU_FLAG_SUPPORT_AMD_OPS)
		sprintf(source + strlen(source),
		"#define R_E(r,x) r.s1=amd_bitalign(x.s0,x.s1,14u);"//ROTATE(x,50UL)
						 "r.s0=amd_bitalign(x.s1,x.s0,14u);"
						"t0.s1=amd_bitalign(x.s0,x.s1,18u);"//ROTATE(x,46UL)
						"t0.s0=amd_bitalign(x.s1,x.s0,18u);"
						"r^=t0;"
						"t0.s0=amd_bitalign(x.s0,x.s1,9u);"//ROTATE(x,23UL)
						"t0.s1=amd_bitalign(x.s1,x.s0,9u);"
						"r^=t0;\n"
		"#define R_A(r,x) r.s1=amd_bitalign(x.s0,x.s1,28u);"//ROTATE(x,36UL)
						 "r.s0=amd_bitalign(x.s1,x.s0,28u);"
						"t0.s0=amd_bitalign(x.s0,x.s1,2u);"//ROTATE(x,30UL)
						"t0.s1=amd_bitalign(x.s1,x.s0,2u);"
						"r^=t0;"
						"t0.s0=amd_bitalign(x.s0,x.s1,7u);"//ROTATE(x,25UL)
						"t0.s1=amd_bitalign(x.s1,x.s0,7u);"
						"r^=t0;\n"
		"#define R0(r,x) r.s1=amd_bitalign(x.s0,x.s1,1u);"//ROTATE(x,63UL)
					    "r.s0=amd_bitalign(x.s1,x.s0,1u);"
					   "t0.s1=amd_bytealign(x.s0,x.s1,1u);"//ROTATE(x,56UL)
					   "t0.s0=amd_bytealign(x.s1,x.s0,1u);"
					   "r^=t0;"
					   "t0.s0=amd_bitalign(x.s1,x.s0,7u);"//x>>7UL
					   "t0.s1=(x.s1>>7u);"
					   "r^=t0;\n"
		"#define R1(r,x) r.s1=amd_bitalign(x.s0,x.s1,19u);"//ROTATE(x,45UL)
					    "r.s0=amd_bitalign(x.s1,x.s0,19u);"
					   "t0.s0=amd_bitalign(x.s0,x.s1,29u);"//ROTATE(x,3UL)
					   "t0.s1=amd_bitalign(x.s1,x.s0,29u);"
					   "r^=t0;"
					   "t0.s0=amd_bitalign(x.s1,x.s0,6u);"//x>>6UL
					   "t0.s1=(x.s1>>6u);"
					   "r^=t0;\n");
	else
		sprintf(source + strlen(source),
		"#define R_E(r,x) r.s1=(x.s0<<18u)|(x.s1>>14u);"//ROTATE(x,50UL)
						 "r.s0=(x.s1<<18u)|(x.s0>>14u);"
						"t0.s1=(x.s0<<14u)|(x.s1>>18u);"//ROTATE(x,46UL)
						"t0.s0=(x.s1<<14u)|(x.s0>>18u);"
						"r^=t0;"
						"t0.s0=(x.s0<<23u)|(x.s1>>9u);"//ROTATE(x,23UL)
						"t0.s1=(x.s1<<23u)|(x.s0>>9u);"
						"r^=t0;\n"
		"#define R_A(r,x) r.s1=(x.s0<<4u)|(x.s1>>28u);"//ROTATE(x,36UL)
						 "r.s0=(x.s1<<4u)|(x.s0>>28u);"
						"t0.s0=(x.s0<<30u)|(x.s1>>2u);"//ROTATE(x,30UL)
						"t0.s1=(x.s1<<30u)|(x.s0>>2u);"
						"r^=t0;"
						"t0.s0=(x.s0<<25u)|(x.s1>>7u);"//ROTATE(x,25UL)
						"t0.s1=(x.s1<<25u)|(x.s0>>7u);"
						"r^=t0;\n"
		"#define R0(r,x) r.s1=(x.s0<<31u)|(x.s1>>1u);"//ROTATE(x,63UL)
					    "r.s0=(x.s1<<31u)|(x.s0>>1u);"
					   "t0.s1=(x.s0<<24u)|(x.s1>>8u);"//ROTATE(x,56UL)
					   "t0.s0=(x.s1<<24u)|(x.s0>>8u);"
					   "r^=t0;"
					   "t0.s0=(x.s0>>7u )|(x.s1<<25u);"//x>>7UL
					   "t0.s1=(x.s1>>7u );"
					   "r^=t0;\n"
		"#define R1(r,x) r.s1=(x.s0<<13u)|(x.s1>>19u);"//ROTATE(x,45UL)
					    "r.s0=(x.s1<<13u)|(x.s0>>19u);"
					   "t0.s0=(x.s0<<3u)|(x.s1>>29u);"//ROTATE(x,3UL)
					   "t0.s1=(x.s1<<3u)|(x.s0>>29u);"
					   "r^=t0;"
					   "t0.s0=(x.s0>>6u)|(x.s1<<26u);"//x>>6UL
					   "t0.s1=(x.s1>>6u);"
					   "r^=t0;\n");
}

PRIVATE void ocl_gen_kernel_with_lenght_ulong(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission, cl_uint workgroup)
{
	char* nt_buffer[] = { "+nt_buffer0", "+nt_buffer1", "+nt_buffer2", "+nt_buffer3", "+nt_buffer4", "+nt_buffer5", "+nt_buffer6" };

	ocl_charset_load_buffer_be(source, key_lenght, &vector_size, div_param, nt_buffer);

	sprintf(source + strlen(source), "ulong A,B,C,D,E,F,G,H,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");
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

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "nt_buffer0+=%uu;", is_charset_consecutive(charset) << 24u);

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "W0=nt_buffer0+(i<<24u);");
	else
		sprintf(source + strlen(source), "W0=nt_buffer0+(((uint)charset[i])<<24u);");

	sprintf(source + strlen(source),
		"W0=(W0<<32ul)%s;"
		"W1=upsample(0u%s,0u%s);"
		"W2=upsample(0u%s,0u%s);"
		"W3=((ulong)0ul%s)<<32ul;"
		, nt_buffer[1]
		, nt_buffer[2], nt_buffer[3]
		, nt_buffer[4], nt_buffer[5]
		, nt_buffer[6]);

	/* Round 1 */
	sprintf(source + strlen(source),
		"A=0x6A09E667F3BCC908UL;E=0x510E527FADE682D1UL;F=0x9B05688C2B3E6C1FUL;"

		"H=0x954d6b38bcfcddf5UL+W0;D=0x621b337bbdb8419cUL+H;"
		"G=R_E(D)+bs(F,E,D)+0x90bb1e3d1f312338UL+W1;C=0x3C6EF372FE94F82BUL+G;G+=R_A(H)+MAJ(H,A,0xBB67AE8584CAA73BUL);"
		"F=R_E(C)+bs(E,D,C)+0x50c6645c178ba74eUL+W2;B=0xBB67AE8584CAA73BUL+F;F+=R_A(G)+MAJ(G,H,A);"
		"E=R_E(B)+bs(D,C,B)+0x3ac42e252f705e8dUL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x3956C25BF348B538UL;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x59F111F1B605D019UL;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x923F82A4AF194F9BUL;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0xAB1C5ED5DA6D8118UL;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0xD807AA98A3030242UL;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0x12835B0145706FBEUL;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x243185BE4EE4B28CUL;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x550C7DC3D5FFB4E2UL;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x72BE5D74F27B896FUL;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x80DEB1FE3B1696B1UL;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x9BDC06A725C71235UL;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+%lluUL;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		, (uint64_t)(key_lenght << 3) + 0xC19BF174CF692694ULL);

	sprintf(source + strlen(source),
		"W0+=R0(W1);"
		"W1+=%lluUL+R0(W2);"
		"W2+=R1(W0)+R0(W3);"
		"W3+=R1(W1);"
		"W4=R1(W2);"
		"W5=R1(W3);"
		"W6=R1(W4)+%lluUL;"
		"W7=R1(W5)+W0;"
		"W8=R1(W6)+W1;"
		"W9=R1(W7)+W2;"
		"W10=R1(W8)+W3;"
		"W11=R1(W9)+W4;"
		"W12=R1(W10)+W5;"
		"W13=R1(W11)+W6;"
		"W14=R1(W12)+W7+%lluUL;"
		"W15=R1(W13)+W8+R0(W0)+%lluUL;"
		, (uint64_t)(R1(key_lenght << 3))
		, (uint64_t)(key_lenght << 3)
		, (uint64_t)(R0(key_lenght << 3))
		, (uint64_t)(key_lenght << 3));

	/* Round 2 */
	sprintf(source + strlen(source),
		"H+=R_E(E)+bs(G,F,E)+0xE49B69C19EF14AD2UL+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xEFBE4786384F25E3UL+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x0FC19DC68B8CD5B5UL+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x240CA1CC77AC9C65UL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x2DE92C6F592B0275UL+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x4A7484AA6EA6E483UL+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x5CB0A9DCBD41FBD4UL+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x76F988DA831153B5UL+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0x983E5152EE66DFABUL+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xA831C66D2DB43210UL+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0xB00327C898FB213FUL+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0xBF597FC7BEEF0EE4UL+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0xC6E00BF33DA88FC2UL+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0xD5A79147930AA725UL+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x06CA6351E003826FUL+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x142929670A0E6E70UL+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x27B70A8546D22FFCUL+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x2E1B21385C26C926UL+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x4D2C6DFC5AC42AEDUL+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x53380D139D95B3DFUL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x650A73548BAF63DEUL+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x766A0ABB3C77B2A8UL+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x81C2C92E47EDAEE6UL+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x92722C851482353BUL+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0xA2BFE8A14CF10364UL+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W9+=R1(W7)+W2+R0(W10);G+=R_E(D)+bs(F,E,D)+0xA81A664BBC423001UL+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W10+=R1(W8)+W3+R0(W11);F+=R_E(C)+bs(E,D,C)+0xC24B8B70D0F89791UL+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W11+=R1(W9)+W4+R0(W12);E+=R_E(B)+bs(D,C,B)+0xC76C51A30654BE30UL+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W12+=R1(W10)+W5+R0(W13);D+=R_E(A)+bs(C,B,A)+0xD192E819D6EF5218UL+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W13+=R1(W11)+W6+R0(W14);C+=R_E(H)+bs(B,A,H)+0xD69906245565A910UL+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W14+=R1(W12)+W7+R0(W15);B+=R_E(G)+bs(A,H,G)+0xF40E35855771202AUL+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W15+=R1(W13)+W8+R0(W0 );A+=R_E(F)+bs(H,G,F)+0x106AA07032BBD1B8UL+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");
	
	/* Round 4 */
	sprintf(source + strlen(source),
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x19A4C116B8D2D0C8UL+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x1E376C085141AB53UL+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x2748774CDF8EEB99UL+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x34B0BCB5E19B48A8UL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x391C0CB3C5C95A63UL+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x4ED8AA4AE3418ACBUL+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x5B9CCA4F7763E373UL+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x682E6FF3D6B2B8A3UL+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0x748F82EE5DEFB2FCUL+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W9+=R1(W7)+W2+R0(W10);G+=R_E(D)+bs(F,E,D)+0x78A5636F43172F60UL+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W10+=R1(W8)+W3+R0(W11);F+=R_E(C)+bs(E,D,C)+0x84C87814A1F0AB72UL+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W11+=R1(W9)+W4+R0(W12);E+=R_E(B)+bs(D,C,B)+0x8CC702081A6439ECUL+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W12+=R1(W10)+W5+R0(W13);D+=R_E(A)+bs(C,B,A)+0x90BEFFFA23631E28UL+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W13+=R1(W11)+W6+R0(W14);C+=R_E(H)+bs(B,A,H)+0xA4506CEBDE82BDE9UL+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W14+=R1(W12)+W7+R0(W15);B+=R_E(G)+bs(A,H,G)+0xBEF9A3F7B2C67915UL+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W15+=R1(W13)+W8+R0(W0);A+=R_E(F)+bs(H,G,F)+0xC67178F2E372532BUL+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");
			

	/* Round 5 */									   													  
	sprintf(source + strlen(source),				   													  
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0xCA273ECEEA26619CUL+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0xD186B8C721C0C207UL+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0xEADA7DD6CDE0EB1EUL+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0xF57D4F7FEE6ED178UL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x06F067AA72176FBAUL+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x0A637DC5A2C898A6UL+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x113F9804BEF90DAEUL+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x1B710B35131C471BUL+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);"
		"W9+=R1(W7)+W2+R0(W10);"
		"W2=W11+R1(W9)+W4+R0(W12);"
		"W1=W13+R1(W2)+W6+R0(W14);"
		"W0=W15+R1(W1)+W8+R0(W0);A+=W0;");

	// Find match
	if (num_passwords_loaded == 1)
	{
		uint64_t* bin = (uint64_t*)binary_values;
		sprintf(source + strlen(source),
			"if(A==%lluUL)"
			"{"
				"A-=W0;"
				"W10+=R1(W8)+W3+R0(W11);"
				"W12+=R1(W10)+W5+R0(W13);"
				"W14+=R1(W12)+W7+R0(W15);"

				"H+=R_E(E)+bs(G,F,E)+0x28DB77F523047D84UL+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
				"G+=R_E(D)+bs(F,E,D)+0x32CAAB7B40C72493UL+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
				"F+=R_E(C)+bs(E,D,C)+0x3C9EBE0A15C9BEBCUL+W10;B+=F;F+=MAJ(G,H,A);"
				"E+=R_E(B)+bs(D,C,B)+0x431D67C49C100D4CUL+W2;A+=E;"
				"D+=R_E(A)+bs(C,B,A)+0x4CC5D4BECB3E42B6UL+W12;H+=D;"
				"C+=R_E(H)+bs(B,A,H)+0x597F299CFC657E2AUL+W1;G+=C;"
				"B+=bs(A,H,G)+W14;"

				"if(B==%lluUL&&C==%lluUL&&D==%lluUL&&E==%lluUL&&F==%lluUL&&G==%lluUL&&H==%lluUL)"
				"{"
					"output[0]=1u;"
					"output[1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
					"output[2]=0;"
				"}"
			"}"
			, bin[0], bin[1], bin[2], bin[3], bin[4], bin[5], bin[6], bin[7]);
	}
	else
	{
		// Find match
		sprintf(source + strlen(source), "uint xx=((uint)A)&%uu;uint fdata;", cbg_mask);
		
		sprintf(source + strlen(source),
			"fdata=(uint)(cbg_filter[xx]);"

			"if(((fdata^((uint)(A>>32u)))&0xFFF8)==0){"
				"indx=cbg_table[xx];"
				"__global ulong* bin=(__global ulong*)binary_values;"
				"if(indx!=0xffffffff&&A==bin[indx*8u]){"

					"ulong aa=A-W0;"
					"W4=W10+R1(W8)+W3+R0(W11);"
					"W6=W12+R1(W4)+W5+R0(W13);"
					"ulong ww14=W14+R1(W6)+W7+R0(W15);"

					"ulong bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

					"hh+=R_E(ee)+bs(gg,ff,ee)+0x28DB77F523047D84UL+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
					"gg+=R_E(dd)+bs(ff,ee,dd)+0x32CAAB7B40C72493UL+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
					"ff+=R_E(cc)+bs(ee,dd,cc)+0x3C9EBE0A15C9BEBCUL+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
					"ee+=R_E(bb)+bs(dd,cc,bb)+0x431D67C49C100D4CUL+W2;aa+=ee;"
					"dd+=R_E(aa)+bs(cc,bb,aa)+0x4CC5D4BECB3E42B6UL+W6;hh+=dd;"
					"cc+=R_E(hh)+bs(bb,aa,hh)+0x597F299CFC657E2AUL+W1;gg+=cc;"
					"bb+=bs(aa,hh,gg)+ww14;"

					"if(bb==bin[indx*8u+1u]&&cc==bin[indx*8u+2u]&&dd==bin[indx*8u+3u]&&"
					"ee==bin[indx*8u+4u]&&ff==bin[indx*8u+5u]&&gg==bin[indx*8u+6u]&&"
					"hh==bin[indx*8u+7u]){"
						"uint found=atomic_inc(output);"
						"if(found<%uu){"
							"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
							"output[2*found+2]=indx;}"
					"}"
				"}"
			"}", output_size);
				
		sprintf(source + strlen(source),
			"if(fdata&4){"// Is second
				"xx+=fdata&1?-1:1;"
				"if(((((uint)cbg_filter[xx])^((uint)(A>>32u)))&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"__global ulong* bin=(__global ulong*)binary_values;"
					"if(indx!=0xffffffff&&A==bin[indx*8u]){"

						"ulong aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"ulong ww14=W14+R1(W6)+W7+R0(W15);"

						"ulong bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"hh+=R_E(ee)+bs(gg,ff,ee)+0x28DB77F523047D84UL+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
						"gg+=R_E(dd)+bs(ff,ee,dd)+0x32CAAB7B40C72493UL+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x3C9EBE0A15C9BEBCUL+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x431D67C49C100D4CUL+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x4CC5D4BECB3E42B6UL+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0x597F299CFC657E2AUL+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==bin[indx*8u+1u]&&cc==bin[indx*8u+2u]&&dd==bin[indx*8u+3u]&&"
						"ee==bin[indx*8u+4u]&&ff==bin[indx*8u+5u]&&gg==bin[indx*8u+6u]&&"
						"hh==bin[indx*8u+7u]){"
							"uint found=atomic_inc(output);"
							"if(found<%uu){"
								"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
								"output[2*found+2]=indx;}"
						"}"
					"}"
				"}"
			"}", output_size);

		sprintf(source + strlen(source),
			"if(fdata&2){"// Is unlucky
				"xx=((uint)(A>>32u))&%uu;"
				"fdata=(uint)(cbg_filter[xx]);"
				"if(((fdata^((uint)A))&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"__global ulong* bin=(__global ulong*)binary_values;"
					"if(indx!=0xffffffff&&A==bin[indx*8u]){"

						"ulong aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"ulong ww14=W14+R1(W6)+W7+R0(W15);"

						"ulong bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"hh+=R_E(ee)+bs(gg,ff,ee)+0x28DB77F523047D84UL+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
						"gg+=R_E(dd)+bs(ff,ee,dd)+0x32CAAB7B40C72493UL+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x3C9EBE0A15C9BEBCUL+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x431D67C49C100D4CUL+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x4CC5D4BECB3E42B6UL+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0x597F299CFC657E2AUL+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==bin[indx*8u+1u]&&cc==bin[indx*8u+2u]&&dd==bin[indx*8u+3u]&&"
						"ee==bin[indx*8u+4u]&&ff==bin[indx*8u+5u]&&gg==bin[indx*8u+6u]&&"
						"hh==bin[indx*8u+7u]){"
							"uint found=atomic_inc(output);"
							"if(found<%uu){"
								"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
								"output[2*found+2]=indx;}"
						"}"
					"}"
				"}"
			, cbg_mask, output_size);

		sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx])^((uint)A))&0xFFF8)==0){"
						"indx=cbg_table[xx];"
						"__global ulong* bin=(__global ulong*)binary_values;"
						"if(indx!=0xffffffff&&A==bin[indx*8u]){"

							"ulong aa=A-W0;"
							"W4=W10+R1(W8)+W3+R0(W11);"
							"W6=W12+R1(W4)+W5+R0(W13);"
							"ulong ww14=W14+R1(W6)+W7+R0(W15);"

							"ulong bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

							"hh+=R_E(ee)+bs(gg,ff,ee)+0x28DB77F523047D84UL+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
							"gg+=R_E(dd)+bs(ff,ee,dd)+0x32CAAB7B40C72493UL+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
							"ff+=R_E(cc)+bs(ee,dd,cc)+0x3C9EBE0A15C9BEBCUL+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
							"ee+=R_E(bb)+bs(dd,cc,bb)+0x431D67C49C100D4CUL+W2;aa+=ee;"
							"dd+=R_E(aa)+bs(cc,bb,aa)+0x4CC5D4BECB3E42B6UL+W6;hh+=dd;"
							"cc+=R_E(hh)+bs(bb,aa,hh)+0x597F299CFC657E2AUL+W1;gg+=cc;"
							"bb+=bs(aa,hh,gg)+ww14;"

							"if(bb==bin[indx*8u+1u]&&cc==bin[indx*8u+2u]&&dd==bin[indx*8u+3u]&&"
							"ee==bin[indx*8u+4u]&&ff==bin[indx*8u+5u]&&gg==bin[indx*8u+6u]&&"
							"hh==bin[indx*8u+7u]){"
								"uint found=atomic_inc(output);"
								"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
									"output[2*found+2]=indx;}"
							"}"
						"}"
					"}"
				"}"
			"}", output_size);
	}

	strcat(source, "}}");
}
PRIVATE void ocl_gen_kernel_with_lenght_uint2(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table1, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission1, cl_uint workgroup)
{
	char* nt_buffer[] = { "+nt_buffer0", "+nt_buffer1", "+nt_buffer2", "+nt_buffer3", "+nt_buffer4", "+nt_buffer5", "+nt_buffer6" };

	ocl_charset_load_buffer_be(source, key_lenght, &vector_size, div_param, nt_buffer);

	sprintf(source + strlen(source), "uint2 A,B,C,D,E,F,G,H,t0,t,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");
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

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "nt_buffer0+=%uu;", is_charset_consecutive(charset) << 24u);

	{
		sprintf(source + strlen(source), 
		"W1.s1=0u%s;"
		"W1.s0=0u%s;"
		"W2.s1=0u%s;"
		"W2.s0=0u%s;"
		"W3.s1=0u%s;"
		"W3.s0=0u;"
		, nt_buffer[2]
		, nt_buffer[3]
		, nt_buffer[4]
		, nt_buffer[5]
		, nt_buffer[6]);

		uint64_t _r1_w15 = (uint64_t)(R1(key_lenght << 3));
		sprintf(source + strlen(source),
			"uint2 W1_R0, W1_2, W2_2, W3_2, W5_2, W6_2, W5_R1;"

			"R0(W1_R0, W1);"
			"W1_R0.s0=W1_R0.s0%s;"
			"W1_R0.s1+=W1_R0.s0<(0u%s);"

			"ADD_CONST(W1_2,W1,%uu,%uu);R0(t,W2);ADD(W1_2,W1_2,t);"
			"R0(t,W3);ADD(W2_2,W2,t);"
			"R1(t,W1_2);ADD(W3_2,W3,t);"
			"R1(W5_2,W3_2);"
			"R1(W5_R1,W5_2);"
			, nt_buffer[1], nt_buffer[1]
			, (uint32_t)(_r1_w15>>32), (uint32_t)_r1_w15);
	}

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "W0.s1=nt_buffer0+(i<<24u);");
	else
		sprintf(source + strlen(source), "W0.s1=nt_buffer0+(((uint)charset[i])<<24u);");

	sprintf(source + strlen(source), 
		"W0.s0=0u%s;"
		"W1.s1=0u%s;"
		"W1.s0=0u%s;"
		"W2.s1=0u%s;"
		"W2.s0=0u%s;"
		"W3.s1=0u%s;"
		"W3.s0=0u;"
		, nt_buffer[1]
		, nt_buffer[2]
		, nt_buffer[3]
		, nt_buffer[4]
		, nt_buffer[5]
		, nt_buffer[6]);

	uint64_t _w15 = (uint64_t)(key_lenght << 3) + 0xC19BF174CF692694ULL;
	/* Round 1 */
	sprintf(source + strlen(source),
		"A.s0=0xF3BCC908;A.s1=0x6A09E667;B.s0=0x84CAA73B;B.s1=0xBB67AE85;C.s0=0xFE94F82B;C.s1=0x3C6EF372;E.s0=0xADE682D1;E.s1=0x510E527F;F.s0=0x2B3E6C1F;F.s1=0x9B05688C;"

		"ADD_CONST(H,W0,0x954d6b38,0xbcfcddf5);ADD_CONST(D,H,0x621b337b,0xbdb8419c);"
		"R_E(G,D);t=bs(F,E,D);ADD(G,G,t);ADD_CONST(G,G,0x90bb1e3d,0x1f312338);ADD(G,G,W1);ADD(C,C,G);R_A(t,H);ADD(G,G,t);t=MAJ(H,A,B);ADD(G,G,t);"
		"R_E(F,C);t=bs(E,D,C);ADD(F,F,t);ADD_CONST(F,F,0x50c6645c,0x178ba74e);ADD(F,F,W2);ADD(B,B,F);R_A(t,G);ADD(F,F,t);t=MAJ(G,H,A);ADD(F,F,t);"
		"R_E(E,B);t=bs(D,C,B);ADD(E,E,t);ADD_CONST(E,E,0x3ac42e25,0x2f705e8d);ADD(E,E,W3);ADD(A,A,E);R_A(t,F);ADD(E,E,t);t=MAJ(F,G,H);ADD(E,E,t);"
		"R_E(t,A);ADD(D,D,t);t=bs(C,B,A);ADD(D,D,t);ADD_CONST(D,D,0x3956C25B,0xF348B538) ;ADD(H,H,D);R_A(t,E);ADD(D,D,t);t=MAJ(E,F,G);ADD(D,D,t);"
		"R_E(t,H);ADD(C,C,t);t=bs(B,A,H);ADD(C,C,t);ADD_CONST(C,C,0x59F111F1,0xB605D019) ;ADD(G,G,C);R_A(t,D);ADD(C,C,t);t=MAJ(D,E,F);ADD(C,C,t);"
		"R_E(t,G);ADD(B,B,t);t=bs(A,H,G);ADD(B,B,t);ADD_CONST(B,B,0x923F82A4,0xAF194F9B) ;ADD(F,F,B);R_A(t,C);ADD(B,B,t);t=MAJ(C,D,E);ADD(B,B,t);"
		"R_E(t,F);ADD(A,A,t);t=bs(H,G,F);ADD(A,A,t);ADD_CONST(A,A,0xAB1C5ED5,0xDA6D8118) ;ADD(E,E,A);R_A(t,B);ADD(A,A,t);t=MAJ(B,C,D);ADD(A,A,t);"
		"R_E(t,E);ADD(H,H,t);t=bs(G,F,E);ADD(H,H,t);ADD_CONST(H,H,0xD807AA98,0xA3030242) ;ADD(D,D,H);R_A(t,A);ADD(H,H,t);t=MAJ(A,B,C);ADD(H,H,t);"
		"R_E(t,D);ADD(G,G,t);t=bs(F,E,D);ADD(G,G,t);ADD_CONST(G,G,0x12835B01,0x45706FBE) ;ADD(C,C,G);R_A(t,H);ADD(G,G,t);t=MAJ(H,A,B);ADD(G,G,t);"
		"R_E(t,C);ADD(F,F,t);t=bs(E,D,C);ADD(F,F,t);ADD_CONST(F,F,0x243185BE,0x4EE4B28C) ;ADD(B,B,F);R_A(t,G);ADD(F,F,t);t=MAJ(G,H,A);ADD(F,F,t);"
		"R_E(t,B);ADD(E,E,t);t=bs(D,C,B);ADD(E,E,t);ADD_CONST(E,E,0x550C7DC3,0xD5FFB4E2) ;ADD(A,A,E);R_A(t,F);ADD(E,E,t);t=MAJ(F,G,H);ADD(E,E,t);"
		"R_E(t,A);ADD(D,D,t);t=bs(C,B,A);ADD(D,D,t);ADD_CONST(D,D,0x72BE5D74,0xF27B896F) ;ADD(H,H,D);R_A(t,E);ADD(D,D,t);t=MAJ(E,F,G);ADD(D,D,t);"
		"R_E(t,H);ADD(C,C,t);t=bs(B,A,H);ADD(C,C,t);ADD_CONST(C,C,0x80DEB1FE,0x3B1696B1) ;ADD(G,G,C);R_A(t,D);ADD(C,C,t);t=MAJ(D,E,F);ADD(C,C,t);"
		"R_E(t,G);ADD(B,B,t);t=bs(A,H,G);ADD(B,B,t);ADD_CONST(B,B,0x9BDC06A7,0x25C71235) ;ADD(F,F,B);R_A(t,C);ADD(B,B,t);t=MAJ(C,D,E);ADD(B,B,t);"
		"R_E(t,F);ADD(A,A,t);t=bs(H,G,F);ADD(A,A,t);ADD_CONST(A,A,%uu,%uu);ADD(E,E,A);R_A(t,B);ADD(A,A,t);t=MAJ(B,C,D);ADD(A,A,t);"
		, (uint32_t)(_w15>>32), (uint32_t)_w15);

	_w15 = (uint64_t)(key_lenght << 3);
	uint64_t _r0_w15 = (uint64_t)(R0(key_lenght << 3));
	sprintf(source + strlen(source),
	"W0.s0=W1_R0.s0;"
	"W0.s1+=W1_R0.s1;"

	"W1=W1_2;"
	"R1(t,W0);ADD(W2,W2_2,t);"
	"W3=W3_2;"
	"R1(W4,W2);"
	"W5=W5_2;"
	"R1(W6,W4);ADD_CONST(W6,W6,%uu,%uu);"
	"ADD(W7,W5_R1,W0);"

	"R1(W8,W6);ADD(W8,W8,W1);"
	"R1(W9,W7);ADD(W9,W9,W2);"
	"R1(W10,W8);ADD(W10,W10,W3);"
	"R1(W11,W9);ADD(W11,W11,W4);"
	"R1(W12,W10);ADD(W12,W12,W5);"
	"R1(W13,W11);ADD(W13,W13,W6);"
	"R1(W14,W12);ADD(W14,W14,W7);ADD_CONST(W14,W14,%uu,%uu);"
	"R1(W15,W13);ADD(W15,W15,W8);ADD_CONST(W15,W15,%uu,%uu);R0(t,W0);ADD(W15,W15,t);"
	, (uint32_t)(_w15>>32), (uint32_t)_w15
	, (uint32_t)(_r0_w15>>32), (uint32_t)_r0_w15
	, (uint32_t)(_w15>>32), (uint32_t)_w15);

	/* Round 2 */
	sprintf(source + strlen(source),
		"STEP(H,E,G,F,0xE49B69C1,0x9EF14AD2,W0,D,A,B,C);"
		"STEP(G,D,F,E,0xEFBE4786,0x384F25E3,W1,C,H,A,B);"
		"STEP(F,C,E,D,0x0FC19DC6,0x8B8CD5B5,W2,B,G,H,A);"
		"STEP(E,B,D,C,0x240CA1CC,0x77AC9C65,W3,A,F,G,H);"
		"STEP(D,A,C,B,0x2DE92C6F,0x592B0275,W4,H,E,F,G);"
		"STEP(C,H,B,A,0x4A7484AA,0x6EA6E483,W5,G,D,E,F);"
		"STEP(B,G,A,H,0x5CB0A9DC,0xBD41FBD4,W6,F,C,D,E);"
		"STEP(A,F,H,G,0x76F988DA,0x831153B5,W7,E,B,C,D);"
		"STEP(H,E,G,F,0x983E5152,0xEE66DFAB,W8,D,A,B,C);"
		"STEP(G,D,F,E,0xA831C66D,0x2DB43210,W9,C,H,A,B);"
		"STEP(F,C,E,D,0xB00327C8,0x98FB213F,W10,B,G,H,A);"
		"STEP(E,B,D,C,0xBF597FC7,0xBEEF0EE4,W11,A,F,G,H);"
		"STEP(D,A,C,B,0xC6E00BF3,0x3DA88FC2,W12,H,E,F,G);"
		"STEP(C,H,B,A,0xD5A79147,0x930AA725,W13,G,D,E,F);"
		"STEP(B,G,A,H,0x06CA6351,0xE003826F,W14,F,C,D,E);"
		"STEP(A,F,H,G,0x14292967,0x0A0E6E70,W15,E,B,C,D);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"WR(W0,W14,W9,W1);STEP(H,E,G,F,0x27B70A85,0x46D22FFC,W0,D,A,B,C);"
		"WR(W1,W15,W10,W2);STEP(G,D,F,E,0x2E1B2138,0x5C26C926,W1,C,H,A,B);"
		"WR(W2,W0,W11,W3);STEP(F,C,E,D,0x4D2C6DFC,0x5AC42AED,W2,B,G,H,A);"
		"WR(W3,W1,W12,W4);STEP(E,B,D,C,0x53380D13,0x9D95B3DF,W3,A,F,G,H);"
		"WR(W4,W2,W13,W5);STEP(D,A,C,B,0x650A7354,0x8BAF63DE,W4,H,E,F,G);"
		"WR(W5,W3,W14,W6);STEP(C,H,B,A,0x766A0ABB,0x3C77B2A8,W5,G,D,E,F);"
		"WR(W6,W4,W15,W7);STEP(B,G,A,H,0x81C2C92E,0x47EDAEE6,W6,F,C,D,E);"
		"WR(W7,W5,W0,W8);STEP(A,F,H,G,0x92722C85,0x1482353B,W7,E,B,C,D);"
		"WR(W8,W6,W1,W9);STEP(H,E,G,F,0xA2BFE8A1,0x4CF10364,W8,D,A,B,C);"
		"WR(W9,W7,W2,W10);STEP(G,D,F,E,0xA81A664B,0xBC423001,W9,C,H,A,B);"
		"WR(W10,W8,W3,W11);STEP(F,C,E,D,0xC24B8B70,0xD0F89791,W10,B,G,H,A);"
		"WR(W11,W9,W4,W12);STEP(E,B,D,C,0xC76C51A3,0x0654BE30,W11,A,F,G,H);"
		"WR(W12,W10,W5,W13);STEP(D,A,C,B,0xD192E819,0xD6EF5218,W12,H,E,F,G);"
		"WR(W13,W11,W6,W14);STEP(C,H,B,A,0xD6990624,0x5565A910,W13,G,D,E,F);"
		"WR(W14,W12,W7,W15);STEP(B,G,A,H,0xF40E3585,0x5771202A,W14,F,C,D,E);"
		"WR(W15,W13,W8,W0);STEP(A,F,H,G,0x106AA070,0x32BBD1B8,W15,E,B,C,D);");
	
	/* Round 4 */
	sprintf(source + strlen(source),
		"WR(W0,W14,W9,W1);STEP(H,E,G,F,0x19A4C116,0xB8D2D0C8,W0,D,A,B,C);"
		"WR(W1,W15,W10,W2);STEP(G,D,F,E,0x1E376C08,0x5141AB53,W1,C,H,A,B);"
		"WR(W2,W0,W11,W3);STEP(F,C,E,D,0x2748774C,0xDF8EEB99,W2,B,G,H,A);"
		"WR(W3,W1,W12,W4);STEP(E,B,D,C,0x34B0BCB5,0xE19B48A8,W3,A,F,G,H);"
		"WR(W4,W2,W13,W5);STEP(D,A,C,B,0x391C0CB3,0xC5C95A63,W4,H,E,F,G);"
		"WR(W5,W3,W14,W6);STEP(C,H,B,A,0x4ED8AA4A,0xE3418ACB,W5,G,D,E,F);"
		"WR(W6,W4,W15,W7);STEP(B,G,A,H,0x5B9CCA4F,0x7763E373,W6,F,C,D,E);"
		"WR(W7,W5,W0,W8);STEP(A,F,H,G,0x682E6FF3,0xD6B2B8A3,W7,E,B,C,D);"
		"WR(W8,W6,W1,W9);STEP(H,E,G,F,0x748F82EE,0x5DEFB2FC,W8,D,A,B,C);"
		"WR(W9,W7,W2,W10);STEP(G,D,F,E,0x78A5636F,0x43172F60,W9,C,H,A,B);"
		"WR(W10,W8,W3,W11);STEP(F,C,E,D,0x84C87814,0xA1F0AB72,W10,B,G,H,A);"
		"WR(W11,W9,W4,W12);STEP(E,B,D,C,0x8CC70208,0x1A6439EC,W11,A,F,G,H);"
		"WR(W12,W10,W5,W13);STEP(D,A,C,B,0x90BEFFFA,0x23631E28,W12,H,E,F,G);"
		"WR(W13,W11,W6,W14);STEP(C,H,B,A,0xA4506CEB,0xDE82BDE9,W13,G,D,E,F);"
		"WR(W14,W12,W7,W15);STEP(B,G,A,H,0xBEF9A3F7,0xB2C67915,W14,F,C,D,E);"
		"WR(W15,W13,W8,W0);STEP(A,F,H,G,0xC67178F2,0xE372532B,W15,E,B,C,D);");
			

	/* Round 5 */									   													  
	sprintf(source + strlen(source),
		"WR(W0,W14,W9,W1);STEP(H,E,G,F,0xCA273ECE,0xEA26619C,W0,D,A,B,C);"
		"WR(W1,W15,W10,W2);STEP(G,D,F,E,0xD186B8C7,0x21C0C207,W1,C,H,A,B);"
		"WR(W2,W0,W11,W3);STEP(F,C,E,D,0xEADA7DD6,0xCDE0EB1E,W2,B,G,H,A);"
		"WR(W3,W1,W12,W4);STEP(E,B,D,C,0xF57D4F7F,0xEE6ED178,W3,A,F,G,H);"
		"WR(W4,W2,W13,W5);STEP(D,A,C,B,0x06F067AA,0x72176FBA,W4,H,E,F,G);"
		"WR(W5,W3,W14,W6);STEP(C,H,B,A,0x0A637DC5,0xA2C898A6,W5,G,D,E,F);"
		"WR(W6,W4,W15,W7);STEP(B,G,A,H,0x113F9804,0xBEF90DAE,W6,F,C,D,E);"
		"WR(W7,W5,W0,W8);STEP(A,F,H,G,0x1B710B35,0x131C471B,W7,E,B,C,D);"
		"WR(W8,W6,W1,W9);"
		"WR(W9,W7,W2,W10);"
		"R1(W2,W9);ADD(W2,W2,W11);ADD(W2,W2,W4);R0(t,W12);ADD(W2,W2,t);"
		"R1(W1,W2);ADD(W1,W1,W13);ADD(W1,W1,W6);R0(t,W14);ADD(W1,W1,t);"
		"R0(t,W0);W0=t;R1(t,W1);ADD(W0,W0,t);ADD(W0,W0,W15);ADD(W0,W0,W8);ADD(A,A,W0);");

	// Find match
	if (num_passwords_loaded == 1)
	{
		uint64_t* bin = (uint64_t*)binary_values;
		sprintf(source + strlen(source),
				"if(A.s0==%uu&&A.s1==%uu)"
				"{"
					"SUB(A,A,W0);"
					"WR(W10,W8,W3,W11);"
					"WR(W12,W10,W5,W13);"
					"WR(W14,W12,W7,W15);"
					
					    "STEP(H,E,G,F,0x28DB77F5,0x23047D84,W8,D,A,B,C);"
					    "STEP(G,D,F,E,0x32CAAB7B,0x40C72493,W9,C,H,A,B);"
					"STEP_1ST(F,C,E,D,0x3C9EBE0A,0x15C9BEBC,W10,B);t=MAJ(G,H,A);ADD(F,F,t);"
					"STEP_1ST(E,B,D,C,0x431D67C4,0x9C100D4C,W2,A);"
					"STEP_1ST(D,A,C,B,0x4CC5D4BE,0xCB3E42B6,W12,H);"
					"STEP_1ST(C,H,B,A,0x597F299C,0xFC657E2A,W1,G);"
					"ADD(B,B,W14);t=bs(A,H,G);ADD(B,B,t);"
					
					"if(B.s0==%uu&&B.s1==%uu&&C.s0==%uu&&C.s1==%uu&&D.s0==%uu&&D.s1==%uu&&"
					   "E.s0==%uu&&E.s1==%uu&&F.s0==%uu&&F.s1==%uu&&G.s0==%uu&&G.s1==%uu&&H.s0==%uu&&H.s1==%uu)"
					"{"
						"output[0]=1u;"
						"output[1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
						"output[2]=0;"
					"}"
				"}"
				, (uint32_t)(bin[0]), (uint32_t)(bin[0]>>32)
				, (uint32_t)(bin[1]), (uint32_t)(bin[1]>>32)
				, (uint32_t)(bin[2]), (uint32_t)(bin[2]>>32)
				, (uint32_t)(bin[3]), (uint32_t)(bin[3]>>32)
				, (uint32_t)(bin[4]), (uint32_t)(bin[4]>>32)
				, (uint32_t)(bin[5]), (uint32_t)(bin[5]>>32)
				, (uint32_t)(bin[6]), (uint32_t)(bin[6]>>32)
				, (uint32_t)(bin[7]), (uint32_t)(bin[7]>>32));
	}
	else
	{
		// Find match
		sprintf(source + strlen(source), "uint xx=A.s0&%uu;uint fdata;", cbg_mask);
		
		sprintf(source + strlen(source),
			"fdata=(uint)(cbg_filter[xx]);"

			"if(((fdata^A.s1)&0xFFF8)==0){"
				"indx=cbg_table[xx];"
				"if(indx!=0xffffffff&&A.s0==binary_values[indx*16u]&&A.s1==binary_values[indx*16u+1u]){"

					"uint2 aa,ww14;"
					"SUB(aa,A,W0);"
					"ADD(W4,W10,W3);R1(t,W8);ADD(W4,W4,t);R0(t,W11);ADD(W4,W4,t);"
					"ADD(W6,W12,W5);R1(t,W4);ADD(W6,W6,t);R0(t,W13);ADD(W6,W6,t);"
					"ADD(ww14,W14,W7);R1(t,W6);ADD(ww14,ww14,t);R0(t,W15);ADD(ww14,ww14,t);"

					"uint2 bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

					"STEP(hh,ee,gg,ff,0x28DB77F5,0x23047D84,W8,dd,aa,bb,cc);"
					"STEP(gg,dd,ff,ee,0x32CAAB7B,0x40C72493,W9,cc,hh,aa,bb);"
					"STEP_1ST(ff,cc,ee,dd,0x3C9EBE0A,0x15C9BEBC,W4,bb);t=MAJ(gg,hh,aa);ADD(ff,ff,t);"
					"STEP_1ST(ee,bb,dd,cc,0x431D67C4,0x9C100D4C,W2,aa);"
					"STEP_1ST(dd,aa,cc,bb,0x4CC5D4BE,0xCB3E42B6,W6,hh);"
					"STEP_1ST(cc,hh,bb,aa,0x597F299C,0xFC657E2A,W1,gg);"
					"ADD(bb,bb,ww14);t=bs(aa,hh,gg);ADD(bb,bb,t);"

					"if(bb.s0==binary_values[indx*16u+2u]&&bb.s1==binary_values[indx*16u+3u]&&cc.s0==binary_values[indx*16u+4u]&&cc.s1==binary_values[indx*16u+5u]&&"
					"dd.s0==binary_values[indx*16u+6u]&&dd.s1==binary_values[indx*16u+7u]&&ee.s0==binary_values[indx*16u+8u]&&ee.s1==binary_values[indx*16u+9u]&&"
					"ff.s0==binary_values[indx*16u+10u]&&ff.s1==binary_values[indx*16u+11u]&&gg.s0==binary_values[indx*16u+12u]&&gg.s1==binary_values[indx*16u+13u]&&"
					"hh.s0==binary_values[indx*16u+14u]&&hh.s1==binary_values[indx*16u+15u]){"
						"uint found=atomic_inc(output);"
						"if(found<%uu){"
							"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
							"output[2*found+2]=indx;}"
					"}"
				"}"
			"}", output_size);
				
		sprintf(source + strlen(source),
			"if(fdata&4){"// Is second
				"xx+=fdata&1?-1:1;"
				"if(((((uint)cbg_filter[xx])^A.s1)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&A.s0==binary_values[indx*16u]&&A.s1==binary_values[indx*16u+1u]){"

						"uint2 aa,ww14;"
						"SUB(aa,A,W0);"
						"ADD(W4,W10,W3);R1(t,W8);ADD(W4,W4,t);R0(t,W11);ADD(W4,W4,t);"
						"ADD(W6,W12,W5);R1(t,W4);ADD(W6,W6,t);R0(t,W13);ADD(W6,W6,t);"
						"ADD(ww14,W14,W7);R1(t,W6);ADD(ww14,ww14,t);R0(t,W15);ADD(ww14,ww14,t);"

						"uint2 bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"STEP(hh,ee,gg,ff,0x28DB77F5,0x23047D84,W8,dd,aa,bb,cc);"
						"STEP(gg,dd,ff,ee,0x32CAAB7B,0x40C72493,W9,cc,hh,aa,bb);"
						"STEP_1ST(ff,cc,ee,dd,0x3C9EBE0A,0x15C9BEBC,W4,bb);t=MAJ(gg,hh,aa);ADD(ff,ff,t);"
						"STEP_1ST(ee,bb,dd,cc,0x431D67C4,0x9C100D4C,W2,aa);"
						"STEP_1ST(dd,aa,cc,bb,0x4CC5D4BE,0xCB3E42B6,W6,hh);"
						"STEP_1ST(cc,hh,bb,aa,0x597F299C,0xFC657E2A,W1,gg);"
						"ADD(bb,bb,ww14);t=bs(aa,hh,gg);ADD(bb,bb,t);"

						"if(bb.s0==binary_values[indx*16u+2u]&&bb.s1==binary_values[indx*16u+3u]&&cc.s0==binary_values[indx*16u+4u]&&cc.s1==binary_values[indx*16u+5u]&&"
						"dd.s0==binary_values[indx*16u+6u]&&dd.s1==binary_values[indx*16u+7u]&&ee.s0==binary_values[indx*16u+8u]&&ee.s1==binary_values[indx*16u+9u]&&"
						"ff.s0==binary_values[indx*16u+10u]&&ff.s1==binary_values[indx*16u+11u]&&gg.s0==binary_values[indx*16u+12u]&&gg.s1==binary_values[indx*16u+13u]&&"
						"hh.s0==binary_values[indx*16u+14u]&&hh.s1==binary_values[indx*16u+15u]){"
							"uint found=atomic_inc(output);"
							"if(found<%uu){"
								"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
								"output[2*found+2]=indx;}"
						"}"
					"}"
				"}"
			"}", output_size);

		sprintf(source + strlen(source),
			"if(fdata&2){"// Is unlucky
				"xx=A.s1&%uu;"
				"fdata=(uint)(cbg_filter[xx]);"
				"if(((fdata^A.s0)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&A.s0==binary_values[indx*16u]&&A.s1==binary_values[indx*16u+1u]){"

						"uint2 aa,ww14;"
						"SUB(aa,A,W0);"
						"ADD(W4,W10,W3);R1(t,W8);ADD(W4,W4,t);R0(t,W11);ADD(W4,W4,t);"
						"ADD(W6,W12,W5);R1(t,W4);ADD(W6,W6,t);R0(t,W13);ADD(W6,W6,t);"
						"ADD(ww14,W14,W7);R1(t,W6);ADD(ww14,ww14,t);R0(t,W15);ADD(ww14,ww14,t);"

						"uint2 bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"STEP(hh,ee,gg,ff,0x28DB77F5,0x23047D84,W8,dd,aa,bb,cc);"
						"STEP(gg,dd,ff,ee,0x32CAAB7B,0x40C72493,W9,cc,hh,aa,bb);"
						"STEP_1ST(ff,cc,ee,dd,0x3C9EBE0A,0x15C9BEBC,W4,bb);t=MAJ(gg,hh,aa);ADD(ff,ff,t);"
						"STEP_1ST(ee,bb,dd,cc,0x431D67C4,0x9C100D4C,W2,aa);"
						"STEP_1ST(dd,aa,cc,bb,0x4CC5D4BE,0xCB3E42B6,W6,hh);"
						"STEP_1ST(cc,hh,bb,aa,0x597F299C,0xFC657E2A,W1,gg);"
						"ADD(bb,bb,ww14);t=bs(aa,hh,gg);ADD(bb,bb,t);"

						"if(bb.s0==binary_values[indx*16u+2u]&&bb.s1==binary_values[indx*16u+3u]&&cc.s0==binary_values[indx*16u+4u]&&cc.s1==binary_values[indx*16u+5u]&&"
						"dd.s0==binary_values[indx*16u+6u]&&dd.s1==binary_values[indx*16u+7u]&&ee.s0==binary_values[indx*16u+8u]&&ee.s1==binary_values[indx*16u+9u]&&"
						"ff.s0==binary_values[indx*16u+10u]&&ff.s1==binary_values[indx*16u+11u]&&gg.s0==binary_values[indx*16u+12u]&&gg.s1==binary_values[indx*16u+13u]&&"
						"hh.s0==binary_values[indx*16u+14u]&&hh.s1==binary_values[indx*16u+15u]){"
							"uint found=atomic_inc(output);"
							"if(found<%uu){"
								"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
								"output[2*found+2]=indx;}"
						"}"
					"}"
				"}"
			, cbg_mask, output_size);

		sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx])^A.s0)&0xFFF8)==0){"
						"indx=cbg_table[xx];"
						"if(indx!=0xffffffff&&A.s0==binary_values[indx*16u]&&A.s1==binary_values[indx*16u+1u]){"

							"uint2 aa,ww14;"
							"SUB(aa,A,W0);"
							"ADD(W4,W10,W3);R1(t,W8);ADD(W4,W4,t);R0(t,W11);ADD(W4,W4,t);"
							"ADD(W6,W12,W5);R1(t,W4);ADD(W6,W6,t);R0(t,W13);ADD(W6,W6,t);"
							"ADD(ww14,W14,W7);R1(t,W6);ADD(ww14,ww14,t);R0(t,W15);ADD(ww14,ww14,t);"

							"uint2 bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

							"STEP(hh,ee,gg,ff,0x28DB77F5,0x23047D84,W8,dd,aa,bb,cc);"
							"STEP(gg,dd,ff,ee,0x32CAAB7B,0x40C72493,W9,cc,hh,aa,bb);"
							"STEP_1ST(ff,cc,ee,dd,0x3C9EBE0A,0x15C9BEBC,W4,bb);t=MAJ(gg,hh,aa);ADD(ff,ff,t);"
							"STEP_1ST(ee,bb,dd,cc,0x431D67C4,0x9C100D4C,W2,aa);"
							"STEP_1ST(dd,aa,cc,bb,0x4CC5D4BE,0xCB3E42B6,W6,hh);"
							"STEP_1ST(cc,hh,bb,aa,0x597F299C,0xFC657E2A,W1,gg);"
							"ADD(bb,bb,ww14);t=bs(aa,hh,gg);ADD(bb,bb,t);"

							"if(bb.s0==binary_values[indx*16u+2u]&&bb.s1==binary_values[indx*16u+3u]&&cc.s0==binary_values[indx*16u+4u]&&cc.s1==binary_values[indx*16u+5u]&&"
							"dd.s0==binary_values[indx*16u+6u]&&dd.s1==binary_values[indx*16u+7u]&&ee.s0==binary_values[indx*16u+8u]&&ee.s1==binary_values[indx*16u+9u]&&"
							"ff.s0==binary_values[indx*16u+10u]&&ff.s1==binary_values[indx*16u+11u]&&gg.s0==binary_values[indx*16u+12u]&&gg.s1==binary_values[indx*16u+13u]&&"
							"hh.s0==binary_values[indx*16u+14u]&&hh.s1==binary_values[indx*16u+15u]){"
								"uint found=atomic_inc(output);"
								"if(found<%uu){"
									"output[2*found+1]=get_global_id(0)*NUM_CHAR_IN_CHARSET+i;"
									"output[2*found+2]=indx;}"
							"}"
						"}"
					"}"
				"}"
			"}", output_size);
	}

	strcat(source, "}}");
}

PRIVATE uint64_t sha512_one_char[8*256]={
0x223d53d81eff894eULL, 0xd6112b752c3d107bULL, 0x4fd7d74b5d5313e6ULL, 0xbecf91646acc7f73ULL, 0x117fa3a0a0e85dd9ULL, 0xefd22d262184320cULL, 0x2b0049882a16177aULL, 0x67a36bd7cfeaef75ULL,
0x13ac687ec401942dULL, 0xc8624a162926f995ULL, 0x5d5a0f309a38ab69ULL, 0x2856d47bb8c50a0bULL, 0x47ed7c289feaea30ULL, 0xa732b76f5e1a5484ULL, 0x14c0e23bd48dd255ULL, 0x4e3e16ad235bc1c0ULL,
0xa51250c0deca4720ULL, 0x50c0b665b35d8907ULL, 0x3f3b8f7a9d6d8ee0ULL, 0x8c8b06d094397cc5ULL, 0x04adbe6985e37d02ULL, 0xbeaecd0003647adeULL, 0xc7307ad92c1f39caULL, 0xcdee34b17bebbb51ULL,
0x9e0cd8e29393641aULL, 0x3a868277daf002d2ULL, 0xf8bd456927ecf8bfULL, 0x3eb84a8f9663f206ULL, 0x7bae83a848ddc96bULL, 0x93195e5a000597ffULL, 0x66c3afe78e1ccdb9ULL, 0x8a313431a728988bULL,
0x3bd863527eb27629ULL, 0x9f837a23a8f5efb1ULL, 0xf1721d00d00e6e9cULL, 0x4f3210b20947cb14ULL, 0xf53b715f6521576bULL, 0x92a17dde00e3b097ULL, 0x614e6e2189a3bcbfULL, 0x8658e1aff9af36f0ULL,
0x348fabd27a134d68ULL, 0xa35cfcb5f4d6d79cULL, 0x4aacee2ff8b4ba76ULL, 0x39786aa695da2f9bULL, 0xe9575973826710a4ULL, 0x53d0227e667ec5ecULL, 0xce37a4b42e475ef4ULL, 0xa134b10f2b3d206cULL,
0x782eeff4a43370cdULL, 0x4c8e1a2aff7eda15ULL, 0xb51c74f28d0f84b6ULL, 0x7170056abd5cb12aULL, 0xb024ce1db247f57fULL, 0x8caf12b992ca7012ULL, 0x8ea065bdba0e0c05ULL, 0x60c2a5476d7673bcULL,
0xa27889958af772e6ULL, 0x11a70a030770f6c2ULL, 0x7f6e70c5d7f13803ULL, 0xba4d078ba99d642fULL, 0x801cbf82a8d9249cULL, 0xf2cea9d37207ed15ULL, 0x15a1118380d4ed4eULL, 0x620075d5130d304dULL,
0x4b57203ae9ad95b8ULL, 0x47659f35e9ac7985ULL, 0x45ed0aa66ea633e8ULL, 0x50e32b20bf46612eULL, 0x4834fd91e0bdd527ULL, 0x54f806a304f4160eULL, 0x08296fad83df5f8dULL, 0x42668ceeb5830fb2ULL,
0x457b1ac8a961af68ULL, 0x43bff6bae1422d43ULL, 0xabc4639790c495a9ULL, 0x33985db9e7f05c9dULL, 0x2cb622bb7e0fed01ULL, 0x792cb73e1a001965ULL, 0x249952a98b739030ULL, 0x3dbc27a465902addULL,
0xf3b6c8584c878a40ULL, 0x72ef0b2a554db8fdULL, 0x5e57c678b72f4bd0ULL, 0x682468e9768623b3ULL, 0x5dfb5a5b111694c9ULL, 0x867ed8d84a69fb64ULL, 0x68c6cfd04438762fULL, 0x32ef685ebbf69c90ULL,
0xe479f33b6104d542ULL, 0x83dcb289743e99fbULL, 0x2d01dcfba997400aULL, 0x9176fa56d76d1f2fULL, 0xd584cf5bd17963e8ULL, 0xdb60366e682c7b7eULL, 0xc3cdc721d9509d7aULL, 0x16a8c625d8a19fdaULL,
0x1876c814a3a255cbULL, 0xba24d57651c9b00aULL, 0x008566a5abc7cac9ULL, 0xf9420aaccafde61dULL, 0x48bc531d3bcb11a3ULL, 0x571f969ce7c44886ULL, 0x95ccd1edde1e7703ULL, 0x14a46d4370215c40ULL,
0xe59b24058b7f0f1aULL, 0xe26f1e1e1fcbf859ULL, 0x4446de4d3ea855daULL, 0x73b7f8fef916b726ULL, 0xec14577abf9df7ebULL, 0x766ae8036ad34725ULL, 0xe4b405baecb7569bULL, 0xb6489c179109f9b3ULL,
0x4265f44f29aed196ULL, 0xb76cf876b421575bULL, 0xa7e7302701991768ULL, 0x547df876269982c1ULL, 0x66e3d894e3316c8bULL, 0x72e273d0bfa6e4b6ULL, 0x63b5a1deb9d9a820ULL, 0xa52bfb57417af475ULL,
0xf8651be27d55ca98ULL, 0x8ba01d5721340098ULL, 0xb0841cdec8e29c87ULL, 0xfdb7f72305c3a3a0ULL, 0x163d2c7616c9726dULL, 0x2639632b65a9dae3ULL, 0x6ba514a16a8fa103ULL, 0xf1fcc89d12a277eaULL,
0x6afc926d7f8e95a0ULL, 0x273ac045cf527b82ULL, 0xabe1e00fd57f6a88ULL, 0xd7624b05fdcfbb7dULL, 0x660d4e10dd335ed3ULL, 0x019c928a90da66a8ULL, 0xb0f53ed2538afbf7ULL, 0x85499253037808b5ULL,
0xe8d53c8aeb53d2f0ULL, 0x605cbf4afada9ad3ULL, 0xde2f41aabf35a1f2ULL, 0x7d48b988bc0682b6ULL, 0x2b2c5052b1b6c827ULL, 0x980369f09dcd10b9ULL, 0x6d76b3148a381de9ULL, 0xccf1d8c308de7beaULL,
0x7cea9473851f838cULL, 0xaacb08c7ae0dca4dULL, 0x0102b09de12be59bULL, 0x4af4b67b362f08a6ULL, 0xbec7d0f3b36e1a5dULL, 0xcf1d257356020334ULL, 0xdc9a7e45dfdf615dULL, 0x855f9ff4a5458b6dULL,
0xcca7b97d53268948ULL, 0x2f7dd41a0ef4ecdfULL, 0x379cec5a5d5b72f0ULL, 0x6b31953bd33d403dULL, 0x2667c63594a7fc2cULL, 0x19336bfcc5efd8c1ULL, 0xe1041e183dcabbbaULL, 0x74f9a3c95dd72f3cULL,
0x17af445ee60adafeULL, 0x2740b0608ae4e9c6ULL, 0x648207c9bd5730dcULL, 0x6c24b8f433df8d33ULL, 0xc38d7310a509c142ULL, 0x9c059aad34b6078fULL, 0x5c67f5d1f8300a8dULL, 0xdae6707f8441b7a7ULL,
0x0bb9a05187da7491ULL, 0xa4b0ce59f600367fULL, 0xe4fda7de8747b71cULL, 0x9b4580ddfe52ae1dULL, 0xf4fff5743526f43cULL, 0xe51b7f04a86c7296ULL, 0xd7b50f6807de8167ULL, 0x64500001cffe9602ULL,
0xc1cd743612ea3e54ULL, 0x01b032b8103aa2b6ULL, 0xef9f5227cd1b54acULL, 0x0bed5533ae5b35c1ULL, 0xe180e04ef17a0627ULL, 0xf22767ccbfdfa248ULL, 0x1b90aeda0cc707e2ULL, 0xa9e71ddb4aeec868ULL,
0xc182d33b84cafe01ULL, 0xd77bb847e79493e8ULL, 0xc5cfd4f2b1bb2733ULL, 0x8c280e90a8631b42ULL, 0x94dc54c534e69ed7ULL, 0xa633c296cf9a1fb0ULL, 0x4de50fad9084ff08ULL, 0xb27b38f6f9570e94ULL,
0x88262c2bca4fbe22ULL, 0x2b4fc1a402a209daULL, 0x500282e4c7105af2ULL, 0x63ac152ca24acc1bULL, 0x3ee5e118f3f15a7aULL, 0xf24f863a442603bdULL, 0xd6c275a09a4d1a86ULL, 0xc725bd12fed510cfULL,
0x7cd5b64f5445a2a2ULL, 0x1df7b7e2d7c73d28ULL, 0xadff50e37369a6c9ULL, 0x50c95397763d059bULL, 0x75a5aafcbc315645ULL, 0xbbcc0db2abb969aeULL, 0x1abe063d6d2529ffULL, 0x348f3e8b4dd4a902ULL,
0x5a424744a3919e01ULL, 0xa25ec7ac847e49e6ULL, 0xac417d9d77ea532bULL, 0xee82b7aefcf09bfeULL, 0xf7a15a8fcfab7af1ULL, 0x3224b6e627c01ed5ULL, 0xa9c2891c6cd5bd9fULL, 0x77b90d9a6a539adaULL,
0xcd5379b3ca72a5b9ULL, 0x77e70be60e930218ULL, 0xa072714aa02618c8ULL, 0x7639abca18160b00ULL, 0x41fa6a1b21345658ULL, 0xab9a2fb35f198671ULL, 0x046bbeeac0bf8fdaULL, 0x42cc661a5e07ffd1ULL,
0x12a91763cb3791f6ULL, 0x1438519e396473daULL, 0x8e6e9de75edd10cdULL, 0x0d3d0dfd25c60610ULL, 0xb2c6889d6416c6a4ULL, 0x2c3f0723a66ef61dULL, 0xf6d231a0f4ab4f2fULL, 0x584a125567c8989bULL,
0x9ccc28f13e6e1365ULL, 0xeef26c4a9b514261ULL, 0x7fcdcf4d78d26832ULL, 0xb7a90e25a7d3df8cULL, 0xe76c9c33f3f2d77eULL, 0xf6edce08d50fb0ebULL, 0x38b588013b5c3b73ULL, 0xbfec570c842d9fafULL,
0xec265f0731f5a857ULL, 0xd7f36713ba935411ULL, 0xb89a6c466c18d138ULL, 0x0d3185b03c1ea8e7ULL, 0x541dc1e76ada1536ULL, 0x0f8d20157dde1131ULL, 0x0ef8b94f0931d752ULL, 0x884b79591edd9b6bULL,
0x7c96d62c02c5d15bULL, 0x9efc0211c66c402fULL, 0x07973b487b142e2fULL, 0x2a72f118c52900acULL, 0x6e83294f5a55e7cdULL, 0xaa4d275a24325a53ULL, 0xe8de9e3fee124ef0ULL, 0xc76a8c320a70bd65ULL,
0xea19faa8b25a1ef3ULL, 0x31a33506ffb74111ULL, 0xe42a79555177cc65ULL, 0xf7abec8d011e334bULL, 0xdf8a6110419a36ceULL, 0xf2f9d6d450401eb8ULL, 0xd89bb28ecdf7d98bULL, 0xf78e221fd265e5efULL,
0xb5193ba599cea3b9ULL, 0xf9a3e55417e4d53dULL, 0x2c972ca503a69e7cULL, 0x31287e50ffa8997bULL, 0xb14089b3b98116ecULL, 0xd07aa69292605986ULL, 0xa97e2fa0579c750dULL, 0x9779a8d2aee0e7c1ULL,
0x753fb2316ce004f3ULL, 0xd9ed8fa14de637b9ULL, 0x1b952b83545d3027ULL, 0x07edff816d90b1f4ULL, 0x4885488aa5ace0b8ULL, 0xcbc2c968fdefad92ULL, 0x5a8a6c9413cf4608ULL, 0x7ae15f2bcdff6760ULL,
0x7cf7f0959f868b15ULL, 0x10f1cf01f3980211ULL, 0x5223ae66eb8719ebULL, 0xa904979fefe8e344ULL, 0xe6a93e0b457053d1ULL, 0x5b08f458eda56558ULL, 0x7a504a8e8607f882ULL, 0x89ed506ff7de50bdULL,
0x36550c526c60809bULL, 0xa1eb5b54fdc159f2ULL, 0xbdcba501a75da25eULL, 0xbe47b272031b92e1ULL, 0x8309f1c1b7931f52ULL, 0xad2373d04b01a09aULL, 0x389d4392ac861fbbULL, 0xd5b534e4cd9ba23bULL,
0xef72ba936aac93b9ULL, 0x2c37ae45e29b2257ULL, 0x6ef3b27b2331af97ULL, 0x27690042de86839bULL, 0x2a2c9ff3493936aaULL, 0x0de4e4248944dfbbULL, 0x1bc6a2d08043e625ULL, 0xccfd88939baf6699ULL,
0x5bff58877938ca1dULL, 0xb8f68d6ec74bac6fULL, 0x25c65dd1e8aefa9aULL, 0x2c5cf793beb6be25ULL, 0x55ac90a7c63432eaULL, 0xa0acc15340a969e6ULL, 0x40416071bc9787a8ULL, 0x656628ff6d56f577ULL,
0x88b2551db57fcc59ULL, 0xcd3d8f31594991ceULL, 0x957aa48c776cc96bULL, 0xdc0c665406c969b7ULL, 0x81c5c03f281e6e34ULL, 0xa69f57ea0da38912ULL, 0x9c784320e0a0cb7aULL, 0x55bf69a83be17d0bULL,
0x48b80fb720dd67a1ULL, 0x86b8546a453f208aULL, 0x32e18e81228035fbULL, 0xad9d7e8693884261ULL, 0x80192f2853d9fec3ULL, 0x945ef9d351343844ULL, 0xecfbd0ed275f2fcaULL, 0x72d7cf8330dae828ULL,
0xc0e71e6e7a5826a9ULL, 0xd8452705b14ccba2ULL, 0x30a4b3183cb7fa8cULL, 0x6c7d2d4d1ead7e06ULL, 0x6ce67016219c4758ULL, 0x5091c1663a136953ULL, 0x7d0dfcb948c371a4ULL, 0x1f79d58571bb81cbULL,
0x02ad7154e77af3a3ULL, 0xcfb597e6b25bd678ULL, 0x0534bfc369f97cc0ULL, 0x8730ba51d958247cULL, 0x80f34fccd2b33ea1ULL, 0x926eda9cba0aba23ULL, 0x2b239f20a0771155ULL, 0xe2c6597435158389ULL,
0x82fb320c428a299eULL, 0xc257e939408c25c8ULL, 0x021a8f218324dc6cULL, 0xdcf9fa26f8619341ULL, 0x23376a87561a7b79ULL, 0x520da0b566b1b6d9ULL, 0xc41970938d6557c5ULL, 0x6201fdce29b84f92ULL,
0x5d23116cad36d1b1ULL, 0xe0bdff9dcc52624cULL, 0x60477f05a62bf4f1ULL, 0xf0c4f45fb1da9419ULL, 0xb697876411c9f3b2ULL, 0x7357c4f70265339fULL, 0xb4d7bc5cf274a882ULL, 0x068197f2f93d4a98ULL,
0x75491ed28bb93228ULL, 0x4ec19fd4bb107897ULL, 0x7141123b5701a0dcULL, 0xcdff28a6ff081a6fULL, 0xf63d989ecf69aec0ULL, 0x3e37a81ffe4331f8ULL, 0x4604a827a623223aULL, 0x7b13f9809e944cc4ULL,
0x1c9aace8073b1955ULL, 0x05e7a89cdfbb593bULL, 0x9191069cb4d9ec4bULL, 0x60d0f7b64d6fc7d8ULL, 0xea65feb2a9efb8beULL, 0xdcd9f8e4ac55bf4bULL, 0xb6470e22087a347eULL, 0xf2b29420ed743da8ULL,
0x749bdfdc85b6d593ULL, 0xbb62ccb1d40fc785ULL, 0xa06ce58c4642d026ULL, 0x4c583cdec3f37331ULL, 0xc526887bb54cffe1ULL, 0x8467a9bd35abac83ULL, 0x56ed3669d2504a67ULL, 0xecf483e4d69705d6ULL,
0xb072023a4a9108d6ULL, 0xf3d116fa69a8bf51ULL, 0x8255257007db8107ULL, 0x8e0cbcf4b35464bfULL, 0x83557b5df8eb182eULL, 0x910593d63f565381ULL, 0xd886ff29e33bc5eeULL, 0x74d731c0c8458a20ULL,
0xbf65cd6a086b5486ULL, 0x92d2645ad9f3380dULL, 0xc50469ed9b648c8dULL, 0x5e9a655afa48bc5bULL, 0x011e30bfe4bd34d8ULL, 0x28c5b125582b93d3ULL, 0xc67420110a485537ULL, 0x246271bde6c82f91ULL,
0x604f387b5e86dd2eULL, 0x20b811a4be363bd8ULL, 0x2550e40f2149c7feULL, 0x2c04dbc17aa0003aULL, 0xbb851c61fae1690eULL, 0xd20ebf7ffaddcd14ULL, 0x11c9d639856a4e60ULL, 0x9534e1b18b0f9f9bULL,
0xe4226dd3694d6cd0ULL, 0xb1abf194a6a81484ULL, 0x5afdf0d5de026d9eULL, 0x27a4de68c8e37553ULL, 0xf7357a658d401835ULL, 0xaa45718d0e3b24adULL, 0xa4b799efcb1a90abULL, 0x552b6dddae848d42ULL,
0x12d8ec21635f1981ULL, 0xc5ad3fa83b44f47dULL, 0xc3ac21469e1afca5ULL, 0x31326bb6a040b65fULL, 0x78c1993f5b958f58ULL, 0x111d99e92f01abe0ULL, 0x1d6441bb57452d24ULL, 0x595ce527c4b3a3efULL,
0xb5de1e38316d01dcULL, 0x74f3c744d61ff030ULL, 0x2bd285650804f410ULL, 0xf02d1f58ae06c47cULL, 0x7660eafc58d66c41ULL, 0x4a4139055ef018c7ULL, 0x345b4f49d55bee1bULL, 0x9d4f2e827351fcacULL,
0xa5bf46935fa84128ULL, 0x71c8d25706de7cceULL, 0x012174fabbad882fULL, 0xceea52cf23221abfULL, 0xc5254c1342248429ULL, 0xf4c1cf944ba9544cULL, 0x8b8547cc31228197ULL, 0xacb772e68fda0cc7ULL,
0xd35fe1dfd726abc8ULL, 0x77da2ee490c8b81fULL, 0x4a0604854ca83cf5ULL, 0x7755e878ffffe123ULL, 0xbbdbff78a0220628ULL, 0x3fd8d651fbacd553ULL, 0x66ef9ac4288248beULL, 0x379344545c184808ULL,
0x5da3432c23348c4fULL, 0x96540edd6f1240cbULL, 0x283e53becd91afddULL, 0x90c512b6186c7af9ULL, 0x7dbf87609d425faeULL, 0xb8852c09dae7ce28ULL, 0xafe2095ae997af84ULL, 0xf175366b75ce672bULL,
0x9b9a06f6e388574bULL, 0xe8410f3f61835f31ULL, 0xd30cbf01fbba9af8ULL, 0x726eeff6d552e71eULL, 0x91baf957fa17b9daULL, 0x897439a19ade8c0aULL, 0x0863b9b413d1bd78ULL, 0x36af4bb43910f8ccULL,
0x6aee1bb6920533ebULL, 0xb3c054ed1e77cbebULL, 0x5a58ad068002c7e6ULL, 0x9bdf16fc8829fdb1ULL, 0x847465cf2c16f1afULL, 0x058a9708f4788762ULL, 0xc7d0f0d330ff0412ULL, 0xbc2637d534791196ULL,
0x0eaff4ead66feac9ULL, 0x1c8cb32668e0ea29ULL, 0x5024277b67953fdeULL, 0x09729016379bfd6aULL, 0xa7fb251d2478c722ULL, 0xdf0bf69f0258b74aULL, 0xd0f4b5d1f97bdb93ULL, 0x58502bd5494409a3ULL,
0xe8a385cf1ff2a897ULL, 0x4124724452bc836fULL, 0xd13ebbfe79ff4ed7ULL, 0x34c3f99ff21076a5ULL, 0x1b693b4514833fdcULL, 0x2333b5b9f407df64ULL, 0x8a020fd786a531d2ULL, 0x1c160759112aba90ULL,
0xc2ebbd6f92a41cb5ULL, 0x8e80c4f868d2b615ULL, 0x21c835e01588efbcULL, 0x3a306998b03643a5ULL, 0xa4799ddcca68fcf9ULL, 0x8a3159bdbedfccf2ULL, 0x41bbc9f70635c676ULL, 0x6ed2f0e475e414eaULL,
0x422ddc5c3c856218ULL, 0x33915a7900de57acULL, 0x941857632c6b0feaULL, 0x07bb7c6a1e6e4551ULL, 0xc233a08e266fc118ULL, 0x2f83a19264ee6b0eULL, 0xf1444bbc8b8d1bf6ULL, 0xba48865839df9ebcULL,
0xfa67bb10fc8c348fULL, 0x07da22d002a9554eULL, 0x66e4a67da0c67c0aULL, 0x0c467bb208e89e62ULL, 0xd2b157d3ce17123aULL, 0x15998a3e743ee4ecULL, 0x386c3712f88c2c0bULL, 0xf81e082dfa29b027ULL,
0x55ae6753b03254eaULL, 0x888f267d6322c408ULL, 0xc1f43f87c7e14b6eULL, 0x7686cceba3782174ULL, 0x0e270d7c499e1056ULL, 0xe2dd99bc7269298cULL, 0xb0d78c5ae89243a3ULL, 0x6526d813c46611e0ULL,
0xda005264ee6c6ae9ULL, 0x51dacd4ed4eb8371ULL, 0xbd36395220017b99ULL, 0x702f6c779f3c447aULL, 0x73046224947b1acdULL, 0xdeeff8061e2057b1ULL, 0x11485e7f9283867dULL, 0xec9f4b22e4d8ae7cULL,
0x7432ac9488aed671ULL, 0x88f90fa8030cf5b2ULL, 0x4f023335da662a0bULL, 0xdf7c24c1e3a483daULL, 0xcc512d8786919aaeULL, 0xcad7526b33b7c6eeULL, 0x0f269a4f2f1ce4a2ULL, 0xc7ebb990c57a4896ULL,
0x7820afbd111ccfaaULL, 0xfe3db891bdb6bcbbULL, 0xa4ffb4fe9ff15f51ULL, 0x33642d23dedbca2cULL, 0x3807f03d7f2a77c9ULL, 0x4c1d33f332e7520fULL, 0x3a7632e0307e6a3cULL, 0x5ac393997e4f2c82ULL,
0xed71d171956e1ffaULL, 0xb42f63da1a696cedULL, 0x741e94d2782a3cd3ULL, 0x5d20b8b87590e84eULL, 0xd75bdae2d8a7be23ULL, 0xc39d2a70b33ecc14ULL, 0xd18a2e8fb4274e21ULL, 0x69547af13c70e7b6ULL,
0x4288d8905f99bf41ULL, 0xed0a3eb22967fa60ULL, 0xb4cb3590224519a1ULL, 0xce50e16dae5a8370ULL, 0x912fd15c30af81eaULL, 0x7bba426e5d82532bULL, 0x2fa6357a08e914fcULL, 0x469923ca95479170ULL,
0xa9609149b1870cbcULL, 0x557d912a68ac4909ULL, 0x9a948e5ac38581bdULL, 0xf2c98ab65f72cb0dULL, 0x1f228bd1191b7751ULL, 0x62e42f81d99fb8c8ULL, 0x29c5ce06d06ea575ULL, 0xa9fc91e77f928987ULL,
0x431117349170899aULL, 0x960b96a83a8a4e70ULL, 0x01effd1e128588efULL, 0x50e7b4d9b594c83fULL, 0xc85cd9088c9f2ed1ULL, 0xe8fdc7ff2fbfc8b9ULL, 0x5949ca622bb239d6ULL, 0x59e9320c89f0dc46ULL,
0xcc79e9a8ebf80fa4ULL, 0x5f70015cdc4c011dULL, 0xe1e2292095d70cdfULL, 0x656040d59328882eULL, 0x2cd81b70c4bfeb88ULL, 0xbdbaf1e00545dd94ULL, 0xdc43072c68317f9aULL, 0x345a819808676c23ULL,
0x3f0666a37ae7e026ULL, 0x54422dc1b99afa4eULL, 0x8d7d23b6867d68c3ULL, 0x3facd3b1a853262fULL, 0x372e671b3ada222aULL, 0x1398e27cc4e163acULL, 0x7396da5f2b8bbe61ULL, 0x68f69bf3be1c20feULL,
0x068f88b73c1a38f0ULL, 0x7d205e067d799b5dULL, 0x060fb583f582a2eeULL, 0xd7d785894e131a5cULL, 0x1f07c018374b3c9cULL, 0xee1d5d887776a17fULL, 0x8d9b8944f48d10ceULL, 0xd7d9cc5ff4b0018bULL,
0x1e62ac2fedab5532ULL, 0xcc9320652bbc9756ULL, 0x301b0d0a21f2cba2ULL, 0x140f52645fa589f8ULL, 0x26c38846e514d9a6ULL, 0x51d4c8043c4ae46cULL, 0xcd31660079de52a6ULL, 0x12885e03d3be6ce0ULL,
0x0ba2ba978e7ad336ULL, 0x2f2b908b9c7ae5d3ULL, 0x9bee2acd9766f179ULL, 0x1ce6ae9f5d3dda45ULL, 0xaeed9be12ffb801bULL, 0xfde3c991cecdffe8ULL, 0x233ee5bf5a4288a5ULL, 0x712689e3eea8f976ULL,
0xefe9496ab27a00cdULL, 0xaa57c494678e78b2ULL, 0x428bd6496c3121b1ULL, 0x26e498f968b17ec4ULL, 0x53b7e2cb7fb6a496ULL, 0x30fccf787c5db3e9ULL, 0xa20922e1dd022889ULL, 0x243ccdb9a1982999ULL,
0x903151397839e291ULL, 0xd852fd16b1ecf54fULL, 0x99f5e7d2efd8b37aULL, 0x86e161de5fb37365ULL, 0x3d68fccb61976bb9ULL, 0x892c4e68c17de0eeULL, 0x79b9589afc7ca926ULL, 0x9e9279b7aa90f8f8ULL,
0xe0ec5846db0ca458ULL, 0xab026a30480a3c47ULL, 0x89f3ed0413b493fcULL, 0xb56c8b80930bf22bULL, 0x63a9b423a026b59bULL, 0x47b0646dafb451c3ULL, 0xd78982b3b49357f2ULL, 0x2146e94d291d93fdULL,
0xc86f07af3eb858fdULL, 0x87bc6111468c0673ULL, 0x9ca4894fc613f946ULL, 0x6236a52ef554d5b4ULL, 0xe2e0a8ad52723d41ULL, 0x9c63cc821c1b9c85ULL, 0xdbe5b8c59f01b54aULL, 0xbfbd0b726dd65d88ULL,
0x15b38c54a6b0f952ULL, 0x0d8cc7829a275511ULL, 0x8413743e14bf85e7ULL, 0xf34946449e09d336ULL, 0x8ed9b749791f3132ULL, 0x65ad961a60e48386ULL, 0xcb9da3692237fd89ULL, 0x5627922f698c9e35ULL,
0x735d91a9eadccd8bULL, 0xd454e5ea41fe7d6cULL, 0x34e473b1d7ba703bULL, 0x69e92391a56bfb9dULL, 0x1f8322ccea6ef5caULL, 0xf7f30ede7bf09830ULL, 0xea73483bc3e2d44bULL, 0x5e28cf1b6c5fa0f6ULL,
0x26d0bbb8352f33d7ULL, 0xcf3d7da69dfee37fULL, 0x15493ee9e2079db0ULL, 0xea7522b9ab444695ULL, 0x9a3d90f095689131ULL, 0x7cb7d63d2a6ce7c9ULL, 0xc403941893d7abbcULL, 0xde16f3d436c0bc39ULL,
0x831a1103a2c3c24aULL, 0x4e20abb4091b0584ULL, 0x085236f8e4f918c1ULL, 0x32c3d22cc00d8a3aULL, 0x247928a7060db9adULL, 0xd9e0dd9969409a24ULL, 0xe09a9c71afdbeb3aULL, 0xa5f885200e72caa8ULL,
0x866ecd7938af0c8eULL, 0x3da316a0cddb86c2ULL, 0xd6627e5e53204d91ULL, 0x5a7ccc892f80df4dULL, 0x61cc50a62ab7e223ULL, 0xff6bed4b43724464ULL, 0x5d2fbfbbe50badfaULL, 0xc6332ecc00781002ULL,
0xc839413d66e826eaULL, 0x80ce01e6cf20d35fULL, 0x6ad86f7bbcf3b536ULL, 0x2d9f0135159af4a6ULL, 0x912405f97932800eULL, 0x210f46965e3920fdULL, 0xba54ceb1e9fc382cULL, 0x8841e5dd78d6ae3dULL,
0x829aae50d3c1e7c2ULL, 0x84494946b44dbda7ULL, 0x5768cbc9b8ea9120ULL, 0x7fb37a1295e298f5ULL, 0x2d8bd3b5b9b82581ULL, 0x0af0d5953751fe2dULL, 0x38f06f28dac84ac2ULL, 0x174462c9cf768d06ULL,
0x7b3cb277f4566317ULL, 0xccb62eebc1f72108ULL, 0xe7ab6f5da39ea0e9ULL, 0x92c0a786e2aa1d50ULL, 0x02083400fa8a5993ULL, 0x072c942497a8a85dULL, 0x52aab3be76f0bb48ULL, 0x440ed1368c4801ffULL,
0x26bc92597c5a497dULL, 0x0f1591d4900ae793ULL, 0x3f29ce8d494ae117ULL, 0x9545776b2d0f9125ULL, 0x41dfaf2285fdad45ULL, 0xf4b1a93c31adbbbcULL, 0xc268be3565a94371ULL, 0x24cfa2e77fd4e37aULL,
0x9b77045b647578b7ULL, 0x73c55622cc87567cULL, 0x1b825f8c103d5af0ULL, 0xdfc1dce5efad4c51ULL, 0x6feadc4f7ec6447aULL, 0xb9e31f7e6f15dd67ULL, 0xd665ae8c40a61618ULL, 0x799ea6baedae1eabULL,
0xb4384aa00fe3feffULL, 0xffce2adfdc526ae6ULL, 0x977810ec5c9670bbULL, 0x79a6a6a8c92e5975ULL, 0x5416c37f3bc62980ULL, 0x43d9b960021007e7ULL, 0xb4500439fb27f025ULL, 0x06ee86231d34da38ULL,
0xb6c9db6359fbf8bfULL, 0x2cf648a15330c92dULL, 0x5c19b592d05d4d7bULL, 0xbf3680a74e850451ULL, 0xe552b98b9e5bb98dULL, 0xa3442a1342f86069ULL, 0x12175460c787124fULL, 0xa0897d319c6dc08aULL,
0x24211dee91a244abULL, 0xd70e0bab7879e071ULL, 0x8d13e6a0351bd4f2ULL, 0x7b99e27e7b96423dULL, 0xd7666b6b365d06b4ULL, 0x70438c9317ecf134ULL, 0xcc82a7434e54458aULL, 0x0b4e5a2a5a66672bULL,
0xfe6da3f11a7f87a2ULL, 0xa966640add6f1aaeULL, 0x4762d7bcea68edcbULL, 0xc60a8d2139cd5053ULL, 0x575a5cad7c553f0cULL, 0x438264818a7b658cULL, 0x549e35c79c24c5e8ULL, 0xac96a294fae98204ULL,
0x97f613f48497676dULL, 0x9c3156f0fb924afdULL, 0xb3515b6c6dc47cdfULL, 0xd49a234845ae623fULL, 0xbf835d61da48fd16ULL, 0xff8575681ee6e049ULL, 0x4f943a762b37223cULL, 0xe99e4dba937a273aULL,
0x95172059ea41e3dfULL, 0x61bdb2a0b437d9cdULL, 0xeaffa8bda21dd5f1ULL, 0x7b5e6c510ce5b0f0ULL, 0x550c5f1e9631627aULL, 0x84864d3eea1876f8ULL, 0xb4c993f7908fb4b4ULL, 0x3057184160e1030eULL,
0x92a14f6549e63817ULL, 0x8b969edca2a521a6ULL, 0xaaa82ea21fb9174eULL, 0x40682216a963c1deULL, 0x1b8c924402a6d2d7ULL, 0x2636c86382ceffc5ULL, 0xd3e6220fd34a5564ULL, 0x6bb4ae0d3f8078fcULL,
0xf06167f058742d81ULL, 0x7b0980e2289426e7ULL, 0xdb88252a9b858c20ULL, 0x428c4da3bc1bba72ULL, 0xdba83cf78e9f22f6ULL, 0x9e45a6ac1c3aa450ULL, 0x2b0f9265bc6f8759ULL, 0x33ff80dab325c761ULL,
0x0b38e05d9e542e86ULL, 0xd0b48b035be7097bULL, 0x4544415dfee09275ULL, 0xed6277be9dddb535ULL, 0x58d1a9425f1692f6ULL, 0xabb5db3f1b49ded6ULL, 0x3df1e9da9093aebfULL, 0x6fa1066585653963ULL,
0x0c7873327906cc8aULL, 0x6440614144993e72ULL, 0x7fc6087c152b3688ULL, 0x33670faa1ed07c09ULL, 0x7bcfaa3128a32774ULL, 0x976e26e94385cda5ULL, 0x26fbb7a8fa515ef2ULL, 0x9a84f9305941b47cULL,
0x187ee0839500a1eaULL, 0x5b1d7a99f223eeaeULL, 0xcba33cc1115db97cULL, 0x8cc6e221d5d3f739ULL, 0x1d2eeb6b62bab477ULL, 0xb3a522891f1459b3ULL, 0xbadefd20bebb5077ULL, 0x693e460a33b6ec13ULL,
0xbad5e376320c6114ULL, 0x55ec3476d8e98ce1ULL, 0x129dd2f4fc20b170ULL, 0x5ca5f8360d246976ULL, 0x234012a39adca09aULL, 0x617cd494b402253dULL, 0xe65e7f3be6eeebe3ULL, 0x79218efa743d2ca2ULL,
0x19f735d3d3acec3bULL, 0x927b6af748032d17ULL, 0x0aa5b7a4cb214366ULL, 0x48ab0f57e9c161c7ULL, 0x04abd120ae1f86acULL, 0x48b999709c49599aULL, 0xdec6365430ade565ULL, 0xdd04e1bb65eb1679ULL,
0x3fd532b155930eacULL, 0xb7edeef3aa81ffc3ULL, 0x6f48f4811f1daeb1ULL, 0x7ed73fe1f8aac473ULL, 0x173c2be08bce1841ULL, 0x38293ba427200e5bULL, 0x61afefed179efcc2ULL, 0x53423c7621a2ca1eULL,
0xcce832042ab9bf73ULL, 0x12b122c46ee55352ULL, 0x871c76bc508a0c37ULL, 0x2216cb7a27fa6634ULL, 0x3d4266b04317c2d7ULL, 0x90fc013275774a45ULL, 0x8a2c23c5086f7466ULL, 0x8a797c5ba6d89014ULL,
0x3aa31c67fd950a4fULL, 0x3db86349ffc66b9eULL, 0x5b0a5310da4b618eULL, 0x1b452f6151e112b5ULL, 0xa3cba3d5a45d540dULL, 0x2ed405df93f61549ULL, 0x7554508d650073bfULL, 0x3d7e29224a56bb98ULL,
0xe45bf476be15c1b7ULL, 0x333c06ad6fb1bc08ULL, 0x68bfd032d433b44bULL, 0xed570b035b812338ULL, 0x6f2ca61af7a05c7cULL, 0x16547e657742d748ULL, 0xe0d11879e3f81785ULL, 0x973177f4f72bbbacULL,
0xc08b78c516bf7035ULL, 0x3a665a84cc9cd898ULL, 0x0764fe1ec6a99c75ULL, 0x74c44bd425c86d43ULL, 0x6864d55d9fa9de25ULL, 0x24eb22fe34199269ULL, 0xf106d0430ad01a81ULL, 0x272b4e4de2903fd4ULL,
0x374add40312a9be6ULL, 0x4c8ff1d5c14734a4ULL, 0x150950e41700b70aULL, 0x32cf3ae1e839c2b3ULL, 0xfb93f0e812bcc59dULL, 0x7d5df6de324c46adULL, 0xa17a9928965bde65ULL, 0x031b06575d5192a1ULL,
0x812e91f6019944ecULL, 0xbda64cc39d57201eULL, 0x003f1a93ff3a974eULL, 0x05cad432168ed66bULL, 0x4fe0c18754526056ULL, 0x164d700bae862914ULL, 0xf67c735787b5d6d9ULL, 0x2ea4834929b6a80cULL,
0x9add0e75556dcf15ULL, 0xb0e9b8032b0fadc4ULL, 0x386dd46e563bd857ULL, 0x7ec59f6cce8e2866ULL, 0x57c19950695f6756ULL, 0xc25fec500319fc17ULL, 0xc137e330d7371e01ULL, 0xc84686221b144358ULL,
0xbfbe2efd4761ffdfULL, 0x75393c2ea3d80e7dULL, 0xdcb28e49500e8b2aULL, 0x6a49c1fa873c7b74ULL, 0x85dea66e33e25739ULL, 0xab09a96533142735ULL, 0x9068ca433b9bcd25ULL, 0x7c5ecc76daa59614ULL,
0xbf532b99a4433ff1ULL, 0x8d156e06bc55ccbfULL, 0x2e5473a529093cbfULL, 0x253cf3b676ae055fULL, 0x6d2318dea2767967ULL, 0xd03aefd246dd39e4ULL, 0x0a85f70128baee9cULL, 0x92b9c47f93c7c05cULL,
0x20f459eaddc7bf85ULL, 0xeb9f845482c3308bULL, 0x10229e8ffe244462ULL, 0xfdfdfe3257c9c130ULL, 0x7c530d938cb08730ULL, 0xcf631d3dd37d578aULL, 0xc966d9e7601fbe23ULL, 0xda8cc11cb041bfd3ULL,
0x9a81e049d376ee0dULL, 0xa8bae5c79e251384ULL, 0x4971707071db24f0ULL, 0x154c54ca23b1b237ULL, 0x0470f24a2b036537ULL, 0x31a4e81e03087d9eULL, 0x8125936d75fdf636ULL, 0x41e388e2575e12b8ULL,
0x81f07d6ba90d0451ULL, 0xeed1b8077961798dULL, 0x1af72155c4a09161ULL, 0xb728024337209543ULL, 0xb51bb1bf52ad31bbULL, 0x0e5e3ddcb167512fULL, 0x050493bdc035b264ULL, 0x488d87b8750a7af6ULL,
0x814670e711848269ULL, 0x022d0af42a027b18ULL, 0x0f7aaabc4cbb43bcULL, 0x261077c4562f843cULL, 0xc1eda64ea54c538aULL, 0x789f9eaa9435fdabULL, 0xde69e666dcf9514dULL, 0xc685bdd4fa7125ceULL,
0x5d8f9cf258e0b472ULL, 0x577eea0bc0736800ULL, 0xc6f60c62ab95de13ULL, 0xe7642b9f1f7d5b6cULL, 0x630e0af5f9239bc0ULL, 0xc05e565af01a6d3bULL, 0xe4e8756d4dc5537aULL, 0x7cb2ae8e1b7c6f31ULL,
0x3022cf7c90225ddeULL, 0x87e3ff845e369341ULL, 0x974c49f3f17a3a73ULL, 0x7759e725b4b4f545ULL, 0xefe6cb6acbe7af30ULL, 0xb8acfa118e74f2ceULL, 0xe868681beeaa18ebULL, 0x82541f47c4cf7398ULL,
0x07b37c625470662fULL, 0x8990f0e98b5fb26eULL, 0x4c1890ba664953ddULL, 0x071479ed0e7aee86ULL, 0x1c5be96d956b95b5ULL, 0x8f8ff16f319b8cfdULL, 0x949c7d983e422b1aULL, 0x2936d037419cdce9ULL,
0x9220ae124f011d38ULL, 0xfd9e9d4a0268ed8eULL, 0xc478b034b0a1a261ULL, 0xa8c747ccf8034cc0ULL, 0xcd689e547172dcafULL, 0xee98a5e8bd8453eaULL, 0x712b0284df28ae7fULL, 0x797141b3864840f1ULL,
0x218eb5da2b3bec02ULL, 0x4b87e03779d9fe02ULL, 0xd212cb55a1dab19eULL, 0x97da62a277db6b40ULL, 0xc69a35c19c52e772ULL, 0xd89af50a8a072d1cULL, 0x1d19f5c8415abde3ULL, 0xd47507e0dd1d7e9cULL,
0x48bd75c6e7c1a37dULL, 0x47860b5fc704d666ULL, 0x1d6e07af977245bbULL, 0xd1f9b9ea51505898ULL, 0xe2be7c8c1ce7d90fULL, 0x4aa63c19a33889a9ULL, 0xbd9d25227acf84a0ULL, 0x93d3d1a0713e0251ULL,
0x1317847edc157d9eULL, 0xff85bc122353975bULL, 0x89232dd8027bf103ULL, 0x331df22101c47092ULL, 0xc2b4f32edecf9b0dULL, 0xc615b715868b52f6ULL, 0x6ab1ad2ad26da6bcULL, 0xa4ecce040a2f33beULL,
0xbeaae826f25847a8ULL, 0x48426aec0035be21ULL, 0xfb4a7aab2b96c461ULL, 0xe6f016fcc6846504ULL, 0x9a58440286603175ULL, 0x1dc8d7af4b775a61ULL, 0xbd19a7db0018cadaULL, 0x86b7c9e00d7bd06aULL,
0x2725c0d8dde50f4dULL, 0x7baacc041eda706dULL, 0x6956ab25c1663b77ULL, 0x14760c40b701b321ULL, 0x2141fbb47cb33b8eULL, 0x1aa765f8502f1324ULL, 0x3057bf568ff9e42cULL, 0x1ca66d58126742feULL,
0x2f95b5ce28adc422ULL, 0x6366f156c98a77aeULL, 0xae6272a746aa4400ULL, 0xa4c0ea53c7f41c0dULL, 0x9cbb5b150dd6767fULL, 0x82625ce1a3e5500eULL, 0xb59c6373b8fa01e2ULL, 0xe44f4e92822e55f9ULL,
0xd6c5a8bd73c823adULL, 0xf533aa137cf72124ULL, 0x32d919be932fbe7eULL, 0xd0049df46f81e36bULL, 0xa020ae93f82c9e2fULL, 0xa1bdec6882fc4423ULL, 0xca167514a68f2ed2ULL, 0x8ade0a9e908d0d97ULL,
0x09308829d32984f0ULL, 0xbb0451478ed4e433ULL, 0x90d3e02e767cad6bULL, 0xd22578b784f9c1a0ULL, 0xe5ea7772651f197cULL, 0x341ec93470720c4dULL, 0x17cdc62187b91726ULL, 0x0b1d797076f95199ULL,
0x7ecd18721b4ea0c9ULL, 0x5d6b6a3984de0101ULL, 0xcc3e3b3a2a5d783cULL, 0x853bfaaba4b7a43bULL, 0x29c0ba76c17da951ULL, 0xb9533766a050ea4fULL, 0x58be75bd25a4ba3dULL, 0x03e02600bd9ffeb7ULL,
0x9f4af01f52eec23dULL, 0x1c45f8729936730dULL, 0x72353504a70f34ccULL, 0x4966a01d4f9c0931ULL, 0xfc452512dbe2e558ULL, 0xaaf4feba91fb5488ULL, 0xa6166cac23394e74ULL, 0xaa18594b72d1173eULL,
0xb0c9d5f11e12679dULL, 0x81dfa3820a9a3aecULL, 0x0288f7f0362d9959ULL, 0x25812583ef159dabULL, 0x47be297f73fb4a0cULL, 0x6f3005d8c990ecf4ULL, 0x08389cb4e149bf75ULL, 0xfe25ca556752ea42ULL,
0x2e133a9ee7d06b90ULL, 0x3cbff2877c6c7e00ULL, 0x624c89d1c450e8a8ULL, 0x4e592fdaa531c8ffULL, 0x8fb494726021650eULL, 0x15ec285adaacaf52ULL, 0xbadc915af5739dedULL, 0xdef70bf14e472701ULL,
0xab526ab56c4b2140ULL, 0xec1451626ac812b6ULL, 0x048d754c23f3a4a7ULL, 0x19d88ec514c45984ULL, 0xc5a426fd9cf8eff6ULL, 0xc74662f6787be99dULL, 0xb49f20c3b905e568ULL, 0x43a2b9dcbf979c3dULL,
0x314f8fcc1d19c4b7ULL, 0x372d1f5431c13b53ULL, 0x0d66658c16cc971aULL, 0xe4b68db009cc8c9cULL, 0x0002d07210f06cc2ULL, 0x8a7ed94f58ffe772ULL, 0xa9bb0aedd1bf6bd5ULL, 0x93ef4d73a331f051ULL,
0xc2c23dd5383f0ee3ULL, 0xb347226daffabd09ULL, 0xb3a18070c126005fULL, 0xbcac984fa52e80dcULL, 0x9c1cc306eaf06507ULL, 0xcb1fbdc3cd684882ULL, 0xdaa8fd712a392f38ULL, 0x319061eb52b6f939ULL,
0x6319e5f01939adb5ULL, 0xca678c04983c24d4ULL, 0xb2dfa1604c5e2a3fULL, 0xcb6bd5aaee7d899aULL, 0xefdb39d8c48ae3fcULL, 0x06893689ed06cb6cULL, 0x0642537ca78e6b03ULL, 0x65f13a9205e6d0e7ULL,
0x8862ba1c9af675beULL, 0x74d67bf095aac001ULL, 0x0276bdc7b1e057e8ULL, 0x381b9397cd5c8e46ULL, 0xa573743b3f3f1ee9ULL, 0x08e7435bd7018d4cULL, 0x77d44a892e03f41aULL, 0xf891aa76b3044a82ULL,
0xbf768215258ca107ULL, 0x0af5cc59846e7e47ULL, 0x9bfb59c64b1896ebULL, 0xd37c3a21c9e8ff99ULL, 0xaf52649b22a2bf42ULL, 0x099bff39f84ed1cfULL, 0xae4d6a7cc1ba86baULL, 0x91b61c1a7f701db3ULL,
0x08ae62a5dd3519a1ULL, 0x02c57519619890faULL, 0x65046b76fca4d010ULL, 0x8a1bd3557528a136ULL, 0x27568b8cb043241eULL, 0x9f3ae32a4fb4952dULL, 0xba8876c9fe0d2d96ULL, 0xa4c3bc47e104fab6ULL,
0xd9ec5cca1a8a4a67ULL, 0xd393bfa4d4b65dbfULL, 0x46504f2e88dc9d32ULL, 0xad3bc927ca87bcd5ULL, 0xee6a46578dbd1138ULL, 0xd6e03eb899a44ba0ULL, 0x972811c351c8a9c5ULL, 0x8e04c6ab269ad2ceULL,
0xb3a71965aaa4542cULL, 0x2f01824e288316a5ULL, 0x58dbee6c215725d2ULL, 0x3347c0f3369bfc0dULL, 0x342951acbcaf6d39ULL, 0x16fb69ad99bc207eULL, 0x8690a2ed1a95ac5dULL, 0x260682e7cc8a08d4ULL,
0xe685a81450a5b5f7ULL, 0x805e35a2f75103e4ULL, 0x8efada7826f3324aULL, 0x21808f660b0b2135ULL, 0x9474dee2eea4d5fbULL, 0xa855076c01b8580dULL, 0x5b2be312ce401782ULL, 0xa823cbaaca17d0b1ULL,
0x322fa813c41f4848ULL, 0xbe19cb6d0eca69adULL, 0xeea327c891d31e17ULL, 0xcceeed4a2ad30fa4ULL, 0x00089483323529d0ULL, 0xbeaf5f7622db6dceULL, 0x7e024aef8912cd16ULL, 0x780454149c67c78eULL,
0x4c4896bc50e161d2ULL, 0x8f9b4811af522940ULL, 0x786c63ae59b4dd02ULL, 0xbe21f0406b144167ULL, 0xfec2799c788aa055ULL, 0xd651a2d111f91edeULL, 0xf3a78a99080948a3ULL, 0x8780b39f81dfbb4eULL,
0x611a902dd813f829ULL, 0xb216d8e556f61faaULL, 0x73f01735bfe22982ULL, 0x33a86b1cf6150e58ULL, 0xf456d0cc07ba39fdULL, 0xd75f9c0270d27a9bULL, 0xffb97badc3aec07fULL, 0xd0c9d07fe63f6c1bULL,
0x4eb29047f1dc757dULL, 0x6ab2c835870f2504ULL, 0x6972543785d1e802ULL, 0x40fc4d3bf4f8b1e5ULL, 0xf989e3259759a5ccULL, 0x0d212b54c2aec902ULL, 0x3bcb10f34d77ea4cULL, 0xb9fd0f81813e9f65ULL,
0x39d4068ba595c44cULL, 0xe0369f4a020e216eULL, 0x06cfc39a7b5c484cULL, 0x44cc2077689ca542ULL, 0xcff026191f718976ULL, 0xc02b21a194301b58ULL, 0xe6407d08b1f2bf85ULL, 0x0d640ec9e737c7beULL,
0x675eb495bddbad6aULL, 0xeae813803c075ed5ULL, 0x14ba4847f0d412c1ULL, 0x5b07bb8c7c4fa9abULL, 0x043c46c5834fc0a0ULL, 0xf18f674c260953feULL, 0xd2e44235aa178624ULL, 0xd9458792b3a43286ULL,
0xdc2fbe344465906cULL, 0xb2722d6a2e151268ULL, 0x8250583229e9b588ULL, 0x610759d10c53623bULL, 0xa3436f6b77c1f783ULL, 0xf4058f2b784df0dcULL, 0x41c3700a54de4d3dULL, 0xf05ccc2836e7180aULL,
0x7d58dbe02b2e99adULL, 0x7f9864c2701b3e79ULL, 0x28b98133d80857a5ULL, 0x738af6b7586e644aULL, 0x685315f6a5e28590ULL, 0xd56bfb91fb9937dcULL, 0xacbce57398c2cc37ULL, 0xfa3ba54122ad6907ULL,
0x240190aa04e4e3eaULL, 0x6a493f91094cffc8ULL, 0x037355a9de754401ULL, 0xf662acf8f90a7090ULL, 0xc031f7d4a3b4fa5dULL, 0x18301deebef56b86ULL, 0x4a87f420560863bfULL, 0x5b881c5aa518dc57ULL,
0xf315229c8b387941ULL, 0xb62a8768a253e3a2ULL, 0x6e51e4a4344e2e72ULL, 0xab4eb55dad08958eULL, 0xfe226edac98bfc40ULL, 0x7eac9e90629a553eULL, 0x1c3ad58ca67bfbbdULL, 0xc12316d09f506714ULL,
0xcdd0ca8c17f14662ULL, 0xd167f21ebf7f5743ULL, 0x6bb90f7ed06566d0ULL, 0x347ce125225b25c5ULL, 0x054e7222823f8b53ULL, 0xd335fc1eb0c4d8d1ULL, 0x16e881890665021eULL, 0xf4038cf93290ad15ULL,
0xc846e89a58e86326ULL, 0xd16c7e4f09ca953aULL, 0x3f4352218259aae0ULL, 0x427d3d2bdefb015eULL, 0xbae285d1cf99fecbULL, 0xfa0ab6dc912d4818ULL, 0xa98f127b25c4b5d6ULL, 0x72cf407635332377ULL,
0x4d5ec95cbb222f9aULL, 0xede0d3d3b8258d93ULL, 0xf77aad031420943fULL, 0x339a9e407c7af193ULL, 0x50bcb760c8cf4e6dULL, 0x8d98a691a6cd7fa6ULL, 0x6f0637e7922ff900ULL, 0x1b6d5c6af047d5cfULL,
0x3ef147684175d51aULL, 0x4b3886cf2227e3e7ULL, 0x4aa3a601deb83380ULL, 0xf7b109307b973d9aULL, 0xff0950111808c327ULL, 0xd5e1a1dc8b39e162ULL, 0xa54588345bd02f7dULL, 0xc45e66e9b11dcb17ULL,
0xaeb7d04383ba7bbcULL, 0x0871f457bcf676bcULL, 0x75c3d2e5d01640f2ULL, 0xcf1f41fc301c7798ULL, 0x61b3a1c1316b4f7fULL, 0xa238f49c3a735632ULL, 0xa8951051fd46807fULL, 0xf4ce9e8098b99f13ULL,
0x9c77532454e222dbULL, 0x554682d6a0385c5bULL, 0x2351310d7bbb6610ULL, 0xcda32e65d0ddd13eULL, 0x49c0e74a2fe07227ULL, 0x6bf6109bc8568136ULL, 0x260604809352f9cfULL, 0x6b87080185c0fd0bULL,
0x3cf284c4080e317dULL, 0x50a5cc6cfdefd435ULL, 0xeb272057d9ca0861ULL, 0x153d74a605d9c2a1ULL, 0x135e91815999ccaaULL, 0xe1714f166f4ea62aULL, 0xb95b71b67d1aeb8fULL, 0x5b85817498bcded3ULL,
0x1e72b8ab91cd9ddaULL, 0x7a3820c3f67ecb1eULL, 0x9a399e861acd6154ULL, 0x468b3908b13837e3ULL, 0x12e59687eb76fa5aULL, 0x3633b3e8fddc2035ULL, 0xa9f6aa7fc76332b0ULL, 0x8300a85737581818ULL,
0x29e5108a99aabd97ULL, 0x28b78ac92193e02bULL, 0xea5a61263bbe6b6bULL, 0x02c96c7025ccb9e0ULL, 0x45963527830a7cecULL, 0xb835d2844d4774aeULL, 0x8e1411dbf7ecb16aULL, 0x5535af8cb597b918ULL,
0x178787daa0da585aULL, 0x45c283c3007dc9f4ULL, 0x8423a323330d6483ULL, 0x2dcf3ceb8e9673c4ULL, 0x4b99047532970668ULL, 0xf848323a42ee243aULL, 0x75cdc3c1bc7f7399ULL, 0x579fe815fa28bb53ULL,
0x1ae6014ed0dd14afULL, 0x7bbe403350e4363bULL, 0x0168fb859afd6035ULL, 0x63dfdb67f60f63d4ULL, 0x1a8df97d86c8a03bULL, 0xe9c729b8767fe68bULL, 0xcbc00075f9a27e25ULL, 0x4def2fe4f112d4f8ULL,
0xe2dc0241ca215c81ULL, 0xa890890feb18a6a6ULL, 0x948b3d157c598907ULL, 0x67c7c445d320cd4fULL, 0xd5af2f4b60beece1ULL, 0x29b3977bde071004ULL, 0xe82bbaf0441df2f1ULL, 0x9327204a56e317beULL,
0x78486540e7a6df7bULL, 0x889e8dd05e042a78ULL, 0xafe50ad514bde020ULL, 0xcc0db43c804db711ULL, 0x878a679111597f75ULL, 0x18a2d82e468e2cf1ULL, 0x8657180c88101acbULL, 0x824b3c42d6a604e0ULL,
0x79524a3001f5e0c6ULL, 0xd4fe39893c46cda9ULL, 0xc1a052e9e672e8eaULL, 0x1a1178ae31796ebdULL, 0x40da6c58becb26e1ULL, 0x279fb5ca3b9fa7cbULL, 0xf05eabfd201ebc31ULL, 0x506b6bd8fae1a000ULL,
0x5ef30ebb1d34d981ULL, 0x992ed5b07431abf0ULL, 0x4fa03da119183d4bULL, 0x4201a311d89f52c9ULL, 0x18cbccc7aafe0e93ULL, 0x51637e057bf676a0ULL, 0x1fcd867f4b79c4a7ULL, 0x662c3eb8ab2c4804ULL,
0xd7616804821dacafULL, 0x409041357db5d0b8ULL, 0x42a5abebc096cbc6ULL, 0x573bee60fd1f911fULL, 0xbef323ba74010348ULL, 0xc9d9fd0b30946188ULL, 0xa95774b8cb6b1cbaULL, 0xae06f01e5078067fULL,
0xca355b650eb1aa66ULL, 0xf932ec27fceaedd4ULL, 0x532adebddfacee1dULL, 0xbd93dba59296d3beULL, 0x1c43dbcf5194b7e1ULL, 0xe4295b0bc74a6c68ULL, 0x68bc79816a1606cdULL, 0x3bfd2f578fa36ed2ULL,
0xeb5e5a86c7e70219ULL, 0x9f06e7fce2fd60e9ULL, 0x7a13a2b72b020166ULL, 0xdcb67251675a80c5ULL, 0x756750dc3e86e4eaULL, 0x8ba9c6228ce20edaULL, 0x7ad23b6de13b7b2eULL, 0xb10df1256286b21bULL,
0x0c74cff5a240e2f7ULL, 0x6e9701810af1f4b8ULL, 0xaa4ff8c7c61d250eULL, 0xb728410855c69a55ULL, 0xfa9c56e3193adfd8ULL, 0x9405d3f0aa16e6dbULL, 0x46ef4f30a449e43fULL, 0xf76c03cb2b729956ULL,
0xd94134403ba95b40ULL, 0x875264746991c4eaULL, 0x36eacabf92d3be5dULL, 0x4dea706be000e1a8ULL, 0x8e53733691fd6abaULL, 0x60e9494b5dc822a0ULL, 0x25f5650e22900f25ULL, 0x8b6a53d998bdf703ULL,
0xbd93874407c524a1ULL, 0x8babb9a5b13686daULL, 0x2660286ba42b83e6ULL, 0x22b3e9cfb79106e2ULL, 0x5fb853f69aae4204ULL, 0x39992928947b8c08ULL, 0x72e5290c5817621bULL, 0x30ec98ff71cc1befULL,
0x24cca756465951a9ULL, 0x3e528379cf446286ULL, 0xef01487d84f2579aULL, 0x6a9f4e90a1467531ULL, 0xba3bc9cae1dff204ULL, 0x59e4ecd99a25e140ULL, 0x0ddec05e50a590c3ULL, 0x0afb6b07d40c3cd5ULL,
0x29640450db108826ULL, 0x0f46daba8cf141b8ULL, 0xde3dfbd2ad36603cULL, 0x4a973eeee418f92cULL, 0x58dbd802f541756bULL, 0x5940622995538b23ULL, 0x068650b7672fa65bULL, 0xcd1060f18c11cb7cULL,
0xc754b79a7bc4de3eULL, 0x3f012ed53899ae21ULL, 0x65a91333233a88f9ULL, 0x521c6c7b866322a4ULL, 0xbae14caeb5472465ULL, 0x3d37899e4ab0f63eULL, 0xd88eab054703f01fULL, 0x7dd53f65f2f7e962ULL,
0x6c6f6eaf9335f8b9ULL, 0x903ef3e04a59b768ULL, 0x3f6e98f4a166aff9ULL, 0x2fd4cf8c58d41069ULL, 0xbea0a21035da4463ULL, 0xac53608f7e86f6d3ULL, 0xc80a4731329669e4ULL, 0x8dd79e822bbc7febULL,
0x564b44c1c8a9c90dULL, 0x32591a63d30999aaULL, 0xc2b259a6bb6ac159ULL, 0x2927484394b33361ULL, 0xae8c24e58985e634ULL, 0x368fc80312db9a19ULL, 0xe077b8a0314c7dd7ULL, 0x0525f821bed84dceULL,
0x79c3b136fb6db07aULL, 0xb0d77fedca52ef64ULL, 0x63a1a50b08df5623ULL, 0xedad0078fe870f83ULL, 0x378cb8ab263941f9ULL, 0x54c9588152451800ULL, 0x446274c4efeca1d8ULL, 0x81c78ad29d928820ULL,
0xb5e938c628709266ULL, 0x5a04ade91f32931fULL, 0x26f68c2fe66dc285ULL, 0x897380adcd7a4c0aULL, 0xfec078ede250b7bfULL, 0xb372ff42dfcb500fULL, 0x82f3f10efc1b5621ULL, 0xf4ab8965f3744672ULL,
0x1c686bd987e65cbfULL, 0xf50881d5788405daULL, 0xeaa5c0c046660bd5ULL, 0xc687eeb33c369670ULL, 0x0450a8efdacfa56dULL, 0xf672b897ec286a05ULL, 0xcf0f9db8b45ffeeaULL, 0x583924b050a304d1ULL,
0x4aa05ccb57454ef5ULL, 0xbbceaacfc1da9513ULL, 0x65b1989505c24a77ULL, 0x189744f3c97152d9ULL, 0x56cab6b7ee42056fULL, 0x7f7dbc85afc33b48ULL, 0x6c8c28dcbba97544ULL, 0xfa4475e7ddcda8a4ULL,
0x7f3a60c176fcbb9fULL, 0x64830b3b9719d6f1ULL, 0x05ea37d351bcfdbcULL, 0x4cc453c206236eabULL, 0x6a454f6d9b3aa99aULL, 0xa2906337b3090fbcULL, 0x556ab917a6a81045ULL, 0xd6d7cd571f195d81ULL,
0xf08132f3a8be0c86ULL, 0x463f02442c9ffb9cULL, 0xa9538998da0691b5ULL, 0xd767848d4e60ff32ULL, 0x807535206ead7ae0ULL, 0x921a6c21aee1ef07ULL, 0x67e97dd79d0d74d2ULL, 0xa9c6f491470b0432ULL,
0xda6828fda259d984ULL, 0xcaf638362774fc33ULL, 0x54b3e7a6bba53898ULL, 0xede6878c8e785be2ULL, 0xf1a417d04097a6cfULL, 0x9ffa75e557b51fd1ULL, 0x2481da5af43d4dd8ULL, 0xdd4f03c37e46b81aULL,
0x262e70634f38b603ULL, 0x3c1e319844b24388ULL, 0xf501f31c985b1137ULL, 0x71ff636345dbafbeULL, 0xf0914e53ea2062f5ULL, 0xe84c1e0dbd83c605ULL, 0xb4f3f5902694726fULL, 0x97103f0311acf69dULL,
0x119377555f98f65cULL, 0x16b6597edcd3c874ULL, 0x8339ad383a8551e9ULL, 0x630b574dfbf2aacbULL, 0x8e5f271fd635a169ULL, 0xa39008594b00bec7ULL, 0x20e0507900c6f2efULL, 0x88d521dbf512e5c9ULL,
0xd54a55cd0242dc4cULL, 0x99e9806eed44c286ULL, 0xba511e9d480f038fULL, 0xaba8b24a9009e7d2ULL, 0xbb2438d478c8bb4cULL, 0x641c23e743adfee6ULL, 0x890d6ff0f9adac98ULL, 0x6cc772ca68c15a36ULL,
0xb2d646f632c7a82bULL, 0x7df84617c59db7d2ULL, 0x073ae01dc0bbea81ULL, 0x44395b20e007f233ULL, 0xc29c8fef0bd617d2ULL, 0x1bc15be7c240f8b6ULL, 0x70e1f505f74faa92ULL, 0xc3ea615ac40319f0ULL,
0xa0de0c9d1d907398ULL, 0x5b3cedc450910382ULL, 0x99c8355da93f8452ULL, 0x759227670108bb91ULL, 0xf59143c1ec733278ULL, 0xa4ae9f93abd86965ULL, 0x9604d9d4c55e0e1eULL, 0x49a17db21c62920cULL,
0x1ae232f0e853a88bULL, 0x7048cfb4323d8b0aULL, 0x6e770833fe742512ULL, 0xf70853f337d377e5ULL, 0xe33a2b9670c2c976ULL, 0x7b83ed26387e21cfULL, 0x2ca63c7a592c1c71ULL, 0xb35e403b0e1d7a55ULL,
0x42dec7dacdb85f12ULL, 0x6105cf5f2a233440ULL, 0x8412faf63f96a2f6ULL, 0x28dd84790898372eULL, 0x6d175c4f35f58d3dULL, 0xa75e92b2d9d79b8cULL, 0xc8d0fac601328039ULL, 0x1ed03254ef173172ULL,
0xc312c122abb4fe26ULL, 0x9b0972e22433ea4dULL, 0xbb213b5ca0a221b6ULL, 0x63d35bc9ba7e9b90ULL, 0xe6a3dda4d24487c1ULL, 0xc4057575bcfb16f1ULL, 0x465ff0afd0828156ULL, 0x0e88cafad9320072ULL,
0xa1c44d1000ab7affULL, 0xbd197e0a19a798aaULL, 0x69b8f589061fddd9ULL, 0x24269787748befd8ULL, 0x30765ba9fe58eab7ULL, 0x4a6d52265255f419ULL, 0x22bec27a31806179ULL, 0x9fbf5ee3551c261eULL,
0x070ce810878b0c63ULL, 0x91c7e1bc1dc55728ULL, 0xec1d0db0df19097eULL, 0xb75d90590e5220ddULL, 0xd80668e6b8289b1aULL, 0x11d81ca8ea7c30c1ULL, 0x66e150a8e1a5ac1eULL, 0x3b86021cd628dc24ULL,
0xf785be0933219f60ULL, 0x42c0c8d1ddee36f7ULL, 0x4d5590bf5a741ea7ULL, 0x9da7e805f4f31745ULL, 0xdb81443384953b4dULL, 0x6d5c15b5592ff40dULL, 0xbafee865a5d2e36eULL, 0xde09db75c680f64aULL,
0x52ce258ab991275dULL, 0xed028cb739cff211ULL, 0x326f5ed11b6b81eaULL, 0xba351877e4aae2c9ULL, 0xf74b77ce97d342bcULL, 0x12ddd2a3667ff314ULL, 0xdadcc4267961a64bULL, 0x652bc7215a91f161ULL,
0xd71b4bbf5a918db4ULL, 0x4fc1f8d3fc58852bULL, 0x7746d184f5d69956ULL, 0xb18551941df7634bULL, 0xcf84fc00f79e0f6bULL, 0xab121299d6753ea5ULL, 0x2306d3d06fd93ee5ULL, 0x518765a694bc2268ULL,
0x5000f69036bda00dULL, 0x5d8cea10e1874378ULL, 0xb734f85057b666c9ULL, 0xf0ff7423fdc02427ULL, 0xb4fad0464e9917efULL, 0xc8b797b2771fedbeULL, 0x5fd7abf25070eb4eULL, 0xdb0b38b47465b9e1ULL,
0x796e03c6bf604134ULL, 0xf263f5dc94c01061ULL, 0xdfe4bf3bbeff4e39ULL, 0x8da7aa63167c068cULL, 0x6b047228d6b41096ULL, 0x09b25f583ee0e1f9ULL, 0xd884bc7a0e218e95ULL, 0x76da24ddbab78470ULL,
0xe9f4c95f13619799ULL, 0x206fecbe4df3406fULL, 0x502a49edc32bf747ULL, 0x526241c5f91739e9ULL, 0x549a02ff22228686ULL, 0xa9eaf58254282f96ULL, 0x1761a18679fc97a7ULL, 0xad93ba528ed514c9ULL,
0x900de750100fd542ULL, 0x686be0d933f6e308ULL, 0x79b9e84793b114d5ULL, 0x8da6899f32e4f298ULL, 0xc9fb07c7df01caadULL, 0xfbf2dd7c57dbbbcfULL, 0xf8b923c4205a1c01ULL, 0x80110ca1fb6f5155ULL,
0xdd9948ed8a055a17ULL, 0x1372f70ac8dd17f4ULL, 0x7244e6e1513322b3ULL, 0xafa85ab457768639ULL, 0x227be5c735330c3aULL, 0x8c58ecad22f56ae3ULL, 0x5fb9e5789ba3cbe6ULL, 0xddf08d5722fc9877ULL,
0xb1a366d77d74405dULL, 0x81ea482bc5008bf7ULL, 0x975c38ffba12a147ULL, 0x03c433e5744f1604ULL, 0x20b61fc284cbf7cdULL, 0x1bf277214c652dd4ULL, 0x4300140aca9462ecULL, 0xbd5fb8b35b237427ULL,
0x82fc3743778d2cf9ULL, 0x43035d2dbad2e102ULL, 0x909d37db130ac857ULL, 0xeb15400cf39b7dc0ULL, 0x6f798f2538a2b115ULL, 0xd63f6f346cb320a7ULL, 0xe8f7cf3a1e1bcd7aULL, 0x845bbf992936037dULL,
0x6bfe75b44b6d6ae3ULL, 0xdf2b8ccd5b513b40ULL, 0xcb7bd2a22a8f738aULL, 0x279613a817967763ULL, 0x1856834e2a05eb94ULL, 0x9e99dfd380e2d58cULL, 0x2d8d3bda6fc08679ULL, 0x61d3232e38da60d8ULL,
0xe0a316a35ca2deebULL, 0x5627594e046012e2ULL, 0xc124b3c30b6f38c6ULL, 0x343cc1ac66787bbbULL, 0xf12f29d2b090eab4ULL, 0xd326e65cb87c9a2aULL, 0xb7637340ee215e8fULL, 0x2e73ce31a07d989cULL,
0xd831814d501a758eULL, 0xe45361a286fa663fULL, 0x40a5818d28e25737ULL, 0x557017e51f421e72ULL, 0x6939f006b4dbd37eULL, 0x8a74438fd5758b76ULL, 0x4be1162802e43f10ULL, 0x1cf5f28b817c1c81ULL,
0xc742ca1644108ce2ULL, 0xd056c52ed7c7a94dULL, 0x0d7ae6097bc4c74dULL, 0x42e8042e95a248d2ULL, 0x2831ffe71ed7434fULL, 0x6ac8806fe09ce0d7ULL, 0xdaa71cca0dc947f8ULL, 0x2f200392529be90cULL,
0xbb3261b3d3899291ULL, 0x9ba534afe570e037ULL, 0x9126e190d4b44fadULL, 0x19a059ca50f428c4ULL, 0xa4e306dd52046a26ULL, 0x22500b466e566a36ULL, 0xad9af87ffcf98a00ULL, 0x1037459d0c27e12dULL,
0x813adcb2bf5916e2ULL, 0x71d64c84748757efULL, 0x23f131a595c4cb09ULL, 0x4a2af47ddfa295afULL, 0x1485735a1728f013ULL, 0x480521bd327b3368ULL, 0xf2c56f21e66c7ce4ULL, 0x1f0abb1daf5cda8dULL,
0x5229b2e6ca3feb73ULL, 0x3c3fab0fc946dc6dULL, 0xc66bf89fad3b12d1ULL, 0x9eb11d31bf1e1f17ULL, 0x57d061e308832c23ULL, 0x1fb5a67c2c99ca06ULL, 0x5f7c66a78d89a67dULL, 0x9b2c6bcc8b7c673aULL,
0x2ef8bf6d689db7c3ULL, 0x22b75b86d46bb377ULL, 0xdb7669ef23ebde2dULL, 0x634af9aa9d2e3048ULL, 0xfb73b3daf03a0e23ULL, 0xbca1421b29b9406fULL, 0xe774eb15402b6425ULL, 0x6ddb6831445e2dd5ULL,
0xa3932f1c82d58a0bULL, 0xc3bb21f44251096aULL, 0xcac0edbe5e1b2a35ULL, 0x1a5cb3e0139e5d24ULL, 0xe9be83caab760b4aULL, 0x7460e73a0f0ba654ULL, 0x5f89b472cce6d358ULL, 0x0071319c5ab79611ULL,
0x5219b3bbdce2624fULL, 0xc8798c41c1285fc2ULL, 0x21ac4410d270c612ULL, 0x21c6e1b98fee4fcfULL, 0x01efa6fdadfd54cbULL, 0x051651148a310504ULL, 0xfe7c7ad0ffba0471ULL, 0x1105795c5beb1b1cULL,
0x42f38def7daa6ec8ULL, 0xa923fc755b388aabULL, 0xec4310d81f09eb09ULL, 0x3d30ccb8a8a0bb2bULL, 0xbdbf6dd5d11e6163ULL, 0xfbd37bc3ba3af02cULL, 0x15f36da5a387953dULL, 0xa28cc55bd176ae3bULL,
0x2d2479b33778489fULL, 0x34930f35569687f3ULL, 0x9f6af9d3afa4d83eULL, 0x4ef9d7dc1463bd7dULL, 0x741ebd27a9ff5066ULL, 0x08465127a1a97311ULL, 0xa0f31f78bf7ff5caULL, 0x3f1b9fffc1d22426ULL,
0x9239f48da14fe6c1ULL, 0x6f511d3ac461038aULL, 0x22bf275974fc8879ULL, 0x05d94df6bd9c7f3eULL, 0x8c2c6bfb3ba6b8f4ULL, 0xb59486e0a975404dULL, 0x2aa241f00283fbe5ULL, 0x0682348d383b96d6ULL,
0x2b290d36ba3f5c16ULL, 0xe46052022bbc8d59ULL, 0xe298db90055d0ed0ULL, 0xf5d887ec3a65057bULL, 0xaf4032eac6d2ed3fULL, 0x7271f532a617778fULL, 0x2f84a211fd6332dbULL, 0x12ed1adae2be8dc0ULL,
0x4e5fb40f2ee60164ULL, 0x68e412f0e66a3984ULL, 0xb64554ece728d525ULL, 0x8e86a9d4fbb4154bULL, 0x4de3a93c3f325b73ULL, 0xda4beac33099e78bULL, 0x79482b18b6d4402dULL, 0xd6589785bce4587aULL,
0x48d9467cadd570d0ULL, 0x6a24b174eaf933f8ULL, 0x62412dacb307e0beULL, 0x3bafabd1bb29d72fULL, 0x9638ea44f43c2a36ULL, 0x98193d82499e6b9eULL, 0x8f3f922c3a11dc15ULL, 0x9012a2bf6546f51fULL,
0xe55c3e94e73cda55ULL, 0xe19ca91117d49b65ULL, 0x50c596c12f2d2077ULL, 0x60be8ea7ea0adac6ULL, 0x4d136df4dca71fa6ULL, 0x3b6aad697c5aa013ULL, 0x8c1412ba12ae431fULL, 0x3cc074d66d180f22ULL,
0x8c9708eb7af274a6ULL, 0x308d65e418ee9053ULL, 0x2dab99af2e92e45dULL, 0x85d6f6f4576ee311ULL, 0xc3d75baf283d38acULL, 0x3f301a38c1fbb764ULL, 0xfaf5f170796476b8ULL, 0x727c6cce5675128eULL,
0x32423150b67f2696ULL, 0x684c7b84b8fadbfcULL, 0x6ec398c920d3e3e6ULL, 0xe74457b1d48814dbULL, 0xbe953967e9795f38ULL, 0x1e1450cd2d3de90fULL, 0xa3ed7de84ecb7a0cULL, 0xb13996caf7bad02fULL,
0x3b3aa32e3a02559bULL, 0x7ef18384b6bf1d30ULL, 0xf24ad96c13afaccdULL, 0x524f2ab5ab6377cfULL, 0x33be111158a2c6c8ULL, 0xe96d1c05ce14cc4eULL, 0xc03d53f69b5ca521ULL, 0xa517109c831d5cb2ULL,
0x3beab461b32d9097ULL, 0xf617c3ab2cfedf59ULL, 0xd5a5b2d2f8ddb374ULL, 0x6330bcd280eb233dULL, 0x95259c71e01aa5b8ULL, 0xbc6bfd632fe457a5ULL, 0xa87997ec8cd7900eULL, 0xb3199b8c9dac8e28ULL,
0xab6917f9773f454dULL, 0x232fd588180d3db1ULL, 0x48ad9898bc758654ULL, 0x1b3637aa1209f0f9ULL, 0xe74eddef5c2160efULL, 0xbc3731d79a855326ULL, 0xa9147f283c9c1a90ULL, 0x6e7bcf70e88910c1ULL,
0xc8c5020535adae80ULL, 0x3dc72bd5cd085b62ULL, 0x7d8e70dae19bed91ULL, 0x9a7e5bc75ab03de7ULL, 0xbe9bffdad562a5a7ULL, 0xdb71241f31f8c5baULL, 0x699e8b976d2320cdULL, 0xad3f41cd5d42cc25ULL,
0x6cbc46fa7b78d4ccULL, 0xbbda35ba0db8243fULL, 0x04923952284cbaf6ULL, 0x2e96bba2f00539ddULL, 0xeccc7474b6f4b177ULL, 0xd3090e32ca250f7bULL, 0xa2148da55f3c50f8ULL, 0xacd009d7c4659dcbULL,
0xad8efca4dc47034cULL, 0x52a2ac5716fe5d9cULL, 0x082db98e00d80105ULL, 0x0973b97d9b13c56eULL, 0x71d19c03acbdf235ULL, 0xde5378c8e108e2cbULL, 0x0e64232053c1631cULL, 0xb186c819c25c7d51ULL,
0x153ab4a909ca368cULL, 0xcb07acfeff033f97ULL, 0x42892a3f27ea6efdULL, 0x926e14e032545a6cULL, 0x62753390c0089ee7ULL, 0xf6b8c3035eed3169ULL, 0x468e818076b0bd33ULL, 0xe3d84de0b3f0548dULL,
0xde43ae677c18b524ULL, 0x58e8054746a5c560ULL, 0xbae74f5531a0779cULL, 0xb9ed1a2a571dc262ULL, 0x5b49e25f8387981cULL, 0xef320d8878458accULL, 0x77f491b7da01d4e2ULL, 0x5157a6ab27138036ULL,
0xb335f740a96d3a35ULL, 0x1d787c11cfa7b278ULL, 0x1bd08ed19f592d63ULL, 0x8ef9f6adf221ce35ULL, 0xac8d9867b81a2cf8ULL, 0xdc83cfae38ffa3ebULL, 0x810df42b21de6cc9ULL, 0xe64d9c67c8d1b3edULL,
0x3dfec700e3eeda6bULL, 0x63854fb8be1805a9ULL, 0x072b1e1ac82fff7eULL, 0xdaaf95d18ad0e298ULL, 0xc6e253e294fc20c6ULL, 0xcc367eb94844650dULL, 0x8e242859fdaa292dULL, 0xc02a117eebbfd76cULL,
0x7bdcbb04386cbb6dULL, 0x88227e8510ceb1ceULL, 0x7377026e7d2b5856ULL, 0xbb478084ec1eb2acULL, 0xa23993811e258c78ULL, 0xc6df7fc9f98d0de0ULL, 0xbda1708469aba89bULL, 0x1624f55846eeaefcULL,
0x121c6b3463baf61aULL, 0x3ae743226b3497ccULL, 0x307ef787d240d0cdULL, 0x3e8da37545fa6754ULL, 0x07d574b66b6ea0f1ULL, 0xd3291eef6101b871ULL, 0xb8f7b8e53a0f9b3bULL, 0xb89e17111dc8e0d5ULL,
0x7d01270ffd1b9bcfULL, 0x5bb25f51d12de2f6ULL, 0x35851318181f16c8ULL, 0x5713c5321e679bc9ULL, 0x3e606c8db5d66109ULL, 0x76fb920e7bb6c554ULL, 0xa07d742772adcd3bULL, 0x6b4d170d963cae7dULL,
0xde9fdb7c5e9ec893ULL, 0x7ac9ea5f6d494763ULL, 0xbf028b0e4dd0c77dULL, 0x768b8749d791493bULL, 0x54ed255dd015c621ULL, 0x9a5b70e4ca18d94eULL, 0xd55428583b3b033cULL, 0xd022227104c73df6ULL,
0xfa51dfc68e7bb49fULL, 0x059af7ff6b2ce973ULL, 0x0210c42cfd6ccfcaULL, 0x6d22c14a653a5e69ULL, 0x05b5d0b4de5d0191ULL, 0x8fb805e10405e057ULL, 0x7bc78986a8d5b60cULL, 0x17ee3ee51d0122eeULL,
0xcf0f6782729f3e9aULL, 0xb4972253a5b171a2ULL, 0x897343441b0e9efeULL, 0xe5b4c5b8c62146b8ULL, 0x0d85824612a90574ULL, 0xe8d493160bd5a4d9ULL, 0xba1e2cb8ed032822ULL, 0x49dc1a01cf1cb0edULL,
0x9afadd6cc34a1b81ULL, 0x0f52f3d7290bba99ULL, 0x98df328f2b8be289ULL, 0xe679c8a7d5b3a21bULL, 0x11b9cf8bb19ef9e0ULL, 0xc341158cb46215b8ULL, 0x69efae92ee45d4c2ULL, 0xa66753020d148bddULL,
0x7ae0d4e663ee59a8ULL, 0xf9451fd56d340c43ULL, 0xbeaf36ce86f23fb1ULL, 0xe85ec1bb16c8d3f5ULL, 0x9a45d9c0a2e0ba91ULL, 0x46ec8e22eb7d329aULL, 0x822e26048077aca3ULL, 0x677b61e8c4dcd7c4ULL,
0x834e149f9eb8a311ULL, 0xfbc73a51a36a16e7ULL, 0x0fc2cf2700b250adULL, 0xb1cd72a8bbf4d74fULL, 0x9e0d385f15a568bbULL, 0xcfaa002c9af91887ULL, 0xb4aa18178a31f901ULL, 0xaa39734e418ac96aULL,
0x7d7ddb1ea249eb5fULL, 0x91d3181007eb109aULL, 0x2efb548da676d682ULL, 0xe8478cd7cc662c47ULL, 0x8364cdea6a08032bULL, 0x70c086b380e460e1ULL, 0xe87a87fd6f4f7105ULL, 0xd7c476f2d434e1d7ULL,
0xc8f8766180fa3a33ULL, 0x0cc579b4450a5523ULL, 0x1de1004cdca6c8bcULL, 0x19c67b6b4b912ba9ULL, 0x3cc85662d1d8fc3fULL, 0x1df013f980d144e5ULL, 0x87104e184b9092f9ULL, 0x1480474405cb6fa7ULL,
0xf8d62fc960b26639ULL, 0x7a4b2b8cd522f976ULL, 0xa91a7e0a31e64ddfULL, 0xc8948c4ede94b180ULL, 0x6408ab9aa4261cc0ULL, 0x46994fa782182ed4ULL, 0x403678653a7db0caULL, 0xfb72c1d187ab938dULL,
0x5c24033f3fee68a8ULL, 0x7fde26b743c1c521ULL, 0x86f16fbbb1a59876ULL, 0x6ca91f5f5a5d9ff7ULL, 0x59c17a6e0af10fb4ULL, 0xd3d9501587c01cbbULL, 0x55bb1e2fb52ce1e3ULL, 0x62ae1728df57377dULL,
0x18c3d9b62ac00512ULL, 0x73bed10d9a9f219bULL, 0xee975f4119f97a3dULL, 0x4c75c7e475fa7b16ULL, 0xd2c356421088ab3aULL, 0x3533b6f3fae5c2aaULL, 0xb2e86a5b7a69806cULL, 0xdbd499996f260ffcULL,
0x47d1fbe748b953d0ULL, 0x22bdea619d7e037fULL, 0xc5ac448e762f2deeULL, 0x2ac2737ca2e88177ULL, 0x9b1b58c22d8fd26cULL, 0xfb827d1375896914ULL, 0x530d7d6f18b2522bULL, 0x4e9809de5ee569d1ULL,
0x6b04e935c10ce9ddULL, 0x6f758965113e3ce6ULL, 0xfbde9068b7121467ULL, 0x381cfd594d682e42ULL, 0xc2194fa21df8eba9ULL, 0xab8d4c488a3fb2abULL, 0x145b809d9ace1461ULL, 0x93d7a3e500f9d5dcULL,
0x74aa01378b1f9f83ULL, 0x8cf5e015b89695d6ULL, 0xb7454a45afa5b026ULL, 0xe7b7e8116030e30bULL, 0xa6996fb9b21ded66ULL, 0x1c2f217c0f89a5ddULL, 0xf730aa698b81a146ULL, 0x96b0d3123f070a51ULL,
0xc0e3b99cab0c2f5bULL, 0x0c2037c4913fc058ULL, 0x1101720962f9265fULL, 0x1c873744c52aeea8ULL, 0x2e78b3a7aba005ccULL, 0xd2c5848e4cd9fdafULL, 0x5363c9819a93e551ULL, 0x2b792df305e956b5ULL,
0x13c480bb4e580323ULL, 0x51a0d852cb72e032ULL, 0x70edff071b8ba009ULL, 0x24b5a07378396169ULL, 0xadb441aeafa15404ULL, 0xbc1712885272334fULL, 0x83c59e6c938ed604ULL, 0xf8cb0f8006319774ULL,
0x8e70949f4e42353bULL, 0xfedd375785b6ddf6ULL, 0x7e6abd2cd9d7d335ULL, 0x7167e8be3514550eULL, 0x36e79a50905b1a54ULL, 0xb7e8a3f18f63e4f5ULL, 0xc70c8b7fc533f56fULL, 0x74e2396fa6b1102aULL
};
PRIVATE int ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	cl_uint keys_opencl_divider = 32 * (num_passwords_loaded == 1 ? 2 : 1);
	cl_long sha512_empy_hash[] = {0x322522bb14ec2384ULL, 0xb7acc2d476e22b95ULL, 0xa2ed9a8b815acdcdULL, 0x93b412a0bb64a9e2ULL,
		                          0x7fe24fb57c40ef6aULL, 0x65d97928fdbb399cULL, 0x443558114bffbd16ULL, 0x49576561e5a9b8c5ULL};

	// Do not allow blank in GPU
	if (current_key_lenght == 0)
	{
		unsigned char* bin = (unsigned char*)binary_values;

		for (cl_uint i = 0; i < num_passwords_loaded; i++, bin += BINARY_SIZE)
			if (!memcmp(bin, sha512_empy_hash, BINARY_SIZE))
				password_was_found(i, "");

		current_key_lenght = 1;
		report_keys_processed(1);
	}
	// This hack is needed because bug in Nvidia/Intel_CPU OpenCL driver: The compiler do not finish the compilation
	if (current_key_lenght == 1)
	{
		unsigned char key[2];
		key[1] = 0;
		for (cl_uint i = 0; i < num_char_in_charset; i++)
		{
			key[0] = charset[i];
			// Search for a match
			uint32_t up0 = (uint32_t)(sha512_one_char[8 * charset[i] + 0]);
			uint32_t up1 = (uint32_t)(sha512_one_char[8 * charset[i] + 0] >> 32);

			uint32_t pos = up0 & cbg_mask;
			uint_fast16_t data = cbg_filter[pos];
			if (((data ^ up1) & 0xFFF8) == 0 && cbg_table[pos] != NO_ELEM && !memcmp(((uint64_t*)binary_values) + cbg_table[pos]*8, sha512_one_char + 8*charset[i], BINARY_SIZE))
				password_was_found(cbg_table[pos], key);// Total match

			// 2nd pos
			if (data & 0b110)
			{
				pos += data & 0b1 ? -1 : 1;
				uint_fast16_t hash = cbg_filter[pos];
				if (((hash ^ up1) & 0xFFF8) == 0 && cbg_table[pos] != NO_ELEM && !memcmp(((uint64_t*)binary_values) + cbg_table[pos]*8, sha512_one_char + 8*charset[i], BINARY_SIZE))
					password_was_found(cbg_table[pos], key);// Total match

				// Unluky bucket
				if (data & 0b10)
				{
					pos = up1 & cbg_mask;
					data = cbg_filter[pos];
					if (((data ^ up0) & 0xFFF8) == 0 && cbg_table[pos] != NO_ELEM && !memcmp(((uint64_t*)binary_values) + cbg_table[pos]*8, sha512_one_char + 8*charset[i], BINARY_SIZE))
						password_was_found(cbg_table[pos], key);// Total match

					// 2nd pos
					pos += data & 0b1 ? -1 : 1;
					hash = cbg_filter[pos];
					if (((hash ^ up0) & 0xFFF8) == 0 && cbg_table[pos] != NO_ELEM && !memcmp(((uint64_t*)binary_values) + cbg_table[pos]*8, sha512_one_char + 8*charset[i], BINARY_SIZE))
						password_was_found(cbg_table[pos], key);// Total match
				}
			}
		}

		current_key_lenght = 2;
		report_keys_processed(num_char_in_charset);
	}

	//return ocl_charset_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha512_header_ulong, ocl_gen_kernel_with_lenght_ulong, sha512_empy_hash, CL_FALSE, keys_opencl_divider);
	return ocl_charset_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha512_header_uint2, ocl_gen_kernel_with_lenght_uint2, sha512_empy_hash, CL_FALSE, keys_opencl_divider);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_sha512_ulong(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint value_map_collission, void* salt_param, cl_uint prefered_vector_size)
{
	char nt_buffer[16][16];
	char buffer_vector_size[16];
	// Needed when use a rule with more than one param
	int found_multiplier = found_param_3 ? 3 : 2;
	char output_3[64];
	output_3[0] = 0;

	// Function definition
	sprintf(source + strlen(source), "\n__kernel void %s(const __global uint* keys,__global uint* restrict output", kernel_name);

	if (num_passwords_loaded > 1)
		strcat(source, ",const __global uint* restrict cbg_table,const __global ulong* restrict binary_values,const __global ushort* restrict cbg_filter");

	if (aditional_param)
	{
		sprintf(source + strlen(source), ",uint param");
		*aditional_param = num_passwords_loaded > 1 ? 5 : 2;
	}

	// Begin function code
	sprintf(source + strlen(source), "){uint indx=get_global_id(0);");

	// Convert the key into a nt_buffer
	memset(buffer_vector_size, 1, sizeof(buffer_vector_size));
	ocl_load(source, nt_buffer, buffer_vector_size, lenght, NUM_KEYS_OPENCL, 1);

	sprintf(source + strlen(source), "ulong A,B,C,D,E,F,G,H,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");

	ocl_convert_2_big_endian(source, nt_buffer[0], "W0");
	ocl_convert_2_big_endian(source, nt_buffer[1], "W1");
	ocl_convert_2_big_endian(source, nt_buffer[2], "W2");
	ocl_convert_2_big_endian(source, nt_buffer[3], "W3");
	ocl_convert_2_big_endian(source, nt_buffer[4], "W4");
	ocl_convert_2_big_endian(source, nt_buffer[5], "W5");
	ocl_convert_2_big_endian(source, nt_buffer[6], "W6");
	sprintf(source + strlen(source), "W15=0%s;", nt_buffer[7]);

	sprintf(source + strlen(source), 
		"W0=(W0<<32ul)+W1;"
		"W1=(W2<<32ul)+W3;"
		"W2=(W4<<32ul)+W5;"
		"W3=(W6<<32ul);");

	/* Round 1 */
	sprintf(source + strlen(source),
		"A=0x6A09E667F3BCC908UL;E=0x510E527FADE682D1UL;F=0x9B05688C2B3E6C1FUL;"

		"H=0x954d6b38bcfcddf5UL+W0;D=0x621b337bbdb8419cUL+H;"
		"G=R_E(D)+bs(F,E,D)+0x90bb1e3d1f312338UL+W1;C=0x3C6EF372FE94F82BUL+G;G+=R_A(H)+MAJ(H,A,0xBB67AE8584CAA73BUL);"
		"F=R_E(C)+bs(E,D,C)+0x50c6645c178ba74eUL+W2;B=0xBB67AE8584CAA73BUL+F;F+=R_A(G)+MAJ(G,H,A);"
		"E=R_E(B)+bs(D,C,B)+0x3ac42e252f705e8dUL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x3956C25BF348B538UL;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x59F111F1B605D019UL;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x923F82A4AF194F9BUL;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0xAB1C5ED5DA6D8118UL;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0xD807AA98A3030242UL;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0x12835B0145706FBEUL;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x243185BE4EE4B28CUL;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x550C7DC3D5FFB4E2UL;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x72BE5D74F27B896FUL;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x80DEB1FE3B1696B1UL;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x9BDC06A725C71235UL;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0xC19BF174CF692694UL+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");

	/* Round 2 */
	sprintf(source + strlen(source),
		"W0+=R0(W1);"
		"W1+=R1(W15)+R0(W2);"
		"W2+=R1(W0)+R0(W3);"
		"W3+=R1(W1);"
		"W4=R1(W2);"
		"W5=R1(W3);"
		"W6=R1(W4)+W15;"
		"W7=R1(W5)+W0;"
		"W8=R1(W6)+W1;"
		"W9=R1(W7)+W2;"
		"W10=R1(W8)+W3;"
		"W11=R1(W9)+W4;"
		"W12=R1(W10)+W5;"
		"W13=R1(W11)+W6;"
		"W14=R1(W12)+W7+R0(W15);"
		"W15+=R1(W13)+W8+R0(W0);");

	/* Round 2 */
	sprintf(source + strlen(source),
		"H+=R_E(E)+bs(G,F,E)+0xE49B69C19EF14AD2UL+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xEFBE4786384F25E3UL+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x0FC19DC68B8CD5B5UL+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x240CA1CC77AC9C65UL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x2DE92C6F592B0275UL+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x4A7484AA6EA6E483UL+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x5CB0A9DCBD41FBD4UL+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x76F988DA831153B5UL+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0x983E5152EE66DFABUL+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xA831C66D2DB43210UL+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0xB00327C898FB213FUL+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0xBF597FC7BEEF0EE4UL+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0xC6E00BF33DA88FC2UL+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0xD5A79147930AA725UL+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x06CA6351E003826FUL+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x142929670A0E6E70UL+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x27B70A8546D22FFCUL+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x2E1B21385C26C926UL+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x4D2C6DFC5AC42AEDUL+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x53380D139D95B3DFUL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x650A73548BAF63DEUL+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x766A0ABB3C77B2A8UL+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x81C2C92E47EDAEE6UL+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x92722C851482353BUL+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0xA2BFE8A14CF10364UL+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W9+=R1(W7)+W2+R0(W10);G+=R_E(D)+bs(F,E,D)+0xA81A664BBC423001UL+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W10+=R1(W8)+W3+R0(W11);F+=R_E(C)+bs(E,D,C)+0xC24B8B70D0F89791UL+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W11+=R1(W9)+W4+R0(W12);E+=R_E(B)+bs(D,C,B)+0xC76C51A30654BE30UL+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W12+=R1(W10)+W5+R0(W13);D+=R_E(A)+bs(C,B,A)+0xD192E819D6EF5218UL+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W13+=R1(W11)+W6+R0(W14);C+=R_E(H)+bs(B,A,H)+0xD69906245565A910UL+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W14+=R1(W12)+W7+R0(W15);B+=R_E(G)+bs(A,H,G)+0xF40E35855771202AUL+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W15+=R1(W13)+W8+R0(W0 );A+=R_E(F)+bs(H,G,F)+0x106AA07032BBD1B8UL+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");
	
	/* Round 4 */
	sprintf(source + strlen(source),
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x19A4C116B8D2D0C8UL+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x1E376C085141AB53UL+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x2748774CDF8EEB99UL+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x34B0BCB5E19B48A8UL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x391C0CB3C5C95A63UL+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x4ED8AA4AE3418ACBUL+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x5B9CCA4F7763E373UL+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x682E6FF3D6B2B8A3UL+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0x748F82EE5DEFB2FCUL+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W9+=R1(W7)+W2+R0(W10);G+=R_E(D)+bs(F,E,D)+0x78A5636F43172F60UL+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W10+=R1(W8)+W3+R0(W11);F+=R_E(C)+bs(E,D,C)+0x84C87814A1F0AB72UL+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W11+=R1(W9)+W4+R0(W12);E+=R_E(B)+bs(D,C,B)+0x8CC702081A6439ECUL+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W12+=R1(W10)+W5+R0(W13);D+=R_E(A)+bs(C,B,A)+0x90BEFFFA23631E28UL+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W13+=R1(W11)+W6+R0(W14);C+=R_E(H)+bs(B,A,H)+0xA4506CEBDE82BDE9UL+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W14+=R1(W12)+W7+R0(W15);B+=R_E(G)+bs(A,H,G)+0xBEF9A3F7B2C67915UL+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W15+=R1(W13)+W8+R0(W0);A+=R_E(F)+bs(H,G,F)+0xC67178F2E372532BUL+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");
			

	/* Round 5 */									   													  
	sprintf(source + strlen(source),				   													  
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0xCA273ECEEA26619CUL+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0xD186B8C721C0C207UL+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0xEADA7DD6CDE0EB1EUL+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0xF57D4F7FEE6ED178UL+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x06F067AA72176FBAUL+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x0A637DC5A2C898A6UL+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x113F9804BEF90DAEUL+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x1B710B35131C471BUL+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);"
		"W9+=R1(W7)+W2+R0(W10);"
		"W2=W11+R1(W9)+W4+R0(W12);"
		"W1=W13+R1(W2)+W6+R0(W14);"
		"W0=W15+R1(W1)+W8+R0(W0);A+=W0;");

	// Match
	if (num_passwords_loaded == 1)
	{
		uint64_t* bin = (uint64_t*)binary_values;

			if (found_param_3)
				sprintf(output_3, "output[3u]=%s;", found_param_3);

			sprintf(source + strlen(source),
			"if(A==%lluUL)"
			"{"
				"A-=W0;"
				"W10+=R1(W8)+W3+R0(W11);"
				"W12+=R1(W10)+W5+R0(W13);"
				"W14+=R1(W12)+W7+R0(W15);"

				"H+=R_E(E)+bs(G,F,E)+0x28DB77F523047D84UL+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
				"G+=R_E(D)+bs(F,E,D)+0x32CAAB7B40C72493UL+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
				"F+=R_E(C)+bs(E,D,C)+0x3C9EBE0A15C9BEBCUL+W10;B+=F;F+=MAJ(G,H,A);"
				"E+=R_E(B)+bs(D,C,B)+0x431D67C49C100D4CUL+W2;A+=E;"
				"D+=R_E(A)+bs(C,B,A)+0x4CC5D4BECB3E42B6UL+W12;H+=D;"
				"C+=R_E(H)+bs(B,A,H)+0x597F299CFC657E2AUL+W1;G+=C;"
				"B+=bs(A,H,G)+W14;"

				"if(B==%lluUL&&C==%lluUL&&D==%lluUL&&E==%lluUL&&F==%lluUL&&G==%lluUL&&H==%lluUL)"
				"{"
					"output[0]=1u;"
					"output[1]=get_global_id(0);"
					"output[2]=0;"
					"%s"
				"}"
			"}"
			, bin[0], bin[1], bin[2], bin[3], bin[4], bin[5], bin[6], bin[7], output_3);
	}
	else
	{
		if (found_param_3)
			sprintf(output_3, "output[3u*found+3u]=%s;", found_param_3);

		// Find match
		sprintf(source + strlen(source), "uint xx=((uint)A)&%uu;uint fdata;", cbg_mask);
		
		sprintf(source + strlen(source),
			"fdata=(uint)(cbg_filter[xx]);"

			"if(((fdata^((uint)(A>>32u)))&0xFFF8)==0){"
				"indx=cbg_table[xx];"
				"__global ulong* bin=(__global ulong*)binary_values;"
				"if(indx!=0xffffffff&&A==bin[indx*8u]){"

					"ulong aa=A-W0;"
					"W4=W10+R1(W8)+W3+R0(W11);"
					"W6=W12+R1(W4)+W5+R0(W13);"
					"ulong ww14=W14+R1(W6)+W7+R0(W15);"

					"ulong bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

					"hh+=R_E(ee)+bs(gg,ff,ee)+0x28DB77F523047D84UL+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
					"gg+=R_E(dd)+bs(ff,ee,dd)+0x32CAAB7B40C72493UL+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
					"ff+=R_E(cc)+bs(ee,dd,cc)+0x3C9EBE0A15C9BEBCUL+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
					"ee+=R_E(bb)+bs(dd,cc,bb)+0x431D67C49C100D4CUL+W2;aa+=ee;"
					"dd+=R_E(aa)+bs(cc,bb,aa)+0x4CC5D4BECB3E42B6UL+W6;hh+=dd;"
					"cc+=R_E(hh)+bs(bb,aa,hh)+0x597F299CFC657E2AUL+W1;gg+=cc;"
					"bb+=bs(aa,hh,gg)+ww14;"

					"if(bb==bin[indx*8u+1u]&&cc==bin[indx*8u+2u]&&dd==bin[indx*8u+3u]&&"
					"ee==bin[indx*8u+4u]&&ff==bin[indx*8u+5u]&&gg==bin[indx*8u+6u]&&"
					"hh==bin[indx*8u+7u]){"
						"uint found=atomic_inc(output);"
						"output[%iu*found+1]=get_global_id(0);"
						"output[%iu*found+2]=indx;"
						"%s"
					"}"
				"}"
			"}", found_multiplier, found_multiplier, output_3);
				
		sprintf(source + strlen(source),
			"if(fdata&4){"// Is second
				"xx+=fdata&1?-1:1;"
				"if(((((uint)cbg_filter[xx])^((uint)(A>>32u)))&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"__global ulong* bin=(__global ulong*)binary_values;"
					"if(indx!=0xffffffff&&A==bin[indx*8u]){"

						"ulong aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"ulong ww14=W14+R1(W6)+W7+R0(W15);"

						"ulong bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"hh+=R_E(ee)+bs(gg,ff,ee)+0x28DB77F523047D84UL+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
						"gg+=R_E(dd)+bs(ff,ee,dd)+0x32CAAB7B40C72493UL+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x3C9EBE0A15C9BEBCUL+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x431D67C49C100D4CUL+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x4CC5D4BECB3E42B6UL+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0x597F299CFC657E2AUL+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==bin[indx*8u+1u]&&cc==bin[indx*8u+2u]&&dd==bin[indx*8u+3u]&&"
						"ee==bin[indx*8u+4u]&&ff==bin[indx*8u+5u]&&gg==bin[indx*8u+6u]&&"
						"hh==bin[indx*8u+7u]){"
							"uint found=atomic_inc(output);"
							"output[%iu*found+1]=get_global_id(0);"
							"output[%iu*found+2]=indx;"
							"%s"
						"}"
					"}"
				"}"
			"}", found_multiplier, found_multiplier, output_3);

		sprintf(source + strlen(source),
			"if(fdata&2){"// Is unlucky
				"xx=((uint)(A>>32u))&%uu;"
				"fdata=(uint)(cbg_filter[xx]);"
				"if(((fdata^((uint)A))&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"__global ulong* bin=(__global ulong*)binary_values;"
					"if(indx!=0xffffffff&&A==bin[indx*8u]){"

						"ulong aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"ulong ww14=W14+R1(W6)+W7+R0(W15);"

						"ulong bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"hh+=R_E(ee)+bs(gg,ff,ee)+0x28DB77F523047D84UL+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
						"gg+=R_E(dd)+bs(ff,ee,dd)+0x32CAAB7B40C72493UL+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x3C9EBE0A15C9BEBCUL+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x431D67C49C100D4CUL+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x4CC5D4BECB3E42B6UL+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0x597F299CFC657E2AUL+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==bin[indx*8u+1u]&&cc==bin[indx*8u+2u]&&dd==bin[indx*8u+3u]&&"
						"ee==bin[indx*8u+4u]&&ff==bin[indx*8u+5u]&&gg==bin[indx*8u+6u]&&"
						"hh==bin[indx*8u+7u]){"
							"uint found=atomic_inc(output);"
							"output[%iu*found+1]=get_global_id(0);"
							"output[%iu*found+2]=indx;"
							"%s"
						"}"
					"}"
				"}"
			, cbg_mask, found_multiplier, found_multiplier, output_3);

		sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx])^((uint)A))&0xFFF8)==0){"
						"indx=cbg_table[xx];"
						"__global ulong* bin=(__global ulong*)binary_values;"
						"if(indx!=0xffffffff&&A==bin[indx*8u]){"

							"ulong aa=A-W0;"
							"W4=W10+R1(W8)+W3+R0(W11);"
							"W6=W12+R1(W4)+W5+R0(W13);"
							"ulong ww14=W14+R1(W6)+W7+R0(W15);"

							"ulong bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

							"hh+=R_E(ee)+bs(gg,ff,ee)+0x28DB77F523047D84UL+W8;dd+=hh;hh+=R_A(aa)+MAJ(aa,bb,cc);"
							"gg+=R_E(dd)+bs(ff,ee,dd)+0x32CAAB7B40C72493UL+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
							"ff+=R_E(cc)+bs(ee,dd,cc)+0x3C9EBE0A15C9BEBCUL+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
							"ee+=R_E(bb)+bs(dd,cc,bb)+0x431D67C49C100D4CUL+W2;aa+=ee;"
							"dd+=R_E(aa)+bs(cc,bb,aa)+0x4CC5D4BECB3E42B6UL+W6;hh+=dd;"
							"cc+=R_E(hh)+bs(bb,aa,hh)+0x597F299CFC657E2AUL+W1;gg+=cc;"
							"bb+=bs(aa,hh,gg)+ww14;"

							"if(bb==bin[indx*8u+1u]&&cc==bin[indx*8u+2u]&&dd==bin[indx*8u+3u]&&"
							"ee==bin[indx*8u+4u]&&ff==bin[indx*8u+5u]&&gg==bin[indx*8u+6u]&&"
							"hh==bin[indx*8u+7u]){"
								"uint found=atomic_inc(output);"
								"output[%iu*found+1]=get_global_id(0);"
								"output[%iu*found+2]=indx;"
								"%s"
							"}"
						"}"
					"}"
				"}"
			"}", found_multiplier, found_multiplier, output_3);
	}

	if (ocl_end)	ocl_end(source);
	// End of kernel
	strcat(source, "}");
}
PRIVATE void ocl_gen_kernel_sha512_uint2(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint value_map_collission, void* salt_param, cl_uint prefered_vector_size)
{
	char nt_buffer[16][16];
	char buffer_vector_size[16];
	// Needed when use a rule with more than one param
	int found_multiplier = found_param_3 ? 3 : 2;
	char output_3[64];
	output_3[0] = 0;

	// Function definition
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
	ocl_load(source, nt_buffer, buffer_vector_size, lenght, NUM_KEYS_OPENCL, 1);

	sprintf(source + strlen(source), "uint2 A,B,C,D,E,F,G,H,t0,t,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");

	ocl_convert_2_big_endian(source, nt_buffer[0], "W0.s1");
	ocl_convert_2_big_endian(source, nt_buffer[1], "W0.s0");
	ocl_convert_2_big_endian(source, nt_buffer[2], "W1.s1");
	ocl_convert_2_big_endian(source, nt_buffer[3], "W1.s0");
	ocl_convert_2_big_endian(source, nt_buffer[4], "W2.s1");
	ocl_convert_2_big_endian(source, nt_buffer[5], "W2.s0");
	ocl_convert_2_big_endian(source, nt_buffer[6], "W3.s1");
	sprintf(source + strlen(source), "W15.s0=0%s;"
									 "W15.s1=0u;"
									 "W3.s0=0u;", nt_buffer[7]);

	/* Round 1 */
	sprintf(source + strlen(source),
		"A.s0=0xF3BCC908;A.s1=0x6A09E667;B.s0=0x84CAA73B;B.s1=0xBB67AE85;C.s0=0xFE94F82B;C.s1=0x3C6EF372;E.s0=0xADE682D1;E.s1=0x510E527F;F.s0=0x2B3E6C1F;F.s1=0x9B05688C;"

		"ADD_CONST(H,W0,0x954d6b38,0xbcfcddf5);ADD_CONST(D,H,0x621b337b,0xbdb8419c);"
		"R_E(G,D);t0=bs(F,E,D);ADD(G,G,t0);ADD_CONST(G,G,0x90bb1e3d,0x1f312338);ADD(G,G,W1);ADD(C,C,G);R_A(t,H);ADD(G,G,t);t=MAJ(H,A,B);ADD(G,G,t);"
		"R_E(F,C);t0=bs(E,D,C);ADD(F,F,t0);ADD_CONST(F,F,0x50c6645c,0x178ba74e);ADD(F,F,W2);ADD(B,B,F);R_A(t,G);ADD(F,F,t);t=MAJ(G,H,A);ADD(F,F,t);"
		"R_E(E,B);t0=bs(D,C,B);ADD(E,E,t0);ADD_CONST(E,E,0x3ac42e25,0x2f705e8d);ADD(E,E,W3);ADD(A,A,E);R_A(t,F);ADD(E,E,t);t=MAJ(F,G,H);ADD(E,E,t);"
		"R_E(t,A);ADD(D,D,t);t0=bs(C,B,A);ADD(D,D,t0);ADD_CONST(D,D,0x3956C25B,0xF348B538);ADD(H,H,D);R_A(t,E);ADD(D,D,t);t=MAJ(E,F,G);ADD(D,D,t);"
		"R_E(t,H);ADD(C,C,t);t0=bs(B,A,H);ADD(C,C,t0);ADD_CONST(C,C,0x59F111F1,0xB605D019);ADD(G,G,C);R_A(t,D);ADD(C,C,t);t=MAJ(D,E,F);ADD(C,C,t);"
		"R_E(t,G);ADD(B,B,t);t0=bs(A,H,G);ADD(B,B,t0);ADD_CONST(B,B,0x923F82A4,0xAF194F9B);ADD(F,F,B);R_A(t,C);ADD(B,B,t);t=MAJ(C,D,E);ADD(B,B,t);"
		"R_E(t,F);ADD(A,A,t);t0=bs(H,G,F);ADD(A,A,t0);ADD_CONST(A,A,0xAB1C5ED5,0xDA6D8118);ADD(E,E,A);R_A(t,B);ADD(A,A,t);t=MAJ(B,C,D);ADD(A,A,t);"
		"R_E(t,E);ADD(H,H,t);t0=bs(G,F,E);ADD(H,H,t0);ADD_CONST(H,H,0xD807AA98,0xA3030242);ADD(D,D,H);R_A(t,A);ADD(H,H,t);t=MAJ(A,B,C);ADD(H,H,t);"
		"R_E(t,D);ADD(G,G,t);t0=bs(F,E,D);ADD(G,G,t0);ADD_CONST(G,G,0x12835B01,0x45706FBE);ADD(C,C,G);R_A(t,H);ADD(G,G,t);t=MAJ(H,A,B);ADD(G,G,t);"
		"R_E(t,C);ADD(F,F,t);t0=bs(E,D,C);ADD(F,F,t0);ADD_CONST(F,F,0x243185BE,0x4EE4B28C);ADD(B,B,F);R_A(t,G);ADD(F,F,t);t=MAJ(G,H,A);ADD(F,F,t);"
		"R_E(t,B);ADD(E,E,t);t0=bs(D,C,B);ADD(E,E,t0);ADD_CONST(E,E,0x550C7DC3,0xD5FFB4E2);ADD(A,A,E);R_A(t,F);ADD(E,E,t);t=MAJ(F,G,H);ADD(E,E,t);"
		"R_E(t,A);ADD(D,D,t);t0=bs(C,B,A);ADD(D,D,t0);ADD_CONST(D,D,0x72BE5D74,0xF27B896F);ADD(H,H,D);R_A(t,E);ADD(D,D,t);t=MAJ(E,F,G);ADD(D,D,t);"
		"R_E(t,H);ADD(C,C,t);t0=bs(B,A,H);ADD(C,C,t0);ADD_CONST(C,C,0x80DEB1FE,0x3B1696B1);ADD(G,G,C);R_A(t,D);ADD(C,C,t);t=MAJ(D,E,F);ADD(C,C,t);"
		"R_E(t,G);ADD(B,B,t);t0=bs(A,H,G);ADD(B,B,t0);ADD_CONST(B,B,0x9BDC06A7,0x25C71235);ADD(F,F,B);R_A(t,C);ADD(B,B,t);t=MAJ(C,D,E);ADD(B,B,t);"
		"R_E(t,F);ADD(A,A,t);t0=bs(H,G,F);ADD(A,A,t0);ADD_CONST(A,A,0xC19BF174,0xCF692694);ADD(A,A,W15);ADD(E,E,A);R_A(t,B);ADD(A,A,t);t=MAJ(B,C,D);ADD(A,A,t);");

	sprintf(source + strlen(source),
		"R0(t,W1);ADD(W0,W0,t);"
		"R1(t,W15);ADD(W1,W1,t);R0(t,W2);ADD(W1,W1,t);"
		"R1(t,W0);ADD(W2,W2,t);R0(t,W3);ADD(W2,W2,t);"
		"R1(t,W1);ADD(W3,W3,t);"
		"R1(W4,W2);"
		"R1(W5,W3);"
		"R1(W6,W4);ADD(W6,W6,W15);"
		"R1(W7,W5);ADD(W7,W7,W0);"
		"R1(W8,W6);ADD(W8,W8,W1);"
		"R1(W9,W7);ADD(W9,W9,W2);"
		"R1(W10,W8);ADD(W10,W10,W3);"
		"R1(W11,W9);ADD(W11,W11,W4);"
		"R1(W12,W10);ADD(W12,W12,W5);"
		"R1(W13,W11);ADD(W13,W13,W6);"
		"R1(W14,W12);ADD(W14,W14,W7);R0(t,W15);ADD(W14,W14,t);"
		"R1(t,W13);ADD(W15,W15,t);ADD(W15,W15,W8);R0(t,W0);ADD(W15,W15,t);");

	/* Round 2 */
	sprintf(source + strlen(source),
		"STEP(H,E,G,F,0xE49B69C1,0x9EF14AD2,W0,D,A,B,C);"
		"STEP(G,D,F,E,0xEFBE4786,0x384F25E3,W1,C,H,A,B);"
		"STEP(F,C,E,D,0x0FC19DC6,0x8B8CD5B5,W2,B,G,H,A);"
		"STEP(E,B,D,C,0x240CA1CC,0x77AC9C65,W3,A,F,G,H);"
		"STEP(D,A,C,B,0x2DE92C6F,0x592B0275,W4,H,E,F,G);"
		"STEP(C,H,B,A,0x4A7484AA,0x6EA6E483,W5,G,D,E,F);"
		"STEP(B,G,A,H,0x5CB0A9DC,0xBD41FBD4,W6,F,C,D,E);"
		"STEP(A,F,H,G,0x76F988DA,0x831153B5,W7,E,B,C,D);"
		"STEP(H,E,G,F,0x983E5152,0xEE66DFAB,W8,D,A,B,C);"
		"STEP(G,D,F,E,0xA831C66D,0x2DB43210,W9,C,H,A,B);"
		"STEP(F,C,E,D,0xB00327C8,0x98FB213F,W10,B,G,H,A);"
		"STEP(E,B,D,C,0xBF597FC7,0xBEEF0EE4,W11,A,F,G,H);"
		"STEP(D,A,C,B,0xC6E00BF3,0x3DA88FC2,W12,H,E,F,G);"
		"STEP(C,H,B,A,0xD5A79147,0x930AA725,W13,G,D,E,F);"
		"STEP(B,G,A,H,0x06CA6351,0xE003826F,W14,F,C,D,E);"
		"STEP(A,F,H,G,0x14292967,0x0A0E6E70,W15,E,B,C,D);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"WR(W0,W14,W9,W1);STEP(H,E,G,F,0x27B70A85,0x46D22FFC,W0,D,A,B,C);"
		"WR(W1,W15,W10,W2);STEP(G,D,F,E,0x2E1B2138,0x5C26C926,W1,C,H,A,B);"
		"WR(W2,W0,W11,W3);STEP(F,C,E,D,0x4D2C6DFC,0x5AC42AED,W2,B,G,H,A);"
		"WR(W3,W1,W12,W4);STEP(E,B,D,C,0x53380D13,0x9D95B3DF,W3,A,F,G,H);"
		"WR(W4,W2,W13,W5);STEP(D,A,C,B,0x650A7354,0x8BAF63DE,W4,H,E,F,G);"
		"WR(W5,W3,W14,W6);STEP(C,H,B,A,0x766A0ABB,0x3C77B2A8,W5,G,D,E,F);"
		"WR(W6,W4,W15,W7);STEP(B,G,A,H,0x81C2C92E,0x47EDAEE6,W6,F,C,D,E);"
		"WR(W7,W5,W0,W8);STEP(A,F,H,G,0x92722C85,0x1482353B,W7,E,B,C,D);"
		"WR(W8,W6,W1,W9);STEP(H,E,G,F,0xA2BFE8A1,0x4CF10364,W8,D,A,B,C);"
		"WR(W9,W7,W2,W10);STEP(G,D,F,E,0xA81A664B,0xBC423001,W9,C,H,A,B);"
		"WR(W10,W8,W3,W11);STEP(F,C,E,D,0xC24B8B70,0xD0F89791,W10,B,G,H,A);"
		"WR(W11,W9,W4,W12);STEP(E,B,D,C,0xC76C51A3,0x0654BE30,W11,A,F,G,H);"
		"WR(W12,W10,W5,W13);STEP(D,A,C,B,0xD192E819,0xD6EF5218,W12,H,E,F,G);"
		"WR(W13,W11,W6,W14);STEP(C,H,B,A,0xD6990624,0x5565A910,W13,G,D,E,F);"
		"WR(W14,W12,W7,W15);STEP(B,G,A,H,0xF40E3585,0x5771202A,W14,F,C,D,E);"
		"WR(W15,W13,W8,W0);STEP(A,F,H,G,0x106AA070,0x32BBD1B8,W15,E,B,C,D);");
	
	/* Round 4 */
	sprintf(source + strlen(source),
		"WR(W0,W14,W9,W1);STEP(H,E,G,F,0x19A4C116,0xB8D2D0C8,W0,D,A,B,C);"
		"WR(W1,W15,W10,W2);STEP(G,D,F,E,0x1E376C08,0x5141AB53,W1,C,H,A,B);"
		"WR(W2,W0,W11,W3);STEP(F,C,E,D,0x2748774C,0xDF8EEB99,W2,B,G,H,A);"
		"WR(W3,W1,W12,W4);STEP(E,B,D,C,0x34B0BCB5,0xE19B48A8,W3,A,F,G,H);"
		"WR(W4,W2,W13,W5);STEP(D,A,C,B,0x391C0CB3,0xC5C95A63,W4,H,E,F,G);"
		"WR(W5,W3,W14,W6);STEP(C,H,B,A,0x4ED8AA4A,0xE3418ACB,W5,G,D,E,F);"
		"WR(W6,W4,W15,W7);STEP(B,G,A,H,0x5B9CCA4F,0x7763E373,W6,F,C,D,E);"
		"WR(W7,W5,W0,W8);STEP(A,F,H,G,0x682E6FF3,0xD6B2B8A3,W7,E,B,C,D);"
		"WR(W8,W6,W1,W9);STEP(H,E,G,F,0x748F82EE,0x5DEFB2FC,W8,D,A,B,C);"
		"WR(W9,W7,W2,W10);STEP(G,D,F,E,0x78A5636F,0x43172F60,W9,C,H,A,B);"
		"WR(W10,W8,W3,W11);STEP(F,C,E,D,0x84C87814,0xA1F0AB72,W10,B,G,H,A);"
		"WR(W11,W9,W4,W12);STEP(E,B,D,C,0x8CC70208,0x1A6439EC,W11,A,F,G,H);"
		"WR(W12,W10,W5,W13);STEP(D,A,C,B,0x90BEFFFA,0x23631E28,W12,H,E,F,G);"
		"WR(W13,W11,W6,W14);STEP(C,H,B,A,0xA4506CEB,0xDE82BDE9,W13,G,D,E,F);"
		"WR(W14,W12,W7,W15);STEP(B,G,A,H,0xBEF9A3F7,0xB2C67915,W14,F,C,D,E);"
		"WR(W15,W13,W8,W0);STEP(A,F,H,G,0xC67178F2,0xE372532B,W15,E,B,C,D);");
			

	/* Round 5 */									   													  
	sprintf(source + strlen(source),
		"WR(W0,W14,W9,W1);STEP(H,E,G,F,0xCA273ECE,0xEA26619C,W0,D,A,B,C);"
		"WR(W1,W15,W10,W2);STEP(G,D,F,E,0xD186B8C7,0x21C0C207,W1,C,H,A,B);"
		"WR(W2,W0,W11,W3);STEP(F,C,E,D,0xEADA7DD6,0xCDE0EB1E,W2,B,G,H,A);"
		"WR(W3,W1,W12,W4);STEP(E,B,D,C,0xF57D4F7F,0xEE6ED178,W3,A,F,G,H);"
		"WR(W4,W2,W13,W5);STEP(D,A,C,B,0x06F067AA,0x72176FBA,W4,H,E,F,G);"
		"WR(W5,W3,W14,W6);STEP(C,H,B,A,0x0A637DC5,0xA2C898A6,W5,G,D,E,F);"
		"WR(W6,W4,W15,W7);STEP(B,G,A,H,0x113F9804,0xBEF90DAE,W6,F,C,D,E);"
		"WR(W7,W5,W0,W8);STEP(A,F,H,G,0x1B710B35,0x131C471B,W7,E,B,C,D);"
		"WR(W8,W6,W1,W9);"
		"WR(W9,W7,W2,W10);"
		"R1(W2,W9);ADD(W2,W2,W11);ADD(W2,W2,W4);R0(t,W12);ADD(W2,W2,t);"
		"R1(W1,W2);ADD(W1,W1,W13);ADD(W1,W1,W6);R0(t,W14);ADD(W1,W1,t);"
		"R0(t,W0);W0=t;R1(t,W1);ADD(W0,W0,t);ADD(W0,W0,W15);ADD(W0,W0,W8);ADD(A,A,W0);");

	// Match
	if (num_passwords_loaded == 1)
	{
		uint64_t* bin = (uint64_t*)binary_values;

		if (found_param_3)
			sprintf(output_3, "output[3u]=%s;", found_param_3);

		sprintf(source + strlen(source),
		"if(A.s0==%uu&&A.s1==%uu)"
		"{"
			"SUB(A,A,W0);"
			"WR(W10,W8,W3,W11);"
			"WR(W12,W10,W5,W13);"
			"WR(W14,W12,W7,W15);"
				
				"STEP(H,E,G,F,0x28DB77F5,0x23047D84,W8,D,A,B,C);"
				"STEP(G,D,F,E,0x32CAAB7B,0x40C72493,W9,C,H,A,B);"
			"STEP_1ST(F,C,E,D,0x3C9EBE0A,0x15C9BEBC,W10,B);t=MAJ(G,H,A);ADD(F,F,t);"
			"STEP_1ST(E,B,D,C,0x431D67C4,0x9C100D4C,W2,A);"
			"STEP_1ST(D,A,C,B,0x4CC5D4BE,0xCB3E42B6,W12,H);"
			"STEP_1ST(C,H,B,A,0x597F299C,0xFC657E2A,W1,G);"
			"ADD(B,B,W14);t=bs(A,H,G);ADD(B,B,t);"
				
			"if(B.s0==%uu&&B.s1==%uu&&C.s0==%uu&&C.s1==%uu&&D.s0==%uu&&D.s1==%uu&&"
				"E.s0==%uu&&E.s1==%uu&&F.s0==%uu&&F.s1==%uu&&G.s0==%uu&&G.s1==%uu&&H.s0==%uu&&H.s1==%uu)"
			"{"
				"output[0]=1u;"
				"output[1]=get_global_id(0);"
				"output[2]=0;"
				"%s"
			"}"
		"}"
		, (uint32_t)(bin[0]), (uint32_t)(bin[0]>>32)
		, (uint32_t)(bin[1]), (uint32_t)(bin[1]>>32)
		, (uint32_t)(bin[2]), (uint32_t)(bin[2]>>32)
		, (uint32_t)(bin[3]), (uint32_t)(bin[3]>>32)
		, (uint32_t)(bin[4]), (uint32_t)(bin[4]>>32)
		, (uint32_t)(bin[5]), (uint32_t)(bin[5]>>32)
		, (uint32_t)(bin[6]), (uint32_t)(bin[6]>>32)
		, (uint32_t)(bin[7]), (uint32_t)(bin[7]>>32), output_3);
	}
	else
	{
		if (found_param_3)
			sprintf(output_3, "output[3u*found+3u]=%s;", found_param_3);

		// Find match
		sprintf(source + strlen(source), "uint xx=A.s0&%uu;uint fdata;", cbg_mask);
		
		sprintf(source + strlen(source),
			"fdata=(uint)(cbg_filter[xx]);"

			"if(((fdata^A.s1)&0xFFF8)==0){"
				"indx=cbg_table[xx];"
				"if(indx!=0xffffffff&&A.s0==binary_values[indx*16u]&&A.s1==binary_values[indx*16u+1u]){"

					"uint2 aa,ww14;"
					"SUB(aa,A,W0);"
					"ADD(W4,W10,W3);R1(t,W8);ADD(W4,W4,t);R0(t,W11);ADD(W4,W4,t);"
					"ADD(W6,W12,W5);R1(t,W4);ADD(W6,W6,t);R0(t,W13);ADD(W6,W6,t);"
					"ADD(ww14,W14,W7);R1(t,W6);ADD(ww14,ww14,t);R0(t,W15);ADD(ww14,ww14,t);"

					"uint2 bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

					"STEP(hh,ee,gg,ff,0x28DB77F5,0x23047D84,W8,dd,aa,bb,cc);"
					"STEP(gg,dd,ff,ee,0x32CAAB7B,0x40C72493,W9,cc,hh,aa,bb);"
					"STEP_1ST(ff,cc,ee,dd,0x3C9EBE0A,0x15C9BEBC,W4,bb);t=MAJ(gg,hh,aa);ADD(ff,ff,t);"
					"STEP_1ST(ee,bb,dd,cc,0x431D67C4,0x9C100D4C,W2,aa);"
					"STEP_1ST(dd,aa,cc,bb,0x4CC5D4BE,0xCB3E42B6,W6,hh);"
					"STEP_1ST(cc,hh,bb,aa,0x597F299C,0xFC657E2A,W1,gg);"
					"ADD(bb,bb,ww14);t=bs(aa,hh,gg);ADD(bb,bb,t);"

					"if(bb.s0==binary_values[indx*16u+2u]&&bb.s1==binary_values[indx*16u+3u]&&cc.s0==binary_values[indx*16u+4u]&&cc.s1==binary_values[indx*16u+5u]&&"
					"dd.s0==binary_values[indx*16u+6u]&&dd.s1==binary_values[indx*16u+7u]&&ee.s0==binary_values[indx*16u+8u]&&ee.s1==binary_values[indx*16u+9u]&&"
					"ff.s0==binary_values[indx*16u+10u]&&ff.s1==binary_values[indx*16u+11u]&&gg.s0==binary_values[indx*16u+12u]&&gg.s1==binary_values[indx*16u+13u]&&"
					"hh.s0==binary_values[indx*16u+14u]&&hh.s1==binary_values[indx*16u+15u]){"
						"uint found=atomic_inc(output);"
						"output[%iu*found+1]=get_global_id(0);"
						"output[%iu*found+2]=indx;"
						"%s"
					"}"
				"}"
			"}", found_multiplier, found_multiplier, output_3);
				
		sprintf(source + strlen(source),
			"if(fdata&4){"// Is second
				"xx+=fdata&1?-1:1;"
				"if(((((uint)cbg_filter[xx])^A.s1)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&A.s0==binary_values[indx*16u]&&A.s1==binary_values[indx*16u+1u]){"

						"uint2 aa,ww14;"
						"SUB(aa,A,W0);"
						"ADD(W4,W10,W3);R1(t,W8);ADD(W4,W4,t);R0(t,W11);ADD(W4,W4,t);"
						"ADD(W6,W12,W5);R1(t,W4);ADD(W6,W6,t);R0(t,W13);ADD(W6,W6,t);"
						"ADD(ww14,W14,W7);R1(t,W6);ADD(ww14,ww14,t);R0(t,W15);ADD(ww14,ww14,t);"

						"uint2 bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"STEP(hh,ee,gg,ff,0x28DB77F5,0x23047D84,W8,dd,aa,bb,cc);"
						"STEP(gg,dd,ff,ee,0x32CAAB7B,0x40C72493,W9,cc,hh,aa,bb);"
						"STEP_1ST(ff,cc,ee,dd,0x3C9EBE0A,0x15C9BEBC,W4,bb);t=MAJ(gg,hh,aa);ADD(ff,ff,t);"
						"STEP_1ST(ee,bb,dd,cc,0x431D67C4,0x9C100D4C,W2,aa);"
						"STEP_1ST(dd,aa,cc,bb,0x4CC5D4BE,0xCB3E42B6,W6,hh);"
						"STEP_1ST(cc,hh,bb,aa,0x597F299C,0xFC657E2A,W1,gg);"
						"ADD(bb,bb,ww14);t=bs(aa,hh,gg);ADD(bb,bb,t);"

						"if(bb.s0==binary_values[indx*16u+2u]&&bb.s1==binary_values[indx*16u+3u]&&cc.s0==binary_values[indx*16u+4u]&&cc.s1==binary_values[indx*16u+5u]&&"
						"dd.s0==binary_values[indx*16u+6u]&&dd.s1==binary_values[indx*16u+7u]&&ee.s0==binary_values[indx*16u+8u]&&ee.s1==binary_values[indx*16u+9u]&&"
						"ff.s0==binary_values[indx*16u+10u]&&ff.s1==binary_values[indx*16u+11u]&&gg.s0==binary_values[indx*16u+12u]&&gg.s1==binary_values[indx*16u+13u]&&"
						"hh.s0==binary_values[indx*16u+14u]&&hh.s1==binary_values[indx*16u+15u]){"
							"uint found=atomic_inc(output);"
							"output[%iu*found+1]=get_global_id(0);"
							"output[%iu*found+2]=indx;"
							"%s"
						"}"
					"}"
				"}"
			"}", found_multiplier, found_multiplier, output_3);

		sprintf(source + strlen(source),
			"if(fdata&2){"// Is unlucky
				"xx=A.s1&%uu;"
				"fdata=(uint)(cbg_filter[xx]);"
				"if(((fdata^A.s0)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&A.s0==binary_values[indx*16u]&&A.s1==binary_values[indx*16u+1u]){"

						"uint2 aa,ww14;"
						"SUB(aa,A,W0);"
						"ADD(W4,W10,W3);R1(t,W8);ADD(W4,W4,t);R0(t,W11);ADD(W4,W4,t);"
						"ADD(W6,W12,W5);R1(t,W4);ADD(W6,W6,t);R0(t,W13);ADD(W6,W6,t);"
						"ADD(ww14,W14,W7);R1(t,W6);ADD(ww14,ww14,t);R0(t,W15);ADD(ww14,ww14,t);"

						"uint2 bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"STEP(hh,ee,gg,ff,0x28DB77F5,0x23047D84,W8,dd,aa,bb,cc);"
						"STEP(gg,dd,ff,ee,0x32CAAB7B,0x40C72493,W9,cc,hh,aa,bb);"
						"STEP_1ST(ff,cc,ee,dd,0x3C9EBE0A,0x15C9BEBC,W4,bb);t=MAJ(gg,hh,aa);ADD(ff,ff,t);"
						"STEP_1ST(ee,bb,dd,cc,0x431D67C4,0x9C100D4C,W2,aa);"
						"STEP_1ST(dd,aa,cc,bb,0x4CC5D4BE,0xCB3E42B6,W6,hh);"
						"STEP_1ST(cc,hh,bb,aa,0x597F299C,0xFC657E2A,W1,gg);"
						"ADD(bb,bb,ww14);t=bs(aa,hh,gg);ADD(bb,bb,t);"

						"if(bb.s0==binary_values[indx*16u+2u]&&bb.s1==binary_values[indx*16u+3u]&&cc.s0==binary_values[indx*16u+4u]&&cc.s1==binary_values[indx*16u+5u]&&"
						"dd.s0==binary_values[indx*16u+6u]&&dd.s1==binary_values[indx*16u+7u]&&ee.s0==binary_values[indx*16u+8u]&&ee.s1==binary_values[indx*16u+9u]&&"
						"ff.s0==binary_values[indx*16u+10u]&&ff.s1==binary_values[indx*16u+11u]&&gg.s0==binary_values[indx*16u+12u]&&gg.s1==binary_values[indx*16u+13u]&&"
						"hh.s0==binary_values[indx*16u+14u]&&hh.s1==binary_values[indx*16u+15u]){"
							"uint found=atomic_inc(output);"
							"output[%iu*found+1]=get_global_id(0);"
							"output[%iu*found+2]=indx;"
							"%s"
						"}"
					"}"
				"}"
			, cbg_mask, found_multiplier, found_multiplier, output_3);

		sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx])^A.s0)&0xFFF8)==0){"
						"indx=cbg_table[xx];"
						"if(indx!=0xffffffff&&A.s0==binary_values[indx*16u]&&A.s1==binary_values[indx*16u+1u]){"

							"uint2 aa,ww14;"
							"SUB(aa,A,W0);"
							"ADD(W4,W10,W3);R1(t,W8);ADD(W4,W4,t);R0(t,W11);ADD(W4,W4,t);"
							"ADD(W6,W12,W5);R1(t,W4);ADD(W6,W6,t);R0(t,W13);ADD(W6,W6,t);"
							"ADD(ww14,W14,W7);R1(t,W6);ADD(ww14,ww14,t);R0(t,W15);ADD(ww14,ww14,t);"

							"uint2 bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

							"STEP(hh,ee,gg,ff,0x28DB77F5,0x23047D84,W8,dd,aa,bb,cc);"
							"STEP(gg,dd,ff,ee,0x32CAAB7B,0x40C72493,W9,cc,hh,aa,bb);"
							"STEP_1ST(ff,cc,ee,dd,0x3C9EBE0A,0x15C9BEBC,W4,bb);t=MAJ(gg,hh,aa);ADD(ff,ff,t);"
							"STEP_1ST(ee,bb,dd,cc,0x431D67C4,0x9C100D4C,W2,aa);"
							"STEP_1ST(dd,aa,cc,bb,0x4CC5D4BE,0xCB3E42B6,W6,hh);"
							"STEP_1ST(cc,hh,bb,aa,0x597F299C,0xFC657E2A,W1,gg);"
							"ADD(bb,bb,ww14);t=bs(aa,hh,gg);ADD(bb,bb,t);"

							"if(bb.s0==binary_values[indx*16u+2u]&&bb.s1==binary_values[indx*16u+3u]&&cc.s0==binary_values[indx*16u+4u]&&cc.s1==binary_values[indx*16u+5u]&&"
							"dd.s0==binary_values[indx*16u+6u]&&dd.s1==binary_values[indx*16u+7u]&&ee.s0==binary_values[indx*16u+8u]&&ee.s1==binary_values[indx*16u+9u]&&"
							"ff.s0==binary_values[indx*16u+10u]&&ff.s1==binary_values[indx*16u+11u]&&gg.s0==binary_values[indx*16u+12u]&&gg.s1==binary_values[indx*16u+13u]&&"
							"hh.s0==binary_values[indx*16u+14u]&&hh.s1==binary_values[indx*16u+15u]){"
								"uint found=atomic_inc(output);"
								"output[%iu*found+1]=get_global_id(0);"
								"output[%iu*found+2]=indx;"
								"%s"
							"}"
						"}"
					"}"
				"}"
			"}", found_multiplier, found_multiplier, output_3);
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
	return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha512_header_uint2, ocl_gen_kernel_sha512_uint2, kernels2common + UTF8_INDEX_IN_KERNELS, 32, ocl_rule_simple_copy_utf8_le);
#else
	//return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha512_header_ulong, ocl_gen_kernel_sha512_ulong, kernels2common + UTF8_INDEX_IN_KERNELS, 4/*consider 2 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
	return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha512_header_uint2, ocl_gen_kernel_sha512_uint2, kernels2common + UTF8_INDEX_IN_KERNELS, 4/*consider 2 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
#endif

}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	//return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha512_header_ulong, ocl_gen_kernel_sha512_ulong, kernels2common + PHRASES_INDEX_IN_KERNELS, 64/*consider 32 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
	return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha512_header_uint2, ocl_gen_kernel_sha512_uint2, kernels2common + PHRASES_INDEX_IN_KERNELS, 64/*consider 32 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	//return ocl_rules_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha512_header_ulong, ocl_gen_kernel_sha512_ulong, RULE_UTF8_LE_INDEX, 8);
	return ocl_rules_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha512_header_uint2, ocl_gen_kernel_sha512_uint2, RULE_UTF8_LE_INDEX, 8);
}
#endif

Format raw_sha512_format = {
	"Raw-SHA512",
	"Raw SHA2-512 format.",
	"$SHA512$",
	NTLM_MAX_KEY_LENGHT,
	BINARY_SIZE,
	0,
	8,
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