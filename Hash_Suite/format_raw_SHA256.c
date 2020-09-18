// This file is part of Hash Suite password cracker,
// Copyright (c) 2015,2018 by Alain Espinosa. See LICENSE.

#include "common.h"
#include "attack.h"

//Initial values
#define INIT_A  0x6a09e667
#define INIT_B  0xbb67ae85
#define INIT_C  0x3c6ef372
#define INIT_D  0xa54ff53a
#define INIT_E  0x510e527f
#define INIT_F  0x9b05688c
#define INIT_G  0x1f83d9ab
#define INIT_H  0x5be0cd19

#define BINARY_SIZE			32
#define NTLM_MAX_KEY_LENGHT	27

#define R_E(x) (ROTATE(x,26) ^ ROTATE(x,21) ^ ROTATE(x,7 ))
#define R_A(x) (ROTATE(x,30) ^ ROTATE(x,19) ^ ROTATE(x,10))
#define R0(x)  (ROTATE(x,25) ^ ROTATE(x,14) ^ (x>>3))
#define R1(x)  (ROTATE(x,15) ^ ROTATE(x,13) ^ (x>>10))

PRIVATE int is_valid(char* user_name, char* sha256, char* unused, char* unused1)
{
	if (user_name)
	{
		char* hash = sha256 ? sha256 : user_name;

		if (valid_hex_string(hash, 64) || valid_base64_string(hash, 43) || (!memcmp(hash, "$SHA256$", 8) && valid_hex_string(hash+8, 64)) || (!memcmp(hash, "$cisco4$", 8) && valid_base64_string(hash+8, 43)))
			return TRUE;
	}

	return FALSE;
}

PRIVATE sqlite3_int64 add_hash_from_line(ImportParam* param, char* user_name, char* sha256, char* unused, char* unused1)
{
	if (user_name)
	{
		char* hash = sha256 ? sha256 : user_name;
		char* user = sha256 ? user_name : NULL;

		if (valid_hex_string(hash, 64))
			return insert_hash_account1(param, user, _strupr(hash), SHA256_INDEX);

		if (!memcmp(hash, "$SHA256$", 8) && valid_hex_string(hash+8, 64))
			return insert_hash_account1(param, user, _strupr(hash+8), SHA256_INDEX);

		if (valid_base64_string(hash, 43) || (!memcmp(hash, "$cisco4$", 8) && valid_base64_string(hash + 8, 43)))
		{
			const char* itoa16 = "0123456789ABCDEF";
			unsigned char hex[65];
			char* p = !memcmp(hash, "$cisco4$", 8) ? hash + 8 : hash;
			char* o = hex;
			
			while(*p)
			{
				uint32_t ch, b;

				// Get 1st byte of input (1st and 2nd)
				ch = *p++;
				b = ((base64_to_num[ch] << 2) & 252) + (base64_to_num[*p] >> 4 & 0x03);
				*o++ = itoa16[b >> 4];
				*o++ = itoa16[b & 0x0f];

				// Get 2nd byte of input (2nd and 3rd)
				ch = *p++;
				b = ((base64_to_num[ch] << 4) & 240) + (base64_to_num[*p] >> 2 & 0x0f);
				*o++ = itoa16[b >> 4];
				*o++ = itoa16[b & 0x0f];

				if (!p[1])
					break;

				// Get 3rd byte of input (3rd and 4th)
				ch = *p++;
				b = ((base64_to_num[ch] << 6) & 192) + (base64_to_num[*p++] & 0x3f);
				*o++ = itoa16[b >> 4];
				*o++ = itoa16[b & 0x0f];
			}
			hex[64] = 0;

			return insert_hash_account1(param, user, hex, SHA256_INDEX);
		}
	}

	return -1;
}
#define VALUE_MAP_INDEX0 0
#define VALUE_MAP_INDEX1 7
PRIVATE uint32_t get_binary(const unsigned char* ciphertext, void* binary, void* salt)
{
	uint32_t* out = (uint32_t*)binary;

	for (uint32_t i = 0; i < 8; i++)
	{
		uint32_t temp = (hex_to_num[ciphertext[i * 8 + 0]]) << 28;
		temp |= (hex_to_num[ciphertext[i * 8 + 1]]) << 24;
		
		temp |= (hex_to_num[ciphertext[i * 8 + 2]]) << 20;
		temp |= (hex_to_num[ciphertext[i * 8 + 3]]) << 16;
		
		temp |= (hex_to_num[ciphertext[i * 8 + 4]]) << 12;
		temp |= (hex_to_num[ciphertext[i * 8 + 5]]) << 8;
		
		temp |= (hex_to_num[ciphertext[i * 8 + 6]]) << 4;
		temp |= (hex_to_num[ciphertext[i * 8 + 7]]) << 0;

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

	//A += R_A(B) + ((B & C) | (D & (B | C)));										E += A;			A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC67178F2;
	out[0] -= R_A(out[1]) + ((out[1] & out[2]) | (out[3] & (out[1] | out[2]))); out[4] -= out[0]; out[0] -= R_E(out[5]) + (out[7] ^ (out[5] & (out[6] ^ out[7]))) + 0xC67178F2;

	//B += R_A(C) + ((C & D) | (E & (C | D)));                                   F += B;            B    +=   R_E(G)    + 0xBEF9A3F7
	out[1] -= R_A(out[2]) + ((out[2] & out[3]) | (out[4] & (out[2] | out[3]))); out[5] -= out[1]; out[1] -= R_E(out[6]) + 0xBEF9A3F7;

	// C += R_A(D) + ((D & E) | (F & (D | E)));
	out[2] -= R_A(out[3]) + ((out[3] & out[4]) | (out[5] & (out[3] | out[4])));

	// G += C;                         D += R_A(E) + ((E & F) | (G & (E | F)));
	uint32_t G = out[6] - out[2]; out[3] -= R_A(out[4]) + ((out[4] & out[5]) | (G & (out[4] | out[5])));

	// H += D;                        E += R_A(F) + ((F & G) | (H & (F | G)));
	uint32_t H = out[7] - out[3]; out[4] -= R_A(out[5]) + ((out[5] & G) | (H & (out[5] | G)));

	// F += R_A(G)
	out[5] -= R_A(G);

	// A += E;
	out[0] -= out[4];

	out[7] -= out[3];

	return out[0];
}
PRIVATE void binary2hex(const void* binary, const void* salt, unsigned char* ciphertext)
{
	uint32_t bin[BINARY_SIZE / sizeof(uint32_t)];
	memcpy(bin, binary, BINARY_SIZE);

	bin[7] += bin[3];

	// A += E;
	bin[0] += bin[4];
	// F += R_A(G)
	uint32_t G = bin[6] - bin[2];
	bin[5] += R_A(G);
	// H += D;                        E += R_A(F) + ((F & G) | (H & (F | G)));
	uint32_t H = bin[7] - bin[3]; bin[4] += R_A(bin[5]) + ((bin[5] & G) | (H & (bin[5] | G)));
	// G += C;                         D += R_A(E) + ((E & F) | (G & (E | F)));
	bin[3] += R_A(bin[4]) + ((bin[4] & bin[5]) | (G & (bin[4] | bin[5])));
	// C += R_A(D) + ((D & E) | (F & (D | E)));
	bin[2] += R_A(bin[3]) + ((bin[3] & bin[4]) | (bin[5] & (bin[3] | bin[4])));
	//B += R_A(C) + ((C & D) | (E & (C | D)));                                   F += B;            B    +=   R_E(G)    + 0xBEF9A3F7
	bin[1] += R_E(bin[6]) + 0xBEF9A3F7; bin[5] += bin[1]; bin[1] += R_A(bin[2]) + ((bin[2] & bin[3]) | (bin[4] & (bin[2] | bin[3])));
	//A += R_A(B) + ((B & C) | (D & (B | C)));										E += A;			A += R_E(F) + (H ^ (F & (G ^ H))) + 0xC67178F2;
	bin[0] += R_E(bin[5]) + (bin[7] ^ (bin[5] & (bin[6] ^ bin[7]))) + 0xC67178F2; bin[4] += bin[0]; bin[0] += R_A(bin[1]) + ((bin[1] & bin[2]) | (bin[3] & (bin[1] | bin[2])));

	// Reverse
	bin[0] += INIT_A;
	bin[1] += INIT_B;
	bin[2] += INIT_C;
	bin[3] += INIT_D;
	bin[4] += INIT_E;
	bin[5] += INIT_F;
	bin[6] += INIT_G;
	bin[7] += INIT_H;

	binary_to_hex(bin, ciphertext, BINARY_SIZE / sizeof(uint32_t), FALSE);
}

#ifdef HS_ARM
	#define NT_NUM_KEYS		    128
#endif

#ifdef HS_X86
	#define NT_NUM_KEYS		    256
#endif

PRIVATE uint32_t compare_elem(uint32_t i, uint32_t cbg_table_pos, uint32_t* unpacked_W)
{
	if (cbg_table_pos == NO_ELEM) return FALSE;

	uint32_t* bin = ((uint32_t*)binary_values) + cbg_table_pos * 8;

	uint32_t* unpacked_as = unpacked_W + 4 * NT_NUM_KEYS;
	uint32_t* unpacked_bs = unpacked_W + 16 * NT_NUM_KEYS;
	uint32_t* unpacked_cs = unpacked_bs + NT_NUM_KEYS;
	uint32_t* unpacked_ds = unpacked_cs + NT_NUM_KEYS;
	uint32_t* unpacked_es = unpacked_ds + NT_NUM_KEYS;
	uint32_t* unpacked_fs = unpacked_es + NT_NUM_KEYS;
	uint32_t* unpacked_gs = unpacked_fs + NT_NUM_KEYS;
	uint32_t* unpacked_hs = unpacked_W + 6 * NT_NUM_KEYS;

	if (unpacked_as[i] != bin[0] || unpacked_hs[i] != bin[7]) return FALSE;

	uint32_t aa = unpacked_as[i], bb, cc, dd, ee, ff, gg, hh, W10, W12, W14;
	uint32_t* W = unpacked_W + i;

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

	gg += R_E(dd) + (ff ^ (dd & (ee ^ ff))) + 0x78A5636F + W[9 * NT_NUM_KEYS]; cc += gg; gg += R_A(hh) + ((hh & aa) | (bb & (hh | aa)));
	ff += R_E(cc) + (ee ^ (cc & (dd ^ ee))) + 0x84C87814 + W10               ; bb += ff; ff +=           ((gg & hh) | (aa & (gg | hh)));
	ee += R_E(bb) + (dd ^ (bb & (cc ^ dd))) + 0x8CC70208 + W[2 * NT_NUM_KEYS]; aa += ee;
	dd += R_E(aa) + (cc ^ (aa & (bb ^ cc))) + 0x90BEFFFA + W12               ; hh += dd;
	cc += R_E(hh) + (bb ^ (hh & (aa ^ bb))) + 0xA4506CEB + W[1 * NT_NUM_KEYS]; gg += cc;
	bb +=           (aa ^ (gg & (hh ^ aa)))              + W14 ;

	if (bb != bin[1] || cc != bin[2] || dd != bin[3] || ee != bin[4] || ff != bin[5] || gg != bin[6])
		return FALSE;

	return TRUE;
}

PRIVATE void crypt_utf8_coalesc_protocol_body(CryptParam* param, crypt_kernel_asm_func* crypt_kernel_asm)
{
	uint32_t* nt_buffer = (uint32_t*)_aligned_malloc((8+16+6) * sizeof(uint32_t) * NT_NUM_KEYS, 64);

	uint32_t* unpacked_W  = nt_buffer  + 8 * NT_NUM_KEYS;
	uint32_t* unpacked_as = unpacked_W + 4 * NT_NUM_KEYS;
	uint32_t* unpacked_hs = unpacked_W + 6 * NT_NUM_KEYS;

	unsigned char key[MAX_KEY_LENGHT_SMALL];

	memset(nt_buffer, 0, 8 * sizeof(uint32_t)* NT_NUM_KEYS);
	memset(key, 0, sizeof(key));

	while (continue_attack && param->gen(nt_buffer, NT_NUM_KEYS, param->thread_id))
	{
		crypt_kernel_asm(nt_buffer);

		for (uint32_t i = 0; i < NT_NUM_KEYS; i++)
		{
			uint32_t up0 = unpacked_as[i];
			uint32_t up1 = unpacked_hs[i];

			uint32_t pos = up0 & cbg_mask;
			uint_fast16_t data = cbg_filter[pos];
			if (((data ^ up1) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], unpacked_W))
				password_was_found(cbg_table[pos], utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match

			// 2nd pos
			if (data & 0b110)
			{
				pos += data & 0b1 ? -1 : 1;
				uint_fast16_t hash = cbg_filter[pos];
				if (((hash ^ up1) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], unpacked_W))
					password_was_found(cbg_table[pos], utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match

				// Unluky bucket
				if (data & 0b10)
				{
					pos = up1 & cbg_mask;
					data = cbg_filter[pos];
					if (((data ^ up0) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], unpacked_W))
						password_was_found(cbg_table[pos], utf8_coalesc2utf8_key(nt_buffer, key, NT_NUM_KEYS, i));// Total match

					// 2nd pos
					pos += data & 0b1 ? -1 : 1;
					hash = cbg_filter[pos];
					if (((hash ^ up0) & 0xFFF8) == 0 && compare_elem(i, cbg_table[pos], unpacked_W))
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
PRIVATE void crypt_kernel_c_code(uint32_t* nt_buffer)
{
	uint32_t A, B, C, D, E, F, G, H;
	uint32_t* W = nt_buffer + 8 * NT_NUM_KEYS;

	for (int i = 0; i < NT_NUM_KEYS; i++, nt_buffer++, W++)
	{
		W[0 * NT_NUM_KEYS] = _byteswap_ulong(nt_buffer[0 * NT_NUM_KEYS]);
		W[1 * NT_NUM_KEYS] = _byteswap_ulong(nt_buffer[1 * NT_NUM_KEYS]);
		W[2 * NT_NUM_KEYS] = _byteswap_ulong(nt_buffer[2 * NT_NUM_KEYS]);
		W[3 * NT_NUM_KEYS] = _byteswap_ulong(nt_buffer[3 * NT_NUM_KEYS]);
		W[4 * NT_NUM_KEYS] = _byteswap_ulong(nt_buffer[4 * NT_NUM_KEYS]);
		W[5 * NT_NUM_KEYS] = _byteswap_ulong(nt_buffer[5 * NT_NUM_KEYS]);
		W[6 * NT_NUM_KEYS] = _byteswap_ulong(nt_buffer[6 * NT_NUM_KEYS]);
		W[15 * NT_NUM_KEYS] = nt_buffer[7 * NT_NUM_KEYS];

		/* Rounds */
		H  = 0xfc08884d + W[0 * NT_NUM_KEYS];											D=0x9cbf5a55+H;
		G  = R_E(D) + (INIT_F ^ (D & 0xca0b3af3  )) + 0x90bb1e3c + W[ 1 * NT_NUM_KEYS]; C=INIT_C+G; G += R_A(H) + ((H & INIT_A) | (INIT_B & (H | INIT_A)));
		F  = R_E(C) + (INIT_E ^ (C & (D ^ INIT_E))) + 0x50c6645b + W[ 2 * NT_NUM_KEYS]; B=INIT_B+F; F += R_A(G) + ((G & H) | (INIT_A & (G | H)));
		E  = R_E(B) + (D ^ (B & (C ^ D)))			+ 0x3ac42e24 + W[ 3 * NT_NUM_KEYS]; A=INIT_A+E; E += R_A(F) + ((F & G) | (H & (F | G)));
		D += R_E(A) + (C ^ (A & (B ^ C)))			+ 0x3956C25B + W[ 4 * NT_NUM_KEYS]; H += D;	    D += R_A(E) + ((E & F) | (G & (E | F)));
		C += R_E(H) + (B ^ (H & (A ^ B)))			+ 0x59F111F1 + W[ 5 * NT_NUM_KEYS]; G += C;	    C += R_A(D) + ((D & E) | (F & (D | E)));
		B += R_E(G) + (A ^ (G & (H ^ A)))			+ 0x923F82A4 + W[ 6 * NT_NUM_KEYS]; F += B;	    B += R_A(C) + ((C & D) | (E & (C | D)));
		A += R_E(F) + (H ^ (F & (G ^ H)))			+ 0xAB1C5ED5                      ; E += A;	    A += R_A(B) + ((B & C) | (D & (B | C)));
		H += R_E(E) + (G ^ (E & (F ^ G)))			+ 0xD807AA98                      ; D += H;	    H += R_A(A) + ((A & B) | (C & (A | B)));
		G += R_E(D) + (F ^ (D & (E ^ F)))			+ 0x12835B01                      ; C += G;	    G += R_A(H) + ((H & A) | (B & (H | A)));
		F += R_E(C) + (E ^ (C & (D ^ E)))			+ 0x243185BE                      ; B += F;	    F += R_A(G) + ((G & H) | (A & (G | H)));
		E += R_E(B) + (D ^ (B & (C ^ D)))			+ 0x550C7DC3                      ; A += E;	    E += R_A(F) + ((F & G) | (H & (F | G)));
		D += R_E(A) + (C ^ (A & (B ^ C)))			+ 0x72BE5D74                      ; H += D;	    D += R_A(E) + ((E & F) | (G & (E | F)));
		C += R_E(H) + (B ^ (H & (A ^ B)))			+ 0x80DEB1FE                      ; G += C;	    C += R_A(D) + ((D & E) | (F & (D | E)));
		B += R_E(G) + (A ^ (G & (H ^ A)))			+ 0x9BDC06A7                      ; F += B;	    B += R_A(C) + ((C & D) | (E & (C | D)));
		A += R_E(F) + (H ^ (F & (G ^ H)))			+ 0xC19BF174 + W[15 * NT_NUM_KEYS]; E += A;	    A += R_A(B) + ((B & C) | (D & (B | C)));

		W[ 0 * NT_NUM_KEYS] +=					                               R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xE49B69C1 + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS])                       + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xEFBE4786 + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS])                       + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x0FC19DC6 + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS])                       + R0(W[4  * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x240CA1CC + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS] += R1(W[2  * NT_NUM_KEYS])                       + R0(W[5  * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x2DE92C6F + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS] += R1(W[3  * NT_NUM_KEYS])                       + R0(W[6  * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4A7484AA + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS] += R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS]                          ; B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5CB0A9DC + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS]  = R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS]                          ; A += R_E(F) + (H ^ (F & (G ^ H))) + 0x76F988DA + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS]  = R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS]                          ; H += R_E(E) + (G ^ (E & (F ^ G))) + 0x983E5152 + W[ 8 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 9 * NT_NUM_KEYS]  = R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS]                          ; G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA831C66D + W[ 9 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[10 * NT_NUM_KEYS]  = R1(W[8  * NT_NUM_KEYS]) + W[3  * NT_NUM_KEYS]                          ; F += R_E(C) + (E ^ (C & (D ^ E))) + 0xB00327C8 + W[10 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[11 * NT_NUM_KEYS]  = R1(W[9  * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS]                          ; E += R_E(B) + (D ^ (B & (C ^ D))) + 0xBF597FC7 + W[11 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[12 * NT_NUM_KEYS]  = R1(W[10 * NT_NUM_KEYS]) + W[5  * NT_NUM_KEYS]                          ; D += R_E(A) + (C ^ (A & (B ^ C))) + 0xC6E00BF3 + W[12 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[13 * NT_NUM_KEYS]  = R1(W[11 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS]                          ; C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD5A79147 + W[13 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[14 * NT_NUM_KEYS]  = R1(W[12 * NT_NUM_KEYS]) + W[7  * NT_NUM_KEYS] + R0(W[15 * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x06CA6351 + W[14 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[15 * NT_NUM_KEYS] += R1(W[13 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x14292967 + W[15 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																    
		W[ 0 * NT_NUM_KEYS] += R1(W[14 * NT_NUM_KEYS]) + W[9  * NT_NUM_KEYS] + R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x27B70A85 + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS]) + W[10 * NT_NUM_KEYS] + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x2E1B2138 + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS]) + W[11 * NT_NUM_KEYS] + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x4D2C6DFC + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS]) + W[12 * NT_NUM_KEYS] + R0(W[4  * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x53380D13 + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS] += R1(W[2  * NT_NUM_KEYS]) + W[13 * NT_NUM_KEYS] + R0(W[5  * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x650A7354 + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS] += R1(W[3  * NT_NUM_KEYS]) + W[14 * NT_NUM_KEYS] + R0(W[6  * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x766A0ABB + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS] += R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS] + R0(W[7  * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x81C2C92E + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS] += R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS] + R0(W[8  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x92722C85 + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS] += R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS] + R0(W[9  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0xA2BFE8A1 + W[ 8 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 9 * NT_NUM_KEYS] += R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS] + R0(W[10 * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0xA81A664B + W[ 9 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[10 * NT_NUM_KEYS] += R1(W[8  * NT_NUM_KEYS]) + W[3  * NT_NUM_KEYS] + R0(W[11 * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0xC24B8B70 + W[10 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[11 * NT_NUM_KEYS] += R1(W[9  * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS] + R0(W[12 * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0xC76C51A3 + W[11 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[12 * NT_NUM_KEYS] += R1(W[10 * NT_NUM_KEYS]) + W[5  * NT_NUM_KEYS] + R0(W[13 * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0xD192E819 + W[12 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[13 * NT_NUM_KEYS] += R1(W[11 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS] + R0(W[14 * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0xD6990624 + W[13 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[14 * NT_NUM_KEYS] += R1(W[12 * NT_NUM_KEYS]) + W[7  * NT_NUM_KEYS] + R0(W[15 * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0xF40E3585 + W[14 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[15 * NT_NUM_KEYS] += R1(W[13 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x106AA070 + W[15 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
																    
		W[ 0 * NT_NUM_KEYS] += R1(W[14 * NT_NUM_KEYS]) + W[9  * NT_NUM_KEYS] + R0(W[1  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x19A4C116 + W[ 0 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		W[ 1 * NT_NUM_KEYS] += R1(W[15 * NT_NUM_KEYS]) + W[10 * NT_NUM_KEYS] + R0(W[2  * NT_NUM_KEYS]); G += R_E(D) + (F ^ (D & (E ^ F))) + 0x1E376C08 + W[ 1 * NT_NUM_KEYS]; C += G; G += R_A(H) + ((H & A) | (B & (H | A)));
		W[ 2 * NT_NUM_KEYS] += R1(W[0  * NT_NUM_KEYS]) + W[11 * NT_NUM_KEYS] + R0(W[3  * NT_NUM_KEYS]); F += R_E(C) + (E ^ (C & (D ^ E))) + 0x2748774C + W[ 2 * NT_NUM_KEYS]; B += F; F += R_A(G) + ((G & H) | (A & (G | H)));
		W[ 3 * NT_NUM_KEYS] += R1(W[1  * NT_NUM_KEYS]) + W[12 * NT_NUM_KEYS] + R0(W[4  * NT_NUM_KEYS]); E += R_E(B) + (D ^ (B & (C ^ D))) + 0x34B0BCB5 + W[ 3 * NT_NUM_KEYS]; A += E; E += R_A(F) + ((F & G) | (H & (F | G)));
		W[ 4 * NT_NUM_KEYS] += R1(W[2  * NT_NUM_KEYS]) + W[13 * NT_NUM_KEYS] + R0(W[5  * NT_NUM_KEYS]); D += R_E(A) + (C ^ (A & (B ^ C))) + 0x391C0CB3 + W[ 4 * NT_NUM_KEYS]; H += D; D += R_A(E) + ((E & F) | (G & (E | F)));
		W[ 5 * NT_NUM_KEYS] += R1(W[3  * NT_NUM_KEYS]) + W[14 * NT_NUM_KEYS] + R0(W[6  * NT_NUM_KEYS]); C += R_E(H) + (B ^ (H & (A ^ B))) + 0x4ED8AA4A + W[ 5 * NT_NUM_KEYS]; G += C; C += R_A(D) + ((D & E) | (F & (D | E)));
		W[ 6 * NT_NUM_KEYS] += R1(W[4  * NT_NUM_KEYS]) + W[15 * NT_NUM_KEYS] + R0(W[7  * NT_NUM_KEYS]); B += R_E(G) + (A ^ (G & (H ^ A))) + 0x5B9CCA4F + W[ 6 * NT_NUM_KEYS]; F += B; B += R_A(C) + ((C & D) | (E & (C | D)));
		W[ 7 * NT_NUM_KEYS] += R1(W[5  * NT_NUM_KEYS]) + W[0  * NT_NUM_KEYS] + R0(W[8  * NT_NUM_KEYS]); A += R_E(F) + (H ^ (F & (G ^ H))) + 0x682E6FF3 + W[ 7 * NT_NUM_KEYS]; E += A; A += R_A(B) + ((B & C) | (D & (B | C)));
		W[ 8 * NT_NUM_KEYS] += R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS] + R0(W[9  * NT_NUM_KEYS]); H += R_E(E) + (G ^ (E & (F ^ G))) + 0x748F82EE + W[ 8 * NT_NUM_KEYS]; D += H; H += R_A(A) + ((A & B) | (C & (A | B)));
		//W[ 8 * NT_NUM_KEYS] += R1(W[6  * NT_NUM_KEYS]) + W[1  * NT_NUM_KEYS] + R0(W[9  * NT_NUM_KEYS]);
		W[ 9 * NT_NUM_KEYS] += R1(W[7  * NT_NUM_KEYS]) + W[2  * NT_NUM_KEYS] + R0(W[10 * NT_NUM_KEYS]);
		W[2 * NT_NUM_KEYS] = W[11 * NT_NUM_KEYS] + R1(W[9 * NT_NUM_KEYS]) + W[4  * NT_NUM_KEYS] + R0(W[12 * NT_NUM_KEYS]);
		W[1 * NT_NUM_KEYS] = W[13 * NT_NUM_KEYS] + R1(W[2 * NT_NUM_KEYS]) + W[6  * NT_NUM_KEYS] + R0(W[14 * NT_NUM_KEYS]);
		W[0 * NT_NUM_KEYS] = W[15 * NT_NUM_KEYS] + R1(W[1 * NT_NUM_KEYS]) + W[8  * NT_NUM_KEYS] + R0(W[0  * NT_NUM_KEYS]); A += W[0 * NT_NUM_KEYS]; 

		W[4  * NT_NUM_KEYS] = A;
		W[16 * NT_NUM_KEYS] = B;
		W[17 * NT_NUM_KEYS] = C;
		W[18 * NT_NUM_KEYS] = D;
		W[19 * NT_NUM_KEYS] = E;
		W[20 * NT_NUM_KEYS] = F;
		W[21 * NT_NUM_KEYS] = G;
		W[6  * NT_NUM_KEYS] = H;
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

void crypt_sha256_neon_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_utf8_coalesc_protocol_neon(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_sha256_neon_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SSE2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86
#include "arch_simd.h"

#define SHA1_NUM		(NT_NUM_KEYS/4)
#define LOAD_BIG_ENDIAN_SSE2(x,data) x = SSE2_ROTATE(data, 16); x = SSE2_ADD(_mm_slli_epi32(SSE2_AND(x, mask), 8), SSE2_AND(_mm_srli_epi32(x, 8), mask));

#undef R_E
#undef R_A
#undef R0
#undef R1
#define R_E(x) SSE2_3XOR(SSE2_ROTATE(x,26), SSE2_ROTATE(x,21), SSE2_ROTATE(x,7 ))
#define R_A(x) SSE2_3XOR(SSE2_ROTATE(x,30), SSE2_ROTATE(x,19), SSE2_ROTATE(x,10))
#define R0(x)  SSE2_3XOR(SSE2_ROTATE(x,25), SSE2_ROTATE(x,14), SSE2_SR(x,3))
#define R1(x)  SSE2_3XOR(SSE2_ROTATE(x,15), SSE2_ROTATE(x,13), SSE2_SR(x,10))

PRIVATE void crypt_kernel_sse2(SSE2_WORD* nt_buffer)
{
	SSE2_WORD* W = nt_buffer + 8 * SHA1_NUM;
	SSE2_WORD mask = SSE2_CONST(0x00FF00FF);
	SSE2_WORD A, B, C, D, E, F, G, H;

	for (int i = 0; i < SHA1_NUM; i++, nt_buffer++, W++)
	{
		LOAD_BIG_ENDIAN_SSE2(W[0*SHA1_NUM], nt_buffer[0*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[1*SHA1_NUM], nt_buffer[1*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[2*SHA1_NUM], nt_buffer[2*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[3*SHA1_NUM], nt_buffer[3*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[4*SHA1_NUM], nt_buffer[4*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[5*SHA1_NUM], nt_buffer[5*SHA1_NUM]);
		LOAD_BIG_ENDIAN_SSE2(W[6*SHA1_NUM], nt_buffer[6*SHA1_NUM]);
		W[15*SHA1_NUM] = nt_buffer[7*SHA1_NUM];
		
		/* Rounds */
		H = SSE2_ADD(SSE2_CONST(0xfc08884d), W[0 * SHA1_NUM]);						                                                                 D = SSE2_ADD(SSE2_CONST(0x9cbf5a55), H);
		G = SSE2_4ADD(R_E(D), SSE2_XOR(SSE2_CONST(INIT_F), SSE2_AND(D, SSE2_CONST(0xca0b3af3)))         , SSE2_CONST(0x90bb1e3c), W[ 1 * SHA1_NUM]); C = SSE2_ADD(SSE2_CONST(INIT_C),G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, SSE2_CONST(INIT_A)), SSE2_AND(SSE2_CONST(INIT_B), SSE2_OR(H, SSE2_CONST(INIT_A)))));
		F = SSE2_4ADD(R_E(C), SSE2_XOR(SSE2_CONST(INIT_E), SSE2_AND(C, SSE2_XOR(D, SSE2_CONST(INIT_E)))), SSE2_CONST(0x50c6645b), W[ 2 * SHA1_NUM]); B = SSE2_ADD(SSE2_CONST(INIT_B),F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(SSE2_CONST(INIT_A), SSE2_OR(G, H))));
		E = SSE2_4ADD(R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D)))			                        , SSE2_CONST(0x3ac42e24), W[ 3 * SHA1_NUM]); A = SSE2_ADD(SSE2_CONST(INIT_A),E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C)))			                    , SSE2_CONST(0x3956C25B), W[ 4 * SHA1_NUM]); H = SSE2_ADD(H, D);                 D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B)))			                    , SSE2_CONST(0x59F111F1), W[ 5 * SHA1_NUM]); G = SSE2_ADD(G, C);                 C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A)))			                    , SSE2_CONST(0x923F82A4), W[ 6 * SHA1_NUM]); F = SSE2_ADD(F, B);                 B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		A = SSE2_4ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H)))			                    , SSE2_CONST(0xAB1C5ED5)                  ); E = SSE2_ADD(E, A);                 A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		H = SSE2_4ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G)))			                    , SSE2_CONST(0xD807AA98)                  ); D = SSE2_ADD(D, H);                 H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		G = SSE2_4ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F)))			                    , SSE2_CONST(0x12835B01)                  ); C = SSE2_ADD(C, G);                 G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		F = SSE2_4ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E)))			                    , SSE2_CONST(0x243185BE)                  ); B = SSE2_ADD(B, F);                 F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		E = SSE2_4ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D)))			                    , SSE2_CONST(0x550C7DC3)                  ); A = SSE2_ADD(A, E);                 E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		D = SSE2_4ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C)))			                    , SSE2_CONST(0x72BE5D74)                  ); H = SSE2_ADD(H, D);                 D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		C = SSE2_4ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B)))			                    , SSE2_CONST(0x80DEB1FE)                  ); G = SSE2_ADD(G, C);                 C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		B = SSE2_4ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A)))			                    , SSE2_CONST(0x9BDC06A7)                  ); F = SSE2_ADD(F, B);                 B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H)))			                    , SSE2_CONST(0xC19BF174), W[15 * SHA1_NUM]); E = SSE2_ADD(E, A);                 A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));

		W[ 0 * SHA1_NUM] = SSE2_ADD (W[ 0 * SHA1_NUM], 				                           R0(W[1  * SHA1_NUM])); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0xE49B69C1), W[ 0 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA1_NUM] = SSE2_3ADD(W[ 1 * SHA1_NUM], R1(W[15 * SHA1_NUM]),                   R0(W[2  * SHA1_NUM])); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0xEFBE4786), W[ 1 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA1_NUM] = SSE2_3ADD(W[ 2 * SHA1_NUM], R1(W[0  * SHA1_NUM]),                   R0(W[3  * SHA1_NUM])); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0x0FC19DC6), W[ 2 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA1_NUM] = SSE2_3ADD(W[ 3 * SHA1_NUM], R1(W[1  * SHA1_NUM]),                   R0(W[4  * SHA1_NUM])); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0x240CA1CC), W[ 3 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA1_NUM] = SSE2_3ADD(W[ 4 * SHA1_NUM], R1(W[2  * SHA1_NUM]),                   R0(W[5  * SHA1_NUM])); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0x2DE92C6F), W[ 4 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA1_NUM] = SSE2_3ADD(W[ 5 * SHA1_NUM], R1(W[3  * SHA1_NUM]),                   R0(W[6  * SHA1_NUM])); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0x4A7484AA), W[ 5 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA1_NUM] = SSE2_3ADD(W[ 6 * SHA1_NUM], R1(W[4  * SHA1_NUM]), W[15 * SHA1_NUM]                      ); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0x5CB0A9DC), W[ 6 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA1_NUM] = SSE2_ADD (                  R1(W[5  * SHA1_NUM]), W[0  * SHA1_NUM]                      ); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x76F988DA), W[ 7 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA1_NUM] = SSE2_ADD (                  R1(W[6  * SHA1_NUM]), W[1  * SHA1_NUM]                      ); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0x983E5152), W[ 8 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 9 * SHA1_NUM] = SSE2_ADD (                  R1(W[7  * SHA1_NUM]), W[2  * SHA1_NUM]                      ); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0xA831C66D), W[ 9 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[10 * SHA1_NUM] = SSE2_ADD (                  R1(W[8  * SHA1_NUM]), W[3  * SHA1_NUM]                      ); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0xB00327C8), W[10 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[11 * SHA1_NUM] = SSE2_ADD (                  R1(W[9  * SHA1_NUM]), W[4  * SHA1_NUM]                      ); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0xBF597FC7), W[11 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[12 * SHA1_NUM] = SSE2_ADD (                  R1(W[10 * SHA1_NUM]), W[5  * SHA1_NUM]                      ); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0xC6E00BF3), W[12 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[13 * SHA1_NUM] = SSE2_ADD (                  R1(W[11 * SHA1_NUM]), W[6  * SHA1_NUM]                      ); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0xD5A79147), W[13 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[14 * SHA1_NUM] = SSE2_3ADD(                  R1(W[12 * SHA1_NUM]), W[7  * SHA1_NUM], R0(W[15 * SHA1_NUM])); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0x06CA6351), W[14 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[15 * SHA1_NUM] = SSE2_4ADD(W[15 * SHA1_NUM], R1(W[13 * SHA1_NUM]), W[8  * SHA1_NUM], R0(W[0  * SHA1_NUM])); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x14292967), W[15 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
																    												  
		W[ 0 * SHA1_NUM] = SSE2_4ADD(W[ 0 * SHA1_NUM], R1(W[14 * SHA1_NUM]), W[9  * SHA1_NUM], R0(W[1  * SHA1_NUM])); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0x27B70A85), W[ 0 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA1_NUM] = SSE2_4ADD(W[ 1 * SHA1_NUM], R1(W[15 * SHA1_NUM]), W[10 * SHA1_NUM], R0(W[2  * SHA1_NUM])); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0x2E1B2138), W[ 1 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA1_NUM] = SSE2_4ADD(W[ 2 * SHA1_NUM], R1(W[0  * SHA1_NUM]), W[11 * SHA1_NUM], R0(W[3  * SHA1_NUM])); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0x4D2C6DFC), W[ 2 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA1_NUM] = SSE2_4ADD(W[ 3 * SHA1_NUM], R1(W[1  * SHA1_NUM]), W[12 * SHA1_NUM], R0(W[4  * SHA1_NUM])); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0x53380D13), W[ 3 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA1_NUM] = SSE2_4ADD(W[ 4 * SHA1_NUM], R1(W[2  * SHA1_NUM]), W[13 * SHA1_NUM], R0(W[5  * SHA1_NUM])); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0x650A7354), W[ 4 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA1_NUM] = SSE2_4ADD(W[ 5 * SHA1_NUM], R1(W[3  * SHA1_NUM]), W[14 * SHA1_NUM], R0(W[6  * SHA1_NUM])); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0x766A0ABB), W[ 5 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA1_NUM] = SSE2_4ADD(W[ 6 * SHA1_NUM], R1(W[4  * SHA1_NUM]), W[15 * SHA1_NUM], R0(W[7  * SHA1_NUM])); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0x81C2C92E), W[ 6 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA1_NUM] = SSE2_4ADD(W[ 7 * SHA1_NUM], R1(W[5  * SHA1_NUM]), W[0  * SHA1_NUM], R0(W[8  * SHA1_NUM])); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x92722C85), W[ 7 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA1_NUM] = SSE2_4ADD(W[ 8 * SHA1_NUM], R1(W[6  * SHA1_NUM]), W[1  * SHA1_NUM], R0(W[9  * SHA1_NUM])); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0xA2BFE8A1), W[ 8 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 9 * SHA1_NUM] = SSE2_4ADD(W[ 9 * SHA1_NUM], R1(W[7  * SHA1_NUM]), W[2  * SHA1_NUM], R0(W[10 * SHA1_NUM])); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0xA81A664B), W[ 9 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[10 * SHA1_NUM] = SSE2_4ADD(W[10 * SHA1_NUM], R1(W[8  * SHA1_NUM]), W[3  * SHA1_NUM], R0(W[11 * SHA1_NUM])); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0xC24B8B70), W[10 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[11 * SHA1_NUM] = SSE2_4ADD(W[11 * SHA1_NUM], R1(W[9  * SHA1_NUM]), W[4  * SHA1_NUM], R0(W[12 * SHA1_NUM])); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0xC76C51A3), W[11 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[12 * SHA1_NUM] = SSE2_4ADD(W[12 * SHA1_NUM], R1(W[10 * SHA1_NUM]), W[5  * SHA1_NUM], R0(W[13 * SHA1_NUM])); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0xD192E819), W[12 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[13 * SHA1_NUM] = SSE2_4ADD(W[13 * SHA1_NUM], R1(W[11 * SHA1_NUM]), W[6  * SHA1_NUM], R0(W[14 * SHA1_NUM])); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0xD6990624), W[13 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[14 * SHA1_NUM] = SSE2_4ADD(W[14 * SHA1_NUM], R1(W[12 * SHA1_NUM]), W[7  * SHA1_NUM], R0(W[15 * SHA1_NUM])); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0xF40E3585), W[14 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[15 * SHA1_NUM] = SSE2_4ADD(W[15 * SHA1_NUM], R1(W[13 * SHA1_NUM]), W[8  * SHA1_NUM], R0(W[0  * SHA1_NUM])); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x106AA070), W[15 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
																    								 						
		W[ 0 * SHA1_NUM] = SSE2_4ADD(W[ 0 * SHA1_NUM], R1(W[14 * SHA1_NUM]), W[9  * SHA1_NUM], R0(W[1  * SHA1_NUM])); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0x19A4C116), W[ 0 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 1 * SHA1_NUM] = SSE2_4ADD(W[ 1 * SHA1_NUM], R1(W[15 * SHA1_NUM]), W[10 * SHA1_NUM], R0(W[2  * SHA1_NUM])); G = SSE2_5ADD(G, R_E(D), SSE2_XOR(F, SSE2_AND(D, SSE2_XOR(E, F))), SSE2_CONST(0x1E376C08), W[ 1 * SHA1_NUM]); C = SSE2_ADD(C, G); G = SSE2_3ADD(G, R_A(H), SSE2_OR(SSE2_AND(H, A), SSE2_AND(B, SSE2_OR(H, A))));
		W[ 2 * SHA1_NUM] = SSE2_4ADD(W[ 2 * SHA1_NUM], R1(W[0  * SHA1_NUM]), W[11 * SHA1_NUM], R0(W[3  * SHA1_NUM])); F = SSE2_5ADD(F, R_E(C), SSE2_XOR(E, SSE2_AND(C, SSE2_XOR(D, E))), SSE2_CONST(0x2748774C), W[ 2 * SHA1_NUM]); B = SSE2_ADD(B, F); F = SSE2_3ADD(F, R_A(G), SSE2_OR(SSE2_AND(G, H), SSE2_AND(A, SSE2_OR(G, H))));
		W[ 3 * SHA1_NUM] = SSE2_4ADD(W[ 3 * SHA1_NUM], R1(W[1  * SHA1_NUM]), W[12 * SHA1_NUM], R0(W[4  * SHA1_NUM])); E = SSE2_5ADD(E, R_E(B), SSE2_XOR(D, SSE2_AND(B, SSE2_XOR(C, D))), SSE2_CONST(0x34B0BCB5), W[ 3 * SHA1_NUM]); A = SSE2_ADD(A, E); E = SSE2_3ADD(E, R_A(F), SSE2_OR(SSE2_AND(F, G), SSE2_AND(H, SSE2_OR(F, G))));
		W[ 4 * SHA1_NUM] = SSE2_4ADD(W[ 4 * SHA1_NUM], R1(W[2  * SHA1_NUM]), W[13 * SHA1_NUM], R0(W[5  * SHA1_NUM])); D = SSE2_5ADD(D, R_E(A), SSE2_XOR(C, SSE2_AND(A, SSE2_XOR(B, C))), SSE2_CONST(0x391C0CB3), W[ 4 * SHA1_NUM]); H = SSE2_ADD(H, D); D = SSE2_3ADD(D, R_A(E), SSE2_OR(SSE2_AND(E, F), SSE2_AND(G, SSE2_OR(E, F))));
		W[ 5 * SHA1_NUM] = SSE2_4ADD(W[ 5 * SHA1_NUM], R1(W[3  * SHA1_NUM]), W[14 * SHA1_NUM], R0(W[6  * SHA1_NUM])); C = SSE2_5ADD(C, R_E(H), SSE2_XOR(B, SSE2_AND(H, SSE2_XOR(A, B))), SSE2_CONST(0x4ED8AA4A), W[ 5 * SHA1_NUM]); G = SSE2_ADD(G, C); C = SSE2_3ADD(C, R_A(D), SSE2_OR(SSE2_AND(D, E), SSE2_AND(F, SSE2_OR(D, E))));
		W[ 6 * SHA1_NUM] = SSE2_4ADD(W[ 6 * SHA1_NUM], R1(W[4  * SHA1_NUM]), W[15 * SHA1_NUM], R0(W[7  * SHA1_NUM])); B = SSE2_5ADD(B, R_E(G), SSE2_XOR(A, SSE2_AND(G, SSE2_XOR(H, A))), SSE2_CONST(0x5B9CCA4F), W[ 6 * SHA1_NUM]); F = SSE2_ADD(F, B); B = SSE2_3ADD(B, R_A(C), SSE2_OR(SSE2_AND(C, D), SSE2_AND(E, SSE2_OR(C, D))));
		W[ 7 * SHA1_NUM] = SSE2_4ADD(W[ 7 * SHA1_NUM], R1(W[5  * SHA1_NUM]), W[0  * SHA1_NUM], R0(W[8  * SHA1_NUM])); A = SSE2_5ADD(A, R_E(F), SSE2_XOR(H, SSE2_AND(F, SSE2_XOR(G, H))), SSE2_CONST(0x682E6FF3), W[ 7 * SHA1_NUM]); E = SSE2_ADD(E, A); A = SSE2_3ADD(A, R_A(B), SSE2_OR(SSE2_AND(B, C), SSE2_AND(D, SSE2_OR(B, C))));
		W[ 8 * SHA1_NUM] = SSE2_4ADD(W[ 8 * SHA1_NUM], R1(W[6  * SHA1_NUM]), W[1  * SHA1_NUM], R0(W[9  * SHA1_NUM])); H = SSE2_5ADD(H, R_E(E), SSE2_XOR(G, SSE2_AND(E, SSE2_XOR(F, G))), SSE2_CONST(0x748F82EE), W[ 8 * SHA1_NUM]); D = SSE2_ADD(D, H); H = SSE2_3ADD(H, R_A(A), SSE2_OR(SSE2_AND(A, B), SSE2_AND(C, SSE2_OR(A, B))));
		W[ 9 * SHA1_NUM] = SSE2_4ADD(W[ 9 * SHA1_NUM], R1(W[7  * SHA1_NUM]), W[2  * SHA1_NUM], R0(W[10 * SHA1_NUM]));
		W[ 2 * SHA1_NUM] = SSE2_4ADD(W[11 * SHA1_NUM], R1(W[9  * SHA1_NUM]), W[4  * SHA1_NUM], R0(W[12 * SHA1_NUM]));
		W[ 1 * SHA1_NUM] = SSE2_4ADD(W[13 * SHA1_NUM], R1(W[2  * SHA1_NUM]), W[6  * SHA1_NUM], R0(W[14 * SHA1_NUM]));
		W[ 0 * SHA1_NUM] = SSE2_4ADD(W[15 * SHA1_NUM], R1(W[1  * SHA1_NUM]), W[8  * SHA1_NUM], R0(W[0  * SHA1_NUM])); A = SSE2_ADD(A, W[0 * SHA1_NUM]); 

		W[4  * SHA1_NUM] = A;
		W[16 * SHA1_NUM] = B;
		W[17 * SHA1_NUM] = C;
		W[18 * SHA1_NUM] = D;
		W[19 * SHA1_NUM] = E;
		W[20 * SHA1_NUM] = F;
		W[21 * SHA1_NUM] = G;
		W[6  * SHA1_NUM] = H;
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

void crypt_sha256_avx_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_utf8_coalesc_protocol_avx(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_sha256_avx_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AVX2 code
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_X86

void crypt_sha256_avx2_kernel_asm(uint32_t* nt_buffer);
PRIVATE void crypt_utf8_coalesc_protocol_avx2(CryptParam* param)
{
	crypt_utf8_coalesc_protocol_body(param, crypt_sha256_avx2_kernel_asm);
}
#endif

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OpenCL Implementations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
#undef R1
#undef R0
#define R0(x)  (ROTATE(x,25u)^ROTATE(x,14u)^((x)>>3u))
#define R1(x)  (ROTATE(x,15u)^ROTATE(x,13u)^((x)>>10u))
PRIVATE void ocl_write_sha256_header(char* source, GPUDevice* gpu, cl_uint ntlm_size_bit_table1)
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
		"#define R_E(x) (rotate(x,26u)^rotate(x,21u)^rotate(x,7u))\n"
		"#define R_A(x) (rotate(x,30u)^rotate(x,19u)^rotate(x,10u))\n"
		"#define R0(x) (rotate(x,25u)^rotate(x,14u)^((x)>>3u))\n"
		"#define R1(x) (rotate(x,15u)^rotate(x,13u)^((x)>>10u))\n");
}

PRIVATE void ocl_gen_kernel_with_lenght(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table1, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission1, cl_uint workgroup)
{
	char* nt_buffer[] = { "+nt_buffer0", "+nt_buffer1", "+nt_buffer2", "+nt_buffer3", "+nt_buffer4", "+nt_buffer5", "+nt_buffer6" };

	ocl_charset_load_buffer_be(source, key_lenght, &vector_size, div_param, nt_buffer);

	sprintf(source + strlen(source), "uint A,B,C,D,E,F,G,H,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");
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

	sprintf(source + strlen(source),
		"uint wW1=%uu+R0(0u%s)%s;"
		"uint wW3=R1(wW1)+R0(0u%s)%s;"
		"uint wW5=R1(wW3)+R0(0u%s)%s;"

		"uint R1_wW5=R1(wW5);"

		"uint R0_wW1=R0(wW1);"
		"uint R0_wW3=R0(wW3);"
		"uint R0_wW5=R0(wW5);"

		"uint R0_W1=R0(0u%s);"
		"uint R0_W3=R0(0u%s);"
		"uint R0_W5=R0(0u%s);"
		, R1(key_lenght << 3), nt_buffer[2], nt_buffer[1]
		, nt_buffer[4], nt_buffer[3]
		, nt_buffer[6], nt_buffer[5]

		, nt_buffer[1]
		, nt_buffer[3]
		, nt_buffer[5]);

	// Begin cycle changing first character
	sprintf(source + strlen(source), "for(uint i=0;i<%uU;i+=%uU){", num_char_in_charset, vector_size);

	if (is_charset_consecutive(charset))
		sprintf(source + strlen(source), "W0=nt_buffer0+(i<<24u);");
	else
		sprintf(source + strlen(source), "W0=nt_buffer0+(((uint)charset[i])<<24u);");

	/* Round 1 */
	sprintf(source + strlen(source),
		"H=0xfc08884dU+W0;D=0x9cbf5a55U+H;"
		"G=R_E(D)+(%uu^(D&%uu))+0x90bb1e3cU%s;C=0x3c6ef372U+G;G+=R_A(H)+MAJ(H,%uu,%uu);"
		"F=R_E(C)+bs(%uu,D,C)+0x50c6645bU%s;B=0xbb67ae85U+F;F+=R_A(G)+MAJ(G,H,%uu);"
		"E=R_E(B)+bs(D,C,B)+0x3ac42e24U%s;A=0x6a09e667U+E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x3956C25BU%s;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x59F111F1U%s;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x923F82A4U%s;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0xAB1C5ED5U;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0xD807AA98U;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0x12835B01U;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x243185BEU;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x550C7DC3U;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x72BE5D74U;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x80DEB1FEU;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x9BDC06A7U;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+%uu;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		, 0x9b05688c, 0xca0b3af3, nt_buffer[1], 0x6a09e667, 0xbb67ae85
		, 0x510e527f, nt_buffer[2], 0x6a09e667
		, nt_buffer[3], nt_buffer[4], nt_buffer[5], nt_buffer[6], (key_lenght << 3) + 0xC19BF174);

	sprintf(source + strlen(source),
			"W0+=R0_W1;"
			"W2=R1(W0)+R0_W3%s;"
			"W4=R1(W2)+R0_W5%s;"
			"W6=R1(W4)+%uu%s;"
			"W7=R1_wW5+W0;"
			"W8=R1(W6)+wW1;"
			"W9=R1(W7)+W2;"
			"W10=R1(W8)+wW3;"
			"W11=R1(W9)+W4;"
			"W12=R1(W10)+wW5;"
			"W13=R1(W11)+W6;"
			"W14=R1(W12)+W7+%uu;"
			"W15=R1(W13)+W8+R0(W0)+%uu;"
			, nt_buffer[2]
			, nt_buffer[4]
			, key_lenght << 3, nt_buffer[6]
			, R0(key_lenght << 3)
			, key_lenght << 3);

	/* Round 2 */
	sprintf(source + strlen(source),
		"H+=R_E(E)+bs(G,F,E)+0xE49B69C1U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xEFBE4786U+wW1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x0FC19DC6U+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x240CA1CCU+wW3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x2DE92C6FU+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x4A7484AAU+wW5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x5CB0A9DCU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x76F988DAU+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0x983E5152U+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xA831C66DU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0xB00327C8U+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0xBF597FC7U+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0xC6E00BF3U+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0xD5A79147U+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x06CA6351U+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x14292967U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"W0+=R1(W14)+W9 +R0_wW1;H+=R_E(E)+bs(G,F,E)+0x27B70A85U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1=wW1+R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x2E1B2138U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0_wW3;F+=R_E(C)+bs(E,D,C)+0x4D2C6DFCU+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3=wW3+R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x53380D13U+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0_wW5;D+=R_E(A)+bs(C,B,A)+0x650A7354U+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5=wW5+R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x766A0ABBU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x81C2C92EU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x92722C85U+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0xA2BFE8A1U+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W9+=R1(W7)+W2+R0(W10);G+=R_E(D)+bs(F,E,D)+0xA81A664BU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W10+=R1(W8)+W3+R0(W11);F+=R_E(C)+bs(E,D,C)+0xC24B8B70U+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W11+=R1(W9)+W4+R0(W12);E+=R_E(B)+bs(D,C,B)+0xC76C51A3U+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W12+=R1(W10)+W5+R0(W13);D+=R_E(A)+bs(C,B,A)+0xD192E819U+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W13+=R1(W11)+W6+R0(W14);C+=R_E(H)+bs(B,A,H)+0xD6990624U+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W14+=R1(W12)+W7+R0(W15);B+=R_E(G)+bs(A,H,G)+0xF40E3585U+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W15+=R1(W13)+W8+R0(W0);A+=R_E(F)+bs(H,G,F)+0x106AA070U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");
													   													  
	/* Round 4 */									   													  
	sprintf(source + strlen(source),				   													  
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x19A4C116U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x1E376C08U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x2748774CU+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x34B0BCB5U+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x391C0CB3U+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x4ED8AA4AU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x5B9CCA4FU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x682E6FF3U+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);");

	// Find match
	if (num_passwords_loaded == 1)
	{
		uint32_t* bin = (uint32_t*)binary_values;
		sprintf(source + strlen(source),
			"W8+=R1(W6)+W1+R0(W9);"
			"W9+=R1(W7)+W2+R0(W10);"
			"W2=W11+R1(W9)+W4+R0(W12);"
			"W1=W13+R1(W2)+W6+R0(W14);"
			"W0=W15+R1(W1)+W8+R0(W0);A+=W0;"

			"if(A==%uu)"
			"{"
				"A-=W0;"
				"W10+=R1(W8)+W3+R0(W11);"
				"W12+=R1(W10)+W5+R0(W13);"
				"W14+=R1(W12)+W7+R0(W15);"

				"H+=R_E(E)+bs(G,F,E)+0x748F82EEU+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
				"G+=R_E(D)+bs(F,E,D)+0x78A5636FU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
				"F+=R_E(C)+bs(E,D,C)+0x84C87814U+W10;B+=F;F+=MAJ(G,H,A);"
				"E+=R_E(B)+bs(D,C,B)+0x8CC70208U+W2;A+=E;"
				"D+=R_E(A)+bs(C,B,A)+0x90BEFFFAU+W12;H+=D;"
				"C+=R_E(H)+bs(B,A,H)+0xA4506CEBU+W1;G+=C;"
				"B+=bs(A,H,G)+W14;"
				"H-=D;"

				"if(B==%uu&&C==%uu&&D==%uu&&E==%uu&&F==%uu&&G==%uu&&H==%uu)"
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
		sprintf(source + strlen(source),
			"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0x748F82EEU+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"W9+=R1(W7)+W2+R0(W10);"
			"W2=W11+R1(W9)+W4+R0(W12);"
			"W1=W13+R1(W2)+W6+R0(W14);"
			"W0=W15+R1(W1)+W8+R0(W0);A+=W0;");

		// Find match
		sprintf(source + strlen(source), "uint xx=A&%uu;uint fdata;", cbg_mask);
		
		sprintf(source + strlen(source),
			"fdata=(uint)(cbg_filter[xx]);"

			"if(((fdata^H)&0xFFF8)==0){"
				"indx=cbg_table[xx];"
				"if(indx!=0xffffffff&&A==binary_values[indx*8u]&&H==binary_values[indx*8u+7u]){"

					"uint aa=A-W0;"
					"W4=W10+R1(W8)+W3+R0(W11);"
					"W6=W12+R1(W4)+W5+R0(W13);"
					"uint ww14=W14+R1(W6)+W7+R0(W15);"

					"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

					"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
					"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
					"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
					"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
					"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
					"bb+=bs(aa,hh,gg)+ww14;"

					"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]"
					 "&&ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]){"
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
				"if(((((uint)cbg_filter[xx])^H)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&A==binary_values[indx*8u]&&H==binary_values[indx*8u+7u]){"

						"uint aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"uint ww14=W14+R1(W6)+W7+R0(W15);"

						"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]"
						"&&ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]){"
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
				"xx=H&%uu;"
				"fdata=(uint)(cbg_filter[xx]);"
				"if(((fdata^A)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&A==binary_values[indx*8u]&&H==binary_values[indx*8u+7u]){"

						"uint aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"uint ww14=W14+R1(W6)+W7+R0(W15);"

						"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]"
						"&&ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]){"
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
					"if(((((uint)cbg_filter[xx])^A)&0xFFF8)==0){"
						"indx=cbg_table[xx];"
						"if(indx!=0xffffffff&&A==binary_values[indx*8u]&&H==binary_values[indx*8u+7u]){"

							"uint aa=A-W0;"
							"W4=W10+R1(W8)+W3+R0(W11);"
							"W6=W12+R1(W4)+W5+R0(W13);"
							"uint ww14=W14+R1(W6)+W7+R0(W15);"

							"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

							"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
							"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
							"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
							"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
							"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
							"bb+=bs(aa,hh,gg)+ww14;"

							"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]"
							"&&ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]){"
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

PRIVATE uint32_t sha256_one_char[8 * 256] = {
	0xA9D34CC5,0xB40EA40F,0xD7C2C05E,0xB7854398,0xBF6E6169,0x1C4E0266,0x658DC95B,0x04498F6C,
	0x8866B527,0x3034AEAB,0xA0264B6F,0xD463D9D7,0x0526A0BB,0x51507E5B,0xB8490891,0x47409EAA,
	0x8C73CCEA,0xECA461B2,0xD69FE65A,0xF8BFECB2,0x11F9E9F9,0x99B3C3F8,0x2BF310ED,0x0FB71FBB,
	0x8C1F052D,0xA0915880,0x1C1CB6AA,0xE7034348,0xCDE1A0FF,0x3A937B4E,0xF23280EF,0x6B1B1964,
	0xB90AB6F1,0x5F0D3C76,0x28D27338,0xC4BE8F59,0x41977F8C,0xC4439B7A,0x431CC2F8,0x612941FF,
	0x2CDFB78B,0x91CBFD3A,0x348D2961,0x58169921,0x5E5BA2EE,0x9591F14F,0x6A672BF1,0xA6BFDDA1,
	0x293C2C31,0x8FF47005,0xBBA888E4,0x13C8C997,0x06C3617B,0x7F0F71F1,0xD9196DDB,0x991C5646,
	0xD4E0D0B8,0x6EBF8D18,0x5D7C5515,0x51A09E69,0xE8B04E62,0x33321951,0x5E43E574,0x52DD7CF7,
	0xB7AAD1B6,0xF2828342,0x7ADED40D,0x1D4BA982,0x295CFAF2,0xC7038148,0x91A4D96D,0x14950BFF,
	0x35ACDF65,0xAB878814,0x7A6612F6,0x311E4014,0x8E02C392,0x8DB2426C,0x6C00E11B,0xD81D2F8C,
	0x34EB4E3F,0x0A5D4137,0x507C0AFF,0xD513B654,0xD1E9D6B2,0xC7F2F263,0xD00BBE5A,0xA9D5D0FE,
	0x65F0F6E4,0x651828C0,0x6B5F1651,0x47C77B77,0xF9A467E9,0x763A3769,0xF529F986,0xA7D47B16,
	0x422D4B28,0xACE71780,0x4012AF00,0x4CCED208,0x715824DA,0x2AEE7A13,0x967CF9DE,0xF2952A56,
	0x6CA4CBA2,0x94F2D221,0x364CDEB1,0x5D97C6F7,0x6E7DDD2A,0x5FDA3D5A,0xD38AE083,0x57BD05B4,
	0x619C5E9A,0x2EDEAA4C,0xDA3BCAC4,0x014FA1D7,0x23DB4969,0xFD00C5A8,0xEAD2630A,0x3CDCA057,
	0xBA6FA118,0x013E1F53,0x59CA3CDF,0x8671F0A1,0x6081F185,0xA5EAB71C,0x72B70012,0x00BCCEFE,
	0xB9BD3607,0xA2006BDC,0x94947E12,0xCB8642C2,0x8EC194DC,0xCA7102D7,0x2959588C,0x62517F08,
	0x8EA1BE74,0xF214A648,0xB3C32420,0xFDC47A0F,0x1C048924,0x78C52D95,0xA558CF0A,0xC3A960E2,
	0xB2B36A67,0x4A10963F,0x13C94C56,0x0DDBA4C7,0xA940B85D,0x9138A6EB,0x5737E593,0x7F62032C,
	0xC0E4301D,0x22D5539F,0x3A1FF093,0x35C11B16,0x6C266266,0x57BF994D,0x39D4C45B,0x9E687AB3,
	0x44A8AA20,0xE96A7544,0xDB6E561F,0xBBA9B6EE,0xFE22B009,0x04AE3979,0x8736E0FD,0x9CC85472,
	0x661065C1,0xC2EEB008,0xF3519277,0xA77F8F15,0x421BDE16,0x1B6509F4,0x1B56FEF5,0x6C9529DA,
	0x42513B32,0xCCFC3AF5,0xD7458F63,0x583D2E09,0x502ED7E2,0x798FCF62,0x8F2D15DD,0x265A3E98,
	0xA261C606,0xD79D87D1,0x54A26B9B,0xD766CCC0,0x07625759,0x2F793BFA,0xDDE501BB,0x075BD65B,
	0x56A080B3,0x9EC96F08,0xC67C44CF,0x1945FD37,0x0146925E,0x152A08EC,0xF57A3B46,0x493DECFF,
	0x8496E58F,0xECF16176,0x271BAE39,0xD40DEA89,0x9275A7EC,0xFFB6AC6E,0x23ECC261,0x6BD52C32,
	0x524F1EA7,0x1D32EB96,0x1E702FDD,0xE03D1C39,0x21BA8809,0x286A52CA,0x14C1D112,0x284B89FB,
	0xC77DA159,0x50F8E913,0xD3249533,0xF1C43EC7,0x11F6729A,0xE8F96309,0xA3ED21D1,0xC7A9561D,
	0x787B5008,0x4698B485,0xC52E0C03,0xB1226447,0xF2E704B8,0x44A3E1AF,0xE7BFA829,0xDFEACEB8,
	0xEDA0AB9F,0x18871BA6,0x6467EA05,0xBA36A7F6,0x2D9DAC82,0x153A805D,0x98E15CA4,0x2B505EBE,
	0xF5AFDC9F,0xEBD1EC2C,0xD8BEE125,0xF0CEBABB,0x1E3A10DB,0x1C319B84,0x6D1FBF28,0xC9D3F2A6,
	0x317E066B,0x1B9A914E,0xDC7FDB9C,0x69ED9FD0,0xB18FBD8D,0xD90BAA2B,0xEFD57109,0x77538D35,
	0x787FA7DA,0x59639CCB,0x168A5DB2,0x3F040D6F,0xE1BCD212,0x202464A2,0x2F6FF24F,0x1B2F75E0,
	0x031FCFBC,0x952B074B,0xE62E1B73,0x8DD762E5,0x61B7D8F1,0x6D7B204E,0x47732F81,0x51EC0B64,
	0x74BA4DFC,0xC5CF8C53,0x21E58D11,0x97B859E9,0xACECC695,0x184D1DD9,0xD50801AC,0xAE2D0905,
	0xABE23D05,0xD7F6181D,0x98D6B9E9,0x946E058B,0x42D99CE0,0x1EFAFEA1,0xF00C3E7F,0x11D129E7,
	0x6A389E61,0xA0D656DE,0xE3EABFD6,0x03AA0B46,0x1DCBE6CD,0x9FE27119,0xCD7D4650,0x37490CEC,
	0x3BCDFF79,0x0F2BFF62,0x7863E902,0x02E6B566,0x522C00FD,0x5BE5074C,0x58F67382,0x696B366D,
	0x23CC9C15,0x78B791DC,0x87BEFFD4,0xF44B6041,0x16EFA048,0x349A4704,0x533B86FB,0x0C6BF5DE,
	0xC15722F6,0x0561A0E5,0x83239496,0x66A52382,0xCB95C02D,0xBBFA81B9,0x165D42E3,0xB2E2646E,
	0x3FADD532,0xFE42858A,0xC413712A,0xAAF4F433,0x120E7379,0x7572D842,0xF34035FF,0x4BB4D07D,
	0x6620700D,0x3859C299,0x96C9171C,0x965CAC65,0xDEAE7B6A,0xBEE66F1B,0x30D6B419,0x15878870,
	0x7CB9723D,0xEBFC8073,0x58530E57,0x2399ECF8,0x836CC018,0x38726112,0x9C5DE75E,0xDFCE95B0,
	0xCE7DA949,0xD4029DBF,0x28964F84,0x6D303F6A,0x1C0EDE3A,0x65657AED,0x45AEC8C1,0xDC7F60B8,
	0x8CE57656,0x85829FE5,0x54260FC7,0xB2C6A3EF,0xF12B8C3A,0x70CA41AD,0x2D6C0DE8,0xBF63C2DF,
	0xF9BA7BFC,0x47353E37,0x0CA9F1D4,0x47962E4E,0xC88AA0FF,0x54DF7358,0x2A7F3B33,0xF62855AB,
	0x0A815CB0,0xE326CF40,0x95FE37C1,0x42DF36E1,0xCAF16D3B,0x4F0F288E,0x177828FD,0x8F5835AE,
	0x8D8CBA42,0x35AD8B61,0xF0DFBAE2,0x4F62A656,0x9276AACA,0xDBC8AA00,0xF4B3AFD1,0x12BB2D82,
	0x61A50E23,0x7B9585C6,0xE5254325,0xDE4EE123,0x3B40357C,0x6096C76C,0x47A5FD8F,0xEDCBA9AD,
	0x00F4BADA,0x0BDB687D,0x97B11512,0x1CB1FB02,0x502DB559,0x13BF25EE,0xA09A7932,0x3EF49330,
	0x055A4A59,0x743775C7,0x4F43768E,0x60E8468B,0x31870F5E,0xF383644F,0xBAB68CC3,0x2F4A9791,
	0x3C82CA9C,0xFB8D5F52,0x245F6792,0xA680F1C3,0xD8281103,0xDEF98D83,0x4487A49C,0x2752E0F2,
	0x20E94E63,0x358D5ACF,0xF2855933,0x57B49142,0xC8B04AFE,0x7D1AC0E2,0x6BD15851,0xF945612F,
	0x36D71327,0xFA107867,0x589AC42F,0x03153A42,0x74A801E3,0x6E751EF3,0x9F43B5AA,0x05B9DC42,
	0x77368310,0xECC26D04,0x68A8A310,0xB945F67A,0x7DA6DD93,0xAF1FC83C,0xDD77A83B,0xDB6AD2F0,
	0xDA610ABD,0xD7AE9F26,0x0DFD49C3,0x9FC89F33,0x866EBCB1,0xE00528F1,0x0623009E,0x0C71B805,
	0x29375795,0xFF4A9D67,0xE2E974BA,0x62761BE0,0xF86EAAF3,0xFEAB9672,0xB98B16C4,0x20A47BAA,
	0x7072FE18,0x3DA79D4A,0xB667E350,0xB3B7A37B,0xF9B79E98,0x122E1FE5,0xCF801E18,0xF1E34523,
	0xBF56255D,0x81FD63D6,0xC3FAED9C,0x03D39303,0x9626749E,0x0AB94C32,0xE2459C31,0xA0AADA4B,
	0x6930C3F1,0x577CD80C,0xE888E78A,0x14FD1522,0x00FCAC74,0xED2131F4,0x0F84A6D9,0x22B6BFA9,
	0x1DB3542A,0x8B5CB8F1,0x1CE32835,0xB13E141C,0x24178F13,0xBE806C09,0xBBD274FA,0xEBD0CD3D,
	0x439BF08E,0xB5251554,0xF1B91FDF,0x43B8BF5F,0x1E11C46B,0xFF136358,0x344C5E19,0xA405A54B,
	0x6AE4DE37,0xA154F23B,0xFBA97273,0x6A222D94,0xFF57D6EB,0x8ABA76F5,0x3426D68A,0x0AB3B774,
	0x3E5E0D1D,0xB4619DA3,0x20031BF0,0x4A750A4A,0x8F1D33FB,0xDA3E8F4A,0x9CB2055A,0x3313517E,
	0x93088D36,0x5311833E,0xDCDCF9F5,0x7648B6F5,0xCD672966,0x0354E72D,0x0A4717EC,0xFD9915A0,
	0x9EFEA9C4,0x7B75B0D0,0x5B4EFBA4,0x793CC5C6,0x0AAE6678,0xA9750495,0xCF6F40DD,0xCB724D1E,
	0x71225F91,0x337BB6B5,0xD0E644B1,0xDEE2EC19,0xECBFF905,0x15F4B15A,0x7D299430,0xC86E512A,
	0x50FA7790,0xD08704F4,0x187AF7CD,0xF73F15F4,0xD26C5373,0x27B932CD,0xFDB5C2BA,0x0867B100,
	0xCE350060,0xD04AA41B,0xB3943B47,0x1D5CBDA7,0x784D036C,0xFC94883B,0xBA962841,0x8C36D283,
	0x241F73AB,0x5ABBB7D1,0x9646F6E6,0xF2569058,0x0E671A76,0x1F956CB7,0x0283DEED,0xC3FC8EE7,
	0x5584581C,0x68D73BDD,0x198988A8,0xAA19796B,0x99D44BE7,0x8F644BD9,0x079FFE14,0xA6C3E225,
	0xF595D37B,0x44EEDAB3,0x5FFB2655,0x659835F0,0x02FDB15B,0x0B5D8706,0x8F65152B,0x15888E9A,
	0x901C8332,0xDC1F8B99,0x59E05DDB,0xCDA35C11,0x6971B221,0x07FF1417,0x5044C66F,0x3A7472F7,
	0x8D7A80C2,0x1403D495,0x54AA091F,0x5A2D6845,0x7C8D4B46,0x4041A26C,0x001BC795,0xFA42570E,
	0x7CB3D93F,0x7BA8F713,0x52670E61,0x245984C5,0xD7A615F7,0x6658F129,0xF4A53C5F,0xDB82C3D7,
	0x866AA730,0x5A89C5AF,0xF353B9AB,0x23AC597D,0xC5AEDE41,0xCE53AD24,0xCF6217E0,0x68608AE1,
	0xF2ACF883,0x390893C0,0xF62A2F43,0xF0260878,0x5FD07E4B,0xF55EB430,0x93256130,0x9E098D69,
	0xB9D3E893,0xA2A90B12,0x3861AEC8,0xF52CC495,0xC2D5B4BD,0xDD80647F,0xA543F4B2,0x5A66E243,
	0x429E6B8F,0xF48B2E7D,0xC8A0AA43,0x08A6BF7C,0xDE8B168C,0x7043B53A,0x58564C18,0x050097D6,
	0x97534B9F,0xA2933018,0xC7320482,0x570D2E27,0xA40F4D10,0xA80A6D0A,0x3BEBE91A,0xB3B2AF4C,
	0x08C7376E,0xCFD0E97B,0xFF6DF31C,0xBFA9A06B,0xC752BECC,0x174C1E4A,0xFF0700B0,0xFF02B94E,
	0x687FD48F,0xE07564BB,0xAF35B6AD,0x3A18B954,0x7ABC6A11,0xB4706BAD,0xFF65E660,0xF6C9ABF3,
	0xEDDB4F99,0x479FA542,0xA7A5FF90,0xA0EE739A,0x7AE58CBE,0x46FFD2EF,0xB99A5855,0x900000F9,
	0x1BB9B73A,0xD29A76F8,0x02474C06,0x7B9D3BF6,0x1A3E58ED,0x1F403403,0xC2B3D878,0xD7CCCD34,
	0xCDA35B5F,0x3597B8E6,0xE67B3748,0x734CB7B3,0x36468F79,0xC7046A7C,0xD2C933C4,0xC2A2E507,
	0x5E5CA563,0xCF44D58B,0xAC27007E,0xB46CCACF,0x96F73013,0xFD22289B,0xD8374B97,0x65F28FFF,
	0xAD020E0B,0x71E852D2,0xE193BC88,0x11D938D7,0x246F4A91,0x1F8D50B5,0xAFB31F7A,0x3386CADC,
	0x04E88A1C,0x6520E269,0xEFA8DA6D,0xE6F60BB8,0x9314FBD5,0xA4A3743C,0x132C4026,0x30BC1E23,
	0xCD2EDCD5,0xE3AFE0D6,0x68205816,0xDA969F35,0xE3E289AE,0xEE85A80A,0xBE2A10B2,0xBFD413C7,
	0x20555DDF,0x94D8034F,0xB16CADF7,0x85153D6F,0x9B378AD5,0x385DB55C,0x8BE8DDE8,0x3A7C0ACA,
	0xA12C720D,0x660F4F24,0x43217CE0,0xA04ACE80,0x26691A51,0xD5233A2B,0x775F915A,0x529A13EA,
	0xF31ACA5B,0x280D79D1,0xC203F9B9,0x8F22EABB,0x99B4141F,0x7529BEF1,0x1DBF0EB8,0xE75FD03D,
	0xFD738A15,0x25E408F7,0x2439ADF5,0x0E59E24B,0xCCFEF2BE,0xC67F0105,0x6C951FD4,0x6D68D807,
	0xFB0FB0F9,0xCF4CB388,0xD2B170F4,0x66236143,0x8807EC4E,0x138055EA,0x63894A31,0x315611A3,
	0xD711FDE3,0xC2762C39,0x1808A921,0xCA0083B7,0x9A77BEF6,0x3205639D,0x416DDA9B,0x2B18CCFB,
	0x368A216B,0x7744E490,0x50733D71,0x3E55FA09,0x2FBAD000,0xA0CCEA2D,0xE7863C95,0x757FC8BC,
	0xBBAD3A78,0x87C6D7EB,0xB7525D7F,0x0C0F67A6,0x9075446F,0x3AD20758,0xEB4FACB7,0x0E4EDF14,
	0xB634ACF4,0x908C5863,0x35A56967,0x174515C6,0x7F863D00,0xD417A6B0,0x99FC9DDA,0x3CC865DC,
	0xADEB0BB7,0x2438A967,0x005FA86A,0x82FD5AFA,0x0179D942,0x643115D2,0xABF01503,0xF6BDD88A,
	0x627C8CBD,0x3DF35194,0x9456476A,0xC0F47CD8,0xA49C4A9F,0x38B12A44,0x79EE8BF6,0x8585A5D5,
	0x2A5CA6C6,0x33641A41,0xB7BA5007,0xDB4683A8,0x40D763DD,0x39DAEAD1,0x638BD55E,0xFDCDA823,
	0x3638A1DE,0xDDBA18BC,0x775497C0,0xE9EDE9A0,0x46E17D71,0x02000D36,0x18AFA1DD,0x8435B731,
	0xDEFB309D,0x390E6DE1,0x4667C167,0x17EC888C,0x2CDEC071,0x41CABC12,0x6A534ADF,0x0F0C9B6C,
	0xE68BBA11,0x141B5B4D,0x38B624AF,0xC6A40E89,0x33DF0097,0x124EFA19,0x45291378,0x1A162287,
	0x28F44E66,0xC01FCF9A,0x65BCBAE0,0xD4E138C1,0x10C0706C,0x5718375D,0x8AA461C6,0xB58BAB49,
	0x22AD4846,0xA5D72622,0xC6170AD5,0x6547BCAD,0x4E5CB097,0x15BBA0D5,0x99A317FA,0xE6BEDC11,
	0x8CEE8B39,0xE7F3028D,0x1796CF4E,0x05FE33B9,0xD0F1A5F6,0x4CDC944C,0xEFD59500,0xCC3956E5,
	0x42C21C4C,0x938466AF,0xBF93EFC4,0xD8E03F96,0xCA516688,0xDB0A6A55,0xF52B6986,0x2F8700CB,
	0x98B7A1D4,0xC40784DB,0x9F16CACB,0xC314DA32,0x200F3BB6,0x55565817,0xCD5DCAD8,0x3C9E4FA5,
	0x267DB957,0x220B229A,0x7E9F5927,0x7E84F39D,0xCDBA1F91,0x07D81EDA,0x1D658908,0xD1707BA4,
	0x97F2B729,0xB9C87530,0x50DA78CF,0xEDFDDDC4,0x9DADD894,0xA53312C3,0xCC2435D7,0xECE992DC,
	0x51A06107,0xF07208DB,0x836080C7,0xC62D02AC,0xEBAD869F,0xE9C6BA8C,0xB4C5B805,0x6A4B230D,
	0x6DF62278,0x58623C82,0x03C0833B,0xA591A31A,0xD2BCF861,0xB31BBEDD,0xDAA5D2D2,0xDE58290D,
	0x912F7C25,0x2B4D3286,0xCB196BEC,0x2D6CD753,0x29EEC655,0x95E9255D,0x7C66A8FB,0x310A5363,
	0x3C4DE6E5,0x3F660623,0xE61785E7,0x373932C8,0x753EA99C,0x8B4389A1,0x45345607,0x80DB93C0,
	0x9927FA71,0xE9990BD6,0xC32FC44F,0xEB1903C9,0x88A249AD,0x0E28E4B3,0x200E8363,0x0BC4DEA7,
	0xB2C59DB1,0x54F83FFF,0x8B44DAD9,0x2EA2F91A,0x9413776E,0x0C10F976,0xCCBD6680,0x6BA377A5,
	0x04BD6988,0xE1B98EDF,0x19A721AB,0x377BF209,0x0C0BFB3F,0xC2B37928,0xA08893D4,0x8BBF4BB4,
	0x297D7057,0x4A464F31,0xC448AE1B,0xA92D11A9,0x02059ADD,0xD672662D,0x309CB4A7,0x6A4281BE,
	0x4BE0EA24,0xB479B520,0x65AEB867,0xFEA3D064,0x999AC287,0xC9956C3A,0x3DAD2B70,0xB55925A9,
	0x3DE47646,0xA26BA456,0x26E6FAC6,0xD4C25295,0xC94DC89F,0x73FFC37F,0xE2A1AD6C,0x617728D3,
	0xD03A6F20,0xB741AEA2,0xDBED7BA7,0x3A3F0ED5,0x095AB976,0xEA2F7898,0x7BB3F706,0x7B28D50C,
	0x5660643C,0x87D682CC,0x0229ACB8,0x22A05582,0xD819B664,0x8D49AABF,0xB08AAB1A,0xA655586B,
	0xF167600C,0x023551EE,0x7B0080EF,0x60251DB0,0xFB59E2FF,0xDA209242,0x4C391940,0xF80392CD,
	0xD0C024C2,0x3064F276,0xA80E89AC,0x9561DC29,0xC42CD07F,0x66A801C7,0x80E68B66,0xDEACCB65,
	0x854F7723,0xFBB353DB,0x62DDA745,0x5DCD69DA,0xB0E6B221,0xDD8B9625,0x730934E8,0x7C3B0EDF,
	0xE6A46C2A,0x09392564,0x656F8E64,0xC4ABA2A4,0xF6D40C8D,0xC3AA5925,0x2A776965,0x6AC7BFE7,
	0x9EDC2D84,0x42DAEA29,0x3C38F1ED,0x75D7537C,0x718B5996,0xB382E614,0x341293F6,0x30D4969C,
	0x1C8D37B1,0x4C5507EA,0x34655A40,0x53DF034E,0xD5D279A6,0xB7D5200C,0xB82CD5EB,0xD9D5DC0A,
	0xD79106EE,0x01968417,0x22DDAF3D,0xB807952A,0x2BF3C5AD,0x163698B5,0x707FF7D4,0x00DBDE63,
	0x1BAEB275,0x813C48B5,0xEE8DDCA5,0x571C35BD,0x023B050B,0x5CC0D792,0x9748F20B,0x99942EF8,
	0x980A6F08,0x7F889654,0x9468531F,0x0A2A92A7,0xEFDE53A4,0xC75784A8,0xAD11046E,0x838349EB,
	0x30852C2D,0x9CC94F74,0x418CC095,0xF48DC2EE,0xD134F3D2,0xFEA624A6,0x5A2B8F09,0xEEE757BE,
	0xBC20DA6A,0x33A5CE00,0x7607D1E2,0x576BE69F,0xAADB07A5,0x2BF7F96C,0x49C3B304,0x747CBEC4,
	0xE6EED45A,0xAD73664B,0x98B7A678,0x3F4E41E6,0x193D394F,0x207F26D4,0xB20F5920,0x5F9C98C9,
	0x3AD3F8C5,0x01A13B8B,0x4481F4C2,0x415497BA,0xEA96C286,0xB63BC6EB,0x8032AE08,0xC7E999CA,
	0x5DC66779,0x6B992FD6,0xCE9E5037,0xBDB78F58,0x41E92A8F,0xFDAE4873,0x7A7129C1,0xB21169D9,
	0x7CE27673,0x484AE2DC,0xDE0B9A7C,0x645B1DB2,0xEF195A94,0x9B6895B8,0x7DFEE290,0x25CDD7C9,
	0xFC9C5412,0x6D036B75,0xDE9DE836,0xFA492EAA,0x9CDE6306,0x03BB0532,0x12106395,0x7E4DCCCD,
	0x25537502,0xA2C9D478,0x762108AA,0xA6782A21,0x7397D8A6,0x2A6BD4FA,0x3C6A3D0B,0xE7E92696,
	0xDE5EF639,0x79D1A7D9,0x3D9819F0,0x0619C03B,0x5FC6B565,0x648CCD33,0x3EF309F9,0x559A78F4,
	0x3D1DFBA7,0x71162E9A,0xD53E8781,0xC50044FB,0xE873A1F4,0xB0858C4B,0xEEF9DB9A,0x3C637E72,
	0x6F250DAF,0xC1CB4111,0x7738A7DB,0xD9D20F06,0x757ACB65,0x8C9F109E,0x8DE4E70E,0x5D3E0B90,
	0x59FCAD8B,0x9FB163F1,0xF2223F1A,0x48213643,0x7BC8FB93,0xEBDA1191,0x49285414,0x1E005108,
	0x95A3028A,0x94360053,0x61569C95,0xAB489C89,0x2C39A5CC,0x2B109ADE,0xCE6AE59E,0xFC767B1B,
	0xFE2735E3,0x0160C575,0x8C4717D1,0xF4E8C9A2,0x05B3017A,0x023851B4,0x65434362,0x933005E1,
	0x3983869D,0xC67EF8E4,0xE7BC2C4A,0x76B74CE6,0x23517D64,0xEA2FBB96,0x3B4B094F,0xD4C545DE,
	0x5EFB151C,0x0EAAD0BE,0x82D2E54B,0xF7F3175E,0x7FB23E6A,0xA2131C0B,0xA8C0A612,0xA0EF9D24,
	0x5F60CE35,0x90DBFD93,0x428DD144,0x8C42B364,0x2CB80A7C,0xEF306A21,0x32AAA4A1,0xB334E500,
	0x818FAACE,0xAA4C64DC,0x73FAA6DA,0x70E4AA2A,0x60597B4C,0xDCA739BE,0x398C0A31,0xDE46BC58,
	0x4BA590D1,0xEC4EE9B6,0xB6C395C4,0xA78B2892,0x3467907E,0x1F7F05E7,0x7063B941,0xEC249D38,
	0x0B53A797,0x69DF0F8A,0xD5C03B8B,0xBF80071B,0x5854EAA4,0x07025CF6,0x5A6FBD41,0x514BF69F,
	0xF451D0AC,0x4B15D5A0,0xED6C9FE3,0x2B814C0C,0x660DBB4D,0xD34B4B7E,0x904E90EF,0xC7BE5425,
	0xEDD50356,0xC3251157,0xCA65E921,0xABD3DDA5,0xD107EE66,0x77382A98,0xF1E972E5,0x638F4A9A,
	0xEF65C20F,0xA22C4C5C,0x2A44BAF7,0x8A3DC37A,0xC5B79304,0xC692775E,0xA816C745,0x5B3B5EAE,
	0x454CDCF4,0x55489A7A,0xCEA78207,0x1AC739DF,0x140B1D90,0xEAFC331E,0xE7EC19EA,0x4D906266,
	0x01F892CB,0xA1BCF7C1,0xD9B61DDA,0xFFAFD217,0x8BFD6096,0x4F1D69A1,0xD689664F,0x9E99A724,
	0x2CB44AB6,0x7BC6443D,0xA860BA8F,0x927BC6AF,0x98A1AAF2,0x8204401A,0x67C6DBD4,0xA19E7266,
	0x95AFDE1A,0xF23C45E9,0xFC29FDCF,0x32DA17D0,0x8F346B20,0xC2F36C3E,0x8A034280,0x6D1FC649,
	0xBB7C5B99,0x4282619D,0xF05BEE16,0x5A4CD051,0x8C7877EC,0x0ECB339B,0x41689D73,0xE5092CE7,
	0x4454B7C0,0x29E57FB2,0xF44FD75D,0x89D9929C,0xA5D31D5E,0x5398B048,0x2BFE0289,0x76BFF6EB,
	0xD46D144C,0xB917A6D7,0xB895D528,0xED988A4E,0xB7AFEFDD,0x4DEE4C69,0x560CCC74,0xE37049F0,
	0xAE0E6FB9,0x6A4A9061,0x9890C060,0x0EF51D7F,0x260E48EA,0x6C9A289D,0x7849A74E,0x5E96EEE2,
	0xB52FC228,0x7B4C9DB5,0xBC925ED5,0x3C15B90E,0xDEC489DD,0x63E60772,0x8DDD1AC6,0x5AD1AD24,
	0x38E65D44,0x08996B89,0x1B450DAE,0x216F2DF8,0x31AA10A2,0x4CBB4124,0x27FB8AB5,0x8D0AD30E,
	0xCA925EDE,0x9017819F,0xAA030A09,0x13580386,0x65233376,0xCD137D6C,0xDD2FD42F,0xD4801993,
	0xE9747BCD,0x1D7829A1,0xB1F9F4EC,0xB0A44CBC,0x4A86A9AC,0x2FB9B0FC,0xA865EB0B,0xE74EA546,
	0x510457DC,0x9C04CF59,0x3C8F43B5,0xBC5978C2,0x9243853A,0x16A79F01,0x1C42B7BA,0xCF10DD12,
	0xFAC9D6E5,0x230714F8,0x68E7E4F0,0x87B35E29,0x51899C06,0xF5297317,0x9102EAEF,0x51F8FF27,
	0x5D5F45E4,0xDBD8E13F,0xBA167F6F,0x4269E679,0x1C0D86AE,0xA7F88AD4,0x9FCB6D58,0x1D8B249B,
	0x6F9D6F4A,0x393C4E1E,0xD9E4258B,0xE7196B8E,0xEEED71C4,0xB6DB404E,0x431AACC7,0x5106E1D6,
	0x7FB6C142,0x964580C8,0x06AC166B,0x11525D6C,0x8E7AFC49,0x3B72CCCF,0x750DC09B,0xFE130DAC,
	0x1A6CA55D,0xC59BEA8B,0x6E1B34DF,0xCEB07A52,0x7AE492FB,0x56432898,0xEB9CB88F,0xFD0377B7,
	0x0E8C5721,0xAE24861A,0xD225B885,0xFAEE35EA,0x48908007,0xE7441205,0x7E2F8614,0x0C3486C1,
	0xD380C315,0x9A2E3A8E,0x15E2D981,0x7DF6A77E,0xB87D864C,0x2F0F24EC,0x24E9A7BE,0x73583F12,
	0x731655AA,0x90B79802,0x0B827087,0x3A05EFB6,0xAAA9C34B,0xE3B8E168,0x15B8BA0C,0x18722E6E,
	0x49C69CDE,0xC159A8EF,0x90880B6C,0xD3C5E9C3,0x7F801F94,0xABC7E98C,0xC4063B5C,0x49E15059,
	0xAA1AA595,0x50777770,0xB3536D3F,0x853C25D2,0x4314A071,0x364936A7,0x0D495D15,0x8E2C5B72,
	0x35BFB42D,0x8AD30FA6,0x0A7DC879,0xBE956435,0x7499CAEC,0xEDCC27D9,0x312291BA,0xAEA0224C,
	0xF7BD09C7,0x52C5CC59,0xF0C2B520,0xCA9136CC,0xFF0504DE,0x0E0E5969,0x9D84491E,0xB5432B37,
	0x7E50F755,0x29FD1C8E,0xA80C9EF6,0xAFC8A98F,0xC76C02C6,0xE2C25665,0x36A1A53C,0x7A1EA069,
	0xF1297E2A,0x4469ABAC,0x3D9A4FE5,0x19A431C8,0xDBD4B37C,0x092FEA0A,0xB06F9333,0xDA0C4D31,
	0x4638F5FC,0x61FE4C3C,0xC1F6F1DD,0x37254B73,0xF9953E18,0x47DF1505,0x532C74F8,0x8FEC7624,
	0x96488578,0xA46AABD1,0x0D797F38,0x9FE94AC1,0x8FA81F8C,0x47DD5B29,0xC812103F,0x18256573,
	0x469A9151,0xF3E9EB69,0x311863A1,0xC4A2DEFC,0xB7F16FCA,0x0D9ED944,0x2D01CE93,0xE840717D,
	0x99D68545,0xBD569429,0xDD7B1489,0x36C7EABE,0xA30EA606,0x4DFC7E3D,0xF683EE84,0x73878E7A,
	0x08A1BF82,0x5A749C6F,0xD3D92AFF,0xE50AAEA7,0xCD5A128A,0x6959CFE6,0x6EE073F7,0xEE0405C6,
	0x33E89D4B,0x5FAE4E6E,0x1A92475E,0x639F1EC2,0x92AF5DC5,0x602C4326,0x630D0385,0xA95B6412,
	0x5B116C5E,0x23BF6EB9,0x4730AC1F,0xE8D24FAB,0xC8182B7C,0x1B966BB4,0x36B8C259,0x09E94003,
	0x8C4AA6D6,0xAB2898D2,0x919B97A3,0x54F87AD5,0x5BFA3FC8,0xABD178D5,0xC18E2B15,0xDF252B3D,
	0xCAF65E21,0xB7E603B3,0x8CEAF425,0xD78D63E1,0x3718C1F0,0x76CA1592,0xAC25C4D9,0xCE94C849,
	0x24B247D3,0x3F58F379,0xB837815D,0xE745D4B2,0x92950E80,0x86CA4EB9,0x3CBEED18,0x05B8ADF4,
	0xC3F83512,0xC513B35F,0xD0F4FAEF,0x885D2853,0x81F64A13,0x1B5819CA,0xF01195EF,0xE8D0BE8B,
	0xEEE45337,0xD15F243F,0x462D62A6,0xBEF8D660,0xC2F5DEFE,0x0D75E6B9,0x14138636,0x4A6BDE4A,
	0x5CC1168C,0xA91E27CC,0x4A99BFF2,0x969690FD,0xD3FBAE0A,0x4B8B8622,0x8E7C3F0C,0xD3936355,
	0x63D9AF77,0xB2A0DA57,0x17CECFE2,0x6A23AB53,0x1CF16062,0xC11437CB,0x7A90AFCD,0xC359BD32,
	0xA342A3F9,0xFB721C8A,0x1CEF3B85,0x31FA22FB,0x9CA03B8F,0xB4CD091E,0x41BFA6E4,0x930C31D3,
	0xE989C72E,0x70ED1BD5,0x65DCF8B9,0xF975E03B,0x83846C7F,0x2D64DF9A,0xE0FA64C4,0x5C2FBDF3,
	0x7C1CD805,0xE4106601,0xE4CFE66F,0xDB619A90,0xE1E82C36,0x15E3A81D,0xAF5E65C4,0x86E5EFCF,
	0x54BA0F13,0x280BF828,0x08146C9F,0x9061EB0C,0xB7D087DA,0xCA8EC7F9,0xFFFBBA00,0x9C050F21,
	0x147091BB,0xE5C88F41,0x73688700,0x563DE9DF,0x060ECF84,0xD81FB126,0x5FCC8492,0x94B7D4E3,
	0xE3B87141,0x913BF72D,0xEE26DC27,0x9892661F,0xC692D608,0xE568E72F,0xA4064E6D,0x206B1F02,
	0xC820A681,0xED760E59,0x537E643C,0x2F1E8B6E,0xC22FB22B,0x3EE79150,0xE4569D0F,0x59C2662A,
	0x536CF47A,0xF785C490,0x37A436D6,0x83523A0F,0xAFEE1A98,0x0751CC3D,0x873B17BC,0xAD8427F5,
	0x52C364D1,0x06C799A4,0xA39FAA81,0x382372B4,0x8F0E0840,0xD83BE9C6,0xE22F8B3E,0x88994809,
	0x092E749C,0x99D5EE44,0x1F8FF9C7,0xA10BE901,0x996C8F44,0x73403FEE,0x75577DDD,0xC6CB4FB7,
	0x4A2DE995,0x41BD8F63,0xDE90EC81,0xDA792B54,0xDE07BB2F,0xADD68686,0xC67E72F0,0xB62D900B,
	0x256F5CF0,0x7A4F610A,0xC1DAA775,0xA4361D79,0x255A0E15,0x600B72DF,0xBDCB5DCD,0x8EF0708B,
	0xE56ABCEB,0x09DBD8D5,0x203C46E5,0xF3544BA7,0x4C2A17D3,0xC9D82142,0xB487156B,0x7223FE55,
	0x4547DAF3,0x8BA9D2CB,0x2A4DA80B,0x6092DF55,0x2C907811,0xB42E20D1,0x54895D7A,0x5303B92B,
	0x8DEEAA17,0x62ED8DCD,0x55CFAF0F,0x19A37877,0xA3B4F04A,0x61ABCCF4,0xEF57E114,0xC455218A,
	0x50602500,0x5E41DA45,0xDF12DC8C,0x2C92B674,0x77441A7A,0x04686A60,0x0967ED47,0x32247F34,
	0x273279EE,0xA8E1A708,0x33586D0F,0x9C9D979C,0x54EAD8D8,0x5B5FB4D0,0x22C6D245,0x298F3A9C,
	0x25A3F73C,0x1CFD7438,0x5EFE3268,0xACD9B70C,0xEA5DB41B,0x1FB68916,0x53653DFE,0x93C0A701,
	0x8A38BAD6,0x025432A8,0x39BEA800,0xDF61F30C,0xD397F214,0xE956B4FF,0x84684518,0xD796EB13,
	0x9367EA6A,0x4245736E,0xC9062113,0x18BA22AA,0x90CC43DF,0xF625F69B,0xE66F956D,0x4DF5A550,
	0xAD107A2B,0x0D7D7ECA,0xA014D204,0x3778955B,0x6375FA1D,0x4260030C,0xDFB0C8C9,0x61BAD3BB,
	0xCF4784CF,0xAEA80610,0xDEE57929,0x85C8D1EC,0xF6CFB398,0xF46E825F,0x96233AC4,0xD4AB35E7,
	0x5E904638,0x3D0C5492,0xC47C1195,0x5C36C467,0x2585F750,0x92E6C095,0x8595FB25,0x9E0D4620,
	0x40ACA851,0xD6682543,0xAB837530,0x925C06FA,0x8CC94555,0xD6E9C8C3,0xAD34D9AD,0x0BD700D6,
	0x9B03D8FB,0x1623C9C7,0x0A9869A2,0x917950BF,0x5ACEE365,0xF931D78F,0x2A05D5AC,0x46447CEB,
	0x02DA1D57,0xA7433E6F,0xECB87BA4,0xFC7E472C,0xC9B037A7,0x3E55A0AB,0x63452FC6,0x397421BD,
	0x038FB8C6,0xAD39D13E,0xDD86BCCE,0xA5221321,0x6F5625C6,0xFD8FA734,0x607A7198,0x0E83FF9B,
	0x72D374C4,0xEEA8A6A2,0x7182D16E,0xD4C2F825,0x8F464FB5,0x3E3CFCAE,0x95FED6DE,0x7F758A64,
	0x311FA65E,0xEB32E476,0x70BA57E9,0xA680AF8D,0x8EE3BC76,0x63937A78,0x44F9E702,0x7F8BA4B1,
	0x05025436,0x66AAA09F,0x31A8C7A3,0xD07221CE,0x2FB029BF,0x7AB1EA02,0xA4C8F135,0xAE57B75D,
	0x85F0DF32,0x56A1045C,0x4AC35E5D,0xEC65688B,0xF77BF1EB,0x4B7F32DF,0xA74F7E01,0x65114FCE,
	0xB5BC91F6,0x3D855B7C,0x9A653EE5,0xFBAAE146,0xFCFD774B,0x50DB5778,0xF93D2DC6,0x50F2BB93,
	0xE37EA181,0x157C3440,0x7B7DAEC7,0xC0EFE691,0xFCA326E4,0x082547B4,0x3A15509B,0x5EF06653,
	0x5A663583,0x2BBFFA0A,0xC15A7130,0x35D23DE0,0xD0A3A653,0x3CA723BD,0x65FA5082,0xC4D84C2C,
	0x85C46170,0x0EAD4B45,0xCC9FABF6,0x955D5639,0x907A66FD,0x64D698E8,0x263992C4,0xDED4ED49,
	0xEEDA21CF,0x3C0CB894,0xFE5B7887,0x9E717C6A,0x2031935F,0x40A652CD,0x26B98C09,0x4F79D9C9,
	0xC8CE1B07,0x4ACA2062,0x1E45534B,0x63EEA923,0x185517A8,0x8223098A,0x950FF2FA,0xBD13F7F2,
	0x50239569,0x1D53DB9E,0xAA503FAF,0x9E1F8DF0,0x922FEC7A,0x5CA619FE,0x53963F96,0xCDA4E004,
	0xFFF37193,0xD3832AAA,0x9A61C34F,0x26335C54,0x7B98CD53,0x3DFE8B1A,0xC874776E,0x1BE2F75C,
	0x31C27308,0xCE7DCB31,0x3D3014F1,0x83AE9840,0x0FF41A46,0xF29857D2,0x6ED74EEA,0x3DF4E4E6,
	0xC1F0B97A,0x55FDE681,0xDCC2C6BC,0xF4DF3955,0xE6E0B290,0x852FE14A,0x0D70D247,0x701A8E56,
	0xC1F61A5C,0xA78F3F8A,0x9B932B07,0xE09F1837,0x35038156,0xFCD88FE6,0x71139AFC,0x9E2E1734,
	0x9842716B,0x2383FB1F,0x8E57EE9F,0xCDD21C66,0xA4BB112D,0x181ED042,0x229E0B36,0x1C7EC204,
	0xD1C91F2E,0xD5AEBAED,0xEB56CDCE,0x88295ABA,0xD6284235,0xEE8B49B9,0xF291A653,0x66A01398,
	0xC0640DDC,0x344494BB,0x27CEAF58,0xB667C9CE,0x52D6D025,0x1E9AF30E,0x0BAAD63C,0x29BB0D08,
	0x8D9DF6EE,0xF0F7BBC7,0x737DA614,0x2638EBB6,0x2E98A490,0x395233E0,0x9E896D00,0xD61FFD45,
	0xADFBC198,0x3FD444EC,0x488E1747,0x7AE53A84,0xCE501A60,0x00DB331F,0x41201501,0x60AAFC42,
	0x14129C00,0x33FED87A,0xECA6C45B,0x18E3DBC7,0x0F5516E2,0x613FEEB8,0x19ECD7CD,0x64790BA1,
	0xD957A6E0,0xD5CA7DF3,0x29731C6E,0xB3CA1658,0x52A34129,0x0010C824,0x31E193CE,0x9E180B61,
	0x755AD012,0x5C19C7BA,0xC7EFF482,0xF83E7E2F,0x351CBA69,0x3AAFDD19,0x7FE9230C,0xEAB0A228,
	0xB79A1B2C,0x179B3AC3,0xC8960260,0x5B042D46,0xAA7831AB,0xFF5F71B2,0x1CCD0828,0xA66964B4,
	0x7CA2C01E,0x9268C541,0x4D5A23A9,0xC8825CED,0xC493FB8D,0xFD9DE9EF,0x5CD37515,0xC67614AD,
	0x1CFD2CE6,0x034B4BD0,0x7C7D6DBF,0x4DADE7CF,0xF756D66B,0xEB09C8F1,0xDD3DEC3B,0xA3498C84,
	0xCE2F6DB8,0x503B808B,0x47F5D0CC,0x9874AB25,0x5202906B,0x5203F404,0xB06DC274,0xE211AD76,
	0xE0A37226,0x9BEED89A,0xB3E9BE7E,0xD9E99114,0xC4493B6A,0x91A063BD,0x72FE0DBF,0x557EAAB1,
	0xF2D31649,0x77B2A0CC,0x82BBAAE8,0x317B62D3,0xE6550746,0xA1EAF358,0xF85724E1,0x0F7D8082,
	0x0FCB960F,0x99E6DD6D,0x1CEE1CBF,0x6A20EBDC,0x6D3E25D4,0xA0441C54,0x17871F41,0x844C5E55,
	0x0CAAB3BD,0xA3AA58CA,0x5388ACEE,0x5FF98D8A,0x10197FBD,0xA079D2B4,0x6FAB96F5,0xCA8FF8F8,
	0xB52E442E,0xEBD5703B,0x3FF76AF1,0x5F1B5FBE,0x0CA5FE46,0x297E6C5C,0xADB3981F,0xEF71A7F0,
	0x11F9DE0B,0xCFDD0AFC,0x99EFD88F,0x42040EC3,0x0FE15653,0x074FD3A8,0xB9B43EED,0xDA4E0FAD
};
PRIVATE int ocl_protocol_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	cl_uint keys_opencl_divider = 8 * (num_passwords_loaded == 1 ? 2 : 1);
	cl_uint sha256_empy_hash[] = {0x3cc244af, 0x7c9d7e7b, 0x9d2579b4, 0x9daa992a, 0xa98c2030, 0x4418ce34, 0x8511bf70, 0x7ec75212};

	// Do not allow blank in GPU
	if (current_key_lenght == 0)
	{
		unsigned char* bin = (unsigned char*)binary_values;

		for (cl_uint i = 0; i < num_passwords_loaded; i++, bin += BINARY_SIZE)
			if (!memcmp(bin, sha256_empy_hash, BINARY_SIZE))
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
			uint32_t up0 = sha256_one_char[8*charset[i] + 0];
			uint32_t up1 = sha256_one_char[8*charset[i] + 7];

			uint32_t pos = up0 & cbg_mask;
			uint_fast16_t data = cbg_filter[pos];
			if (((data ^ up1) & 0xFFF8) == 0 && cbg_table[pos] != NO_ELEM && !memcmp(((uint32_t*)binary_values) + cbg_table[pos]*8, sha256_one_char + 8*charset[i], BINARY_SIZE))
				password_was_found(cbg_table[pos], key);// Total match

			// 2nd pos
			if (data & 0b110)
			{
				pos += data & 0b1 ? -1 : 1;
				uint_fast16_t hash = cbg_filter[pos];
				if (((hash ^ up1) & 0xFFF8) == 0 && cbg_table[pos] != NO_ELEM && !memcmp(((uint32_t*)binary_values) + cbg_table[pos]*8, sha256_one_char + 8*charset[i], BINARY_SIZE))
					password_was_found(cbg_table[pos], key);// Total match

				// Unluky bucket
				if (data & 0b10)
				{
					pos = up1 & cbg_mask;
					data = cbg_filter[pos];
					if (((data ^ up0) & 0xFFF8) == 0 && cbg_table[pos] != NO_ELEM && !memcmp(((uint32_t*)binary_values) + cbg_table[pos]*8, sha256_one_char + 8*charset[i], BINARY_SIZE))
						password_was_found(cbg_table[pos], key);// Total match

					// 2nd pos
					pos += data & 0b1 ? -1 : 1;
					hash = cbg_filter[pos];
					if (((hash ^ up0) & 0xFFF8) == 0 && cbg_table[pos] != NO_ELEM && !memcmp(((uint32_t*)binary_values) + cbg_table[pos]*8, sha256_one_char + 8*charset[i], BINARY_SIZE))
						password_was_found(cbg_table[pos], key);// Total match
				}
			}
		}

		current_key_lenght = 2;
		report_keys_processed(num_char_in_charset);
	}

	return ocl_charset_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha256_header, ocl_gen_kernel_with_lenght, sha256_empy_hash, CL_FALSE, keys_opencl_divider);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_gen_kernel_sha256(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint value_map_collission, void* salt_param, cl_uint prefered_vector_size)
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

	sprintf(source + strlen(source), "uint A,B,C,D,E,F,G,H,W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;");

	ocl_convert_2_big_endian(source, nt_buffer[0], "W0");
	ocl_convert_2_big_endian(source, nt_buffer[1], "W1");
	ocl_convert_2_big_endian(source, nt_buffer[2], "W2");
	ocl_convert_2_big_endian(source, nt_buffer[3], "W3");
	ocl_convert_2_big_endian(source, nt_buffer[4], "W4");
	ocl_convert_2_big_endian(source, nt_buffer[5], "W5");
	ocl_convert_2_big_endian(source, nt_buffer[6], "W6");
	sprintf(source + strlen(source), "W15=0%s;", nt_buffer[7]);

	// Round 1
	sprintf(source + strlen(source),
		"H=0xfc08884dU+W0;D=0x9cbf5a55U+H;"
		"G=R_E(D)+(%uu^(D&%uu))+0x90bb1e3cU+W1;C=0x3c6ef372U+G;G+=R_A(H)+MAJ(H,%uu,%uu);"
		"F=R_E(C)+bs(%uu,D,C)+0x50c6645bU+W2;B=0xbb67ae85U+F;F+=R_A(G)+MAJ(G,H,%uu);"
		"E=R_E(B)+bs(D,C,B)+0x3ac42e24U+W3;A=0x6a09e667U+E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x3956C25BU+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x59F111F1U+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x923F82A4U+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0xAB1C5ED5U;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0xD807AA98U;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0x12835B01U;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x243185BEU;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x550C7DC3U;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x72BE5D74U;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x80DEB1FEU;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x9BDC06A7U;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0xC19BF174U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		, 0x9b05688c, 0xca0b3af3, 0x6a09e667, 0xbb67ae85
		, 0x510e527f, 0x6a09e667);

	sprintf(source + strlen(source),
		"W0+=R0(W1);"
		"W1+=R1(W15)+R0(W2);"
		"W2+=R1(W0)+R0(W3);"
		"W3+=R1(W1)+R0(W4);"
		"W4+=R1(W2)+R0(W5);"
		"W5+=R1(W3)+R0(W6);"
		"W6+=R1(W4)+W15;"
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
		"H+=R_E(E)+bs(G,F,E)+0xE49B69C1U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xEFBE4786U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0x0FC19DC6U+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0x240CA1CCU+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0x2DE92C6FU+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0x4A7484AAU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x5CB0A9DCU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x76F988DAU+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"H+=R_E(E)+bs(G,F,E)+0x983E5152U+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"G+=R_E(D)+bs(F,E,D)+0xA831C66DU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"F+=R_E(C)+bs(E,D,C)+0xB00327C8U+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"E+=R_E(B)+bs(D,C,B)+0xBF597FC7U+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"D+=R_E(A)+bs(C,B,A)+0xC6E00BF3U+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"C+=R_E(H)+bs(B,A,H)+0xD5A79147U+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"B+=R_E(G)+bs(A,H,G)+0x06CA6351U+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"A+=R_E(F)+bs(H,G,F)+0x14292967U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");

	/* Round 3 */
	sprintf(source + strlen(source),
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x27B70A85U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x2E1B2138U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x4D2C6DFCU+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x53380D13U+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x650A7354U+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x766A0ABBU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x81C2C92EU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x92722C85U+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);"
		"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0xA2BFE8A1U+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W9+=R1(W7)+W2+R0(W10);G+=R_E(D)+bs(F,E,D)+0xA81A664BU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W10+=R1(W8)+W3+R0(W11);F+=R_E(C)+bs(E,D,C)+0xC24B8B70U+W10;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W11+=R1(W9)+W4+R0(W12);E+=R_E(B)+bs(D,C,B)+0xC76C51A3U+W11;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W12+=R1(W10)+W5+R0(W13);D+=R_E(A)+bs(C,B,A)+0xD192E819U+W12;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W13+=R1(W11)+W6+R0(W14);C+=R_E(H)+bs(B,A,H)+0xD6990624U+W13;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W14+=R1(W12)+W7+R0(W15);B+=R_E(G)+bs(A,H,G)+0xF40E3585U+W14;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W15+=R1(W13)+W8+R0(W0);A+=R_E(F)+bs(H,G,F)+0x106AA070U+W15;E+=A;A+=R_A(B)+MAJ(B,C,D);");
													   													  
	/* Round 4 */									   													  
	sprintf(source + strlen(source),				   													  
		"W0+=R1(W14)+W9+R0(W1);H+=R_E(E)+bs(G,F,E)+0x19A4C116U+W0;D+=H;H+=R_A(A)+MAJ(A,B,C);"
		"W1+=R1(W15)+W10+R0(W2);G+=R_E(D)+bs(F,E,D)+0x1E376C08U+W1;C+=G;G+=R_A(H)+MAJ(H,A,B);"
		"W2+=R1(W0)+W11+R0(W3);F+=R_E(C)+bs(E,D,C)+0x2748774CU+W2;B+=F;F+=R_A(G)+MAJ(G,H,A);"
		"W3+=R1(W1)+W12+R0(W4);E+=R_E(B)+bs(D,C,B)+0x34B0BCB5U+W3;A+=E;E+=R_A(F)+MAJ(F,G,H);"
		"W4+=R1(W2)+W13+R0(W5);D+=R_E(A)+bs(C,B,A)+0x391C0CB3U+W4;H+=D;D+=R_A(E)+MAJ(E,F,G);"
		"W5+=R1(W3)+W14+R0(W6);C+=R_E(H)+bs(B,A,H)+0x4ED8AA4AU+W5;G+=C;C+=R_A(D)+MAJ(D,E,F);"
		"W6+=R1(W4)+W15+R0(W7);B+=R_E(G)+bs(A,H,G)+0x5B9CCA4FU+W6;F+=B;B+=R_A(C)+MAJ(C,D,E);"
		"W7+=R1(W5)+W0+R0(W8);A+=R_E(F)+bs(H,G,F)+0x682E6FF3U+W7;E+=A;A+=R_A(B)+MAJ(B,C,D);");

	// Match
	if (num_passwords_loaded == 1)
	{
		uint32_t* bin = (uint32_t*)binary_values;

			if (found_param_3)
				sprintf(output_3, "output[3u]=%s;", found_param_3);

			sprintf(source + strlen(source),
				"W8+=R1(W6)+W1+R0(W9);"
				"W9+=R1(W7)+W2+R0(W10);"
				"W2=W11+R1(W9)+W4+R0(W12);"
				"W1=W13+R1(W2)+W6+R0(W14);"
				"W0=W15+R1(W1)+W8+R0(W0);A+=W0;"

				"if(A==%uu)"
				"{"
					"A-=W0;"
					"W10+=R1(W8)+W3+R0(W11);"
					"W12+=R1(W10)+W5+R0(W13);"
					"W14+=R1(W12)+W7+R0(W15);"

					"H+=R_E(E)+bs(G,F,E)+0x748F82EEU+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
					"G+=R_E(D)+bs(F,E,D)+0x78A5636FU+W9;C+=G;G+=R_A(H)+MAJ(H,A,B);"
					"F+=R_E(C)+bs(E,D,C)+0x84C87814U+W10;B+=F;F+=MAJ(G,H,A);"
					"E+=R_E(B)+bs(D,C,B)+0x8CC70208U+W2;A+=E;"
					"D+=R_E(A)+bs(C,B,A)+0x90BEFFFAU+W12;H+=D;"
					"C+=R_E(H)+bs(B,A,H)+0xA4506CEBU+W1;G+=C;"
					"B+=bs(A,H,G)+W14;"
					"H-=D;"

					"if(B==%uu&&C==%uu&&D==%uu&&E==%uu&&F==%uu&&G==%uu&&H==%uu)"
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

		sprintf(source + strlen(source),
			"W8+=R1(W6)+W1+R0(W9);H+=R_E(E)+bs(G,F,E)+0x748F82EEU+W8;D+=H;H+=R_A(A)+MAJ(A,B,C);"
			"W9+=R1(W7)+W2+R0(W10);"
			"W2=W11+R1(W9)+W4+R0(W12);"
			"W1=W13+R1(W2)+W6+R0(W14);"
			"W0=W15+R1(W1)+W8+R0(W0);A+=W0;");

		// Find match
		sprintf(source + strlen(source), "uint xx=A&%uu;uint fdata;", cbg_mask);
		
		sprintf(source + strlen(source),
			"fdata=(uint)(cbg_filter[xx]);"

			"if(((fdata^H)&0xFFF8)==0){"
				"indx=cbg_table[xx];"
				"if(indx!=0xffffffff&&A==binary_values[indx*8u]&&H==binary_values[indx*8u+7u]){"

					"uint aa=A-W0;"
					"W4=W10+R1(W8)+W3+R0(W11);"
					"W6=W12+R1(W4)+W5+R0(W13);"
					"uint ww14=W14+R1(W6)+W7+R0(W15);"

					"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

					"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
					"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
					"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
					"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
					"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
					"bb+=bs(aa,hh,gg)+ww14;"

					"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]"
					 "&&ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]){"
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
				"if(((((uint)cbg_filter[xx])^H)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&A==binary_values[indx*8u]&&H==binary_values[indx*8u+7u]){"

						"uint aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"uint ww14=W14+R1(W6)+W7+R0(W15);"

						"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]"
						"&&ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]){"
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
				"xx=H&%uu;"
				"fdata=(uint)(cbg_filter[xx]);"
				"if(((fdata^A)&0xFFF8)==0){"
					"indx=cbg_table[xx];"
					"if(indx!=0xffffffff&&A==binary_values[indx*8u]&&H==binary_values[indx*8u+7u]){"

						"uint aa=A-W0;"
						"W4=W10+R1(W8)+W3+R0(W11);"
						"W6=W12+R1(W4)+W5+R0(W13);"
						"uint ww14=W14+R1(W6)+W7+R0(W15);"

						"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

						"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
						"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
						"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
						"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
						"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
						"bb+=bs(aa,hh,gg)+ww14;"

						"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]"
						"&&ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]){"
							"uint found=atomic_inc(output);"
							"output[%iu*found+1]=get_global_id(0);"
							"output[%iu*found+2]=indx;"
							"%s"
						"}"
					"}"
				"}"
			, cbg_mask
			, found_multiplier, found_multiplier, output_3);

		sprintf(source + strlen(source),
				"if(fdata&4){"// Is second
					"xx+=fdata&1?-1:1;"
					"if(((((uint)cbg_filter[xx])^A)&0xFFF8)==0){"
						"indx=cbg_table[xx];"
						"if(indx!=0xffffffff&&A==binary_values[indx*8u]&&H==binary_values[indx*8u+7u]){"

							"uint aa=A-W0;"
							"W4=W10+R1(W8)+W3+R0(W11);"
							"W6=W12+R1(W4)+W5+R0(W13);"
							"uint ww14=W14+R1(W6)+W7+R0(W15);"

							"uint bb=B,cc=C,dd=D,ee=E,ff=F,gg=G,hh=H;"

							"gg+=R_E(dd)+bs(ff,ee,dd)+0x78A5636FU+W9;cc+=gg;gg+=R_A(hh)+MAJ(hh,aa,bb);"
							"ff+=R_E(cc)+bs(ee,dd,cc)+0x84C87814U+W4;bb+=ff;ff+=MAJ(gg,hh,aa);"
							"ee+=R_E(bb)+bs(dd,cc,bb)+0x8CC70208U+W2;aa+=ee;"
							"dd+=R_E(aa)+bs(cc,bb,aa)+0x90BEFFFAU+W6;hh+=dd;"
							"cc+=R_E(hh)+bs(bb,aa,hh)+0xA4506CEBU+W1;gg+=cc;"
							"bb+=bs(aa,hh,gg)+ww14;"

							"if(bb==binary_values[indx*8u+1u]&&cc==binary_values[indx*8u+2u]&&dd==binary_values[indx*8u+3u]"
							"&&ee==binary_values[indx*8u+4u]&&ff==binary_values[indx*8u+5u]&&gg==binary_values[indx*8u+6u]){"
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
	return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha256_header, ocl_gen_kernel_sha256, kernels2common + UTF8_INDEX_IN_KERNELS, 32, ocl_rule_simple_copy_utf8_le);
#else
	return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha256_header, ocl_gen_kernel_sha256, kernels2common + UTF8_INDEX_IN_KERNELS, 4/*consider 2 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
#endif
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	return ocl_common_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha256_header, ocl_gen_kernel_sha256, kernels2common + PHRASES_INDEX_IN_KERNELS, 64/*consider 32 for Nvidia*/, ocl_rule_simple_copy_utf8_le);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE int ocl_protocol_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt)
{
	return ocl_rules_init(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_sha256_header, ocl_gen_kernel_sha256, RULE_UTF8_LE_INDEX, 2);
}
#endif

Format raw_sha256_format = {
	"Raw-SHA256",
	"Raw SHA-256 format.",
	"$SHA256$",
	NTLM_MAX_KEY_LENGHT,
	BINARY_SIZE,
	0,
	7,
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