// This file is part of Hash Suite password cracker,
// Copyright (c) 2015-2016 by Alain Espinosa

#include "Interface.h"

PRIVATE bool performing_bench;// To stop the benchmark
PRIVATE int m_benchmark_time = 5;// Time used in each attack.
PRIVATE int quick_benchmark = TRUE;

PRIVATE bool have_same_bench_values(int format_index1, int format_index2)
{
	if (format_index1 < 0)
		return true;

	if (formats[format_index1].lenght_bench_values != formats[format_index2].lenght_bench_values)
		return false;

	for (int i = 0; i < formats[format_index1].lenght_bench_values; i++)
		if (formats[format_index1].bench_values[i] != formats[format_index2].bench_values[i])
			return false;

	return true;
}

#ifdef _WIN32
	#include <Windows.h>
	#define execute_bench(bench_format_index, show_index, bench_value_index) execute_bench_func(bench_format_index, show_index, bench_value_index)
#else
	#include <jni.h>
	#define Sleep(time) env->CallStaticVoidMethod(thread_cls, thread_sleep, time)
	#define execute_bench(bench_format_index, show_index, bench_value_index) execute_bench_func(bench_format_index, show_index, bench_value_index, env, my_class, thread_cls, thread_sleep, SetBenchData_id)
#endif

PRIVATE void execute_bench_func(int bench_format_index, int show_index, int bench_value_index
#ifndef _WIN32
,JNIEnv* env, jclass my_class, jclass thread_cls, jmethodID thread_sleep, jmethodID SetBenchData_id
#endif
)
{
	// Params to benchmark
	char bench_buffer[16];
	char* all_chars = (char*)"qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM 0123456789!@#$%^&*()-_+=~`[]{}|:;\"'<>,.?/\\";
	const int key_lenght = 7;

	MAX_NUM_PASWORDS_LOADED = formats[bench_format_index].bench_values[bench_value_index];
	// Benchmark
	benchmark_init_complete = FALSE;
	new_crack(bench_format_index, CHARSET_INDEX, key_lenght, key_lenght, all_chars, &receive_message, FALSE);
	// Wait to complete initialization
	while (!benchmark_init_complete) Sleep(200ll);
	// Wait a time to obtain the benchmark
	for (int j = 0; j < m_benchmark_time && performing_bench; j++)
		Sleep(1000ll);
	// Show data to user
#ifdef _WIN32
	if (bench_wnd_to_post)
		bench_wnd_to_post->OnSetBenchData(show_index, 2 + bench_value_index, password_per_sec(bench_buffer));
#else
	env->CallStaticVoidMethod(my_class, SetBenchData_id, env->NewStringUTF(password_per_sec(bench_buffer)), show_index, m_benchmark_time);
#endif

	// Stop attack
	continue_attack = FALSE;
	while (num_threads > 0) Sleep(200ll);
	Sleep(200ll);// wait a little for attack to stop
}

//#define BENCH_ONLY_CPU
//#define BENCH_ONLY_GPU
//#define BENCH_ONLY_ALL_GPU
//#define BENCH_SLEEP_TIME	5000ll
#ifdef USE_MAJ_SELECTOR
PUBLIC extern "C" int MAJ_SELECTOR = -1;
#endif

#ifdef BENCH_ONLY_ALL_GPU
#ifndef BENCH_ONLY_GPU
#define BENCH_ONLY_GPU
#endif
#endif

#ifdef _WIN32
PRIVATE uint32_t bench_thread(void* pParam)
#else
PRIVATE uint32_t bench_thread(JNIEnv* env, jclass my_class, jclass thread_cls, jmethodID thread_sleep, jmethodID SetBenchData_id, jmethodID complete_benchmark_id)
#endif
{
	// Calculate the max number of values
	int max_lenght_bench_values = 0;
	for (int i = 0; i < num_formats; i++)
		if (max_lenght_bench_values < formats[i].lenght_bench_values)
			max_lenght_bench_values = formats[i].lenght_bench_values;

	// Benchmark for all data
#ifdef USE_MAJ_SELECTOR
	max_lenght_bench_values = 4;
	MAJ_SELECTOR++;
#endif
	for (int i = 0; i < max_lenght_bench_values && performing_bench; i++)
		for (int bench_format_index = 0, show_index = bench_format_index * (num_gpu_devices + 1); bench_format_index < num_formats && performing_bench; bench_format_index++)
		{
			if (i >= formats[bench_format_index].lenght_bench_values)
				break;// TODO: Only works if it is the last
			if (!have_same_bench_values(bench_format_index - 1, bench_format_index))
				show_index++;

#ifdef BENCH_SLEEP_TIME
			Sleep(BENCH_SLEEP_TIME);
#endif
			// Benchmark CPU cores
			for (uint32_t j = 0; j < num_gpu_devices; j++)
				GPU_SET_FLAG_DISABLE(gpu_devices[j].flags, GPU_FLAG_IS_USED);
			for (app_num_threads = quick_benchmark ? current_cpu.logical_processors : 1; app_num_threads <= current_cpu.logical_processors && performing_bench; app_num_threads *= 2, show_index++)
#ifndef BENCH_ONLY_GPU
				execute_bench(bench_format_index, show_index, i)
#endif
				;

			// Benchmark each GPU
			app_num_threads = 0;
			for (uint32_t gpu_index = 0; gpu_index < num_gpu_devices && performing_bench; gpu_index++, show_index++)
			{
				gpu_devices[gpu_index].flags |= GPU_FLAG_IS_USED;
				if (gpu_index) GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index - 1].flags, GPU_FLAG_IS_USED);
#if !defined(BENCH_ONLY_ALL_GPU) && !defined(BENCH_ONLY_CPU)
				execute_bench(bench_format_index, show_index, i);
#endif
			}

			// Benchmark concurrent hardware
			if (performing_bench && !quick_benchmark)
			{
				for (uint32_t j = 0; j < num_gpu_devices; j++)
					gpu_devices[j].flags |= GPU_FLAG_IS_USED;
				if (num_gpu_devices > 1)// All GPUs
				{
					execute_bench(bench_format_index, show_index, i);
					show_index++;
				}

				if (performing_bench && num_gpu_devices > 0)// CPU+GPUs
				{
					app_num_threads = current_cpu.logical_processors;
#ifndef BENCH_ONLY_GPU
					execute_bench(bench_format_index, show_index, i);
#endif
					show_index++;
				}
			}
		}

#ifdef _WIN32
	if (bench_wnd_to_post)
		bench_wnd_to_post->OnCompleteBench();
#else
	if (performing_bench)
		env->CallStaticVoidMethod(my_class, complete_benchmark_id);
#endif

	return 0;
}



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Testing
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//#define HS_TESTING
#ifdef HS_TESTING

#ifndef _WIN32
#include <math.h>
#include <ctype.h>
unsigned char* _strupr(unsigned char *string);
unsigned char* _strlwr(unsigned char *string);
uint32_t _rotl(uint32_t v, uint32_t sh);
#endif

static int is_testing = FALSE;
extern "C" const char itoa64[];

static unsigned char* tt_usernames = NULL;
static unsigned char* tt_cleartexts = NULL;
static sqlite3_int64* tt_hash_ids = NULL;
static int* rule_used_clear = NULL;
static int* rule_param_used_clear = NULL;
static cl_uint tt_num_hashes_gen = 0;

#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476
#define INIT_E 0xC3D2E1F0

extern "C" void md5_process_block(uint32_t* state, const void* block);
static void apply_md5(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t md5_state[4];
	uint32_t nt_buffer[16];
	uint32_t len = (uint32_t)strlen((char*)cleartext);

	memset(nt_buffer, 0, sizeof(nt_buffer));
	strcpy((char*)nt_buffer, (char*)cleartext);
	((unsigned char*)nt_buffer)[len] = 0x80;
	nt_buffer[14] = len << 3;

	/* Round 1 */
	md5_state[0] = INIT_A;
	md5_state[1] = INIT_B;
	md5_state[2] = INIT_C;
	md5_state[3] = INIT_D;
	md5_process_block(md5_state, nt_buffer);

	hash[0] = 0;
	for (uint32_t i = 0; i < 4; i++)
	{
		SWAP_ENDIANNESS(md5_state[i], md5_state[i]);
		sprintf((char*)hash + strlen((char*)hash), "%08x", md5_state[i]);
	}
}
static void apply_lm(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	hash_lm((char*)cleartext, (char*)hash);
}
static void apply_ntlm(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	hash_ntlm(cleartext, (char*)hash);
}

extern "C" void sha1_process_block_simd(uint32_t* state, uint32_t* W, uint32_t simd_with);
static void apply_sha1(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t nt_buffer[8];
	uint32_t W[16];
	uint32_t sha1_state[5];

	uint32_t len = (uint32_t)strlen((char*)cleartext);

	memset(nt_buffer, 0, sizeof(nt_buffer));
	strcpy((char*)nt_buffer, (char*)cleartext);
	((unsigned char*)nt_buffer)[len] = 0x80;

	memset(W, 0, sizeof(W));

	SWAP_ENDIANNESS(W[0], nt_buffer[0]);
	SWAP_ENDIANNESS(W[1], nt_buffer[1]);
	SWAP_ENDIANNESS(W[2], nt_buffer[2]);
	SWAP_ENDIANNESS(W[3], nt_buffer[3]);
	SWAP_ENDIANNESS(W[4], nt_buffer[4]);
	SWAP_ENDIANNESS(W[5], nt_buffer[5]);
	SWAP_ENDIANNESS(W[6], nt_buffer[6]);

	W[15] = len << 3;

	sha1_state[0] = INIT_A;
	sha1_state[1] = INIT_B;
	sha1_state[2] = INIT_C;
	sha1_state[3] = INIT_D;
	sha1_state[4] = INIT_E;
	sha1_process_block_simd(sha1_state, W, 1);

	hash[0] = 0;
	for (uint32_t i = 0; i < 5; i++)
		sprintf((char*)hash+strlen((char*)hash), "%08x", sha1_state[i]);
}

// SHA-256
extern "C" void sha256_process_block(uint32_t* state, uint32_t* W);
static void apply_sha256(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t nt_buffer[8];
	uint32_t W[16];
	uint32_t sha256_state[8];

	uint32_t len = (uint32_t)strlen((char*)cleartext);

	memset(nt_buffer, 0, sizeof(nt_buffer));
	strcpy((char*)nt_buffer, (char*)cleartext);
	((unsigned char*)nt_buffer)[len] = 0x80;

	memset(W, 0, sizeof(W));

	SWAP_ENDIANNESS(W[0], nt_buffer[0]);
	SWAP_ENDIANNESS(W[1], nt_buffer[1]);
	SWAP_ENDIANNESS(W[2], nt_buffer[2]);
	SWAP_ENDIANNESS(W[3], nt_buffer[3]);
	SWAP_ENDIANNESS(W[4], nt_buffer[4]);
	SWAP_ENDIANNESS(W[5], nt_buffer[5]);
	SWAP_ENDIANNESS(W[6], nt_buffer[6]);

	W[15] = len << 3;

	sha256_state[0] = 0x6A09E667;
	sha256_state[1] = 0xBB67AE85;
	sha256_state[2] = 0x3C6EF372;
	sha256_state[3] = 0xA54FF53A;
	sha256_state[4] = 0x510E527F;
	sha256_state[5] = 0x9B05688C;
	sha256_state[6] = 0x1F83D9AB;
	sha256_state[7] = 0x5BE0CD19;
	sha256_process_block(sha256_state, W);
	
	hash[0] = 0;
	for (uint32_t i = 0; i < 8; i++)
		sprintf((char*)hash+strlen((char*)hash), "%08x", sha256_state[i]);
}

// SHA512
extern "C" void sha512_process_block(uint64_t* state, uint64_t* W);
static void apply_sha512(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t nt_buffer[8];
	uint64_t W[16];
	uint64_t sha512_state[8];
	uint32_t tmp0, tmp1;

	uint32_t len = (uint32_t)strlen((char*)cleartext);

	memset(nt_buffer, 0, sizeof(nt_buffer));
	strcpy((char*)nt_buffer, (char*)cleartext);
	((unsigned char*)nt_buffer)[len] = 0x80;

	memset(W, 0, sizeof(W));

	SWAP_ENDIANNESS(tmp0, nt_buffer[0]);
	SWAP_ENDIANNESS(tmp1, nt_buffer[1]);
	W[0] = (((uint64_t)tmp0) << 32) + tmp1;
	SWAP_ENDIANNESS(tmp0, nt_buffer[2]);
	SWAP_ENDIANNESS(tmp1, nt_buffer[3]);
	W[1] = (((uint64_t)tmp0) << 32) + tmp1;
	SWAP_ENDIANNESS(tmp0, nt_buffer[4]);
	SWAP_ENDIANNESS(tmp1, nt_buffer[5]);
	W[2] = (((uint64_t)tmp0) << 32) + tmp1;

	SWAP_ENDIANNESS(tmp0, nt_buffer[6]);
	W[3] = ((uint64_t)tmp0) << 32;
	W[15] = len << 3;

	sha512_state[0] = 0x6A09E667F3BCC908ULL;
	sha512_state[1] = 0xBB67AE8584CAA73BULL;
	sha512_state[2] = 0x3C6EF372FE94F82BULL;
	sha512_state[3] = 0xA54FF53A5F1D36F1ULL;
	sha512_state[4] = 0x510E527FADE682D1ULL;
	sha512_state[5] = 0x9B05688C2B3E6C1FULL; 
	sha512_state[6] = 0x1F83D9ABFB41BD6BULL;
	sha512_state[7] = 0x5BE0CD19137E2179ULL;
	sha512_process_block(sha512_state, W);

	hash[0] = 0;
	for (uint32_t i = 0; i < 8; i++)
		sprintf((char*)hash+strlen((char*)hash), "%016llx", sha512_state[i]);
}

#undef ROTATE
#define ROTATE(x,shift)		ROTATE32(x,shift)
#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

extern "C" {
	typedef struct
	{
		char          essid[36];
		unsigned char mac1[6];
		unsigned char mac2[6];
		unsigned char nonce1[32];
		unsigned char nonce2[32];
		unsigned char eapol[256];
		int           eapol_size;
		int           keyver;
		unsigned char keymic[16];
	} hccap_t;
	typedef struct
	{
		uint32_t keymic[4];
		unsigned char prf_buffer[128];
		unsigned char eapol[256+64];
		uint32_t  eapol_blocks;
		int           keyver;
	} hccap_bin;

	void dcc_ntlm_part_c_code(uint32_t* nt_buffer, uint32_t* crypt_result);
	void dcc_salt_part_c_code(uint32_t* salt_buffer, uint32_t* crypt_result);
	void dcc2_body_c_code(uint32_t* salt_buffer, uint32_t* crypt_result, uint32_t* sha1_hash, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W);
	void wpa_body_c_code(uint32_t* nt_buffer, uint32_t* essid_block, uint32_t* crypt_result, uint32_t* sha1_hash, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W);
	void wpa_postprocess_c_code(hccap_bin* salt, uint32_t* crypt_result, uint32_t* sha1_hash, uint32_t* opad_state, uint32_t* ipad_state, uint32_t* W);
	void convert_utf8_2_coalesc(const unsigned char* key, uint32_t* nt_buffer, uint32_t max_number, uint32_t len);
	extern uint32_t max_lenght;
	void swap_endianness_array(uint32_t* data, int count);
}
static void convert2wpa_salt(hccap_t hccap, hccap_bin* salt)
{
	// Preproccess salt
	salt->keyver = hccap.keyver;
	// eapol
	salt->eapol_blocks = 1 + (hccap.eapol_size + 8) / 64;
	memcpy(salt->eapol, hccap.eapol, hccap.eapol_size);
	salt->eapol[hccap.eapol_size] = 0x80;
	memset(salt->eapol + hccap.eapol_size + 1, 0, sizeof(salt->eapol) - hccap.eapol_size - 1);
	uint32_t* eapol_ptr = ((uint32_t*)salt->eapol);
	if (hccap.keyver != 1)
		for (uint32_t i = 0; i < (sizeof(salt->eapol)/4-2); i++)
		{
			SWAP_ENDIANNESS(eapol_ptr[i], eapol_ptr[i]);
		}
	eapol_ptr[16 * (salt->eapol_blocks-1) + ((hccap.keyver == 1) ? 14 : 15)] = (64 + hccap.eapol_size) << 3;

	// prf_512 preprocess----------------------------------------------------
	memcpy(salt->prf_buffer, "Pairwise key expansion", 23);

	//insert_mac
	int k = memcmp(hccap.mac1, hccap.mac2, 6);
	if (k > 0) {
		memcpy(salt->prf_buffer + 23, hccap.mac2, 6);
		memcpy(salt->prf_buffer + 6 + 23, hccap.mac1, 6);
	} else {
		memcpy(salt->prf_buffer + 23, hccap.mac1, 6);
		memcpy(salt->prf_buffer + 6 + 23, hccap.mac2, 6);
	}
	//insert_nonce
	k = memcmp(hccap.nonce1, hccap.nonce2, 32);
	if (k > 0) {
		memcpy(salt->prf_buffer + 12 + 23, hccap.nonce2, 32);
		memcpy(salt->prf_buffer + 32 + 12 + 23, hccap.nonce1, 32);
	} else {
		memcpy(salt->prf_buffer + 12 + 23, hccap.nonce1, 32);
		memcpy(salt->prf_buffer + 32 + 12 + 23, hccap.nonce2, 32);
	}
	salt->prf_buffer[99] = 0;
	salt->prf_buffer[100] = 0x80;
	memset(salt->prf_buffer + 101, 0, sizeof(salt->prf_buffer) - 4 - 101);

	uint32_t* prf_buffer_ptr = ((uint32_t*)salt->prf_buffer);
	prf_buffer_ptr[16+15] = (64 + 100) << 3;

	for (uint32_t i = 0; i < 104/4; i++)
	{
		SWAP_ENDIANNESS(prf_buffer_ptr[i], prf_buffer_ptr[i]);
	}
	//------------------------------------------------------------------------------
}

static void apply_wpa(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t crypt_result[10], sha1_hash[5], opad_state[5], ipad_state[5], W[16];
	uint32_t nt_buffer[17 * 64];
	uint32_t len = (uint32_t)strlen((char*)cleartext);

	// nt_buffer
	max_lenght = 63;
	memset(nt_buffer, 0, sizeof(nt_buffer));
	convert_utf8_2_coalesc(cleartext, nt_buffer, 64, len);
	uint32_t _0x80_index = len / 4 * 64;
	((unsigned char*)nt_buffer)[_0x80_index * 4 + (len & 3)] = 0;
	nt_buffer[16 * 64] = len << 3;
	len = (len + 3) / 4;
	for (uint32_t j = 0; j < len; j++)
	{
		SWAP_ENDIANNESS(nt_buffer[j * 64], nt_buffer[j * 64]);
	}

	// Salt
	hccap_t wpa_data;
	hccap_bin salt;
	strcpy(wpa_data.essid, (char*)username);
	unsigned char* r_data = ((unsigned char*)&wpa_data) + 36;
	for (uint32_t i = 0; i < (256+32+32+6+6); i++)
		r_data[i] = rand() & 0xff;
	wpa_data.eapol_size = rand() & 0x7f;
	wpa_data.keyver = (rand() & 1) + 1;

	convert2wpa_salt(wpa_data, &salt);
	// Convert essid_block
	uint32_t essid_block[16];
	uint32_t essid_len = (uint32_t)strlen(wpa_data.essid);
	strcpy((char*)essid_block, wpa_data.essid);
	memcpy(((char*)essid_block) + essid_len, "\x0\x0\x0\x1\x80", 5);
	memset(((char*)essid_block) + essid_len + 5, 0, 60 - (essid_len + 5));
	essid_block[15] = (64 + essid_len + 4) << 3;
	for (uint32_t k = 0; k < 14; k++)
	{
		SWAP_ENDIANNESS(essid_block[k], essid_block[k]);
	}

	// Execute the format
	wpa_body_c_code(nt_buffer, essid_block, crypt_result, sha1_hash, opad_state, ipad_state, W);
	wpa_postprocess_c_code(&salt, crypt_result, sha1_hash, opad_state, ipad_state, W);

	if (wpa_data.keyver != 1)
		for (uint32_t i = 0; i < 4; i++)
		{
			SWAP_ENDIANNESS(crypt_result[i], crypt_result[i]);
		}

	memcpy(wpa_data.keymic, crypt_result, 16);

	// Write hash
	sprintf((char*)hash, "%s#", username);
	unsigned char* base64 = hash + strlen((char*)hash);
	for (int i = 0; i < 118; i++)
	{
		base64[0] = itoa64[ (r_data[0] >> 2)];
		base64[1] = itoa64[((r_data[0] & 0x3) << 4) |(r_data[1] >> 4)];
		base64[2] = itoa64[((r_data[1] & 0xf) << 2) |(r_data[2] >> 6)];
		base64[3] = itoa64[  r_data[2] & 0x3f];

		r_data += 3;
		base64 += 4;
	}
	base64[0] = itoa64[ (r_data[0] >> 2)];
	base64[1] = itoa64[((r_data[0] & 0x3) << 4) |(r_data[1] >> 4)];
	base64[2] = itoa64[((r_data[1] & 0xf) << 2)];
	base64[3] = 0;
}
static void apply_dcc2(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t crypt_result[12], sha1_hash[5], opad_state[5], ipad_state[5], W[16];
	uint32_t i;
	uint32_t nt_buffer[16 * 64];
	uint32_t salt_buffer[11];
	uint32_t len = (uint32_t)strlen((char*)cleartext);

	// nt_buffer
	memset(nt_buffer, 0, sizeof(nt_buffer));
	for (i = 0; i < len / 2; i++)
		nt_buffer[i * 64] = cleartext[2 * i] + (cleartext[2 * i + 1] << 16);

	nt_buffer[i * 64] = (len % 2) ? cleartext[2 * i] + 0x800000 : 0x80;
	nt_buffer[14 * 64] = len << 4;

	// Salt
	len = (uint32_t)strlen((char*)username);
	memset(salt_buffer, 0, sizeof(salt_buffer));
	for (i = 0; i < len / 2; i++)
		salt_buffer[i] = tolower(username[2 * i]) + (tolower(username[2 * i + 1]) << 16);

	salt_buffer[i] = (len % 2) ? tolower(username[2 * i]) + 0x800000 : 0x80;
	salt_buffer[10] = (8 + len) << 4;

	dcc_ntlm_part_c_code(nt_buffer, crypt_result);
	dcc_salt_part_c_code(salt_buffer, crypt_result);
	dcc2_body_c_code(salt_buffer, crypt_result, sha1_hash, opad_state, ipad_state, W);

	uint32_t a = crypt_result[8 + 0];
	uint32_t b = crypt_result[8 + 1];
	uint32_t c = crypt_result[8 + 2];
	uint32_t d = crypt_result[8 + 3];

	sprintf((char*)hash, "%s:%08x%08x%08x%08x", username, a, b, c, d);
}
static void apply_dcc(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t i;
	uint32_t nt_buffer[16];
	uint32_t salt_buffer[11];
	uint32_t len = (uint32_t)strlen((char*)cleartext);

	// nt_buffer
	memset(nt_buffer, 0, sizeof(nt_buffer));
	for (i = 0; i < len / 2; i++)
		nt_buffer[i] = cleartext[2 * i] + (cleartext[2 * i + 1] << 16);

	nt_buffer[i] = (len % 2) ? cleartext[2 * i] + 0x800000 : 0x80;
	nt_buffer[14] = len << 4;

	// Salt
	len = (uint32_t)strlen((char*)username);
	memset(salt_buffer, 0, sizeof(salt_buffer));
	for (i = 0; i < len / 2; i++)
		salt_buffer[i] = tolower(username[2 * i]) + (tolower(username[2 * i + 1]) << 16);

	salt_buffer[i] = (len % 2) ? tolower(username[2 * i]) + 0x800000 : 0x80;
	salt_buffer[10] = (8 + len) << 4;

	uint32_t a, b, c, d;

	/* Round 1 */
	a = 0xFFFFFFFF + nt_buffer[0]; a = ROTATE(a, 3);
	d = INIT_D + (INIT_C ^ (a & 0x77777777)) + nt_buffer[1]; d = ROTATE(d, 7);
	c = INIT_C + (INIT_B ^ (d & (a ^ INIT_B))) + nt_buffer[2]; c = ROTATE(c, 11);
	b = INIT_B + (a ^ (c & (d ^ a))) + nt_buffer[3]; b = ROTATE(b, 19);

	a += (d ^ (b & (c ^ d))) + nt_buffer[4]; a = ROTATE(a, 3);
	d += (c ^ (a & (b ^ c))) + nt_buffer[5]; d = ROTATE(d, 7);
	c += (b ^ (d & (a ^ b))) + nt_buffer[6]; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))) + nt_buffer[7]; b = ROTATE(b, 19);

	a += (d ^ (b & (c ^ d))) + nt_buffer[8]; a = ROTATE(a, 3);
	d += (c ^ (a & (b ^ c))) + nt_buffer[9]; d = ROTATE(d, 7);
	c += (b ^ (d & (a ^ b))) + nt_buffer[10]; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))) + nt_buffer[11]; b = ROTATE(b, 19);

	a += (d ^ (b & (c ^ d))) + nt_buffer[12]; a = ROTATE(a, 3);
	d += (c ^ (a & (b ^ c))) + nt_buffer[13]; d = ROTATE(d, 7);
	c += (b ^ (d & (a ^ b))) + nt_buffer[14]; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))); b = ROTATE(b, 19);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2; a = ROTATE(a, 3);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2; d = ROTATE(d, 5);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2; c = ROTATE(c, 9);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2; b = ROTATE(b, 13);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2; a = ROTATE(a, 3);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2; d = ROTATE(d, 5);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2; c = ROTATE(c, 9);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2; b = ROTATE(b, 13);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2; a = ROTATE(a, 3);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2; d = ROTATE(d, 5);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2; c = ROTATE(c, 9);
	b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2; b = ROTATE(b, 13);

	a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2; a = ROTATE(a, 3);
	d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2; d = ROTATE(d, 5);
	c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2; c = ROTATE(c, 9);
	b += ((c & (d | a)) | (d & a)) + SQRT_2; b = ROTATE(b, 13);

	/* Round 3 */
	a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3; a = ROTATE(a, 3);
	d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3; d = ROTATE(d, 9);
	c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3; c = ROTATE(c, 11);
	b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3; b = ROTATE(b, 15);

	a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3; a = ROTATE(a, 3);
	d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3; d = ROTATE(d, 9);
	c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3; c = ROTATE(c, 11);
	b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3; b = ROTATE(b, 15);

	a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3; a = ROTATE(a, 3);
	d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3; d = ROTATE(d, 9);
	c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3; c = ROTATE(c, 11);
	b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3; b = ROTATE(b, 15);

	a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3; a = ROTATE(a, 3);
	d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3; d = ROTATE(d, 9);
	c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3; c = ROTATE(c, 11);
	b += (a ^ d ^ c) + SQRT_3; b = ROTATE(b, 15);

	uint32_t crypta = a + INIT_A;
	uint32_t cryptb = b + INIT_B;
	uint32_t cryptc = c + INIT_C;
	uint32_t cryptd = d + INIT_D;

	//Another MD4_crypt for the salt
	/* Round 1 */
	a = 0xFFFFFFFF + crypta; a = ROTATE(a, 3);
	d = INIT_D + (INIT_C ^ (a & 0x77777777)) + cryptb; d = ROTATE(d, 7);
	c = INIT_C + (INIT_B ^ (d & (a ^ INIT_B))) + cryptc; c = ROTATE(c, 11);
	b = INIT_B + (a ^ (c & (d ^    a))) + cryptd; b = ROTATE(b, 19);

	a += (d ^ (b & (c ^ d))) + salt_buffer[0]; a = ROTATE(a, 3);
	d += (c ^ (a & (b ^ c))) + salt_buffer[1]; d = ROTATE(d, 7);
	c += (b ^ (d & (a ^ b))) + salt_buffer[2]; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))) + salt_buffer[3]; b = ROTATE(b, 19);

	a += (d ^ (b & (c ^ d))) + salt_buffer[4]; a = ROTATE(a, 3);
	d += (c ^ (a & (b ^ c))) + salt_buffer[5]; d = ROTATE(d, 7);
	c += (b ^ (d & (a ^ b))) + salt_buffer[6]; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))) + salt_buffer[7]; b = ROTATE(b, 19);

	a += (d ^ (b & (c ^ d))) + salt_buffer[8]; a = ROTATE(a, 3);
	d += (c ^ (a & (b ^ c))) + salt_buffer[9]; d = ROTATE(d, 7);
	c += (b ^ (d & (a ^ b))) + salt_buffer[10]; c = ROTATE(c, 11);
	b += (a ^ (c & (d ^ a))); b = ROTATE(b, 19);

	/* Round 2 */
	a += ((b & (c | d)) | (c & d)) + crypta + SQRT_2; a = ROTATE(a, 3);
	d += ((a & (b | c)) | (b & c)) + salt_buffer[0] + SQRT_2; d = ROTATE(d, 5);
	c += ((d & (a | b)) | (a & b)) + salt_buffer[4] + SQRT_2; c = ROTATE(c, 9);
	b += ((c & (d | a)) | (d & a)) + salt_buffer[8] + SQRT_2; b = ROTATE(b, 13);

	a += ((b & (c | d)) | (c & d)) + cryptb + SQRT_2; a = ROTATE(a, 3);
	d += ((a & (b | c)) | (b & c)) + salt_buffer[1] + SQRT_2; d = ROTATE(d, 5);
	c += ((d & (a | b)) | (a & b)) + salt_buffer[5] + SQRT_2; c = ROTATE(c, 9);
	b += ((c & (d | a)) | (d & a)) + salt_buffer[9] + SQRT_2; b = ROTATE(b, 13);

	a += ((b & (c | d)) | (c & d)) + cryptc + SQRT_2; a = ROTATE(a, 3);
	d += ((a & (b | c)) | (b & c)) + salt_buffer[2] + SQRT_2; d = ROTATE(d, 5);
	c += ((d & (a | b)) | (a & b)) + salt_buffer[6] + SQRT_2; c = ROTATE(c, 9);
	b += ((c & (d | a)) | (d & a)) + salt_buffer[10] + SQRT_2; b = ROTATE(b, 13);

	a += ((b & (c | d)) | (c & d)) + cryptd + SQRT_2; a = ROTATE(a, 3);
	d += ((a & (b | c)) | (b & c)) + salt_buffer[3] + SQRT_2; d = ROTATE(d, 5);
	c += ((d & (a | b)) | (a & b)) + salt_buffer[7] + SQRT_2; c = ROTATE(c, 9);
	b += ((c & (d | a)) | (d & a)) + SQRT_2; b = ROTATE(b, 13);

	/* Round 3 */
	a += (b ^ c ^ d) + crypta + SQRT_3; a = ROTATE(a, 3);
	d += (a ^ b ^ c) + salt_buffer[4] + SQRT_3; d = ROTATE(d, 9);
	c += (d ^ a ^ b) + salt_buffer[0] + SQRT_3; c = ROTATE(c, 11);
	b += (c ^ d ^ a) + salt_buffer[8] + SQRT_3; b = ROTATE(b, 15);

	a += (b ^ c ^ d) + cryptc + SQRT_3; a = ROTATE(a, 3);
	d += (a ^ b ^ c) + salt_buffer[6] + SQRT_3; d = ROTATE(d, 9);
	c += (d ^ a ^ b) + salt_buffer[2] + SQRT_3; c = ROTATE(c, 11);
	b += (c ^ d ^ a) + salt_buffer[10] + SQRT_3; b = ROTATE(b, 15);

	a += (b ^ c ^ d) + cryptb + SQRT_3; a = ROTATE(a, 3);
	d += (a ^ b ^ c) + salt_buffer[5] + SQRT_3; d = ROTATE(d, 9);
	c += (d ^ a ^ b) + salt_buffer[1] + SQRT_3; c = ROTATE(c, 11);
	b += (c ^ d ^ a) + salt_buffer[9] + SQRT_3; b = ROTATE(b, 15);

	a += (b ^ c ^ d) + cryptd + SQRT_3; a = ROTATE(a, 3);
	d += (a ^ b ^ c) + salt_buffer[7] + SQRT_3; d = ROTATE(d, 9);
	c += (d ^ a ^ b) + salt_buffer[3] + SQRT_3; c = ROTATE(c, 11);
	b += (c ^ d ^ a) + SQRT_3; b = ROTATE(b, 15);

	a += INIT_A;
	b += INIT_B;
	c += INIT_C;
	d += INIT_D;

	SWAP_ENDIANNESS(a, a);
	SWAP_ENDIANNESS(b, b);
	SWAP_ENDIANNESS(c, c);
	SWAP_ENDIANNESS(d, d);

	sprintf((char*)hash, "%s:%08x%08x%08x%08x", username, a, b, c, d);
}

static void apply_ssha1(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t nt_buffer[14];
	uint32_t W[16];
	uint32_t sha1_state[5];
	// Salt
	unsigned char salt[16];
	uint32_t salt_len = 4 + rand() % 5;// from 4 to 8
	for (uint32_t i = 0; i < salt_len; i++)
		salt[i] = rand() & 0xff;

	uint32_t len = (uint32_t)strlen((char*)cleartext);

	memset(nt_buffer, 0, sizeof(nt_buffer));
	strcpy((char*)nt_buffer, (char*)cleartext);
	memcpy(((char*)nt_buffer) + len, salt, salt_len);
	((unsigned char*)nt_buffer)[len+salt_len] = 0x80;

	// Copy to W
	for (uint32_t i = 0; i < 14; i++)
	{
		SWAP_ENDIANNESS(W[i], nt_buffer[i]);
	}
	W[14] = 0;
	W[15] = (len+salt_len) << 3;

	// Hash
	sha1_state[0] = INIT_A;
	sha1_state[1] = INIT_B;
	sha1_state[2] = INIT_C;
	sha1_state[3] = INIT_D;
	sha1_state[4] = INIT_E;
	sha1_process_block_simd(sha1_state, W, 1);

	// Encode as base64
	swap_endianness_array(sha1_state, 5);
	memcpy(W, sha1_state, 5 * sizeof(uint32_t));
	memcpy(W + 5, salt, salt_len);
	base64_encode_mime((unsigned char*)W, 5 * sizeof(uint32_t) + salt_len, (char*)hash);
}
// Binary salt type, also keeps the number of rounds and hash sub-type.
typedef struct {
	uint32_t salt[4];
	uint32_t rounds;
	uint32_t sign_extension_bug;
} BF_salt;

typedef struct {
	uint32_t S[4][0x100];
	uint32_t P[18];
} BF_ctx;

extern "C" {
	extern BF_ctx BF_init_state;
	void BF_decode(uint32_t *dst, const unsigned char *src, int size);
}

// The string is "OrpheanBeholderScryDoubt" on big-endian.
PRIVATE uint32_t BF_magic_w[6] = { 0x4F727068, 0x65616E42, 0x65686F6C, 0x64657253, 0x63727944, 0x6F756274 };

PRIVATE unsigned char BF_itoa64[64 + 1] =
	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

PRIVATE unsigned char BF_atoi64[0x60] = {
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 0, 1,
	54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 64, 64, 64, 64, 64,
	64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 64, 64, 64, 64, 64,
	64, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 64, 64, 64, 64, 64
};
PRIVATE void BF_encode(unsigned char *dst, const uint32_t* src, int size)
{
	const unsigned char *sptr = (const unsigned char *)src;
	const unsigned char *end = sptr + size;
	unsigned char *dptr = (unsigned char *)dst;
	uint32_t c1, c2;

	do {
		c1 = *sptr++;
		*dptr++ = BF_itoa64[c1 >> 2];
		c1 = (c1 & 0x03) << 4;
		if (sptr >= end) {
			*dptr++ = BF_itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= c2 >> 4;
		*dptr++ = BF_itoa64[c1];
		c1 = (c2 & 0x0f) << 2;
		if (sptr >= end) {
			*dptr++ = BF_itoa64[c1];
			break;
		}

		c2 = *sptr++;
		c1 |= c2 >> 6;
		*dptr++ = BF_itoa64[c1];
		*dptr++ = BF_itoa64[c2 & 0x3f];
	} while (sptr < end);
}

#define BYTE_0(word)	((word & 0xFF))
#define BYTE_1(word)	((word >> 8 ) & 0xFF)
#define BYTE_2(word)	((word >> 16) & 0xFF)
#define BYTE_3(word)	((word >> 24))

#define BF_ENCRYPT \
	L ^= subkeys[0 ]; \
	R ^= subkeys[1 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[2 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[3 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[4 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[5 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[6 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[7 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[8 ] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[9 ] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[10] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[11] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[12] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[13] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[14] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	R ^= subkeys[15] ^ (((sboxs[BYTE_3(L)] + sboxs[BYTE_2(L)+256]) ^ sboxs[BYTE_1(L)+512]) + sboxs[BYTE_0(L)+768]);\
	L ^= subkeys[16] ^ (((sboxs[BYTE_3(R)] + sboxs[BYTE_2(R)+256]) ^ sboxs[BYTE_1(R)+512]) + sboxs[BYTE_0(R)+768]);\
	tmp_swap = R;\
	R = L;\
	L = tmp_swap ^ subkeys[17];

PRIVATE void blowfish_body_c_code(uint32_t* subkeys, uint32_t* sboxs)
{
	uint32_t L = 0, R = 0, tmp_swap;
	for (int i = 0; i < 18; i += 2)
	{
		BF_ENCRYPT;
		subkeys[i  ] = L;
		subkeys[i+1] = R;
	}
	for (int i = 0; i < 256 * 4; i += 2)
	{
		BF_ENCRYPT;
		sboxs[i  ] = L;
		sboxs[i+1] = R;
	}
}
PRIVATE void bf_key(const char* key, BF_salt* salt, uint32_t* crypt_result)
{
	uint32_t* sboxs = (uint32_t*)malloc((4 * 256 + 18 + 18) * sizeof(uint32_t));

	uint32_t* subkeys = sboxs + 4 * 256 ;
	uint32_t* expanded_key = subkeys + 18;

	uint32_t L, R, tmp_swap;

	//blowfish_set_key(buffer, subkeys, expanded_key, NT_NUM_KEYS, salt->sign_extension_bug, NT_NUM_KEYS);
	const char* ptr = key;
	for (int i = 0; i < 18; i++)
	{
		uint32_t tmp = 0;
		for (int j = 0; j < 4; j++)
		{
			tmp <<= 8;
			if (salt->sign_extension_bug)
				tmp |= (int)(signed char)*ptr;
			else
				tmp |= (unsigned char)*ptr;

			if (!*ptr) ptr = key; else ptr++;
		}

		expanded_key[i] = tmp;
		subkeys[i] = BF_init_state.P[i] ^ tmp;
	}
	memcpy(sboxs, BF_init_state.S, sizeof(BF_init_state.S));

	L = R = 0;
	for (int i = 0; i < 18; i+=2)
	{
		L ^= salt->salt[(i & 2)];
		R ^= salt->salt[(i & 2) + 1];
		BF_ENCRYPT;
		subkeys[i  ] = L;
		subkeys[i+1] = R;
	}
	for (int i = 0; i < 256*4; i+=2)
	{
		L ^= salt->salt[(i + 2) & 3];
		R ^= salt->salt[(i + 3) & 3];
		BF_ENCRYPT;
		sboxs[i  ] = L;
		sboxs[i+1] = R;
	}

	// Expensive key schedule
	for (uint32_t round = 0; round < salt->rounds; round++)
	{
		// Key part
		for (int i = 0; i < 18; i++)
			subkeys[i] ^= expanded_key[i];

		blowfish_body_c_code(subkeys, sboxs);

		// Salt part
		for (int i = 0; i < 18; i ++)
			subkeys[i] ^= salt->salt[i&3];

		blowfish_body_c_code(subkeys, sboxs);
	}

	// Final part: Encrypt
	for (int i = 0; i < 6; i += 2)
	{
		L = BF_magic_w[i];
		R = BF_magic_w[i+1];

		for (int j = 0; j < 64; j++)
		{
			BF_ENCRYPT;
		}

		crypt_result[i  ] = L;
		crypt_result[i+1] = R;
	}
	/* This has to be bug-compatible with the original implementation, so only encode 23 of the 24 bytes. :-) */
	crypt_result[5] &= 0xFFFFFF00;

	free(sboxs);
}
PRIVATE void apply_bcrypt(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t crypt_result[6];
	BF_salt salt;
	int exponent = 5;

	salt.rounds = 1 << exponent;
	salt.sign_extension_bug = ((rand() & 3) == 3);
	for (uint32_t i = 0; i < 4*4; i++)
		((unsigned char*)&salt.salt)[i] = rand() & 0xff;

	bf_key((const char*)cleartext, &salt, crypt_result);

	sprintf((char*)hash, "$2%s$%02i$", salt.sign_extension_bug ? "x" : "y", exponent);
	swap_endianness_array(salt.salt, 6);
	BF_encode(hash + 7, salt.salt, 16);
	hash[7 + 22 - 1] = BF_itoa64[(int)BF_atoi64[(int)hash[7 + 22 - 1] - 0x20] & 0x30];

/* This has to be bug-compatible with the original implementation, so
 * only encode 23 of the 24 bytes. :-) */
	swap_endianness_array(crypt_result, 6);
	BF_encode(&hash[7 + 22], crypt_result, 23);
	hash[7 + 22 + 31] = '\0';
}
PRIVATE void apply_bcrypt_bug(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash, uint32_t* given_salt)
{
	uint32_t crypt_result[6];
	BF_salt salt;
	int exponent = 5;

	salt.rounds = 1 << exponent;
	salt.sign_extension_bug = 1;
	memcpy(salt.salt, given_salt, sizeof(salt.salt));

	bf_key((const char*)cleartext, &salt, crypt_result);

	sprintf((char*)hash, "$2%s$%02i$", salt.sign_extension_bug ? "x" : "y", exponent);
	swap_endianness_array(salt.salt, 6);
	BF_encode(hash + 7, salt.salt, 16);
	hash[7 + 22 - 1] = BF_itoa64[(int)BF_atoi64[(int)hash[7 + 22 - 1] - 0x20] & 0x30];

	/* This has to be bug-compatible with the original implementation, so
	* only encode 23 of the 24 bytes. :-) */
	swap_endianness_array(crypt_result, 6);
	BF_encode(&hash[7 + 22], crypt_result, 23);
	hash[7 + 22 + 31] = '\0';
}

// md5crypt-----------------------------------------------------------------------------------------------
typedef struct {
	uint8_t salt[8];
	uint8_t saltlen;
	uint8_t prefix;		/** 0 when $1$ or 1 when $apr1$ or 2 for {smd5} which uses no prefix. **/
} crypt_md5_salt;
PRIVATE char* prefixs[] = { "$1$", "$apr1$", "" };
PRIVATE char* prefixs_show[] = { "$1$", "$apr1$", "{smd5}" };
PRIVATE void md5_one_block_c_code(uint32_t* state, const void* block)
{
	state[0] = INIT_A;
	state[1] = INIT_B;
	state[2] = INIT_C;
	state[3] = INIT_D;
	md5_process_block(state, block);
}
#define TO_BASE64(b1, b2, b3) \
	value = out[b3] | (out[b2] << 8) | (out[b1] << 16);\
	\
	pos[0] = itoa64[(value    ) & 63];\
	pos[1] = itoa64[(value>>6 ) & 63];\
	pos[2] = itoa64[(value>>12) & 63];\
	pos[3] = itoa64[(value>>18) & 63];\
	pos += 4;

PRIVATE void apply_md5crypt(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash)
{
	uint32_t md5_state[4];
	uint8_t buffer[64];
	uint32_t len = (uint32_t)strlen((char*)cleartext);

	crypt_md5_salt salt;
	salt.saltlen = 8;// rand() % 8;
	salt.prefix = rand() % 3;
	for (int i = 0; i < salt.saltlen; i++)
	{
		uint8_t salt_char = 1 + rand() % 255;
		while (salt_char == '$')
			salt_char = 1 + rand() % 255;
		salt.salt[i] = salt_char;
	}

	// 1st digest
	memset(buffer, 0, sizeof(buffer));
	uint32_t buffer_len = 0;
	memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
	memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
	memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
	buffer[buffer_len] = 0x80;
	((uint32_t*)buffer)[14] = buffer_len << 3;
	md5_one_block_c_code(md5_state, buffer);

	// 2nd digest
	memset(buffer, 0, sizeof(buffer));
	buffer_len = 0;
	memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
	memcpy(buffer + buffer_len, prefixs[salt.prefix], strlen(prefixs[salt.prefix])); buffer_len += (uint32_t)strlen(prefixs[salt.prefix]);
	memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
	memcpy(buffer + buffer_len, md5_state, len); buffer_len += len;
	for (uint32_t j = len; j > 0; j >>= 1, buffer_len++)
		buffer[buffer_len] = (j & 1) ? 0 : cleartext[0];
	buffer[buffer_len] = 0x80;
	((uint32_t*)buffer)[14] = buffer_len << 3;
	md5_one_block_c_code(md5_state, buffer);

	// Big cycle
	for (int i = 0; i < 1000; i++)
	{
		memset(buffer, 0, sizeof(buffer));
		uint32_t buffer_len = 0;

		if (i & 1)
		{
			memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
		}
		else
		{
			memcpy(buffer + buffer_len, md5_state, 16); buffer_len += 16;
		}
		if (i % 3)
		{
			memcpy(buffer + buffer_len, salt.salt, salt.saltlen); buffer_len += salt.saltlen;
		}
		if (i % 7)
		{
			memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
		}
		if (i & 1)
		{
			memcpy(buffer + buffer_len, md5_state, 16); buffer_len += 16;
		}
		else
		{
			memcpy(buffer + buffer_len, cleartext, len); buffer_len += len;
		}

		buffer[buffer_len] = 0x80;
		((uint32_t*)buffer)[14] = buffer_len << 3;
		md5_one_block_c_code(md5_state, buffer);
	}

	sprintf((char*)hash, "%s", prefixs_show[salt.prefix]);
	hash += strlen((char*)hash);
	memcpy(hash, salt.salt, salt.saltlen);
	hash[salt.saltlen] = '$';

	char* pos = (char*)hash + salt.saltlen + 1;
	unsigned char* out = (unsigned char*)md5_state;
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

typedef void apply_format(const unsigned char* username, const unsigned char* cleartext, unsigned char* hash);
PRIVATE apply_format* hash_format[MAX_NUM_FORMATS] = {
	apply_lm, apply_ntlm, apply_md5, apply_sha1, apply_sha256, apply_sha512,
	apply_dcc, apply_ssha1, apply_md5crypt, apply_dcc2, apply_wpa, apply_bcrypt
};

extern "C" {
	sqlite3_int64 insert_hash_account1(ImportParam* param, const char* user_name, const char* ciphertext, int db_index);
	sqlite3_int64 insert_when_necesary_tag(const char* tag);
	sqlite3_int64 insert_hash_if_necesary(const char* hex, sqlite3_int64 format_id, ImportResultFormat* hash_stat);
	extern sqlite3_stmt* insert_account_lm;
	extern sqlite3_stmt* insert_account;
}
PRIVATE void generate_hashes_db(cl_uint format_index)
{
	unsigned char* hash = (unsigned char*)malloc((format_index == LM_INDEX) ? 33 : 2*(formats[format_index].binary_size + formats[format_index].salt_size + 8));
	ImportParam param;
	memset(&param, 0, sizeof(param));
#ifdef _WIN32
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_CLEAR_ALL, 0));
#else
	clear_db_accounts();
#endif

	BEGIN_TRANSACTION;
	sqlite3_int64 tag_id = insert_when_necesary_tag("Testing");

	for (uint32_t i = 0; i < tt_num_hashes_gen; i++)
	{
		hash_format[format_index](tt_usernames + i * 32, tt_cleartexts + i * 32, hash);
		if (format_index == LM_INDEX)
		{
			hash[16] = 0;
			tt_hash_ids[i] = insert_hash_if_necesary((char*)hash, formats[LM_INDEX].db_id, param.result.formats_stat + LM_INDEX);

			sqlite3_int64 account_id = insert_hash_account1(&param, "u", "", NTLM_INDEX);

			// Insert account lm
			sqlite3_reset(insert_account_lm);
			sqlite3_bind_int64(insert_account_lm, 1, account_id);
			sqlite3_bind_int64(insert_account_lm, 2, tt_hash_ids[i]);
			sqlite3_bind_int64(insert_account_lm, 3, tt_hash_ids[i]);
			sqlite3_step(insert_account_lm);
		}
		else
		{
			tt_hash_ids[i] = insert_hash_if_necesary((char*)hash, format_index, param.result.formats_stat + format_index);
			
			sqlite3_reset(insert_account);
			sqlite3_bind_text (insert_account, 1, "u", -1, SQLITE_STATIC);
			sqlite3_bind_int64(insert_account, 2, tt_hash_ids[i]);
			
			sqlite3_step(insert_account);// account inserted
		}
	}

	END_TRANSACTION;
	free(hash);

	exist_hashes_release();
	resize_fam();
}

typedef void setup_provider(cl_uint format_index);
#ifdef _WIN32
LRESULT CMainFrame::OnExecuteInUI(WPARAM param1, LPARAM param2)
{
	setup_provider* func = (setup_provider*)param1;
	func((cl_uint)param2);

	return 0;
}
#endif
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Charset
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static unsigned char* tt_charset = NULL;
static uint32_t charset_len;
static uint32_t is_charset_consecutive = FALSE;
static int check_only_lenght = -1;
#ifdef _WIN32
static void charset_change_ui(cl_uint format_index)
{
	CMFCRibbonCheckBox* btn = new CMFCRibbonCheckBox(ID_CHARSET_BASE + m_num_charset, "test");
	btn->SetDescription((char*)tt_charset);
	btn->SetToolTipText(buffer_str);
	// Add to property window
	CCheckBoxProp* charset_prop = new CCheckBoxProp("test", TRUE, buffer_str, btn->GetID());
	charset_prop->SetTextValue((const char*)tt_charset);
	charset_props.push_back(charset_prop);
	m_wndProperties.AddSubProperty(charset_prop, 0);

	m_wndRibbonBar.GetCategory(CATEGORY_PARAMS)->GetPanel(0)->Add(btn);

	SET_EDIT_NUM(keyProvParams[CHARSET_INDEX].min_size->GetID(), check_only_lenght < 0 ? 0 : check_only_lenght);
	SET_EDIT_NUM(keyProvParams[CHARSET_INDEX].max_size->GetID(), check_only_lenght < 0 ? (formats[format_index].salt_size ? 4 : 4/*5*/) : check_only_lenght);
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_KEY_PROV_PARAM + 2 * CHARSET_INDEX, 0));

	for (int i = 0; i < m_num_charset; i++)
	{
		AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_CHARSET_BASE + i, 0));
		AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_CHARSET_BASE + i, 0));
	}

	m_wndRibbonBar.ForceRecalcLayout();
	m_num_charset++;
}
#endif
static void setup_charset(cl_uint format_index)
{
	unsigned char selected[256];
	if (check_only_lenght < 0)
		charset_len = (rand() & (formats[format_index].salt_size ? 63 : 127)) + 2;
	else
	{
		int divider = ((format_index >= DCC2_INDEX) ? 1000 : 1);
		if (format_index == BCRYPT_INDEX) divider = 40000;
		if (format_index == MD5CRYPT_INDEX) divider = 640;
		// High-end GPU
		//if (format_index == MD5CRYPT_INDEX) divider = 128;
		charset_len = CLIP_RANGE((cl_uint)pow(800000000. / divider, 1. / check_only_lenght), 2, 200);
	}
	tt_charset = (unsigned char*)malloc(charset_len + 1);
	memset(selected, 0, sizeof(selected));

	if (is_charset_consecutive)
	{
		unsigned char min = rand() % (255 - charset_len);

		for (uint32_t i = 0; i < charset_len; i++)
			tt_charset[i] = min + i;
	}
	else
	{
		for (uint32_t i = 0; i < charset_len; i++)
		{
			unsigned char char2add = rand() % 254 + 1;
			while (selected[char2add])
				char2add = rand() % 254 + 1;

			tt_charset[i] = char2add;
			selected[char2add] = TRUE;
		}
	}
	tt_charset[charset_len] = 0;

#ifdef _WIN32
	for (int i = 0; i < m_num_charset; i++)
		m_checkedCharset[i] = FALSE;
	m_checkedCharset[m_num_charset] = TRUE;

	AfxGetApp()->GetMainWnd()->SendMessage(WM_EXECUTE_IN_UI, (WPARAM)charset_change_ui, format_index);
#else
	strcpy(test_param, (char*)tt_charset);
#endif
}
static void free_charset()
{
	free(tt_charset);
}
static void gen_charset(unsigned char* cleartext, cl_uint format_index)
{
#ifdef __ANDROID__
	uint32_t len = check_only_lenght < 0 ? (rand() % (formats[format_index].salt_size ? 3 : 4)) : check_only_lenght;
#else
	uint32_t len = check_only_lenght < 0 ? (rand() % (formats[format_index].salt_size ? 5 : 5/*6*/)) : check_only_lenght;
#endif
	for (uint32_t i = 0; i < len; i++)
		cleartext[i] = tt_charset[rand() % charset_len];

	cleartext[len] = 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Wordlist
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static int testing_use_rules;
static int use_zip_file;

static const char* FILEPATH;
static const char* FILENAME;
static int FILESIZE;

static const char* ZIP_FILEPATH;
static const char* ZIP_FILENAME;
static int ZIP_FILESIZE;

static sqlite3_int64 wordlist_id;
extern "C" {
	extern uint32_t num_words;
	extern uint32_t* word_pos;
	extern unsigned char* words;
}
#ifdef _WIN32
static void wordlist_change_ui(cl_uint format_index)
{
	// Add to ribbon
	CMFCRibbonButton* btn = new CMFCRibbonButton(ID_WORDLIST_BASE + m_wordlist_count, FILENAME);
	btn->SetData((DWORD_PTR)wordlist_id);
	m_wordlistsGUI->AddSubItem(btn, m_wordlist_count);
	m_wordlist_count++;
	m_selected_wordlist = m_wordlist_count - 1;

	wordlist_prop->SetValue(use_zip_file ? ZIP_FILENAME : FILENAME);
}
#endif
static void setup_wordlist(cl_uint format_index)
{
	key_providers[WORDLIST_INDEX].use_rules = FALSE;
	// Get all wordlist from 'PHRASES_WORDLISTS' folder
	sqlite3_stmt* _insert_wordlist;
	sqlite3_prepare_v2(db, "INSERT INTO PhrasesWordList (Name,FileName,Length) VALUES (?,?,?);", -1, &_insert_wordlist, NULL);

	sqlite3_bind_text(_insert_wordlist, 1, FILENAME, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(_insert_wordlist, 2, FILEPATH, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(_insert_wordlist, 3, FILESIZE);
	sqlite3_step(_insert_wordlist);

	sqlite3_finalize(_insert_wordlist);

	// Get all wordlist from db
	sqlite3_stmt* _select_wordlists;
	sqlite3_prepare_v2(db, "SELECT ID FROM PhrasesWordList WHERE FileName=?;", -1, &_select_wordlists, NULL);
	sqlite3_bind_text(_select_wordlists, 1, FILEPATH, -1, SQLITE_TRANSIENT);
	sqlite3_step(_select_wordlists);
	sqlite3_int64 id = sqlite3_column_int64(_select_wordlists, 0);

	sqlite3_finalize(_select_wordlists);

	PHRASES_MAX_WORDS_READ = UINT_MAX;
	sprintf(buffer_str, "%lli", id);
	key_providers[PHRASES_INDEX].resume(1, 2, buffer_str, NULL, format_index);

	// Wordlist
	sqlite3_prepare_v2(db, "INSERT INTO WordList (Name,FileName,Length,State) VALUES (?,?,?,0);", -1, &_insert_wordlist, NULL);
	sqlite3_bind_text (_insert_wordlist, 1, use_zip_file ? ZIP_FILENAME : FILENAME, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text (_insert_wordlist, 2, use_zip_file ? ZIP_FILEPATH : FILEPATH, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(_insert_wordlist, 3, use_zip_file ? ZIP_FILESIZE : FILESIZE);
	sqlite3_step(_insert_wordlist);

	sqlite3_finalize(_insert_wordlist);

	sqlite3_prepare_v2(db, "SELECT ID FROM WordList WHERE FileName=?;", -1, &_select_wordlists, NULL);
	sqlite3_bind_text(_select_wordlists, 1, use_zip_file ? ZIP_FILEPATH : FILEPATH, -1, SQLITE_TRANSIENT);
	sqlite3_step(_select_wordlists);
	wordlist_id = sqlite3_column_int64(_select_wordlists, 0);

	sqlite3_finalize(_select_wordlists);

#ifdef _WIN32
	AfxGetApp()->GetMainWnd()->SendMessage(WM_EXECUTE_IN_UI, (WPARAM)wordlist_change_ui, format_index);
#endif
}

static void free_wordlist()
{
	key_providers[PHRASES_INDEX].finish();
}
static void gen_wordlist(unsigned char* cleartext, cl_uint format_index)
{
	uint32_t pos = (((rand() & 0x7FFF) << 15) + (rand() & 0x7FFF)) % num_words;
	if (format_index >= MD5CRYPT_INDEX)
		pos &= 0xfffff;
	else if (format_index >= DCC2_INDEX)//|| use_rules)
		pos &= 0xffff;

	unsigned len = __min(word_pos[pos] >> 27, (uint32_t)formats[format_index].max_plaintext_lenght);
	strncpy((char*)cleartext, (char*)words + (word_pos[pos] & 0x07ffffff), len);
	cleartext[len] = 0;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32
static void phrases_change_ui(cl_uint format_index)
{
	// Add to ribbon
	CMFCRibbonButton* btn = new CMFCRibbonButton(ID_PHRASES_WORDLIST_BASE + m_phrases_wordlist_count, FILENAME);
	btn->SetData((DWORD_PTR)wordlist_id);
	m_PhrasesWordlistsGUI->AddSubItem(btn, m_phrases_wordlist_count);
	m_phrases_wordlist_count++;
	m_selected_phrases_wordlist = m_phrases_wordlist_count - 1;

	phrases_prop->SetValue(FILENAME);

	SET_EDIT_NUM(keyProvParams[PHRASES_INDEX].min_size->GetID(), 2);
	SET_EDIT_NUM(keyProvParams[PHRASES_INDEX].max_size->GetID(), 2);
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_KEY_PROV_PARAM + 2 * PHRASES_INDEX, 0));

	CMFCRibbonComboBox* _num = (CMFCRibbonComboBox*)m_wndRibbonBar.FindByID(ID_PHRASES_MAX_NUMBER_WORD, FALSE);
	_itot(PHRASES_MAX_WORDS_READ, buffer_str, 10);
	_num->SetEditText(buffer_str);
	phrases_max_num_prop->SetNumber(PHRASES_MAX_WORDS_READ);
}
#endif
static void setup_phrases(cl_uint format_index)
{
	key_providers[PHRASES_INDEX].use_rules = FALSE;
	// Get all wordlist from 'PHRASES_WORDLISTS' folder
	sqlite3_stmt* _insert_wordlist;
	sqlite3_prepare_v2(db, "INSERT INTO PhrasesWordList (Name,FileName,Length) VALUES (?,?,?);", -1, &_insert_wordlist, NULL);

	sqlite3_bind_text(_insert_wordlist, 1, FILENAME, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(_insert_wordlist, 2, FILEPATH, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(_insert_wordlist, 3, FILESIZE);
	sqlite3_step(_insert_wordlist);

	sqlite3_finalize(_insert_wordlist);

	// Get all wordlist from db
	sqlite3_stmt* _select_wordlists;
	sqlite3_prepare_v2(db, "SELECT ID FROM PhrasesWordList WHERE FileName=?;", -1, &_select_wordlists, NULL);
	sqlite3_bind_text(_select_wordlists, 1, FILEPATH, -1, SQLITE_TRANSIENT);
	sqlite3_step(_select_wordlists);
	wordlist_id = sqlite3_column_int64(_select_wordlists, 0);

	sqlite3_finalize(_select_wordlists);

	PHRASES_MAX_WORDS_READ = 10000;
	sprintf(buffer_str, "%lli", wordlist_id);
	key_providers[PHRASES_INDEX].resume(1, 2, buffer_str, NULL, format_index);

#ifdef _WIN32
	AfxGetApp()->GetMainWnd()->SendMessage(WM_EXECUTE_IN_UI, (WPARAM)phrases_change_ui, format_index);
#endif
}

static void free_phrases()
{
	key_providers[PHRASES_INDEX].finish();
}
static void gen_phrases(unsigned char* cleartext, cl_uint format_index)
{
	uint32_t pos, len, len2;
	do
	{
		pos = (((rand() & 0x7FFF) << 15) + (rand() & 0x7FFF)) % num_words;
		if (format_index >= DCC2_INDEX)
			pos &= 0xffff;
		len = word_pos[pos] >> 27;
	}
	while (len >= (uint32_t)formats[format_index].max_plaintext_lenght);

	strncpy((char*)cleartext, (char*)words + (word_pos[pos] & 0x07ffffff), len);

	// Second word
	do
	{
		pos = (((rand() & 0x7FFF) << 15) + (rand() & 0x7FFF)) % num_words;
		if (format_index >= DCC2_INDEX)
			pos &= 0xffff;
		len2 = word_pos[pos] >> 27;
	}
	while ((len+len2) > (uint32_t)formats[format_index].max_plaintext_lenght);

	strncpy((char*)cleartext+len, (char*)words + (word_pos[pos] & 0x07ffffff), len2);
	cleartext[len + len2] = 0;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Db info
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static void setup_db_info(cl_uint format_index)
{}
static void gen_db_info(unsigned char* cleartext, cl_uint format_index)
{
	uint32_t pos = (uint32_t)(cleartext - tt_cleartexts) / 32;
	if (pos)
		pos = (((rand() & 0x7FFF) << 15) + (rand() & 0x7FFF)) % pos;
	strncpy((char*)cleartext, (char*)tt_usernames + pos * 32, formats[format_index].max_plaintext_lenght);
	cleartext[formats[format_index].max_plaintext_lenght] = 0;
}
static void free_db_info()
{}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Rules
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static int num_rules_active;
static int my_rules_remap[32];
static int check_all_rules;
static int skip_intensive_rules;
static int rule_active_index = -1;
#ifdef _WIN32
static void rules_change_ui(cl_uint format_index)
{
	for (int i = 0; i < num_rules; i++)
	{
		AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_RULES_BASE + i, 0));
		AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_RULES_BASE + i, 0));
	}
}
#endif
static void setup_rules(cl_uint format_index)
{
	setup_wordlist(format_index);
	key_providers[WORDLIST_INDEX].use_rules = TRUE;
	num_rules_active = 0;

	for (int i = 0; i < num_rules; i++)
		rules[i].checked = FALSE;

	for (int i = 0; i < num_rules; i++)
		if (skip_intensive_rules && rules[i].multipler >= 95 * 95)
		{
			rules[i].checked = FALSE;
		}
		else
		{
			if (check_all_rules)
			{
				rules[i].checked = 1;
			}
			else if (rule_active_index >= 0)
			{
				rules[i].checked = (i == rule_active_index);
			}
			else
			{
				rules[i].checked = rand() & 1;
			}

			if (rules[i].checked)
			{
				my_rules_remap[num_rules_active] = i;
				num_rules_active++;
			}
		}

#ifdef _WIN32
	AfxGetApp()->GetMainWnd()->SendMessage(WM_EXECUTE_IN_UI, (WPARAM)rules_change_ui, format_index);
#endif
}

static int rule_all_gen(unsigned char* plain, cl_uint param)
{
	return TRUE;
}
static unsigned char leet_orig[] = "aaeollssiibccgqttx";
static int check_leet(unsigned char* plain, cl_uint param)
{
	for (cl_uint i = 0; i < strlen((char*)plain); i++)
		if (plain[i] == leet_orig[param])
			return TRUE;

	return FALSE;
}
static int check_leet_lower(unsigned char* plain, cl_uint param)
{
	char text[32];
	strcpy(text, (char*)plain);
#ifdef _WIN32
	_strlwr((char*)text);
#else
	_strlwr((unsigned char*)text);
#endif

	return check_leet((unsigned char*)text, param);
}
static int check_leet_cap(unsigned char* plain, cl_uint param)
{
	unsigned char text[32];
	strcpy((char*)text, (char*)plain);
#ifdef _WIN32
	_strlwr((char*)text);
#else
	_strlwr((unsigned char*)text);
#endif
	// Capitalize
	if (islower(text[0]))
		text[0] -= 32;

	return check_leet(text, param);
}
static int check_lower(unsigned char* plain, cl_uint param)
{
	for (uint32_t i = 0; i < strlen((char*)plain); i++)
		if ((plain[i] - 65u) <= 25u)
			return TRUE;

	return FALSE;
}
static int check_cap(unsigned char* plain, cl_uint param)
{
	if ((plain[0] - 97u) <= 25u)
		return TRUE;
	for (uint32_t i = 1; i < strlen((char*)plain); i++)
		if ((plain[i] - 65u) <= 25u)
			return TRUE;

	return FALSE;
}
static int check_upper(unsigned char* plain, cl_uint param)
{
	for (uint32_t i = 0; i < strlen((char*)plain); i++)
		if ((plain[i] - 97u) <= 25u)
			return TRUE;

	return FALSE;
}
static int check_upper_last(unsigned char* plain, cl_uint param)
{
	uint32_t i;
	for (i = 0; i < (strlen((char*)plain) - 1); i++)
		if ((plain[i] - 65u) <= 25u)
			return TRUE;

	if ((plain[i] - 97u) <= 25u)
		return TRUE;

	return FALSE;
}
typedef int check_rule_gen_func(unsigned char* plain, cl_uint param);
static int min_len_for_rule[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0 };
static int max_len_for_rule[] = { 27, 27, 27, 27, 13, 27, 27, 27, 26, 26, 26, 23, 23, 25, 25, 26, 27, 27, 23, 25, 25, 24, 24 };
static check_rule_gen_func* check_rule_gen[] = { rule_all_gen, check_lower, check_upper, check_cap, rule_all_gen, check_leet_lower,
check_leet_cap, check_upper_last, rule_all_gen, rule_all_gen, rule_all_gen, rule_all_gen,
rule_all_gen, rule_all_gen, rule_all_gen, rule_all_gen, rule_all_gen, rule_all_gen,
rule_all_gen, rule_all_gen, rule_all_gen, rule_all_gen, rule_all_gen };
static void gen_rules(unsigned char* cleartext, cl_uint format_index)
{
	uint32_t param = 0;
	unsigned char plain[32];
	int rule_check_gen = FALSE;

	int rule_used1 = my_rules_remap[rand() % num_rules_active];

	while (!rule_check_gen)
	{
		int len = 50;
		while (len < min_len_for_rule[rule_used1] || len > max_len_for_rule[rule_used1])
		{
			gen_wordlist(plain, format_index);
			len = (int)strlen((char*)plain);
		}

		if (rules[rule_used1].depend_key_lenght)
		{
			int sum_len = (int)len + rules[rule_used1].key_lenght_sum;

			uint32_t mul = rules[rule_used1].multipler / RULE_LENGHT_COMMON;
			if (rules[rule_used1].ocl.max_param_value)
			{
				param = (rand() % sum_len - rules[rule_used1].key_lenght_sum) << 8;
				param += rand() % mul;
			}
			else
				param = rand() % sum_len;
		}
		else
		{
			if (rules[rule_used1].ocl.max_param_value)
				param = ((rand() % rules[rule_used1].ocl.max_param_value) << 8) + rand() % (rules[rule_used1].multipler / rules[rule_used1].ocl.max_param_value);
			else
				param = rand() % rules[rule_used1].multipler;
		}

		rule_check_gen = check_rule_gen[rule_used1](plain, param);
	}
	rules[rule_used1].ocl.get_key(cleartext, plain, param);

	rule_used_clear[(cleartext - tt_cleartexts) / 32] = rule_used1;
	rule_param_used_clear[(cleartext - tt_cleartexts) / 32] = param;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef void generate_cleartext(unsigned char* cleartext, cl_uint format_index);
typedef void free_provider();


setup_provider* setup_providers[] = { setup_charset, setup_wordlist, NULL, setup_phrases, setup_db_info, NULL, NULL, setup_rules };
generate_cleartext* gen_provider_cleartext[] = { gen_charset, gen_wordlist, NULL, gen_phrases, gen_db_info, NULL, NULL, gen_rules };
free_provider* free_providers[] = { free_charset, free_wordlist, NULL, free_phrases, free_db_info, NULL, NULL, free_wordlist };
static void remove_cleartext_duplicates()
{
	uint32_t size_table = 1;
	while(size_table < tt_num_hashes_gen)
		size_table = (size_table << 1) + 1;
	// 3 bits more into account
	for(int i = 0; i < 3; i++)
		size_table = (size_table << 1) + 1;

	// Create hashtable
	uint32_t* table          = (uint32_t*)malloc(sizeof(uint32_t) * (size_table+1));
	uint32_t* same_hash_next = (uint32_t*)malloc(sizeof(uint32_t) * tt_num_hashes_gen);
	char* to_remove = (char*)calloc(tt_num_hashes_gen, 1);

	// Initialize
	memset(table, 0xff, sizeof(uint32_t) * (size_table+1));
	memset(same_hash_next, 0xff, sizeof(uint32_t) * tt_num_hashes_gen);

	for (uint32_t i = 0; i < tt_num_hashes_gen; i++)
	{
		unsigned char* cleartext = tt_cleartexts + 32 * i;
		uint32_t value_map = 5381;

		// Public domain hash function by DJ Bernstein
		int len = (int)strlen((char*)cleartext);
		for (int j = 0; j < len; j++)
			value_map = ((value_map << 5) + value_map) ^ cleartext[j];

		value_map &= size_table;
		// Check if exists
		if (table[value_map] == 0xffffffff)
		{
			table[value_map] = i;
		}
		else
		{
			uint32_t last_index = table[value_map];
			if (!strcmp((char*)cleartext, (char*)tt_cleartexts + 32 * last_index))
			{
				to_remove[i] = TRUE;
			}
			else
			{
				while (same_hash_next[last_index] != 0xffffffff)
				{
					last_index = same_hash_next[last_index];

					if (!strcmp((char*)cleartext, (char*)tt_cleartexts + 32 * last_index))
					{
						to_remove[i] = TRUE;
						break;
					}
				}

				if (!to_remove[i])
					same_hash_next[last_index] = i;
			}
		}
	}
	free(table);
	free(same_hash_next);

	cl_uint num_unique = 0;
	unsigned char* tt_unique_cleartext = (unsigned char*)malloc(32 * tt_num_hashes_gen);
	for (uint32_t i = 0; i < tt_num_hashes_gen; i++)
		if (!to_remove[i])
		{
			strcpy((char*)tt_unique_cleartext + 32 * num_unique, (char*)tt_cleartexts + 32 * i);

			num_unique++;
		}

	free(to_remove);
	free(tt_cleartexts);

	tt_cleartexts = tt_unique_cleartext;
	tt_num_hashes_gen = num_unique;
}
static void generate_accounts(cl_uint format_index, cl_uint provider_index)
{
	const char* name_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	int name_chars_size = (int)strlen(name_chars);
	if (testing_use_rules) provider_index = RULES_INDEX;

	setup_providers[provider_index](format_index);

	for (uint32_t i = 0; i < tt_num_hashes_gen; i++)
	{
		uint32_t len = rand() % 19 + 1;
		for (uint32_t j = 0; j < len; j++)
			tt_usernames[i * 32 + j] = name_chars[rand() % name_chars_size];

		tt_usernames[i * 32 + len] = 0;
		size_t text_len = formats[format_index].max_plaintext_lenght + 1;
		while (text_len > formats[format_index].max_plaintext_lenght)
		{
			gen_provider_cleartext[provider_index](tt_cleartexts + 32 * i, format_index);
			text_len = strlen((char*)tt_cleartexts + 32 * i);
		}
	}

	free_providers[provider_index]();

	remove_cleartext_duplicates();
}

#ifndef _WIN32
static JNIEnv* env;
static jclass m_my_class;
static jmethodID gui_attack;
static jclass thread_cls;
static jmethodID thread_sleep;
#endif

static void attack_cycle(cl_uint format_index, cl_uint provider_index)
{
	// Cycle to test
	generate_hashes_db(format_index);

#ifdef _WIN32
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_FORMAT_BASE + format_index, 0));
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_KEY_PROV_BASE + provider_index, 0));
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_BUTTON_START, 0));

	m_is_cracking = TRUE;
#else
	if (provider_index == CHARSET_INDEX || provider_index == KEYBOARD_INDEX)
		strcpy(buffer_str, test_param);

	m_is_cracking = TRUE;
	env->CallStaticVoidMethod(m_my_class, gui_attack, format_index, provider_index);
#endif
	
	while (m_is_cracking)
		Sleep(500ll);

	if (num_hashes_by_formats1[format_index] != num_hashes_found_by_format1[format_index])
	{
#ifdef _WIN32
		hs_log(HS_LOG_ERROR, "Test Suite", "%i hashes not found.\n%s %s", num_hashes_by_formats1[format_index] - num_hashes_found_by_format1[format_index],
			app_num_threads ? "CPU" : "GPU", app_num_threads ? (current_cpu.capabilites[CPU_CAP_AVX2] ? "AVX2" : (current_cpu.capabilites[CPU_CAP_AVX] ? "AVX" : "SSE2")) : "");
#else
		hs_log(HS_LOG_ERROR, "Test Suite", "%i hashes not found.\n%s %s", num_hashes_by_formats[format_index] - num_hashes_found_by_format[format_index],
			app_num_threads ? "CPU" : "GPU", app_num_threads ? (current_cpu.capabilites[CPU_CAP_NEON] ? "Neon" : "") : "");
#endif
		sqlite3_stmt* _select_cleartext;
		sqlite3_prepare_v2(db, "SELECT ClearText FROM (FindHash INNER JOIN Hash ON FindHash.HashID=Hash.ID) WHERE Hash.ID=?;", -1, &_select_cleartext, NULL);
		
		// Show hashes that fail
		for (cl_uint i = 0; i < tt_num_hashes_gen; i++)
		{
			sqlite3_reset(_select_cleartext);
			sqlite3_bind_int64(_select_cleartext, 1, tt_hash_ids[i]);
		
			if (sqlite3_step(_select_cleartext) != SQLITE_ROW)
			{
				if (testing_use_rules)
					sprintf(buffer_str, "Fail rule: %s with param %i\n%s", rules[rule_used_clear[i]].name, rule_param_used_clear[i], tt_cleartexts + i * 32);
				else
					sprintf(buffer_str, "Len: %i Cleartext: %s", (int)strlen((char*)tt_cleartexts + i * 32), tt_cleartexts + i * 32);
				
				hs_log(HS_LOG_ERROR, "Hash not found", "%s", buffer_str);
			}
		}
		
		sqlite3_finalize(_select_cleartext);
	}
	else
	{
		sqlite3_stmt* _select_cleartext;
		sqlite3_prepare_v2(db, "SELECT ClearText FROM FindHash WHERE FindHash.PK==?;", -1, &_select_cleartext, NULL);

		for (uint32_t i = 0; i < num_hashes_found_by_format1[format_index]; i++)
		{
			sqlite3_reset(_select_cleartext);
			sqlite3_bind_int64(_select_cleartext, 1, load_fam(tt_hash_ids[i]));

			if (sqlite3_step(_select_cleartext) == SQLITE_ROW)
			{
#ifdef _WIN32
				int result = (format_index == LM_INDEX) ?
					_stricmp((char*)tt_cleartexts + i * 32, (const char*)sqlite3_column_text(_select_cleartext, 0)) :
					strcmp((char*)tt_cleartexts + i * 32, (const char*)sqlite3_column_text(_select_cleartext, 0));
#else
				char tmp[32];
				strcpy(tmp, (char*)tt_cleartexts + i * 32);

				if (format_index == LM_INDEX)
					_strupr((unsigned char*)tmp);

				int result = strcmp(tmp, (const char*)sqlite3_column_text(_select_cleartext, 0));
#endif
				if (result)
				{
					int is_collision = FALSE;
					if (format_index == BCRYPT_INDEX)
					{
						// TODO: Do something here
						const unsigned char hex[] = "ERROR NEED TO DO SOMETHING";//sqlite3_column_text(_select_cleartext, 1);
						if (hex[2] == 'x')//sign_extension_bug
						{
							uint32_t salt[4];
							BF_decode(salt, hex + 7, 16);
							swap_endianness_array(salt, 4);

							unsigned char* hash = (unsigned char*)malloc(2 * (formats[format_index].binary_size + formats[format_index].salt_size + 8));

							apply_bcrypt_bug(tt_usernames + i * 32, sqlite3_column_text(_select_cleartext, 0), hash, salt);

							if (strcmp((char*)hash, (const char*)hex) == 0)
								is_collision = TRUE;

							free(hash);
						}
					}
					if (!is_collision)
					{
						if (testing_use_rules)
							hs_log(HS_LOG_ERROR, "Test Suite", "Fail rule: %s with param %i\n%s!= %s", rules[rule_used_clear[i]].name, rule_param_used_clear[i], tt_cleartexts + i * 32, sqlite3_column_text(_select_cleartext, 0));
						else
							hs_log(HS_LOG_ERROR, "Test Suite", "Cleartext: %s != %s", tt_cleartexts + i * 32, sqlite3_column_text(_select_cleartext, 0));
					}
					/*else
					{
						if (testing_use_rules)
							hs_log(HS_LOG_INFO, "Test Suite", "Bcrypt Collision: %s with param %i\n%s!= %s", rules[rule_used_clear[i]].name, rule_param_used_clear[i], tt_cleartexts + i * 32, sqlite3_column_text(_select_cleartext, 0));
						else
							hs_log(HS_LOG_INFO, "Test Suite", "Bcrypt Collision: %s != %s", tt_cleartexts + i * 32, sqlite3_column_text(_select_cleartext, 0));
					}*/
				}
			}
			else
			{
				hs_log(HS_LOG_ERROR, "Test Suite", "Hash not found in db");
			}
		}

		sqlite3_finalize(_select_cleartext);
	}
}
#ifdef _WIN32
static void change_num_threads_in_ui(cl_uint num_threads2set)
{
	SET_EDIT_NUM(ID_NUM_THREADS, num_threads2set);
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_NUM_THREADS, 0));
}
#endif
static void random_body_hashes(cl_uint format_index, cl_uint provider_index)
{
	// Generate the accounts
	tt_usernames = (unsigned char*)malloc(32 * tt_num_hashes_gen);
	tt_cleartexts = (unsigned char*)malloc(32 * tt_num_hashes_gen);
	tt_hash_ids = (sqlite3_int64*)malloc(tt_num_hashes_gen*sizeof(sqlite3_int64));
	rule_used_clear = (int*)malloc(tt_num_hashes_gen*sizeof(int));
	rule_param_used_clear = (int*)malloc(tt_num_hashes_gen*sizeof(int));

#ifdef _WIN32
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_FORMAT_BASE + format_index, 0));
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_KEY_PROV_BASE + provider_index, 0));
#endif

	generate_accounts(format_index, provider_index);

#ifdef _WIN32
	m_checkedFormat = ID_FORMAT_BASE + format_index;
	m_checkedKeyProv = ID_KEY_PROV_BASE + provider_index;
#endif

	// Test CPU
	for (cl_uint i = 0; i < num_gpu_devices; i++)
		GPU_SET_FLAG_DISABLE(gpu_devices[i].flags, GPU_FLAG_IS_USED);

	app_num_threads = current_cpu.logical_processors;

#ifdef _WIN32
	AfxGetApp()->GetMainWnd()->SendMessage(WM_EXECUTE_IN_UI, (WPARAM)change_num_threads_in_ui, current_cpu.logical_processors);
	int had_sse2 = current_cpu.capabilites[CPU_CAP_SSE2];
	int had_avx = current_cpu.capabilites[CPU_CAP_AVX];
	int had_avx2 = current_cpu.capabilites[CPU_CAP_AVX2];
	current_cpu.capabilites[CPU_CAP_SSE2] = FALSE;
	current_cpu.capabilites[CPU_CAP_AVX] = FALSE;
	current_cpu.capabilites[CPU_CAP_AVX2] = FALSE;
#else
	int had_neon = current_cpu.capabilites[CPU_CAP_NEON];
	current_cpu.capabilites[CPU_CAP_NEON] = FALSE;
#endif

	// C code
#ifndef _M_X64
	// attack_cycle(format_index, provider_index);
#endif

#ifdef _WIN32
	if (had_sse2)
	{
		current_cpu.capabilites[CPU_CAP_SSE2] = TRUE;
		//attack_cycle(format_index, provider_index);
	}
	if (had_avx)
	{
		current_cpu.capabilites[CPU_CAP_AVX] = TRUE;
		//attack_cycle(format_index, provider_index);
	}
	if (had_avx2)
	{
		current_cpu.capabilites[CPU_CAP_AVX2] = TRUE;
		//attack_cycle(format_index, provider_index);
	}
#else
	if (had_neon)
	{
		current_cpu.capabilites[CPU_CAP_NEON] = TRUE;
		attack_cycle(format_index, provider_index);
	}
#endif

	// Test GPUs
	for (cl_uint i = 0; i < num_gpu_devices; i++)
		gpu_devices[i].flags |= GPU_FLAG_IS_USED;

	app_num_threads = 0;
#ifdef _WIN32
	AfxGetApp()->GetMainWnd()->SendMessage(WM_EXECUTE_IN_UI, (WPARAM)change_num_threads_in_ui, 0);
#endif
	if (format_index != LM_INDEX || provider_index == CHARSET_INDEX)
		attack_cycle(format_index, provider_index);

	free(tt_usernames);
	free(tt_cleartexts);
	free(tt_hash_ids);
	free(rule_param_used_clear);
	free(rule_used_clear);
}
static int test_num_hashes = 0;
static void random_body_cycle(int format_index, cl_uint provider_index)
{
	key_providers[provider_index].use_rules = testing_use_rules;
#ifdef _WIN32
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_FORMAT_BASE + format_index, 0));
	AfxGetApp()->GetMainWnd()->SendMessage(WM_COMMAND, MAKEWPARAM(ID_KEY_PROV_BASE + provider_index, 0));

	m_checkedFormat = ID_FORMAT_BASE + format_index;
	m_checkedKeyProv = ID_KEY_PROV_BASE + provider_index;
#endif

	// 1 hash
	if (!test_num_hashes)
	{
		tt_num_hashes_gen = 1;
		random_body_hashes(format_index, provider_index);
	}

	// Variuos hashes
#ifdef __ANDROID__
	uint32_t mask = 0xffff;
#else
	uint32_t mask = 0xfffff;
#endif
	if(format_index >= DCC_INDEX)
		mask = 63;
	if (format_index >= MD5CRYPT_INDEX)
		mask = 15;
	if(format_index >= DCC2_INDEX)
		mask = 3;

	if (!test_num_hashes)
		tt_num_hashes_gen = ((((rand() & 0x7FFF) << 15) + (rand() & 0x7FFF)) & mask) + 2;
	else
		tt_num_hashes_gen = test_num_hashes;
	random_body_hashes(format_index, provider_index);
}
#ifdef _WIN32
static void random_body(void* unused)
{
#else
static void* random_body(void* unused)
{
	cached_jvm->AttachCurrentThread(&env, NULL);
#endif
	srand((unsigned)time(NULL));
	testing_use_rules = FALSE;

	is_testing = TRUE;
	hs_log(HS_LOG_INFO, "Test Suite", "Random test begin.");

	int format_index = SSHA_INDEX;
	// Db Info
	//random_body_cycle(format_index, DB_INFO_INDEX);

	//for (size_t i = 0; i < 10; i++)
	{
		is_charset_consecutive = FALSE;
		//random_body_cycle(format_index, CHARSET_INDEX);
		is_charset_consecutive = TRUE;
		//random_body_cycle(format_index, CHARSET_INDEX);
	}

	// Charset
	for (check_only_lenght = (format_index == LM_INDEX) ? 4 : 1; check_only_lenght <= formats[format_index].max_plaintext_lenght; check_only_lenght++)
	{
		//hs_log(HS_LOG_INFO, "Test Suite", "Charset random %i-%i", check_only_lenght, check_only_lenght);
		is_charset_consecutive = FALSE;
		//random_body_cycle(format_index, CHARSET_INDEX);

		//hs_log(HS_LOG_INFO, "Test Suite", "Charset consecutive %i-%i", check_only_lenght, check_only_lenght);
		is_charset_consecutive = TRUE;
		//random_body_cycle(format_index, CHARSET_INDEX);
	}
	check_only_lenght = -1;

	// Wordlist
#ifdef __ANDROID__
	#define DEBUG_DIR "/sdcard/"
#else
	#define DEBUG_DIR "C:\\Users\\alain\\Desktop\\"
#endif
	use_zip_file = FALSE;
	FILEPATH = DEBUG_DIR"wikipedia-wordlist-sraveau-20090325.txt";
	FILENAME = "wikipedia-wordlist-sraveau-20090325.txt";
	FILESIZE = 743503440;

	//hs_log(HS_LOG_INFO, "Test Suite", "Wordlist wikipedia");
	//for (test_num_hashes = 9500; test_num_hashes < 10000; test_num_hashes++)
		//random_body_cycle(format_index, WORDLIST_INDEX);
	//test_num_hashes = 0;

	// Compressed
	use_zip_file = TRUE;
	ZIP_FILEPATH = DEBUG_DIR"wikipedia-wordlist-sraveau-20090325.zip";
	ZIP_FILENAME = "wikipedia-wordlist-sraveau-20090325.zip";
	ZIP_FILESIZE = 181113622;
	//hs_log(HS_LOG_INFO, "Test Suite", "Wordlist wikipedia compressed zip");
	//random_body_cycle(format_index, WORDLIST_INDEX);
	
	ZIP_FILEPATH = DEBUG_DIR"wikipedia-wordlist-sraveau.bz2";
	ZIP_FILENAME = "wikipedia-wordlist-sraveau.bz2";
	ZIP_FILESIZE = 217780548;
	//hs_log(HS_LOG_INFO, "Test Suite", "Wordlist wikipedia compressed bz2");
	//random_body_cycle(format_index, WORDLIST_INDEX);

	ZIP_FILEPATH = DEBUG_DIR"wikipedia-wordlist-sraveau-20090325.txt.gz";
	ZIP_FILENAME = "wikipedia-wordlist-sraveau-20090325.txt.gz";
	ZIP_FILESIZE = 181989365;
	//hs_log(HS_LOG_INFO, "Test Suite", "Wordlist wikipedia compressed gz");
	//random_body_cycle(format_index, WORDLIST_INDEX);

	ZIP_FILEPATH = DEBUG_DIR"wikipedia-wordlist-sraveau-200903251.7z";
	ZIP_FILENAME = "wikipedia-wordlist-sraveau-200903251.7z";
	ZIP_FILESIZE = 181989365;
	//hs_log(HS_LOG_INFO, "Test Suite", "Wordlist wikipedia compressed 7z");
	//random_body_cycle(format_index, WORDLIST_INDEX);
	use_zip_file = FALSE;

	// All Rules-------------------------------------------------------------------------------
	FILEPATH = DEBUG_DIR"wordlist_small.lst";
	FILENAME = "wordlist_small.lst";
	FILESIZE = 22338;
	skip_intensive_rules = TRUE;
	check_all_rules = TRUE;
	testing_use_rules = TRUE;
	//random_body_cycle(format_index, WORDLIST_INDEX);

	// Random Rules
	check_all_rules = FALSE;
	//random_body_cycle(format_index, WORDLIST_INDEX);

	// Big wordlist with random rules
	//FILEPATH = DEBUG_DIR"wikipedia-wordlist-sraveau-20090325.txt";
	//FILENAME = "wikipedia-wordlist-sraveau-20090325.txt";
	//FILESIZE = 743503440;
	skip_intensive_rules = TRUE;

	//check_all_rules = TRUE;
	//skip_intensive_rules = FALSE;
	//for (rule_active_index = 0; rule_active_index < (num_rules-4); rule_active_index++)
	//	random_body_cycle(format_index, WORDLIST_INDEX);

	rule_active_index = -1;

	// Phrases-----------------------------------------------------------------------
	FILEPATH = DEBUG_DIR"wordlist_small.lst";
	FILENAME = "wordlist_small.lst";
	FILESIZE = 22338;
	testing_use_rules = FALSE;
	//random_body_cycle(format_index, PHRASES_INDEX);
	// ------------------------------------------------------------------------------

	hs_log(HS_LOG_INFO, "Test Suite", "Random test had finished.");
	is_testing = FALSE;

#ifndef _WIN32
	env->DeleteGlobalRef(m_my_class);
	env->DeleteGlobalRef(thread_cls);
	cached_jvm->DetachCurrentThread();

	return NULL;
#endif
}
#ifdef _WIN32
static void random_test_cracking()
{
	HS_NEW_THREAD(random_body, NULL);
}
#else
JNIEXPORT void JNICALL Java_com_hashsuite_droid_MainActivity_TestSuite(JNIEnv* env, jclass my_class)
{
	m_my_class = (jclass)env->NewGlobalRef((jobject)env->FindClass("com/hashsuite/droid/MainActivity"));// Create a global reference
	gui_attack = env->GetStaticMethodID(m_my_class, "TestSuiteAttack", "(II)V");

	thread_cls = (jclass)env->NewGlobalRef((jobject)env->FindClass("java/lang/Thread"));
	thread_sleep = env->GetStaticMethodID(thread_cls, "sleep", "(J)V");

	pthread_t hs_pthread_id;
	pthread_create(&hs_pthread_id, NULL, random_body, NULL);
}
#endif
#endif
