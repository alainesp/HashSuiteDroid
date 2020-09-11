// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2015 by Alain Espinosa. See LICENSE.

#ifndef HASH_SUIT_DEF
#define HASH_SUIT_DEF

#include <limits.h>
#include <string.h>
#include "Interface.h"

#pragma warning(disable: 4996)

#define ROTATE(x,shift)		ROTATE32(x,shift)

#define NO_ELEM		UINT_MAX
#define POW2(x)		((x)*(x))
#define POW3(x)		((x)*(x)*(x))

#define FORMAT_USE_SALT num_diff_salts

#define PTR_SIZE_IN_BITS ((int)(sizeof(void*)*8))

#include <assert.h>

#ifndef _WIN32
	int _strnicmp(char* string0, char* string1, int count);
	unsigned char* _strupr(unsigned char *string);
	unsigned char* _strlwr(unsigned char *string);
	long long _filelengthi64(int file);
	uint32_t _rotl(uint32_t v, uint32_t sh);
	uint64_t _rotl64(uint64_t, uint32_t sh);
	void _BitScanReverse(uint32_t* index, uint32_t v);
	void _BitScanForward(uint32_t* index, uint32_t v);
#endif

void remove_str(char* data, const char* pattern);

#ifdef __cplusplus
extern "C" {  // only need to export C interface if used by C++ source code
#endif
	extern sqlite3_stmt* insert_account_lm;
	sqlite3_int64 insert_hash_account1(ImportParam* param, const char* user_name, const char* ciphertext, int db_index);
	sqlite3_int64 insert_hash_if_necesary(const char* hex, sqlite3_int64 format_index, ImportResultFormat* hash_stat);
	extern sqlite3_stmt* insert_tag_account;
	sqlite3_int64 insert_when_necesary_tag(const char* tag);
#ifdef __cplusplus
}  // only need to export C interface if used by C++ source code
#endif

void swap_endianness_array(uint32_t* data, int count);

// Flag to tag non hexadecimal characters------------------------------------------
#define NOT_HEX_CHAR 127
// Map to convert hexadecimal char into his corresponding value
extern unsigned char hex_to_num[];
extern unsigned char base64_to_num[];
#ifdef __cplusplus
extern "C" {  // only need to export C interface if used by C++ source code
#endif
	extern char itoa64[];

	uint32_t is_power_2(uint32_t x);
	uint32_t floor_power_2(uint32_t x);
	uint32_t ceil_power_2(uint32_t x);
	void generate_random(uint8_t* values, size_t size);

#ifdef __cplusplus
}  // only need to export C interface if used by C++ source code
#endif


//#define SECONDS_SINCE(init) ((int)((double)(get_milliseconds() - init) / 1000 + 0.5))
extern int64_t save_time;
uint32_t seconds_since_start(int isTotal);

// Conversion from division by a constant to a multiplication by a constant and a shift
typedef struct DivisionParams
{
	uint32_t magic;
	uint32_t shift;
	unsigned char sum_one;
}
DivisionParams;
DivisionParams get_div_params(uint32_t divisor);

int src_contained_in(const char* src, const char* container);

// Rules
#define RULE_SAVE_KEY_PROV_INDEX(param, key_provider_index) (param[0] = key_provider_index+1)
#define RULE_GET_KEY_PROV_INDEX(param)						(param[0] - 1)

void report_keys_processed(int64_t num);
int64_t get_num_keys_served_from_save();
void get_num_keys_served_ptr(int64_t* from_save, int64_t* from_start);
void add_num_keys_from_save_to_start();
void set_num_keys_zero();
void set_num_keys_save_add_start(int64_t from_save_val, int64_t to_add_start);

// DB related----------------------------------------------------------------------
void register_key_providers(int db_already_initialize);

////////////////////////////////////////////////////////////////////////////////////
// OpenCL
////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
void create_opencl_param(OpenCL_Param* result, cl_uint gpu_device_index, generate_key_funtion* gen, cl_uint size_ouput, int use_ptx);
void release_opencl_param(OpenCL_Param* param);
int build_opencl_program(OpenCL_Param* param, const char* source, char* compiler_options);
int create_opencl_mem(OpenCL_Param* param, cl_uint index, cl_mem_flags flag, size_t size, void* host_ptr);
int create_kernel(OpenCL_Param* param, cl_uint index, char* kernel_name);
void cl_write_buffer(OpenCL_Param* param, cl_uint index, size_t size, void* ptr);

#endif

///////////////////////////////////////////////////////////////////////////////////////////
// Public key implementation
///////////////////////////////////////////////////////////////////////////////////////////
int crypto_scalarmult_curve25519(unsigned char *shared_key, const unsigned char *secret_key, const unsigned char *public_key);
int crypto_scalarmult_curve25519_base(unsigned char *public_key, const unsigned char *secret_key);

void salsa20_crypt_block(unsigned char* message, const uint32_t* nonce, const uint32_t* key, uint32_t counter);

#endif
