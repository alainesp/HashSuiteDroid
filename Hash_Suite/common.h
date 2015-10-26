// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2015 by Alain Espinosa. See LICENSE.

#ifndef HASH_SUIT_DEF
#define HASH_SUIT_DEF

#include <limits.h>
#include <string.h>
#include <time.h>
#include "Interface.h"

#pragma warning(disable: 4996)

#define rotate(x,shift)		rotate32(x,shift)

#define NO_ELEM		UINT_MAX
#define POW2(x)		((x)*(x))
#define POW3(x)		((x)*(x)*(x))

#define FORMAT_USE_SALT num_diff_salts

#define PTR_SIZE_IN_BITS (sizeof(void*)*8)

#ifndef _WIN32
	unsigned char* _strupr(unsigned char *string);
	unsigned char* _strlwr(unsigned char *string);
	long long _filelengthi64(int file);
	unsigned int _rotl(unsigned int v, unsigned int sh);
	uint64_t _rotl64(uint64_t, unsigned int sh);
	void _BitScanReverse(unsigned int* index, unsigned int v);
	void _BitScanForward(unsigned int* index, unsigned int v);
#endif

void remove_str(char* data, const char* pattern);

extern sqlite3_stmt* insert_account_lm;
sqlite3_int64 insert_hash_account(ImportParam* param, const char* user_name, const char* ciphertext, int db_index, sqlite3_int64 tag_id);
sqlite3_int64 insert_hash_if_necesary(const char* hex, sqlite3_int64 format_id, ImportResultFormat* hash_stat);

void swap_endianness_array(uint32_t* data, int count);

// Flag to tag non hexadecimal characters------------------------------------------
#define NOT_HEX_CHAR 127
// Map to convert hexadecimal char into his corresponding value
extern unsigned char hex_to_num[];
extern unsigned char base64_to_num[];

//#define SECONDS_SINCE(init) ((int)((double)(clock() - init) / CLOCKS_PER_SEC + 0.5))
extern clock_t save_time;
unsigned int seconds_since_start(int isTotal);

cl_uint is_power_2(cl_uint x);
cl_uint floor_power_2(cl_uint x);
cl_uint ceil_power_2(cl_uint x);

// Conversion from division by a constant to a multiplication by a constant and a shift
typedef struct DivisionParams
{
	unsigned int magic;
	unsigned int shift;
	unsigned char sum_one;
}
DivisionParams;
DivisionParams get_div_params(unsigned int divisor);

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
void create_opencl_mem(OpenCL_Param* param, cl_uint index, cl_mem_flags flag, size_t size, void* host_ptr);
int create_kernel(OpenCL_Param* param, cl_uint index, char* kernel_name);
void cl_write_buffer(OpenCL_Param* param, cl_uint index, size_t size, void* ptr);

#endif

///////////////////////////////////////////////////////////////////////////////////////////
// Public key implementation
///////////////////////////////////////////////////////////////////////////////////////////
int crypto_scalarmult_curve25519(unsigned char *shared_key, const unsigned char *secret_key, const unsigned char *public_key);
int crypto_scalarmult_curve25519_base(unsigned char *public_key, const unsigned char *secret_key);

void salsa20_crypt_block(unsigned char* message, const unsigned int* nonce, const unsigned int* key, unsigned int counter);

#endif
