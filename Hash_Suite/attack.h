// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2012, 2014 by Alain Espinosa
//
// Code licensed under GPL version 2

#include <stdint.h>

// The binary values of the hashes
extern void* binary_values;
extern char* is_found;

// Table map for fast compare------------------------------------
extern unsigned int* table;
extern unsigned int* bit_table;
// If there are more than one password with the same hash point to next
extern unsigned int* same_hash_next;
extern unsigned int size_table;
extern unsigned int size_bit_table;
extern unsigned int first_bit_size_bit_table;
extern unsigned int first_bit_size_table;
////////////////////////////////////////////////////////////////////////////////////
// Salted hash
////////////////////////////////////////////////////////////////////////////////////
extern void* salts_values;
extern unsigned int num_diff_salts;
extern unsigned int* salt_index;
extern unsigned int* same_salt_next;

////////////////////////////////////////////////////////////////////////////////////
// Charset
////////////////////////////////////////////////////////////////////////////////////
extern unsigned int num_char_in_charset;
extern unsigned char charset[256];
extern unsigned int max_lenght;
extern unsigned int current_key_lenght;

// Below methods are thread-safe
void password_was_found(unsigned int index, unsigned char* cleartext);
void finish_thread();
unsigned char* ntlm2utf8_key(unsigned int* nt_buffer, unsigned char* key, unsigned int NUM_KEYS, unsigned int index);
int is_charset_consecutive(unsigned char* charset);
unsigned int get_bit_table_mask(unsigned int num_passwords_loaded, uint64_t l1_size, uint64_t l2_size);

////////////////////////////////////////////////////////////////////////////////////
// OpenCL
////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
#include <windows.h>

// Saltless
#define GPU_CURRENT_KEY		0
#define GPU_OUTPUT			1
#define GPU_TABLE			2
#define GPU_BIT_TABLE		3
#define GPU_BINARY_VALUES	4
#define GPU_SAME_HASH_NEXT	5
#define GPU_TO_PROCESS_KEY	6
#define GPU_WORDS			7
#define GPU_WORDS_POS		8
#define GPU_ORDERED_KEYS	9
// Salt
//#define GPU_CURRENT_KEY	0
//#define GPU_OUTPUT		1
#define GPU_SALT_VALUES		2
#define GPU_SALT_INDEX		3
//#define GPU_BINARY_VALUES	4
#define GPU_SAME_SALT_NEXT	5

#define KERNEL_PROCESS_KEY_INDEX	(MAX_KEY_LENGHT-1)
#define KERNEL_ORDERED_INDEX		(MAX_KEY_LENGHT-2)
// Functions definitions
typedef void ocl_gen_processed_key(char* source, unsigned int NUM_KEYS_OPENCL);
typedef void ocl_setup_proccessed_keys_params(OpenCL_Param* param, GPUDevice* gpu);
typedef size_t ocl_get_buffer_size(OpenCL_Param* param);
typedef size_t ocl_process_buffer(void* buffer, int fill_result, OpenCL_Param* param, int* num_keys_filled);
typedef void ocl_get_key(void* buffer, unsigned char* out_key, unsigned int key_index, size_t num_work_items);

typedef struct oclKernel2Common
{
	// Protocol supported by this implementation
	int protocol;
	ocl_gen_processed_key* gen_kernel;
	ocl_setup_proccessed_keys_params* setup_params;
	ocl_process_buffer* process_buffer;
	ocl_get_key* get_key;
	ocl_get_buffer_size* get_buffer_size;
}oclKernel2Common;

extern oclKernel2Common kernels2common[];
extern unsigned int num_kernels2common;
void ocl_rule_simple_copy(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL);
void ocl_gen_kernel_common_2_ordered(char* source, unsigned int NUM_KEYS_OPENCL, unsigned int max_key_lenght);
void ocl_calculate_best_work_group(OpenCL_Param* param, cl_kernel kernel, cl_uint max_keys);
void ocl_rules_process_found(OpenCL_Param* param, unsigned int* num_found, unsigned int* gpu_num_keys_by_len, unsigned int* gpu_pos_ordered_by_len);
void ocl_charset_process_found(OpenCL_Param* param, cl_uint* num_found, int is_consecutive, unsigned char* buffer, cl_uint key_lenght);
void ocl_common_process_found(OpenCL_Param* param, cl_uint* num_found, ocl_get_key* get_key, void* buffer, size_t num_work_items);

#define CHARSET_INDEX_IN_KERNELS	0
#define PHRASES_INDEX_IN_KERNELS	1
#define UTF8_INDEX_IN_KERNELS		2
#endif

