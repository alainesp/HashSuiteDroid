// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2012, 2014-2015 by Alain Espinosa. See LICENSE.

#include <stdint.h>

// The binary values of the hashes
extern void* binary_values;
extern char* is_found;

////////////////////////////////////////////////////////////////////////////////////
// Table map for fast compare
////////////////////////////////////////////////////////////////////////////////////
extern unsigned int* table;
extern unsigned int* bit_table;
// If there are more than one password with the same hash point to next
extern unsigned int* same_hash_next;
extern unsigned int size_table;
extern unsigned int size_bit_table;
extern unsigned int first_bit_size_bit_table;
extern unsigned int first_bit_size_table;

typedef void crypt_kernel_asm_func(unsigned int* nt_buffer, unsigned int* bit_table, unsigned int size_bit_table);
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
unsigned char* utf8_coalesc2utf8_key(unsigned int* nt_buffer, unsigned char* key, unsigned int NUM_KEYS, unsigned int index);
unsigned char* utf8_be_coalesc2utf8_key(unsigned int* nt_buffer, unsigned char* key, unsigned int NUM_KEYS, unsigned int index);
unsigned int is_charset_consecutive(unsigned char* charset);
unsigned int get_bit_table_mask(unsigned int num_passwords_loaded, uint64_t l1_size, uint64_t l2_size);

////////////////////////////////////////////////////////////////////////////////////
// OpenCL
////////////////////////////////////////////////////////////////////////////////////
#ifdef USE_MAJ_SELECTOR
extern int MAJ_SELECTOR;
#endif

#ifdef HS_OPENCL_SUPPORT
#ifdef _WIN32
	#include <windows.h>
#else
	#include <pthread.h>
#endif

#define OCL_MULTIPLE_WORKGROUP_SIZE(value,work_group_size)	((((unsigned int)(value)) + ((unsigned int)(work_group_size))-1) & (~(((unsigned int)(work_group_size))-1)))

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
// Slow hashes
#define GPU_RULE_SLOW_BUFFER			10
#define GPU_RULE_SLOW_TRANSFORMED_KEYS	11

#define KERNEL_PROCESS_KEY_INDEX	(MAX_KEY_LENGHT_SMALL-1)
#define KERNEL_ORDERED_INDEX		(MAX_KEY_LENGHT_SMALL-2)
#define KERNEL_RULE_MOVE_TO_BEGIN	(MAX_KEY_LENGHT_SMALL-3)
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
cl_uint ocl_rule_simple_copy_unicode(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size);
cl_uint ocl_rule_simple_copy_utf8_le(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size);
//cl_uint ocl_rule_simple_copy_utf8_be(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint prefered_vector_size);
void ocl_gen_kernel_common_2_ordered(char* source, unsigned int NUM_KEYS_OPENCL, unsigned int max_key_lenght);
void change_value_proportionally(cl_uint* value, cl_uint duration);
cl_ulong ocl_calculate_best_work_group(OpenCL_Param* param, cl_kernel* kernel, cl_uint max_keys, int* kernel_param, int kernel_param_index, cl_bool depend_workgroup, cl_bool change_param);
void ocl_rules_process_found(OpenCL_Param* param, unsigned int* num_found, unsigned int* gpu_num_keys_by_len, unsigned int* gpu_pos_ordered_by_len);
void ocl_charset_process_found(OpenCL_Param* param, cl_uint* num_found, int is_consecutive, unsigned char* buffer, cl_uint key_lenght);
void ocl_common_process_found(OpenCL_Param* param, cl_uint* num_found, ocl_get_key* get_key, void* buffer, size_t num_work_items, cl_uint num_keys_filled);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common non-salted
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef void ocl_write_header_func(char* source, GPUDevice* gpu, unsigned int ntlm_size_bit_table);
typedef void ocl_gen_kernel_with_lenght_func(char* source, cl_uint key_lenght, cl_uint vector_size, cl_uint ntlm_size_bit_table, cl_uint output_size, DivisionParams div_param, char** str_comp, cl_bool value_map_collission, cl_uint workgroup);
typedef void ocl_gen_kernel_func(char* source, char* kernel_name, ocl_begin_rule_funtion* ocl_load, ocl_write_code* ocl_end, char* found_param_3, int* aditional_param, cl_uint lenght, cl_uint NUM_KEYS_OPENCL, cl_uint value_map_collission, void* salt_param, cl_uint prefered_vector_size);

cl_uint get_number_of_32regs(cl_uint num_chars, cl_uint key_lenght, cl_uint* bits_by_char);
void ocl_charset_load_buffer_be(char* source, cl_uint key_lenght, cl_uint* vector_size, DivisionParams div_param, char* nt_buffer[]);
void ocl_convert_2_big_endian(char* source, char* data, char* W);

void ocl_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE, int value_map_pos, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_with_lenght_func* ocl_gen_kernel_with_lenght, void* ocl_empty_hash, cl_uint local_bytes_needed, cl_uint keys_opencl_divider);
void ocl_charset_kernels_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE, int value_map_pos, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_with_lenght_func** ocl_gen_kernel_with_lenght, void* ocl_empty_hash, cl_uint keys_opencl_divider);
void ocl_common_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE, int value_map_pos, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_func* ocl_gen_kernel, oclKernel2Common* ocl_kernel_provider, cl_uint keys_multipler, ocl_begin_rule_funtion* ocl_load);
void ocl_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE, int value_map_pos, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_func* ocl_gen_kernel, int FORMAT_BUFFER, cl_uint keys_opencl_divider);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common salted slow
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define OCL_SLOW_COMBINE_PARAM_KERNEL_INDEX(param_cycle,kernel_index)	((param_cycle<<8) + kernel_index)
#define OCL_SLOW_GET_KERNEL_INDEX(data)									(data & 0xff)
#define OCL_SLOW_GET_CYCLE_PARAM(data)									(data>>8)

typedef char* ocl_gen_kernels_func(GPUDevice* gpu, oclKernel2Common* ocl_kernel_provider, OpenCL_Param* param, int multiplier);
typedef void ocl_slow_work_body_func(OpenCL_Param* param, int num_keys_filled, void* buffer, ocl_get_key* get_key);

void ocl_init_slow_hashes(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, oclKernel2Common* ocl_kernel_provider, int use_rules, cl_uint size_big_chunk, int BINARY_SIZE, int SALT_SIZE, ocl_gen_kernels_func* ocl_gen_kernels, ocl_slow_work_body_func* ocl_work_body, cl_uint num_keys_divider);
void ocl_best_workgroup_pbkdf2(OpenCL_Param* param, int KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE, int KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC);

#define CHARSET_INDEX_IN_KERNELS	0
#define PHRASES_INDEX_IN_KERNELS	1
#define UTF8_INDEX_IN_KERNELS		2
#endif

