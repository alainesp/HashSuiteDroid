// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2020 by Alain Espinosa. See LICENSE.

#ifndef HS_INTERFACE
#define HS_INTERFACE

#include "system.h"
#include "sqlite3.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "compilation_flags.h"

#ifdef HS_OPENCL_SUPPORT
#define CL_TARGET_OPENCL_VERSION 120
#include "OpenCL\cl.h"
#include "OpenCL\cl_ext.h"
#include "OpenCL\cuda_drvapi_dynlink_cuda.h"
#endif

#define MAX_KEY_LENGHT_SMALL	32
#define MAX_KEY_LENGHT_BIG		32
#define LENGTH(x) (sizeof(x)/sizeof(x[0]))

#define ROTATE32(x,shift)	_rotl(x,shift)
#define ROTATE64(x,shift)	_rotl64(x,shift)
//#define SWAP_ENDIANNESS(x, data) x = ROTATE32(data, 16U); x = ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF);
//#define SWAP_ENDIANNESS16(x, data) x = (((data&0xff00)>>8) | ((data&0xff)<<8));

#define PRIVATE static
#define PUBLIC

#define TRUE  1
#define FALSE 0

#ifdef __cplusplus
extern "C" {  // only need to export C interface if used by C++ source code
#endif

typedef struct
{
	int64_t file_size;
	void* wnd_handle;
	void (*send_message)(void* wnd, int percent);

	char md4_hash[32+1];
	char md5_hash[32+1];
	char sha1_hash[40+1];
	char sha256_hash[64+1];
	char sha512_hash[128+1];

	char filename[1024];
}
HASH_FILE_DATA;

extern int is_test;
extern uint32_t test_sleep_time;
extern int test_rules_on_gpu;
extern uint32_t hash_count_to_test[];

// DB related----------------------------------------------------------------------
#define DB_FILE "config.db"
extern sqlite3* db;

#define BEGIN_TRANSACTION (sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL))
#define END_TRANSACTION   (sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL))

#define CLIP_RANGE(num,minValue,maxValue)		(__max(__min((num),(maxValue)),(minValue)))

// Function to generate keys candidates
typedef int generate_key_funtion(void* param, uint32_t count, int thread_id);

typedef struct CryptParam
{
	generate_key_funtion* gen;
	int thread_id;
}
CryptParam;
// Function to perform crypts
typedef void perform_crypt_funtion(CryptParam*);

#ifdef HS_OPENCL_SUPPORT
typedef struct OCL_Rules
{
	// Needed by rules
	cl_kernel* kernels;
	size_t* work_group_sizes;
	cl_uint num_kernels;
}
OCL_Rules;

typedef struct OpenCL_Param
{
	union{// Support OpenCL/Cuda driver API
		cl_device_id id;
		CUdevice cu_id;
	};

	union{// Support OpenCL/Cuda driver API
		cl_context context;
		CUcontext cu_context;
	};

	cl_command_queue queue;

	union{// Support OpenCL/Cuda driver API
		cl_program program;
		CUmodule cu_module;
	};

	union{// Support OpenCL/Cuda driver API
		cl_mem mems[12];
		CUdeviceptr cu_mems[12];
	};

	union{// Support OpenCL/Cuda driver API
		cl_kernel kernels[MAX_KEY_LENGHT_SMALL];
		CUfunction cu_kernels[MAX_KEY_LENGHT_SMALL];
	};

	// Common
	int thread_id;
	cl_uint NUM_KEYS_OPENCL;
	generate_key_funtion* gen;
	cl_uint* output;
	int use_ptx;
	size_t max_work_group_size;
	int param0;
	cl_uint param1;
	void* additional_param;
	void* additional_param1;
	cl_kernel* additional_kernels;
	cl_program* additional_programs;
	cl_uint additional_kernels_size;
	cl_program additional_program;
	// Needed by rules
	OCL_Rules rules;
}
OpenCL_Param;
typedef void gpu_crypt_funtion(OpenCL_Param*);
typedef int create_gpu_crypt_funtion(OpenCL_Param*, cl_uint, generate_key_funtion*, gpu_crypt_funtion**);
#endif

#define MESSAGE_FINISH_BATCH			1
#define MESSAGE_FINISH_ATTACK			2
#define MESSAGE_ATTACK_INIT_COMPLETE	3
#define MESSAGE_ATTACK_GPU_FAIL	        4
#define MESSAGE_TESTING_INIT_COMPLETE	5
#define MESSAGE_TESTING_FAIL			6
#define MESSAGE_TESTING_SUCCEED			7
#define MESSAGE_FLUSHING_KEYS			8
#define MESSAGE_CL_COMPILING            9
#define MESSAGE_TESTING_PROGRESS       10
#define MESSAGE_HARD_STOP			   11

#define MESSAGE_MASK                    0xffff
#define MESSAGE_PUT_DATA(message, data) ((message) | ((data)<<16))
#define MESSAGE_GET_DATA(message)       ((message)>>16)
typedef void callback_funtion(int message);

////////////////////////////////////////////////////////////////////////////////////
// Formats
////////////////////////////////////////////////////////////////////////////////////
#ifndef INCLUDE_DEVELOPING_FORMAT
#define MAX_NUM_FORMATS 14
#endif

#define LM_INDEX			0
#define NTLM_INDEX			1
#define MD5_INDEX			2
#define SHA1_INDEX			3
#define SHA256_INDEX		4
#define SHA512_INDEX		5
#define DCC_INDEX			6
#define SSHA_INDEX			7
#define MD5CRYPT_INDEX		8
#define DCC2_INDEX			9
#define WPA_INDEX			10
#define BCRYPT_INDEX		11
#define SHA256CRYPT_INDEX	12
#define SHA512CRYPT_INDEX	13


// Protocols
#define PROTOCOL_UTF8_LM					1
#define PROTOCOL_NTLM						2
#define PROTOCOL_FAST_LM					3
#define PROTOCOL_CHARSET_OCL				4
#define PROTOCOL_CHARSET_OCL_NO_ALIGNED		5
#define PROTOCOL_FAST_LM_OPENCL				6
#define PROTOCOL_UTF8						7
#define PROTOCOL_RULES_OPENCL				8
#define PROTOCOL_PHRASES_OPENCL				9
#define PROTOCOL_UTF8_COALESC_LE			10// Little endian
#define PROTOCOL_UTF8_COALESC_BE			11// Big endian

////////////////////////////////////////////////////////////////////////////////////
// In-Out
////////////////////////////////////////////////////////////////////////////////////
typedef struct ImportResultFormat
{
	int num_hash_added;
	int num_hash_disable;
	int num_hash_exist;

}ImportResultFormat;

typedef struct ImportResult
{
	int num_users_added;
	int lines_skiped;
	ImportResultFormat formats_stat[MAX_NUM_FORMATS];

}ImportResult;

#define IMPORT_COMPLETITION_UNKNOW -1
typedef struct ImportParam
{
	char filename[FILENAME_MAX];
	char filename2[FILENAME_MAX];
	char tag[FILENAME_MAX];
	int (*select_format)(char* line, int* valid_formats);

	ImportResult result;

	int isEnded;
	int completition;
#ifdef _WIN32
	void* hWnd;// main window
#endif
}ImportParam;

// Data needed by importers to application
#define IMPORT_PARAM_NONE			0
#define IMPORT_PARAM_FILENAME		1
#define IMPORT_PARAM_MACHINE_NAME	2
#define IMPORT_PARAM_REGISTRY		3

typedef struct Importer
{
	int icon_index;
	char* name;
	char* extension;
	char* description;
	void(*function)(ImportParam* param);
	int param_type;// Type of the param(one of IMPORT_PARAM_*)
}
Importer;

// Data needed by exporters from application
typedef struct Exporter
{
	int icon_index;
	char* name;
	char* defaultFileName;
	char* description;
	void(*function)(const char*, int);
}
Exporter;

extern Importer importers[];
extern Exporter exporters[];
extern int num_importers;
extern int num_exporters;
extern int continue_import;

void export_db(const char* filename);

////////////////////////////////////////////////////////////////////////////////////
// FORMAT
////////////////////////////////////////////////////////////////////////////////////
typedef struct FormatImplementation
{
	// What capabilities in the CPU are needed?
	int needed_cap;
	// Protocol supported by this implementation
	int protocol;
	// Perform the crypt. Must be thread-safe
	perform_crypt_funtion* perform_crypt;
}
FormatImplementation;

#ifdef HS_OPENCL_SUPPORT
typedef struct GPUFormatImplementation
{
	// Protocol supported by this implementation
	int protocol;
	// Perform the crypt. Must be thread-safe
	create_gpu_crypt_funtion* perform_crypt;
}
GPUFormatImplementation;
#endif

#define DEFAULT_VALUE_MAP_INDEX 0
typedef struct Format
{
	char* name;
	char* description;
	char* prefix;
	uint32_t max_plaintext_lenght;
	uint32_t binary_size;
	uint32_t salt_size;
	sqlite3_int64 db_id;
	// Benchmark
	int* bench_values;// Each item is a number of passwords to benchmark
	int lenght_bench_values;

	// Convert hexadecimal password into a compact representation
	// and return a value used for hashing in a hash table
	// params: IN: hexadecimal, OUT: binary_value, OUT: salt_value
	uint32_t (*convert_to_binary)(const unsigned char*, void*, void*);
	void (*convert_to_string)(const void* binary, const void* salt, unsigned char* hex);
	uint32_t value_map_index0;
	uint32_t value_map_index1;

	int(*is_valid_line)(char* username, char* p0, char* p1, char* p2);
	sqlite3_int64(*add_hash_from_line)(ImportParam* param, char* username, char* p0, char* p1, char* p2);
	void(*optimize_hashes)();

	// CPU Implementations. Fast implementation first
	FormatImplementation impls[3];
#ifdef HS_OPENCL_SUPPORT
	GPUFormatImplementation opencl_impls[4];
#endif
}
Format;

extern Format formats[];
extern int num_formats;
Format* find_format(sqlite3_int64 db_id);
int find_format_index(sqlite3_int64 db_id);

////////////////////////////////////////////////////////////////////////////////////
// KeyProviders
////////////////////////////////////////////////////////////////////////////////////
#define KEY_SPACE_UNKNOW -1LL
int64_t get_key_space_batch();

#define CHARSET_INDEX	0
#define WORDLIST_INDEX	1
#define KEYBOARD_INDEX	2
#define PHRASES_INDEX	3
#define DB_INFO_INDEX	4
#define LM2NTLM_INDEX	5
#define FAST_LM_INDEX	6
#define RULES_INDEX		7

typedef struct KeyProviderImplementation
{
	// Protocol supported by this implementation
	int protocol;
	// Function to generate the keys. Must be thread-safe
	generate_key_funtion* generate;
}
KeyProviderImplementation;

typedef struct KeyProvider
{
	char* name;
	char* description;
	sqlite3_int64 db_id;

	// Implementations. Fast implementation first
	KeyProviderImplementation impls[5];
	
	// Save current state for latter resume. Must be thread-safe
	void (*save_resume_arg)(char*);
	// Resume keys generation. min_lenght, max_lenght, Params, resume_arg, format_index.
	// If resume_arg==NULL only init
	void (*resume)(int, int, char*, const char*, int);
	void (*finish)();

	// From the param get a short description
	void (*get_param_description)(const char*, char*, int, int);

	uint32_t min_size;
	uint32_t recommend_max_size;
	int show_to_user;
	int use_rules;
	int per_thread_data_size;
}KeyProvider;

extern KeyProvider key_providers[];
extern int num_key_providers;
KeyProvider* find_key_provider(sqlite3_int64 db_id);
int find_key_provider_index(sqlite3_int64 db_id);

extern uint32_t PHRASES_MAX_WORDS_READ;

////////////////////////////////////////////////////////////////////////////////////
// Rules support
////////////////////////////////////////////////////////////////////////////////////
int add_rules_to_param(char* param, int key_provider_index);
typedef void apply_rule_funtion(uint32_t* nt_buffer, uint32_t max_number, uint32_t* rules_data_buffer);
typedef void ocl_get_key_funtion(unsigned char* out_key, unsigned char* plain, uint32_t param);

// Return the vector_size used
typedef uint32_t ocl_begin_rule_funtion(char* source, char nt_buffer[16][16], char nt_buffer_vector_size[16], uint32_t lenght, uint32_t NUM_KEYS_OPENCL, uint32_t prefered_vector_size);
typedef void ocl_write_code(char* source);

typedef void ocl_rule_common(char* source, char* rule_name, uint32_t in_num_keys, uint32_t out_num_keys);
#define RULE_LENGHT_COMMON	10

#define RULE_UNICODE_INDEX	0
#define RULE_UTF8_LE_INDEX	1

typedef struct oclRule
{
	ocl_rule_common* common_implementation; // A common implementation used in slow formats (DCC2)
	ocl_begin_rule_funtion* begin[2];		// Load buffer in a specific format (Unicode or UTF8)
	ocl_write_code* end;					// written at end of crypt cycle
	ocl_get_key_funtion* get_key;			// Obtain the final key from the source key applying the rule trasnformation
	char* found_param;						// Value to save to later recover the key found
	uint32_t max_param_value;			// If value is 0 no need of additional params
	ocl_write_code* setup_constants;		// If the rule need some constants values, this will execute at the begining of kernels
	
}oclRule;

typedef struct Rule
{
	char* name;
	char* description;
	apply_rule_funtion* function[2]; // Apply rule in a specific format (Unicode or UTF8)
	int checked;
	int multipler;					// Number of generate keys from one key
	char depend_key_lenght;			// If the rule depend of the key_lenght
	char key_lenght_sum;			// How much the rule depend of the key_lenght
	// OpenCL support for rules
	oclRule ocl;
}Rule;

extern Rule rules[];
extern int num_rules;

// Fix accounts
#define FIXED_NONE		0
#define FIXED_DISABLE	1
#define FIXED_EXPIRE	2

extern uint32_t* num_user_by_formats1;
extern uint32_t total_deleted_hashes;

// Executed at program init
void init_all(const char* program_exe_path);
void init_opencl();
// Other common funtions
int64_t get_milliseconds();
char* get_full_path(char* filename);
void itoaWithDigitGrouping(int64_t number, char* str);
void filelength2string(int64_t length, char* str);
int64_t get_num_keys_served();
void clear_db_accounts();
int valid_hex_string(unsigned char* ciphertext,int lenght);
void binary_to_hex(const uint32_t* binary, unsigned char* ciphertext, uint32_t num_dwords, int is_big_endian);
void base64_encode_mime(const unsigned char *in, int len, char *outy);
int base64_decode_mime(const char *in, int inlen, unsigned char *out);
int valid_base64_string(unsigned char* ciphertext, int lenght);
char* password_per_sec(char* buffer);
char* get_time_from_begin(int isTotal);
char* finish_time();
char* get_work_done();
int new_crack(int format_index, int key_prov_index, int min_lenght, int max_lenght, char* provider_param, callback_funtion psend_message_gui, int use_rules);
void resume_crack(sqlite3_int64 db_id, callback_funtion psend_message_gui);
int save_attack_state();
int is_wordlist_supported(const char* file_path, char* error_message);
uint32_t load_fam(uint64_t pos);
void save_fam(uint64_t pos, uint32_t value);
void resize_fam();

////////////////////////////////////////////////////////////////////////////////////
// Fingerprint
////////////////////////////////////////////////////////////////////////////////////
#define FINGERPRINT_STATUS_LOADING_DATA 0
#define FINGERPRINT_STATUS_COUNTING		1
#define FINGERPRINT_STATUS_SORTING		2
#define FINGERPRINT_STATUS_SAVING_DATA  3
#define FINGERPRINT_STATUS_END			4

typedef struct
{
	char out_file[512];
	uint32_t percent;
	uint32_t status;

	uint64_t file_size;
	uint64_t num_parts;
}
HASH_TABLE_FINGERPRINT;
void generate_fingerprint_words(HASH_TABLE_FINGERPRINT* fp);
////////////////////////////////////////////////////////////////////////////////////

int has_implementations_compatible(int format_index, int provider_index);

int is_found_all_hashes(int format_index);
void save_num_hashes_cache();
uint32_t total_num_users();
uint32_t total_num_hashes_found();
uint32_t total_num_hashes();
uint32_t has_hashes(int format_index);

extern uint32_t* num_hashes_found_by_format1;
extern uint32_t* num_hashes_by_formats1;
////////////////////////////////////////////////////////////////////////////////////
// Batch
////////////////////////////////////////////////////////////////////////////////////
typedef struct AttackData
{
	sqlite3_int64 attack_db_id;
	int format_index;
	int provider_index;
	uint32_t min_lenght;
	uint32_t max_lenght;
	char params[256];
	char resume_arg[64];
	int is_ended;
	int secs_before_this_attack;// Seconds used in anteriors attacks
	int64_t key_space;
	int64_t num_keys_served;
}AttackData;

extern AttackData* batch;
extern int num_attack_in_batch;
extern int current_attack_index;
extern int cache_had_hashes;
void get_cache_info(char* buffer);
void release_all_cache();

extern uint32_t MAX_NUM_PASWORDS_LOADED;
extern int is_benchmark;
extern int use_cpu_as_gpu;

// Settings
int get_setting(int id, int default_value);
void save_setting(int id, int value);
void save_settings_to_db();

// Number of passwords currently loaded
extern uint32_t num_passwords_loaded;
// Used to stop the attack
extern int continue_attack;
extern int stop_universe;
extern int save_needed;
extern callback_funtion* send_message_gui;

// Hashing
void hash_lm(const char* message, char* hash);
void hash_ntlm(const unsigned char* message, char* hash);
void hash_md5(const char* message, char* hash);
void hash_sha1(const char* message, char* hash);
void hash_sha256(const char* message, char* hash);
void hash_sha512(const char* message, char* hash);
void hash_dcc(const unsigned char* cleartext, char* hash);
void hash_dcc2(const unsigned char* cleartext, char* hash);
void hash_ssha1(const char* cleartext, char* hash);
void hash_md5crypt(const unsigned char* cleartext, char* hash);
void hash_sha256crypt(const char* cleartext, char* hash);
void hash_sha512crypt(const char* cleartext, char* hash);
void hash_wpa(const unsigned char* cleartext, unsigned char* hash);
void hash_bcrypt(const char* cleartext, unsigned char* hash);
void hash_file(void* void_data);

// Hardware Capabilities
#define CPU_CAP_C_CODE			0x0000

#ifdef HS_X86
	#define CPU_CAP_X64				0x0001
	#define CPU_CAP_SSE2			0x0002
	#define CPU_CAP_AVX				0x0003
	#define CPU_CAP_HTT				0x0004
	#define DEV_CAP_OPENCL			0x0005
	#define CPU_CAP_AVX2			0x0006
	#define CPU_CAP_BMI				0x0007
	
	#define MAX_NUM_CAPS			8

#elif defined(HS_ARM)
	#define CPU_CAP_NEON			0x0001
	#define MAX_NUM_CAPS			4
#endif

typedef struct CPUHardware
{
	//int family;
	//int model;
	//char cpu_string[0x20];
	char brand[0x40];
	int img_index;

	uint32_t logical_processors;
	unsigned long cores;
	unsigned long l1_cache_size;// L1 cache in kilobytes
	unsigned long l2_cache_size;// L2 cache in kilobytes
	unsigned long l3_cache_size;// L3 cache in kilobytes
	//unsigned long numa_node_count;
	//unsigned long processor_package_count;

	int capabilites[MAX_NUM_CAPS];
}
CPUHardware;

typedef struct
{
	char os[64];
	char machine_name[16];
	unsigned long major_version;
	unsigned long minor_version;
	int is_64bits;
	unsigned long granularity;      // system allocation granularity
	size_t large_page_size;
	int is_large_page_enable;
}
OtherSystemInfo;

extern uint32_t app_num_threads;
extern uint32_t num_threads;
extern CPUHardware current_cpu;
extern OtherSystemInfo current_system_info;

////////////////////////////////////////////////////////////////////////////////////
// OpenCL
////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
#define MAX_NUMBER_GPUS_SUPPORTED	32

#define OCL_VENDOR_AMD		0
#define OCL_VENDOR_NVIDIA	1
#define OCL_VENDOR_INTEL	2
#define OCL_VENDOR_QUALCOMM 3
#define OCL_VENDOR_UNKNOW	128

#define GPU_STATUS_FAILED		0
#define GPU_STATUS_TEMPERATURE	1
#define GPU_STATUS_FAN			2
#define GPU_STATUS_USE			4

typedef struct GPUStatus
{
	char flag;
	uint32_t temperature;
	uint32_t fan_speed;
	int usage;
}GPUStatus;

typedef struct nvmlDevice_st* nvmlDevice_t;

#define GPU_FLAG_IS_USED				1
#define GPU_FLAG_SUPPORT_STATUS_INFO	(1<<1)
#define GPU_FLAG_NATIVE_BITSELECT		(1<<2)
#define GPU_FLAG_SUPPORT_PTX			(1<<3)
#define GPU_FLAG_HAD_UNIFIED_MEMORY		(1<<4)
#define GPU_FLAG_HAD_LM_UNROll			(1<<5)
#define GPU_FLAG_LM_USE_SHARED_MEMORY	(1<<6)
#define GPU_FLAG_LM_REQUIRE_WORKGROUP	(1<<7)
#define GPU_FLAG_SUPPORT_AMD_OPS		(1<<8)
#define GPU_FLAG_NVIDIA_LOP3			(1<<9)

#define GPU_SET_FLAG_ENABLE(val,flag) val |= flag
#define GPU_SET_FLAG_DISABLE(val,flag) val &= ~((cl_uint)flag)

typedef struct GPUDevice
{
	cl_device_id cl_id;
	cl_uint flags;

	union{// Support Nvidia and AMD
		struct { int id; int version; } amd;
		struct { nvmlDevice_t id; } nv;
	};
	// Hardware Info---------------------
	char vendor;
	int vendor_icon;

	cl_uint cores;
	cl_ulong l1_cache_size;// L1 cache in kilobytes. For each CU
	cl_ulong l2_cache_size;// L2 cache in kilobytes. For all GPU
	cl_ulong l3_cache_size;// L3 cache in kilobytes. Only Intel
	char memory_type[16];
	cl_uint memory_frequency;
	char opencl_version[16];
	char name[64];
	char* compiler_options;
	char* lm_compiler_options;
	cl_uint max_clock_frequency;
	cl_ulong global_memory_size;//in bytes
	cl_ulong local_memory_size;//in bytes
	cl_ulong max_mem_alloc_size;
	cl_uint vector_int_size;//Preferred native vector width size for built-in scalar types that can be put into vectors
	size_t max_work_group_size;
	size_t lm_work_group_size;
	cl_uint major_cc;
	cl_uint NUM_KEYS_OPENCL_DIVIDER;
	cl_uint device_vendor_id;
	char vendor_string[64];
	char driver_version[32];
}
GPUDevice;

extern GPUDevice gpu_devices[MAX_NUMBER_GPUS_SUPPORTED];
extern cl_uint num_gpu_devices;
cl_uint get_num_gpus_used();

// Get status
int gpu_get_updated_status(uint32_t gpu_index, GPUStatus* status);

typedef cl_int (CL_API_CALL *clGetPlatformIDsFunc)(cl_uint, cl_platform_id*, cl_uint*);
typedef cl_int (CL_API_CALL *clGetDeviceIDsFunc)(cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*);
typedef cl_int (CL_API_CALL *clGetDeviceInfoFunc)(cl_device_id, cl_device_info, size_t, void*, size_t*);
typedef cl_context (CL_API_CALL *clCreateContextFunc)(const cl_context_properties*, cl_uint, const cl_device_id*, void (CL_CALLBACK*)(const char *, const void *, size_t, void *), void*, cl_int*);
typedef cl_command_queue (CL_API_CALL *clCreateCommandQueueFunc)(cl_context, cl_device_id, cl_command_queue_properties, cl_int*);
typedef cl_program (CL_API_CALL *clCreateProgramWithSourceFunc)(cl_context, cl_uint, const char**, const size_t*, cl_int*);
typedef cl_program (CL_API_CALL *clCreateProgramWithBinaryFunc)(cl_context, cl_uint, const cl_device_id *,const size_t *,const unsigned char **,cl_int *,cl_int *);
typedef cl_int (CL_API_CALL *clBuildProgramFunc)(cl_program, cl_uint, const cl_device_id*, const char*, void (CL_CALLBACK *  /* pfn_notify */)(cl_program, void*), void*);
typedef cl_kernel (CL_API_CALL *clCreateKernelFunc)(cl_program, const char*, cl_int*);
typedef cl_mem (CL_API_CALL *clCreateBufferFunc)(cl_context, cl_mem_flags, size_t, void*, cl_int*);
typedef void*  (CL_API_CALL *clEnqueueMapBufferFunc)(cl_command_queue, cl_mem, cl_bool, cl_map_flags, size_t, size_t, cl_uint, const cl_event*, cl_event*, cl_int*);
typedef cl_int (CL_API_CALL *clSetKernelArgFunc)(cl_kernel, cl_uint, size_t, const void*);
typedef cl_int (CL_API_CALL *clEnqueueNDRangeKernelFunc)(cl_command_queue, cl_kernel, cl_uint, const size_t*, const size_t*, const size_t*, cl_uint, const cl_event*, cl_event*);
typedef cl_int (CL_API_CALL *clFinishFunc)(cl_command_queue /* command_queue */);
typedef cl_int (CL_API_CALL *clReleaseMemObjectFunc)(cl_mem /* memobj */);
typedef cl_int (CL_API_CALL *clReleaseKernelFunc)(cl_kernel   /* kernel */);
typedef cl_int (CL_API_CALL *clReleaseProgramFunc)(cl_program /* program */);
typedef cl_int (CL_API_CALL *clReleaseCommandQueueFunc)(cl_command_queue /* command_queue */);
typedef cl_int (CL_API_CALL *clReleaseContextFunc)(cl_context /* context */);
typedef cl_int (CL_API_CALL *clEnqueueReadBufferFunc)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, void*, cl_uint, const cl_event*, cl_event*);
typedef cl_int (CL_API_CALL *clEnqueueWriteBufferFunc)(cl_command_queue, cl_mem, cl_bool, size_t, size_t, const void*, cl_uint, const cl_event*, cl_event*);
typedef cl_int (CL_API_CALL *clGetPlatformInfoFunc)(cl_platform_id, cl_platform_info, size_t, void *, size_t *);
typedef cl_int (CL_API_CALL *clGetProgramBuildInfoFunc)(cl_program, cl_device_id, cl_program_build_info, size_t, void*, size_t*);
typedef cl_int (CL_API_CALL *clGetProgramInfoFunc)(cl_program, cl_program_info, size_t, void *, size_t *);
typedef cl_int (CL_API_CALL *clEnqueueCopyBufferFunc) (cl_command_queue, cl_mem, cl_mem, size_t, size_t, size_t, cl_uint, const cl_event*, cl_event*);

typedef cl_int (CL_API_CALL *clGetEventProfilingInfoFunc)(cl_event,cl_profiling_info,size_t,void*,size_t*);
typedef cl_int (CL_API_CALL *clReleaseEventFunc)(cl_event) ;

extern clGetDeviceInfoFunc  pclGetDeviceInfo;
extern clSetKernelArgFunc pclSetKernelArg;
extern clEnqueueNDRangeKernelFunc pclEnqueueNDRangeKernel;
extern clFinishFunc pclFinish;
extern clFinishFunc pclFlush;
extern clEnqueueReadBufferFunc pclEnqueueReadBuffer;
extern clEnqueueWriteBufferFunc pclEnqueueWriteBuffer;
extern clEnqueueCopyBufferFunc pclEnqueueCopyBuffer;
extern clReleaseKernelFunc pclReleaseKernel;
extern clCreateKernelFunc pclCreateKernel;
#endif

#ifdef __cplusplus
}
#endif

#endif
