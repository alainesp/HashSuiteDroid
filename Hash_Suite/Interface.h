// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014 by Alain Espinosa. See LICENSE.

//#ifndef HS_INTERFACE
//#define HS_INTERFACE

#include "system.h"
#include "sqlite3.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "compilation_flags.h"

#ifdef HS_OPENCL_SUPPORT
#include "OpenCL\cl.h"
#include "OpenCL\cl_ext.h"
#include "OpenCL\cuda_drvapi_dynlink_cuda.h"
#endif

#define MAX_KEY_LENGHT 32
#define LENGHT(x) (sizeof(x)/sizeof(x[0]))

#define PRIVATE static
#define PUBLIC

#define TRUE  1
#define FALSE 0

#ifdef __cplusplus
extern "C" {  // only need to export C interface if used by C++ source code
#endif

// DB related----------------------------------------------------------------------
#define DB_FILE "config.db"
extern sqlite3* db;

#define BEGIN_TRANSACTION (sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL))
#define END_TRANSACTION   (sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL))

#define CLIP_RANGE(num,minValue,maxValue)		(__max(__min((num),(maxValue)),(minValue)))

// Function to generate keys candidates
typedef int generate_key_funtion(void* param, unsigned int count, int thread_id);

typedef struct CryptParam
{
	generate_key_funtion* gen;
	int thread_id;
}
CryptParam;
// Function to perform crypts
typedef void perform_crypt_funtion(CryptParam*);

#ifdef HS_OPENCL_SUPPORT
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
		cl_mem mems[10];
		CUdeviceptr cu_mems[10];
	};

	union{// Support OpenCL/Cuda driver API
		cl_kernel kernels[MAX_KEY_LENGHT];
		CUfunction cu_kernels[MAX_KEY_LENGHT];
	};

	// Common
	int thread_id;
	unsigned int NUM_KEYS_OPENCL;
	generate_key_funtion* gen;
	cl_uint* output;
	int use_ptx;
	size_t max_work_group_size;
	int param0;
	void* additional_param;
	cl_uint gpu_device_index;
	// Needed by rules
	cl_kernel* rules_kernels;
	cl_uint num_rules_kernels;
}
OpenCL_Param;
typedef void gpu_crypt_funtion(OpenCL_Param*);
typedef OpenCL_Param* create_gpu_crypt_funtion(unsigned int, generate_key_funtion*, gpu_crypt_funtion**);
#endif

#define MESSAGE_FINISH_BATCH	1
#define MESSAGE_FINISH_ATTACK	2
#define MESSAGE_ERROR_IN_DB		3
typedef void callback_funtion(int message);

////////////////////////////////////////////////////////////////////////////////////
// Formats
////////////////////////////////////////////////////////////////////////////////////
#ifdef INCLUDE_DCC2
#define MAX_NUM_FORMATS 4
#else
#define MAX_NUM_FORMATS 3
#endif

#define LM_INDEX        0
#define NTLM_INDEX      1
#define MSCASH_INDEX    2
#define DCC_INDEX		2
#define DCC2_INDEX		3

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

typedef struct Format
{
	char* name;
	char* description;
	int max_plaintext_lenght;
	unsigned int binary_size;
	unsigned int salt_size;
	sqlite3_int64 db_id;
	// Benchmark
	int* bench_values;// Each item is a number of passwords to benchmark
	int lenght_bench_values;

	// Convert hexadecimal password into a compact representation
	// and return a value used for hashing in a hash table
	// params: IN: hexadecimal, OUT: binary_value, OUT: salt_value
	unsigned int (*convert_to_binary)(const unsigned char*, void*, void*);

	// Implementations. Fast implementation first
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
#define DOUBLE_INDEX	3
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
	KeyProviderImplementation impls[4];
	
	// Save current state for latter resume. Must be thread-safe
	void (*save_resume_arg)(char*);
	// Resume keys generation. min_lenght, max_lenght, Params, resume_arg, format_index.
	// If resume_arg==NULL only init
	void (*resume)(int, int, char*, const char*, int);
	void (*finish)();

	// From the param get a short description
	void (*get_param_description)(const char*, char*, int, int);

	int min_size;
	int recommend_max_size;
	int show_to_user;
	int use_rules;
	int per_thread_data_size;
}KeyProvider;

extern KeyProvider key_providers[];
extern int num_key_providers;
KeyProvider* find_key_provider(sqlite3_int64 db_id);
int find_key_provider_index(sqlite3_int64 db_id);

extern unsigned int PHRASES_MAX_WORDS_READ;

////////////////////////////////////////////////////////////////////////////////////
// Rules support
////////////////////////////////////////////////////////////////////////////////////
int add_rules_to_param(char* param, int key_provider_index);
typedef void apply_rule_funtion(unsigned int* nt_buffer, unsigned int max_number, unsigned int* rules_data_buffer);
typedef void ocl_get_key_funtion(unsigned char* out_key, unsigned char* plain, unsigned int param);

typedef void ocl_begin_rule_funtion(char* source, char nt_buffer[16][16], unsigned int lenght, unsigned int NUM_KEYS_OPENCL);
typedef void ocl_write_code(char* source);
#define RULE_LENGHT_COMMON	10

typedef struct oclRule
{
	ocl_begin_rule_funtion* begin;	// Load nt_buffer
	ocl_write_code* end;			// written at end of crypt cycle
	ocl_get_key_funtion* get_key;	// Obtain the final key from the source key applyyin the rule trasnformation
	char* found_param;				// Value to save to later recover the key found
	unsigned int max_param_value;	// If value is 0 no need of additional params
	ocl_write_code* setup_constants;// If the rule need some constants values, this will execute at the begining of kernels
}oclRule;

typedef struct Rule
{
	char* name;
	char* description;
	apply_rule_funtion* function;
	int checked;
	int multipler;					// Number of generate keys from one key
	char depend_key_lenght;			// If the rule depend of the key_lenght
	char key_lenght_sum;			// How much the rule depend of the key_lenght
	// OpenCL support for rules
	oclRule ocl;
}Rule;

extern Rule rules[];
extern int num_rules;

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
	char tag[FILENAME_MAX];

	ImportResult result;

	int isEnded;
	int completition;
}ImportParam;

// Data needed by importers to application
#define IMPORT_PARAM_NONE			0
#define IMPORT_PARAM_FILENAME		1
#define IMPORT_PARAM_MACHINE_NAME	2

typedef struct Importer
{
	int icon_index;
	char* name;
	char* extension;
	char* description;
	void (*function)(ImportParam* param);
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
	void (*function)(const char*);
}
Exporter;

extern Importer importers[];
extern Exporter exporters[];
extern int num_importers;
extern int num_exporters;
extern int continue_import;

void export_db(const char* filename);

// Fix accounts
#define FIXED_NONE		0
#define FIXED_DISABLE	1
#define FIXED_EXPIRE	2

extern int* num_user_by_formats;

// Executed at program init
void init_all(const char* program_exe_path);
// Other common funtions
char* get_full_path(char* filename);
void itoaWithDigitGrouping(int64_t number, char* str);
void filelength2string(int64_t length, char* str);
int64_t get_num_keys_served();
void clear_db_accounts();
int valid_hex_string(unsigned char* ciphertext,int lenght);
char* password_per_sec();
char* get_time_from_begin(int isTotal);
char* finish_time();
char* get_work_done();
int new_crack(int format_index, int key_prov_index, int min_lenght, int max_lenght, char* provider_param, callback_funtion psend_message_gui, int use_rules);
void resume_crack(sqlite3_int64 db_id, callback_funtion psend_message_gui);
int save_attack_state();
int is_wordlist_supported(const char* file_path, char* error_message);

int has_implementations_compatible(int format_index, int provider_index);

int is_found_all_hashes(int format_index);
int total_num_hashes_found();
int has_hashes(int format_index);

extern int* num_hashes_found_by_format;
extern int* num_hashes_by_formats;
////////////////////////////////////////////////////////////////////////////////////
// Batch
////////////////////////////////////////////////////////////////////////////////////
typedef struct AttackData
{
	sqlite3_int64 attack_db_id;
	int format_index;
	int provider_index;
	int min_lenght;
	int max_lenght;
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

extern unsigned int MAX_NUM_PASWORDS_LOADED;
extern int is_benchmark;

// Settings
int get_setting(int id, int default_value);
void save_setting(int id, int value);
void save_settings_to_db();

// Number of passwords currently loaded
extern unsigned int num_passwords_loaded;
// Used to stop the attack
extern int continue_attack;

// Hashing
void hash_ntlm(const char* message, char* hash);
void hash_lm(const char* message, char* hash);

// Hardware Capabilities
#define CPU_CAP_C_CODE			0x0000

#ifdef HS_X86
	#define CPU_CAP_X64				0x0001
	#define CPU_CAP_MMX				0x0002
	#define CPU_CAP_SSE				0x0003
	#define CPU_CAP_SSE2			0x0004
	#define CPU_CAP_AVX				0x0005
	#define CPU_CAP_MULTITHREADING	0x0006
	#define DEV_CAP_OPENCL			0x0007
	#define CPU_CAP_AVX2			0x0008
	
	#define MAX_NUM_CAPS			12
#endif

#ifdef HS_ARM
	#define CPU_CAP_NEON			0x0001
	#define MAX_NUM_CAPS			4
#endif

typedef struct CPUHardware
{
	int family;
	int model;
	char cpu_string[0x20];
	char brand[0x40];
	int img_index;

	unsigned int logical_processors;
	unsigned long cores;
	unsigned long l1_cache_size;// L1 cache in kilobytes
	unsigned long l2_cache_size;// L2 cache in kilobytes
	unsigned long l3_cache_size;// L3 cache in kilobytes
	unsigned long numa_node_count;
	unsigned long processor_package_count;

	int capabilites[MAX_NUM_CAPS];
}
CPUHardware;

typedef struct OtherSystemInfo
{
	char os[64];
	char machine_name[16];
	unsigned long major_version;
	unsigned long minor_version;
	int is_64bits;
}
OtherSystemInfo;

extern unsigned int app_num_threads;
extern unsigned int num_threads;
extern CPUHardware current_cpu;
extern OtherSystemInfo current_system_info;

////////////////////////////////////////////////////////////////////////////////////
// OpenCL
////////////////////////////////////////////////////////////////////////////////////
#ifdef HS_OPENCL_SUPPORT
#define MAX_NUMBER_GPUS_SUPPORTED	32

#define VENDOR_AMD		0
#define VENDOR_NVIDIA	1
#define VENDOR_INTEL	2
#define VENDOR_UNKNOW	128

#define GPU_STATUS_FAILED		0
#define GPU_STATUS_TEMPERATURE	1
#define GPU_STATUS_FAN			2
#define GPU_STATUS_USE			4

typedef struct GPUStatus
{
	char flag;
	unsigned int temperature;
	unsigned int fan_speed;
	int usage;
}GPUStatus;

typedef struct nvmlDevice_st* nvmlDevice_t;

typedef struct GPUDevice
{
	cl_device_id cl_id;
	cl_bool is_used;

	//  Get status info------------------
	cl_bool support_get_status;
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
	cl_uint max_clock_frequency;
	cl_ulong global_memory_size;//in bytes
	cl_ulong local_memory_size;//in bytes
	char* compiler_options;
	cl_ulong max_mem_alloc_size;
	cl_uint vector_int_size;//Preferred native vector width size for built-in scalar types that can be put into vectors
	cl_uint vector_int_size_when_consecutive;// Hack because bug in Nvidia OpenCL compiler (newer versions fix this problem)
	size_t max_work_group_size1;
	size_t lm_work_group_size;
	cl_uint major_cc;
	cl_uint NUM_KEYS_OPENCL_DIVIDER;
	char vendor_string[64];
	char driver_version[32];
	cl_bool native_bitselect;
	cl_bool support_ptx;
	cl_bool has_unified_memory;
	cl_bool LM_UNROll;
	cl_bool LM_USE_SHARED_MEMORY;
	//cl_bool support_amd_bfe;
}
GPUDevice;

extern GPUDevice gpu_devices[MAX_NUMBER_GPUS_SUPPORTED];
extern cl_uint num_gpu_devices;

// Get status
int gpu_get_updated_status(unsigned int gpu_index, GPUStatus* status);

typedef cl_int (CL_API_CALL *clGetPlatformIDsFunc)(cl_uint, cl_platform_id*, cl_uint*);
typedef cl_int (CL_API_CALL *clGetDeviceIDsFunc)(cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*);
typedef cl_int (CL_API_CALL *clGetDeviceInfoFunc)(cl_device_id, cl_device_info, size_t, void*, size_t*);
typedef cl_context (CL_API_CALL *clCreateContextFunc)(const cl_context_properties*, cl_uint, const cl_device_id*, void (CL_CALLBACK*)(const char *, const void *, size_t, void *), void*, cl_int*);
typedef cl_command_queue (CL_API_CALL *clCreateCommandQueueFunc)(cl_context, cl_device_id, cl_command_queue_properties, cl_int*);
typedef cl_program (CL_API_CALL *clCreateProgramWithSourceFunc)(cl_context, cl_uint, const char**, const size_t*, cl_int*);
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

extern clGetDeviceInfoFunc  pclGetDeviceInfo;
extern clSetKernelArgFunc pclSetKernelArg;
extern clEnqueueNDRangeKernelFunc pclEnqueueNDRangeKernel;
extern clFinishFunc pclFinish;
extern clFinishFunc pclFlush;
extern clEnqueueReadBufferFunc pclEnqueueReadBuffer;
extern clEnqueueWriteBufferFunc pclEnqueueWriteBuffer;
extern clReleaseKernelFunc pclReleaseKernel;
extern clCreateKernelFunc pclCreateKernel;
#endif

#ifdef __cplusplus
}
#endif

//#endif
