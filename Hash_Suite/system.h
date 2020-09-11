// This file is part of Hash Suite password cracker,
// Copyright (c) 2014-2015 by Alain Espinosa. See LICENSE.

#include "compilation_flags.h"

#define HS_OCL_CURRENT_KEY_AS_REGISTERS

#ifdef __ANDROID__
	
	#define HS_ARM
	#define HS_USE_COMPRESS_WORDLISTS
	#define HS_OPENCL_SUPPORT
	#define PATH_SEPARATOR '/'
	#define __forceinline inline
	#define HS_ALIGN(x) __attribute__ ((aligned(x)))
	// OpenCL support------------------------------------------
	// TODO: Check this
	#define HS_SET_PRIORITY_GPU_THREAD	//nice(10)
	#define HS_DLL_HANDLE void*
	#define OPENCL_DLL "libOpenCL.so"
	#define GetProcAddress(handle, func_name) dlsym(handle, func_name)
	#define LoadLibrary(x)				dlopen(x, RTLD_NOW)
	#define OCL_NORMAL_KERNEL_TIME		40
	#define HS_OCL_REDUCE_REGISTER_USE
	#define OCL_MIN_WORKGROUP_SIZE		32
	#define OCL_RULES_ALL_IN_GPU

	#define Sleep(ms) usleep((ms)*((useconds_t)1000))
	// Log support------------------------------------------
	#include <android/log.h>

	#define HS_LOG_DEBUG		ANDROID_LOG_DEBUG
	#define HS_LOG_INFO			ANDROID_LOG_INFO
	#define HS_LOG_WARNING		ANDROID_LOG_WARN
	#define HS_LOG_ERROR		ANDROID_LOG_ERROR

#ifdef HS_TESTING
	#define hs_log __android_log_print
#else
	#define hs_log(priority, tag, format_message, ...)
#endif
	// -----------------------------------------------------

	#define __max(a,b)  		(((a) > (b)) ? (a) : (b))
	#define __min(a,b)  		(((a) < (b)) ? (a) : (b))

	#define _aligned_malloc(byte_size,align)	memalign(align,byte_size)
	#define _aligned_free(x)					free(x)
	#define _aligned_realloc(x,size,align)		realloc(x,size)

	#define HS_NEW_THREAD(function, param) {pthread_t hs_pthread_id;pthread_create(&hs_pthread_id, NULL, (void* (*)(void*))function, (void*)(param));}

	#define HS_MUTEX			pthread_mutex_t
	#define HS_CREATE_MUTEX(x)	pthread_mutex_init(x, NULL)
	#define HS_ENTER_MUTEX(x)	pthread_mutex_lock(x)
	#define HS_LEAVE_MUTEX(x)	pthread_mutex_unlock(x)
	#define HS_DELETE_MUTEX(x)  pthread_mutex_destroy(x)

	typedef unsigned char BYTE;

#elif defined(_WIN32)// Windows OS

	#define HS_USE_COMPRESS_WORDLISTS
	#define PATH_SEPARATOR '\\'
	#define HS_ALIGN(x) __declspec(align(x))
	// OpenCL support------------------------------------------
	#define HS_SET_PRIORITY_GPU_THREAD		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL)
	#define HS_DLL_HANDLE HMODULE
	#define OPENCL_DLL "OpenCL.dll"
	#define OCL_NORMAL_KERNEL_TIME 50
	#define OCL_MIN_WORKGROUP_SIZE 64
	#define OCL_RULES_ALL_IN_GPU
	// Log support------------------------------------------
	#define HS_LOG_DEBUG		0
	#define HS_LOG_INFO			1
	#define HS_LOG_WARNING		2
	#define HS_LOG_ERROR		3

#ifdef HS_TESTING

#ifdef __cplusplus
extern "C"
#endif
	 void hs_log(int priority, const char* tag, char* format_message, ...);
#else
	#define hs_log(priority, tag, format_message, ...)
#endif
	// -----------------------------------------------------

#ifdef _M_ARM// Win Phone 8
	#define HS_ARM
	#define HS_NEW_THREAD(function, param) (function)(param)

	#define HS_MUTEX			SRWLOCK
	#define HS_CREATE_MUTEX(x)	InitializeSRWLock(x)
	#define HS_ENTER_MUTEX(x)	AcquireSRWLockExclusive(x)
	#define HS_LEAVE_MUTEX(x)	ReleaseSRWLockExclusive(x)
	#define HS_DELETE_MUTEX(x)
#else// Windows Desktop
	#define HS_X86
	#define HS_OPENCL_SUPPORT
	#define HS_IMPORT_FROM_SYSTEM
	#define HS_NEW_THREAD(function, param) _beginthread(function, 0, param)

	#ifdef _M_X64
		#define HS_MUTEX			SRWLOCK
		#define HS_CREATE_MUTEX(x)	InitializeSRWLock(x)
		#define HS_ENTER_MUTEX(x)	AcquireSRWLockExclusive(x)
		#define HS_LEAVE_MUTEX(x)	ReleaseSRWLockExclusive(x)
		#define HS_DELETE_MUTEX(x)
	#else
		#define HS_MUTEX			CRITICAL_SECTION
		#define HS_CREATE_MUTEX(x)	InitializeCriticalSection(x)
		#define HS_ENTER_MUTEX(x)	EnterCriticalSection(x)
		#define HS_LEAVE_MUTEX(x)	LeaveCriticalSection(x)
		#define HS_DELETE_MUTEX(x)	DeleteCriticalSection(x)
	#endif
#endif

#endif
