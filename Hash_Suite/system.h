// This file is part of Hash Suite password cracker,
// Copyright (c) 2014 by Alain Espinosa
//
// Code licensed under GPL version 2

#ifdef ANDROID

	#define HS_ARM
	#define PATH_SEPARATOR '/'
	#define __forceinline inline
	#define HS_ALIGN(x) __attribute__ ((aligned(x)))

	#define __max(a,b)  		(((a) > (b)) ? (a) : (b))
	#define __min(a,b)  		(((a) < (b)) ? (a) : (b))
	#define strtok_s(a,b,c) 	strtok_r(a,b,c)

	#define _aligned_malloc(byte_size,align)	memalign(align,byte_size)
	#define _aligned_free(x)					free(x)
	#define _aligned_realloc(x,size,align)		realloc(x,size)

	#define _beginthread(perform_crypt, UNUSED, param) {pthread_t hs_pthread_id;pthread_create(&hs_pthread_id, NULL, perform_crypt, param);}

	#define HS_MUTEX			pthread_mutex_t
	#define HS_CREATE_MUTEX(x)	pthread_mutex_init(x, NULL)
	#define HS_ENTER_MUTEX(x)	pthread_mutex_lock(x)
	#define HS_LEAVE_MUTEX(x)	pthread_mutex_unlock(x)
	#define HS_DELETE_MUTEX(x)  pthread_mutex_destroy(x)

#else

	#define HS_ALIGN(x) __declspec(align(x))
	#define HS_USE_COMPRESS_WORDLISTS
	#define PATH_SEPARATOR '\\'

#ifdef _M_ARM
	#define HS_ARM

	#define _beginthread(perform_crypt, UNUSED, param) (perform_crypt)(param)

	#define HS_MUTEX			SRWLOCK
	#define HS_CREATE_MUTEX(x)	InitializeSRWLock(x)
	#define HS_ENTER_MUTEX(x)	AcquireSRWLockExclusive(x)
	#define HS_LEAVE_MUTEX(x)	ReleaseSRWLockExclusive(x)
	#define HS_DELETE_MUTEX(x)
#else
	#define HS_X86
	#define HS_OPENCL_SUPPORT
	#define HS_IMPORT_FROM_SYSTEM
	
	#define HS_MUTEX			CRITICAL_SECTION
	#define HS_CREATE_MUTEX(x)	InitializeCriticalSection(x)
	#define HS_ENTER_MUTEX(x)	EnterCriticalSection(x)
	#define HS_LEAVE_MUTEX(x)	LeaveCriticalSection(x)
	#define HS_DELETE_MUTEX(x)	DeleteCriticalSection(x)
#endif

#endif
