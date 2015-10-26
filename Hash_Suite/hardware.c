// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2014 by Alain Espinosa. See LICENSE.

#include "common.h"
#ifdef _WIN32
	#include <windows.h>
#endif

PUBLIC CPUHardware current_cpu;
PUBLIC OtherSystemInfo current_system_info;

#ifdef HS_X86
// These are the names of various processors
#define PROC_AMD_AM486          "AMD Am486 CPU"
#define PROC_AMD_K5             "AMD K5 CPU"
#define PROC_AMD_K6             "AMD K6 CPU"
#define PROC_AMD_K6_2           "AMD K6-2 CPU"
#define PROC_AMD_K6_3           "AMD K6-3 CPU"
#define PROC_AMD_ATHLON         "AMD Athlon CPU"
#define PROC_INTEL_486DX        "Intel(R) 486DX CPU"
#define PROC_INTEL_486SX        "Intel(R) 486SX CPU"
#define PROC_INTEL_486DX2       "Intel(R) 486DX2 CPU"
#define PROC_INTEL_486SL        "Intel(R) 486SL CPU"
#define PROC_INTEL_486SX2       "Intel(R) 486SX2 CPU"
#define PROC_INTEL_486DX2E      "Intel(R) 486DX2E CPU"
#define PROC_INTEL_486DX4       "Intel(R) 486DX4 CPU"
#define PROC_INTEL_PENTIUM      "Intel(R) Pentium(R) CPU"
#define PROC_INTEL_PENTIUM_MMX  "Intel(R) Pentium(R) MMX CPU"
#define PROC_INTEL_PENTIUM_PRO  "Intel(R) Pentium(R) Pro CPU"
#define PROC_INTEL_PENTIUM_II   "Intel(R) Pentium(R) II CPU"
#define PROC_INTEL_CELERON      "Intel(R) Celeron(R) CPU"
#define PROC_INTEL_PENTIUM_III  "Intel(R) Pentium(R) III CPU"
#define PROC_INTEL_PENTIUM_4    "Intel(R) Pentium(R) 4 CPU"
#define PROC_CYRIX              "Cyrix CPU"
#define PROC_CENTAUR            "Centaur CPU"
#define PROC_UNKNOWN            "Unknown CPU"

PRIVATE void cpuID(unsigned int i, unsigned int regs[4])
{
	#ifdef _WIN32
	  __cpuid((int*)regs, (int)i);
	#else
	  asm volatile
		("cpuid" : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
		 : "a" (i), "c" (0));
	  // ECX is set to zero for CPUID function 4
	#endif
}

/***
* Checks if OS Supports the capability or not
*
* Entry:
*   feature: the feature we want to check if OS supports it.
* Exit:
*   Returns 1 if OS support exist and 0 when OS doesn't support it.
****************************************************************/
#ifdef _M_X64
PRIVATE int os_support(int feature)
{
	switch (feature)
	{
	case CPU_CAP_SSE2:
		return TRUE;
	case CPU_CAP_AVX:
		{
			int64_t val = _xgetbv(0);       // read XFEATURE_ENABLED_MASK register 
			return (val & 6) == 6;          // check OS has enabled both XMM and YMM support. 
		}
	}

	return 0;
}
#else
PRIVATE int os_support(int feature)
{
	   __try
	   {
	       switch (feature)
		   {
	       case CPU_CAP_SSE2:
	           __asm
			   {
	               xorpd xmm0, xmm0        // executing SSE2 instruction
	           }
	           break;
		   case CPU_CAP_AVX:
			   return FALSE;
		   default:
			   return FALSE;
	       }
	   }
	#pragma warning (suppress: 6320)
	   __except (EXCEPTION_EXECUTE_HANDLER)
	   {
	       return FALSE;
	   }

	   return TRUE;
}
#endif
#endif

#ifdef HS_X86
typedef BOOL (WINAPI *PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);
typedef VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);
PRIVATE void get_os_display_string()
{
	OSVERSIONINFOEX osvi;
	SYSTEM_INFO si;
	PGPI pGPI;
	BOOL bOsVersionInfoEx;
	DWORD dwType;

	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	if( !(bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO *) &osvi)) )
		return;

	GetNativeSystemInfo(&si);// Need XP
	strcpy(current_system_info.os, "");

	current_system_info.major_version = osvi.dwMajorVersion;
	current_system_info.minor_version = osvi.dwMinorVersion;

	// Test for the specific product.
	if( osvi.dwMajorVersion == 6 )
	{
		// Hack given than Windows 8.1 reports as Windows 8
		if (osvi.dwMinorVersion >= 2)
		{
			RtlGetNtVersionNumbers* pRtlGetNtVersionNumbers = (RtlGetNtVersionNumbers*)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlGetNtVersionNumbers");
			if (pRtlGetNtVersionNumbers)
				pRtlGetNtVersionNumbers(&osvi.dwMajorVersion, &osvi.dwMinorVersion, &osvi.dwBuildNumber);
			osvi.dwBuildNumber &= 0x00003fff;
		}

		if( osvi.dwMinorVersion == 0 )
			strcat(current_system_info.os, osvi.wProductType == VER_NT_WORKSTATION ? "Windows Vista " : "Windows Server 2008 ");

		if( osvi.dwMinorVersion == 1 )
			strcat(current_system_info.os, osvi.wProductType == VER_NT_WORKSTATION ? "Windows 7 " : "Windows Server 2008 R2 ");
			
		if( osvi.dwMinorVersion == 2 )
			strcat(current_system_info.os, osvi.wProductType == VER_NT_WORKSTATION ? "Windows 8 " : "Windows Server 2012 ");
			
		if( osvi.dwMinorVersion == 3 )
			strcat(current_system_info.os, osvi.wProductType == VER_NT_WORKSTATION ? "Windows 8.1 " : "Windows Server 2012 R2 ");

		pGPI = (PGPI) GetProcAddress( GetModuleHandle(TEXT("kernel32.dll")), "GetProductInfo");
		pGPI( osvi.dwMajorVersion, osvi.dwMinorVersion, 0, 0, &dwType);

		switch( dwType )
		{
		case PRODUCT_ULTIMATE:
			strcat(current_system_info.os, "Ultimate" );
			break;
		case PRODUCT_PROFESSIONAL:
			strcat(current_system_info.os, "Professional" );
			break;
		case PRODUCT_HOME_PREMIUM:
			strcat(current_system_info.os, "Home Premium" );
			break;
		case PRODUCT_HOME_BASIC:
			strcat(current_system_info.os, "Home Basic" );
			break;
		case PRODUCT_ENTERPRISE:
			strcat(current_system_info.os, "Enterprise" );
			break;
		case PRODUCT_BUSINESS:
			strcat(current_system_info.os, "Business" );
			break;
		case PRODUCT_STARTER:
			strcat(current_system_info.os, "Starter" );
			break;
		case PRODUCT_CLUSTER_SERVER:
			strcat(current_system_info.os, "Cluster Server" );
			break;
		case PRODUCT_DATACENTER_SERVER:
			strcat(current_system_info.os, "Datacenter" );
			break;
		case PRODUCT_DATACENTER_SERVER_CORE:
			strcat(current_system_info.os, "Datacenter (core installation)" );
			break;
		case PRODUCT_ENTERPRISE_SERVER:
			strcat(current_system_info.os, "Enterprise" );
			break;
		case PRODUCT_ENTERPRISE_SERVER_CORE:
			strcat(current_system_info.os, "Enterprise (core installation)" );
			break;
		case PRODUCT_ENTERPRISE_SERVER_IA64:
			strcat(current_system_info.os, "Enterprise for Itanium-based Systems" );
			break;
		case PRODUCT_SMALLBUSINESS_SERVER:
			strcat(current_system_info.os, "Small Business Server" );
			break;
		case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
			strcat(current_system_info.os, "Small Business Server Premium" );
			break;
		case PRODUCT_STANDARD_SERVER:
			strcat(current_system_info.os, "Standard" );
			break;
		case PRODUCT_STANDARD_SERVER_CORE:
			strcat(current_system_info.os, "Standard (core installation)" );
			break;
		case PRODUCT_WEB_SERVER:
			strcat(current_system_info.os, "Web Server" );
			break;
		}
	}

	if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2 )
	{
		if( GetSystemMetrics(SM_SERVERR2) )
			strcat(current_system_info.os, "Windows Server 2003 R2, ");
		else if( osvi.wSuiteMask & VER_SUITE_STORAGE_SERVER )
			strcat(current_system_info.os, "Windows Storage Server 2003");
		else if( osvi.wSuiteMask & VER_SUITE_WH_SERVER )
			strcat(current_system_info.os, "Windows Home Server");
		else if( osvi.wProductType == VER_NT_WORKSTATION && si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
			strcat(current_system_info.os, "Windows XP Professional x64");
		else
			strcat(current_system_info.os,"Windows Server 2003, ");

		// Test for the server type.
		if( osvi.wProductType != VER_NT_WORKSTATION )
		{
			if( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_IA64 )
			{
				if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					strcat(current_system_info.os, "Datacenter for Itanium-based Systems" );
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					strcat(current_system_info.os, "Enterprise for Itanium-based Systems" );
			}
			else if( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
			{
				if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					strcat(current_system_info.os, "Datacenter x64" );
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					strcat(current_system_info.os, "Enterprise x64" );
				else
					strcat(current_system_info.os, "Standard x64" );
			}
			else
			{
				if ( osvi.wSuiteMask & VER_SUITE_COMPUTE_SERVER )
					strcat(current_system_info.os, "Compute Cluster" );
				else if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					strcat(current_system_info.os, "Datacenter" );
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					strcat(current_system_info.os, "Enterprise" );
				else if ( osvi.wSuiteMask & VER_SUITE_BLADE )
					strcat(current_system_info.os, "Web" );
				else
					strcat(current_system_info.os, "Standard" );
			}
		}
	}

	if( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 )
	{
		strcat(current_system_info.os, "Windows XP ");
		strcat(current_system_info.os, osvi.wSuiteMask & VER_SUITE_PERSONAL ? "Home" : "Professional");
	}

	// Include service pack (if any)
	if( osvi.wServicePackMajor > 0 )
	{
		char _sp[4];
		strcat(current_system_info.os, " SP" );
		_itoa(osvi.wServicePackMajor, _sp, 10);
		strcat(current_system_info.os, _sp);
	}
	// Architecture
	if ( osvi.dwMajorVersion >= 6 )
	{
		if( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
			strcat(current_system_info.os, " 64-bit" );
		else if(si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL )
			strcat(current_system_info.os," 32-bit");
	}
}

typedef BOOL (WINAPI *LPFN_GLPI)( PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD);
// Helper function to count set bits in the processor mask.
PRIVATE DWORD count_set_bits(ULONG_PTR bitMask)
{
    DWORD LSHIFT = sizeof(ULONG_PTR)*8 - 1;
    DWORD bitSetCount = 0;
    ULONG_PTR bitTest = (ULONG_PTR)1 << LSHIFT;    
    DWORD i;
    
    for (i = 0; i <= LSHIFT; ++i)
    {
        bitSetCount += ((bitMask & bitTest) ? 1 : 0);
        bitTest/=2;
    }

    return bitSetCount;
}
PRIVATE void detect_logical_processor_info()
{
	SYSTEM_INFO siSysInfo;
	LPFN_GLPI glpi;
	BOOL done = FALSE;
	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL;
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION ptr = NULL;
    DWORD returnLength = 0;
    DWORD byteOffset = 0;

    glpi = (LPFN_GLPI) GetProcAddress( GetModuleHandle(TEXT("kernel32")), "GetLogicalProcessorInformation");
    if (NULL == glpi) 
    {
        // GetLogicalProcessorInformation is not supported, Use 'GetSystemInfo'
		GetSystemInfo(&siSysInfo); 
		current_cpu.cores = siSysInfo.dwNumberOfProcessors;
		current_cpu.logical_processors = current_cpu.cores;
        return;
    }

     while (!done)
        if (FALSE == glpi(buffer, &returnLength)) 
        {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) 
            {
                if (buffer) 
                    free(buffer);

                buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)malloc(returnLength);
            } 
            else 
            {
                //Error --> GetLastError();
                return;
            }
        } 
        else
        {
            done = TRUE;
        }

    ptr = buffer;

    while (byteOffset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) <= returnLength) 
    {
        switch (ptr->Relationship) 
        {
        case RelationNumaNode:
            // Non-NUMA systems report a single record of this type.
            //current_cpu.numa_node_count++;
            break;

        case RelationProcessorCore:
            current_cpu.cores++;
            // A hyper-threaded core supplies more than one logical processor.
            current_cpu.logical_processors += count_set_bits(ptr->ProcessorMask);
            break;

        case RelationCache:
            break;

        case RelationProcessorPackage:
            // Logical processors share a physical package.
            //current_cpu.processor_package_count++;
            break;

        default:
            //Error: Unsupported LOGICAL_PROCESSOR_RELATIONSHIP value;
            break;
        }
        byteOffset += sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
        ptr++;
    }
    
    free(buffer);
}
#endif

#ifdef ANDROID
#include <cpu-features.h>
PUBLIC void detect_hardware()
{
	// Initialize
	memset(&current_cpu, 0, sizeof(CPUHardware));
	current_cpu.capabilites[CPU_CAP_C_CODE] = TRUE;

	uint64_t features = android_getCpuFeatures();
	if (android_getCpuFamily() == ANDROID_CPU_FAMILY_ARM && (features & ANDROID_CPU_ARM_FEATURE_ARMv7) && (features & ANDROID_CPU_ARM_FEATURE_NEON))
		current_cpu.capabilites[CPU_CAP_NEON] = TRUE;

	current_cpu.cores = current_cpu.logical_processors = android_getCpuCount();
}
#else

#ifdef HS_WIN_PHONE
PUBLIC void detect_hardware()
{
	SYSTEM_INFO si;
	int CPUInfo[4] = {-1};
	int nIds = LENGHT(current_system_info.machine_name);

	// Initialize
	memset(&current_cpu, 0, sizeof(CPUHardware));
	current_cpu.capabilites[CPU_CAP_C_CODE] = TRUE;
	current_cpu.capabilites[CPU_CAP_NEON] = TRUE;

	//// OS string
	GetNativeSystemInfo(&si);// Need XP
	current_cpu.cores = current_cpu.logical_processors = si.dwNumberOfProcessors;
}
#else
PUBLIC void detect_hardware()
{
	int CPUInfo[4] = {-1};
	int nIds = LENGHT(current_system_info.machine_name);

	// Initialize
	memset(&current_cpu, 0, sizeof(CPUHardware));
	current_cpu.capabilites[CPU_CAP_C_CODE] = TRUE;

	// OS string
	get_os_display_string();
	GetComputerName(current_system_info.machine_name, &nIds);
	
	detect_logical_processor_info();

	// Normal
	cpuID(0, CPUInfo);
	nIds = CPUInfo[0];
	//*((int*)current_cpu.cpu_string)		= CPUInfo[1];
	//*((int*)(current_cpu.cpu_string+4)) = CPUInfo[3];
	//*((int*)(current_cpu.cpu_string+8)) = CPUInfo[2];

	// General capabilities
	if(nIds >= 1)
	{
		cpuID(1, CPUInfo);

		//current_cpu.capabilites[CPU_CAP_HTT]	=  (CPUInfo[3] >> 28) & 1;
		//current_cpu.capabilites[CPU_CAP_MMX]			= ((CPUInfo[3] >> 23) & 1) && os_support(CPU_CAP_MMX);
		//current_cpu.capabilites[CPU_CAP_SSE]			= ((CPUInfo[3] >> 25) & 1) && os_support(CPU_CAP_SSE);
		current_cpu.capabilites[CPU_CAP_SSE2]			= ((CPUInfo[3] >> 26) & 1) && os_support(CPU_CAP_SSE2);
		current_cpu.capabilites[CPU_CAP_AVX]			= ((CPUInfo[2] >> 28) & 1) && os_support(CPU_CAP_AVX);

		//current_cpu.model  = (CPUInfo[0] >> 4) & 0xF;
		//current_cpu.family = (CPUInfo[0] >> 8) & 0xF;
	}
	// At least one processor exist: needed for wine support
	if (current_cpu.logical_processors <= 0 || current_cpu.cores <= 0)
	{
		SYSTEM_INFO si;
		GetNativeSystemInfo(&si);// Need XP
		current_cpu.logical_processors = current_cpu.cores = si.dwNumberOfProcessors;
	}

	current_cpu.capabilites[CPU_CAP_HTT] = current_cpu.cores < current_cpu.logical_processors;
	// Modern Cache information
	if(nIds >= 4)
	{
		int i;
		int cache_level, ways, partitions, line_size, sets, cache_size;

		for (i = 0; ; i++)
		{
			__cpuidex(CPUInfo, 4, i);
			if(!(CPUInfo[0] & 0xF0)) break;

			cache_level = (CPUInfo[0] & 0xe0) >> 5;
			
			// Calculate cache size
			ways = (CPUInfo[1]) >> 22;
			partitions = (CPUInfo[1] & 0x03ff000) >> 12;
			line_size = (CPUInfo[1] & 0x0fff);
			sets = CPUInfo[2];
			cache_size = (ways + 1) * (partitions + 1) * (line_size + 1) * (sets + 1) / 1024;
			
			switch(cache_level)
			{
			case 1:
				current_cpu.l1_cache_size += cache_size;
				break;
			case 2:
				current_cpu.l2_cache_size += cache_size;
				break;
			case 3:
				current_cpu.l3_cache_size += cache_size;
				break;
			}
		}
	}
	else if(nIds >= 2)// Old Cache information: Pentium M, some Pentium 4 and older CPUs
	{
		int i, j;
		cpuID(2, CPUInfo);

		for(i = 0; i < 4; i++)
			// The most significant bit (bit 31) of each register indicates whether the register contains 
			// valid information (set to 0) or is reserved (set to 1)
			if( !(CPUInfo[i] & 0x80000000) )
				for(j = (i ? 0 : 1); j < 4; j++)
				{
					// If a register contains valid information, the information is contained in 1 byte descriptors.
					// The order of descriptors in the EAX, EBX, ECX, and EDX registers is not defined; that is, 
					// specific bytes are not designated to contain descriptors for specific cache or TLB types.
					// The descriptors may appear in any order.
					unsigned char descriptor = (CPUInfo[i] >> (j*8)) & 0xFF;

					switch(descriptor)
					{
						// L1
					case 0x06: case 0x0A: case 0x66:
						current_cpu.l1_cache_size += 8;
						break;
					case 0x08: case 0x0C: case 0x0D: case 0x60: case 0x67:
						current_cpu.l1_cache_size += 16;
						break;
					case 0x0E:
						current_cpu.l1_cache_size += 24;
						break;
					case 0x09: case 0x2C: case 0x30: case 0x68:
						current_cpu.l1_cache_size += 32;
						break;

						// L2
					case 0x41: case 0x79:
						current_cpu.l2_cache_size += 128;
						break;
					case 0x21: case 0x42: case 0x7A: case 0x82:
						current_cpu.l2_cache_size += 256;
						break;
					case 0x43: case 0x7B: case 0x7F: case 0x80: case 0x83: case 0x86:
						current_cpu.l2_cache_size += 512;
						break;
					case 0x44: case 0x78: case 0x7C: case 0x84: case 0x87:
						current_cpu.l2_cache_size += 1024;
						break;
					case 0x45: case 0x7D: case 0x85:
						current_cpu.l2_cache_size += 2*1024;
						break;
					case 0x48:
						current_cpu.l2_cache_size += 3*1024;
						break;
					case 0x49:
						current_cpu.l2_cache_size += 4*1024;
						break;
					case 0x4E:
						current_cpu.l2_cache_size += 6*1024;
						break;

						// L3
					case 0x22: case 0xD0:
						current_cpu.l3_cache_size += 512;
						break;
					case 0x23: case 0xD1: case 0xD6:
						current_cpu.l3_cache_size += 1024;
						break;
					case 0xDC:
						current_cpu.l3_cache_size += 1024+512;
						break;
					case 0x25: case 0xD2: case 0xD7: case 0xE2:
						current_cpu.l3_cache_size += 2*1024;
						break;
					case 0xDD:
						current_cpu.l3_cache_size += 3*1024;
						break;
					case 0x29: case 0x46: case 0xD8: case 0xE3:
						current_cpu.l3_cache_size += 4*1024;
						break;
					case 0x4A: case 0xDE:
						current_cpu.l3_cache_size += 6*1024;
						break;
					case 0x47: case 0x4B: case 0xE4:
						current_cpu.l3_cache_size += 8*1024;
						break;
					case 0x4C: case 0xEA:
						current_cpu.l3_cache_size += 12*1024;
						break;
					case 0x4D:
						current_cpu.l3_cache_size += 16*1024;
						break;
					case 0xEB:
						current_cpu.l3_cache_size += 18*1024;
						break;
					case 0xEC:
						current_cpu.l3_cache_size += 24*1024;
						break;
					}
				}
	}
	if(nIds >= 7)
	{
		__cpuidex(CPUInfo, 7, 0);
		current_cpu.capabilites[CPU_CAP_AVX2] = ((CPUInfo[1] >> 5) & 1) && current_cpu.capabilites[CPU_CAP_AVX];
		current_cpu.capabilites[CPU_CAP_BMI ] =  (CPUInfo[1] >> 8) & 1;
	}

	// Extended
	cpuID(0x80000000, CPUInfo);
	nIds = CPUInfo[0];

	if(nIds >= 0x80000001)
	{
		cpuID(0x80000001, CPUInfo);
		current_cpu.capabilites[CPU_CAP_X64] = (CPUInfo[3] >> 29) & 1;
	}

	// Brand string
	if(nIds >= 0x80000004)
	{
		int i, k;

		cpuID(0x80000002, CPUInfo);
		memcpy(current_cpu.brand, CPUInfo, sizeof(CPUInfo));

		cpuID(0x80000003, CPUInfo);
		memcpy(current_cpu.brand + 16, CPUInfo, sizeof(CPUInfo));

		cpuID(0x80000004, CPUInfo);
		memcpy(current_cpu.brand + 32, CPUInfo, sizeof(CPUInfo));

		// Eliminate firsts spaces
		for(i = 0; current_cpu.brand[i] == ' '; i++);
		if(i) memmove(current_cpu.brand, current_cpu.brand+i, strlen(current_cpu.brand)-i+1);

		// Eliminate extra spaces
		for(i = 0; current_cpu.brand[i]; i++)
			if(current_cpu.brand[i] == ' ')
			{
				int j = i + 1;

				for(; current_cpu.brand[j] && current_cpu.brand[j] == ' ' ; j++);

				for(k = j; ; k++)
				{
					current_cpu.brand[k - j + i + 1] = current_cpu.brand[k];

					if(!current_cpu.brand[k])
						break;
				}
			}
	}

	if(strstr(current_cpu.brand, "Intel(R) Celeron(R)"))//checked
		current_cpu.img_index = 1;
	else if(strstr(current_cpu.brand, "Intel(R) Pentium(R) III"))//checked
		current_cpu.img_index = 2;
	else if(strstr(current_cpu.brand, "Intel(R) Core(TM) Duo"))
		current_cpu.img_index = 3;
	else if(strstr(current_cpu.brand, "Atom"))
		current_cpu.img_index = 4;
	else if(strstr(current_cpu.brand, "Intel(R) Pentium(R) 4"))
		current_cpu.img_index = 5;
	else if(strstr(current_cpu.brand, "Intel(R) Pentium(R)"))
		current_cpu.img_index = 6;
	else if(strstr(current_cpu.brand, "Athlon X2"))
		current_cpu.img_index = 7;
	else if(strstr(current_cpu.brand, "Turion Ultra"))
		current_cpu.img_index = 8;
	else if(strstr(current_cpu.brand, "Intel(R) Core(TM) i3"))//checked
		current_cpu.img_index = 9;
	else if(strstr(current_cpu.brand, "Intel(R) Core(TM) i5"))//checked
		current_cpu.img_index = 10;
	else if(strstr(current_cpu.brand, "Intel(R) Core(TM) i7"))
		current_cpu.img_index = 11;
	else if(strstr(current_cpu.brand, "Intel(R) Core(TM)2 Quad"))
		current_cpu.img_index = 12;
	else if(strstr(current_cpu.brand, "Intel(R) Core(TM)2 Solo"))
		current_cpu.img_index = 13;
	else if(strstr(current_cpu.brand, "Intel(R) Core(TM)2 Duo"))//checked
		current_cpu.img_index = 14;
	else if(strstr(current_cpu.brand, "Intel(R) Core(TM)2 Extreme"))
		current_cpu.img_index = 15;
	// TODO: Add more and with better images

	// Eliminate redundant words
	remove_str(current_cpu.brand, "processor");
	remove_str(current_cpu.brand, "Processor");
	remove_str(current_cpu.brand, "CPU ");
	remove_str(current_cpu.brand, "@ ");
	remove_str(current_cpu.brand, "(R)");
	remove_str(current_cpu.brand, "(TM)");
	remove_str(current_cpu.brand, "(tm)");
}
#endif
#endif

