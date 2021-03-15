// This file is part of Hash Suite password cracker,
// Copyright (c) 2021 by Alain Espinosa

#include "common.h"

extern "C" clBuildProgramFunc pclBuildProgram;

#ifdef _WIN32

#include <Windows.h>
PRIVATE cl_program program;
PRIVATE cl_device_id gpu_id;
PRIVATE char* compiler_options;

PRIVATE DWORD WINAPI lpBuild(LPVOID lpParam)
{
	__try
	{
		return (DWORD)pclBuildProgram(program, 1, &gpu_id, compiler_options, NULL, NULL);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	return (DWORD)CL_BUILD_PROGRAM_FAILURE;
}
PUBLIC extern "C" cl_int myclBuildProgram(cl_program p_program, cl_device_id p_gpu_id, char* p_compiler_options)
{
	DWORD code = CL_BUILD_PROGRAM_FAILURE;
	program = p_program;
	gpu_id = p_gpu_id;
	compiler_options = p_compiler_options;

	auto hThread = CreateThread(NULL, 0, lpBuild, NULL, 0, NULL);
	if (hThread)
	{
		// Wait 5 minutes for compilation
		if (WAIT_TIMEOUT == WaitForSingleObject(hThread, 5 * 60 * 1000))
			TerminateThread(hThread, CL_BUILD_PROGRAM_FAILURE);

		GetExitCodeThread(hThread, &code);
	}

	return code;
}
#else
// TODO: Do something similar to Windows?
PUBLIC extern "C" cl_int myclBuildProgram(cl_program program, cl_device_id gpu_id, char* compiler_options)
{
	return pclBuildProgram(program, 1, &gpu_id, compiler_options, NULL, NULL);
}
#endif


