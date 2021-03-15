// This file is part of Hash Suite password cracker,
// Copyright (c) 2015-2016 by Alain Espinosa

#include "Interface.h"

PRIVATE bool performing_bench;// To stop the benchmark
PRIVATE int m_benchmark_time = 5;// Time used in each attack.
PRIVATE int quick_benchmark = TRUE;

PRIVATE bool have_same_bench_values(int format_index1, int format_index2)
{
	if (format_index1 < 0)
		return true;

	if (formats[format_index1].lenght_bench_values != formats[format_index2].lenght_bench_values)
		return false;

	for (int i = 0; i < formats[format_index1].lenght_bench_values; i++)
		if (formats[format_index1].bench_values[i] != formats[format_index2].bench_values[i])
			return false;

	return true;
}

#ifdef _WIN32
	#include <Windows.h>
	#define execute_bench(bench_format_index, show_index, bench_value_index) execute_bench_func(bench_format_index, show_index, bench_value_index)
#else
	#include <jni.h>
	#define Sleep(time) env->CallStaticVoidMethod(thread_cls, thread_sleep, time)
	#define execute_bench(bench_format_index, show_index, bench_value_index) execute_bench_func(bench_format_index, show_index, bench_value_index, env, my_class, thread_cls, thread_sleep, SetBenchData_id)
#endif

PRIVATE void execute_bench_func(int bench_format_index, int show_index, int bench_value_index
#ifndef _WIN32
,JNIEnv* env, jclass my_class, jclass thread_cls, jmethodID thread_sleep, jmethodID SetBenchData_id
#endif
)
{
	// Params to benchmark
	char bench_buffer[16];
	char* all_chars = (char*)"qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM 0123456789!@#$%^&*()-_+=~`[]{}|:;\"'<>,.?/\\";
	const int key_lenght = 7;

	MAX_NUM_PASWORDS_LOADED = formats[bench_format_index].bench_values[bench_value_index];
	// Benchmark
	benchmark_init_complete = FALSE;
	benchmark_gpu_fails = FALSE;
	new_crack(bench_format_index, CHARSET_INDEX, key_lenght, key_lenght, all_chars, &receive_message, FALSE);
	// Wait to complete initialization
	while (!benchmark_init_complete) Sleep(200ll);
	// Wait a time to obtain the benchmark
	for (int j = 0; j < m_benchmark_time && performing_bench; j++)
		Sleep(1000ll);
	// Show data to user
#ifdef _WIN32
	if (bench_wnd_to_post)
		bench_wnd_to_post->OnSetBenchData(show_index, 2 + bench_value_index, benchmark_gpu_fails ? "Failed" : password_per_sec(bench_buffer));
#else
	env->CallStaticVoidMethod(my_class, SetBenchData_id, env->NewStringUTF(benchmark_gpu_fails ? "Failed" : password_per_sec(bench_buffer)), show_index, m_benchmark_time);
#endif

	// Stop attack
	continue_attack = FALSE;
	stop_universe = TRUE;
	while (num_threads > 0) Sleep(200ll);
	Sleep(200ll);// wait a little for attack to stop
}

//#define BENCH_ONLY_CPU
//#define BENCH_ONLY_GPU
//#define BENCH_ONLY_ALL_GPU
//#define BENCH_SLEEP_TIME	5000ll
#ifdef USE_MAJ_SELECTOR
PUBLIC extern "C" int MAJ_SELECTOR = -1;
#endif

#ifdef BENCH_ONLY_ALL_GPU
#ifndef BENCH_ONLY_GPU
#define BENCH_ONLY_GPU
#endif
#endif

#ifdef _WIN32
PRIVATE uint32_t bench_thread(void* pParam)
#else
PRIVATE uint32_t bench_thread(JNIEnv* env, jclass my_class, jclass thread_cls, jmethodID thread_sleep, jmethodID SetBenchData_id, jmethodID complete_benchmark_id)
#endif
{
	// Calculate the max number of values
	int max_lenght_bench_values = 0;
	for (int i = 0; i < num_formats; i++)
		if (max_lenght_bench_values < formats[i].lenght_bench_values)
			max_lenght_bench_values = formats[i].lenght_bench_values;

	// Benchmark for all data
#ifdef USE_MAJ_SELECTOR
	max_lenght_bench_values = 4;
	MAJ_SELECTOR++;
#endif
	for (int i = 0; i < max_lenght_bench_values && performing_bench; i++)
		for (int bench_format_index = 0, show_index = bench_format_index * (num_gpu_devices + 1); bench_format_index < num_formats && performing_bench; bench_format_index++)
		{
			if (i >= formats[bench_format_index].lenght_bench_values)
				break;// TODO: Only works if it is the last
			if (!have_same_bench_values(bench_format_index - 1, bench_format_index))
				show_index++;

#ifdef BENCH_SLEEP_TIME
			Sleep(BENCH_SLEEP_TIME);
#endif
			// Benchmark CPU cores
			for (uint32_t j = 0; j < num_gpu_devices; j++)
				GPU_SET_FLAG_DISABLE(gpu_devices[j].flags, GPU_FLAG_IS_USED);
			for (app_num_threads = quick_benchmark ? current_cpu.logical_processors : 1; app_num_threads <= current_cpu.logical_processors && performing_bench; app_num_threads *= 2, show_index++)
#ifndef BENCH_ONLY_GPU
				execute_bench(bench_format_index, show_index, i)
#endif
				;

			// Benchmark each GPU
			app_num_threads = 0;
			for (uint32_t gpu_index = 0; gpu_index < num_gpu_devices && performing_bench; gpu_index++, show_index++)
			{
				gpu_devices[gpu_index].flags |= GPU_FLAG_IS_USED;
				if (gpu_index) GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index - 1].flags, GPU_FLAG_IS_USED);
#if !defined(BENCH_ONLY_ALL_GPU) && !defined(BENCH_ONLY_CPU)
				execute_bench(bench_format_index, show_index, i);
#endif
			}

			// Benchmark concurrent hardware
			if (performing_bench && !quick_benchmark)
			{
				for (uint32_t j = 0; j < num_gpu_devices; j++)
					gpu_devices[j].flags |= GPU_FLAG_IS_USED;
				if (num_gpu_devices > 1)// All GPUs
				{
					execute_bench(bench_format_index, show_index, i);
					show_index++;
				}

				if (performing_bench && num_gpu_devices > 0)// CPU+GPUs
				{
					app_num_threads = current_cpu.logical_processors;
#ifndef BENCH_ONLY_GPU
					execute_bench(bench_format_index, show_index, i);
#endif
					show_index++;
				}
			}
		}

#ifdef _WIN32
	if (bench_wnd_to_post)
		bench_wnd_to_post->OnCompleteBench();
#else
	if (performing_bench)
		env->CallStaticVoidMethod(my_class, complete_benchmark_id);
#endif

	return 0;
}
