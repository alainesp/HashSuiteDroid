// This file is part of Hash Suite password cracker,
// Copyright (c) 2011-2016 by Alain Espinosa

#include <ctype.h>
#include "common.h"
#ifdef _WIN32
	#include <windows.h>
	#include "OpenCL\cuda_drvapi_dynlink_cuda.h"
#else
	#include <dlfcn.h>
#endif

#ifdef HS_OPENCL_SUPPORT

PRIVATE HS_DLL_HANDLE hOpenCL = NULL;

PRIVATE clGetPlatformIDsFunc			pclGetPlatformIDs			= NULL;
PRIVATE clGetDeviceIDsFunc				pclGetDeviceIDs				= NULL;
PUBLIC clGetDeviceInfoFunc				pclGetDeviceInfo			= NULL;
PRIVATE clCreateContextFunc				pclCreateContext			= NULL;
PRIVATE clCreateCommandQueueFunc		pclCreateCommandQueue		= NULL;
PRIVATE clCreateProgramWithSourceFunc	pclCreateProgramWithSource	= NULL;
PRIVATE clBuildProgramFunc				pclBuildProgram				= NULL;
PUBLIC clCreateKernelFunc				pclCreateKernel				= NULL;
PRIVATE clCreateBufferFunc				pclCreateBuffer				= NULL;
PUBLIC clSetKernelArgFunc				pclSetKernelArg				= NULL;
PUBLIC clEnqueueNDRangeKernelFunc		pclEnqueueNDRangeKernel		= NULL;
PUBLIC clFinishFunc						pclFinish					= NULL;
PUBLIC clFinishFunc						pclFlush					= NULL;
PRIVATE clReleaseMemObjectFunc			pclReleaseMemObject			= NULL;
PUBLIC clReleaseKernelFunc				pclReleaseKernel			= NULL;
PRIVATE clReleaseProgramFunc			pclReleaseProgram			= NULL;
PRIVATE clReleaseCommandQueueFunc		pclReleaseCommandQueue		= NULL;
PRIVATE clReleaseContextFunc			pclReleaseContext			= NULL;
PUBLIC clEnqueueReadBufferFunc			pclEnqueueReadBuffer		= NULL;
PUBLIC clEnqueueWriteBufferFunc			pclEnqueueWriteBuffer		= NULL;
PUBLIC clEnqueueCopyBufferFunc			pclEnqueueCopyBuffer		= NULL;

PRIVATE clGetEventProfilingInfoFunc		pclGetEventProfilingInfo	= NULL;
PRIVATE clReleaseEventFunc				pclReleaseEvent				= NULL;
PRIVATE clGetProgramInfoFunc			pclGetProgramInfo			= NULL;
PRIVATE clCreateProgramWithBinaryFunc	pclCreateProgramWithBinary	= NULL;

#ifdef _DEBUG
PRIVATE clGetProgramBuildInfoFunc		pclGetProgramBuildInfo		= NULL;
#endif

PUBLIC GPUDevice gpu_devices[MAX_NUMBER_GPUS_SUPPORTED];
PUBLIC cl_uint num_gpu_devices = 0;

#ifdef _WIN32
PRIVATE HMODULE hcuda = NULL;
PRIVATE CUdevice cuda_gpu_devices[MAX_NUMBER_GPUS_SUPPORTED];

PRIVATE tcuInit					*cuInit 				= NULL;
PRIVATE tcuDeviceGet			*cuDeviceGet			= NULL;
PRIVATE tcuDeviceGetCount		*cuDeviceGetCount		= NULL;
PRIVATE tcuDeviceGetName		*cuDeviceGetName		= NULL;
PRIVATE tcuDeviceGetAttribute	*cuDeviceGetAttribute	= NULL;
PRIVATE tcuDriverGetVersion		*cuDriverGetVersion		= NULL;
PRIVATE tcuCtxCreate			*cuCtxCreate			= NULL;
PRIVATE tcuMemAlloc				*cuMemAlloc				= NULL;
PRIVATE tcuMemFree				*cuMemFree				= NULL;
PUBLIC tcuMemcpyHtoD			*cuMemcpyHtoD			= NULL;
PUBLIC tcuMemcpyDtoH			*cuMemcpyDtoH			= NULL;
PUBLIC tcuLaunchKernel			*cuLaunchKernel			= NULL;
PRIVATE tcuCtxDestroy			*cuCtxDestroy			= NULL;
PRIVATE tcuModuleLoadData		*cuModuleLoadData		= NULL;
PRIVATE tcuModuleUnload			*cuModuleUnload			= NULL;
PRIVATE tcuModuleGetFunction	*cuModuleGetFunction	= NULL;
PUBLIC tcuCtxSynchronize		*cuCtxSynchronize		= NULL;
PUBLIC tcuCtxPopCurrent			*cuCtxPopCurrent		= NULL;
PUBLIC tcuCtxPushCurrent		*cuCtxPushCurrent		= NULL;
PUBLIC tcuFuncSetCacheConfig    *cuFuncSetCacheConfig	= NULL;

// Manage status data about Nvidia devices
PRIVATE HMODULE hnvml = NULL;
#include "OpenCL\nvml.h"
typedef nvmlReturn_t DECLDIR tnvmlInit(void);
typedef nvmlReturn_t DECLDIR tnvmlDeviceGetCount(uint32_t *deviceCount);
typedef nvmlReturn_t DECLDIR tnvmlDeviceGetHandleByIndex(uint32_t index, nvmlDevice_t *device);
typedef nvmlReturn_t DECLDIR tnvmlDeviceGetName(nvmlDevice_t device, char *name, uint32_t length);
typedef nvmlReturn_t DECLDIR tnvmlDeviceGetFanSpeed(nvmlDevice_t device, uint32_t *speed);
typedef nvmlReturn_t DECLDIR tnvmlDeviceGetTemperature(nvmlDevice_t device, nvmlTemperatureSensors_t sensorType, uint32_t *temp);
PRIVATE tnvmlInit* pnvmlInit = NULL;
PRIVATE tnvmlDeviceGetCount* pnvmlDeviceGetCount = NULL;
PRIVATE tnvmlDeviceGetHandleByIndex* pnvmlDeviceGetHandleByIndex = NULL;
PRIVATE tnvmlDeviceGetName* pnvmlDeviceGetName = NULL;
PRIVATE tnvmlDeviceGetFanSpeed* pnvmlDeviceGetFanSpeed = NULL;
PRIVATE tnvmlDeviceGetTemperature* pnvmlDeviceGetTemperature = NULL;

// Manage status data about AMD devices
#include "OpenCL\adl_sdk.h"
PRIVATE HMODULE hamdadl = NULL;
// Definitions of the used function pointers. Add more if you use other ADL APIs
typedef int ( *ADL_MAIN_CONTROL_CREATE )(ADL_MAIN_MALLOC_CALLBACK, int );
typedef int ( *ADL_ADAPTER_NUMBEROFADAPTERS_GET ) ( int* );
typedef int ( *ADL_ADAPTER_ADAPTERINFO_GET ) ( LPAdapterInfo, int );
typedef int ( *ADL_OVERDRIVE_CAPS ) (int iAdapterIndex, int *iSupported, int *iEnabled, int *iVersion);
// Overdrive 5
typedef int ( *ADL_OVERDRIVE5_THERMALDEVICES_ENUM ) (int iAdapterIndex, int iThermalControllerIndex, ADLThermalControllerInfo *lpThermalControllerInfo);
typedef int ( *ADL_OVERDRIVE5_ODPARAMETERS_GET ) ( int  iAdapterIndex,  ADLODParameters *  lpOdParameters );
typedef int ( *ADL_OVERDRIVE5_TEMPERATURE_GET ) (int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature);
typedef int ( *ADL_OVERDRIVE5_CURRENTACTIVITY_GET ) (int iAdapterIndex, ADLPMActivity *lpActivity);
// Overdrive 6
typedef int ( *ADL_OVERDRIVE6_THERMALCONTROLLER_CAPS )(int iAdapterIndex, ADLOD6ThermalControllerCaps *lpThermalControllerCaps);
typedef int ( *ADL_OVERDRIVE6_TEMPERATURE_GET )(int iAdapterIndex, int *lpTemperature);
typedef int ( *ADL_OVERDRIVE6_CAPABILITIES_GET ) (int iAdapterIndex, ADLOD6Capabilities *lpODCapabilities);
typedef int	( *ADL_OVERDRIVE6_CURRENTSTATUS_GET )(int iAdapterIndex, ADLOD6CurrentStatus *lpCurrentStatus);

#define AMDVENDORID             (1002)

ADL_ADAPTER_NUMBEROFADAPTERS_GET ADL_Adapter_NumberOfAdapters_Get;
ADL_ADAPTER_ADAPTERINFO_GET		 ADL_Adapter_AdapterInfo_Get;
ADL_OVERDRIVE_CAPS				 ADL_Overdrive_Caps;
// Overdrive 5
ADL_OVERDRIVE5_THERMALDEVICES_ENUM		ADL_Overdrive5_ThermalDevices_Enum;
ADL_OVERDRIVE5_TEMPERATURE_GET			ADL_Overdrive5_Temperature_Get;
ADL_OVERDRIVE5_ODPARAMETERS_GET			ADL_Overdrive5_ODParameters_Get;
ADL_OVERDRIVE5_CURRENTACTIVITY_GET		ADL_Overdrive5_CurrentActivity_Get;
// Overdrive 6
ADL_OVERDRIVE6_THERMALCONTROLLER_CAPS	ADL_Overdrive6_ThermalController_Caps;
ADL_OVERDRIVE6_TEMPERATURE_GET			ADL_Overdrive6_Temperature_Get;
ADL_OVERDRIVE6_CAPABILITIES_GET			ADL_Overdrive6_Capabilities_Get;
ADL_OVERDRIVE6_CURRENTSTATUS_GET		ADL_Overdrive6_CurrentStatus_Get;
// Memory allocation function
PRIVATE void* __stdcall ADL_Main_Memory_Alloc ( int iSize )
{
    void* lpBuffer = malloc ( iSize );
    return lpBuffer;
}

PUBLIC int gpu_get_updated_status(uint32_t gpu_index, GPUStatus* status)
{
	if (status)
		status->flag = GPU_STATUS_FAILED;
	else
		return GPU_STATUS_FAILED;

	if (gpu_index >= num_gpu_devices || !(gpu_devices[gpu_index].flags & GPU_FLAG_SUPPORT_STATUS_INFO))
		return GPU_STATUS_FAILED;

	// Supported Nvidia GPUs
	if (gpu_devices[gpu_index].vendor == OCL_VENDOR_NVIDIA)
	{
		if (pnvmlDeviceGetFanSpeed(gpu_devices[gpu_index].nv.id, &status->fan_speed) == NVML_SUCCESS)
			status->flag |= GPU_STATUS_FAN;
		if( pnvmlDeviceGetTemperature(gpu_devices[gpu_index].nv.id, NVML_TEMPERATURE_GPU, &status->temperature) == NVML_SUCCESS)
			status->flag |= GPU_STATUS_TEMPERATURE;
	}
	// Supported AMD GPUs
	if (gpu_devices[gpu_index].vendor == OCL_VENDOR_AMD)
	{
		if (gpu_devices[gpu_index].amd.version == 5)
		{
			ADLThermalControllerInfo termalControllerInfo = {0};
			//ADLFanSpeedInfo fanSpeedInfo = {0};
			//int fanSpeedReportingMethod = 0;
			termalControllerInfo.iSize = sizeof (ADLThermalControllerInfo);

			if (!ADL_Overdrive5_ThermalDevices_Enum || !ADL_Overdrive5_Temperature_Get /*|| !ADL_Overdrive5_FanSpeedInfo_Get*/ || !ADL_Overdrive5_ODParameters_Get || !ADL_Overdrive5_CurrentActivity_Get)
				return GPU_STATUS_FAILED;

			for (int iThermalControllerIndex = 0; iThermalControllerIndex < 10; iThermalControllerIndex++) 
			{
				if (ADL_Overdrive5_ThermalDevices_Enum(gpu_devices[gpu_index].amd.id, iThermalControllerIndex, &termalControllerInfo) != ADL_OK)
					break;		

				if (termalControllerInfo.iThermalDomain == ADL_DL_THERMAL_DOMAIN_GPU)
				{
					// Get temperature
					ADLTemperature adlTemperature = {0};
					adlTemperature.iSize = sizeof (ADLTemperature);
					if (ADL_OK == ADL_Overdrive5_Temperature_Get(gpu_devices[gpu_index].amd.id, iThermalControllerIndex, &adlTemperature))
					{
						status->temperature = adlTemperature.iTemperature / 1000; // The temperature is returned in millidegrees Celsius.
						status->flag |= GPU_STATUS_TEMPERATURE;
					}

					//// Get Fan speed
					//fanSpeedInfo.iSize = sizeof (ADLFanSpeedInfo);
					//if ( ADL_OK == ADL_Overdrive5_FanSpeedInfo_Get (gpu_devices[gpu_index].amd.id, iThermalControllerIndex, &fanSpeedInfo))
					//{
					//	ADLFanSpeedValue fanSpeedValue = {0};
					//	fanSpeedReportingMethod = ((fanSpeedInfo.iFlags & ADL_DL_FANCTRL_SUPPORTS_RPM_READ) == ADL_DL_FANCTRL_SUPPORTS_RPM_READ )? ADL_DL_FANCTRL_SPEED_TYPE_RPM : ADL_DL_FANCTRL_SPEED_TYPE_PERCENT;
					//	//Set to ADL_DL_FANCTRL_SPEED_TYPE_RPM or to ADL_DL_FANCTRL_SPEED_TYPE_PERCENT to request fan speed to be returned in rounds per minute or in percentage points.
					//	//Note that the call might fail if requested fan speed reporting method is not supported by the GPU.
					//	fanSpeedValue.iSpeedType = fanSpeedReportingMethod; 
					//	if ( ADL_OK == ADL_Overdrive5_FanSpeed_Get (gpu_devices[gpu_index].amd.id, iThermalControllerIndex, &fanSpeedValue))
					//	{
					//		if (fanSpeedReportingMethod == ADL_DL_FANCTRL_SPEED_TYPE_RPM)
					//		{
					//			if (fanSpeedValue.iFanSpeed >= fanSpeedInfo.iMinRPM && fanSpeedValue.iFanSpeed <= fanSpeedInfo.iMaxRPM)
					//			{
					//				status->flag |= GPU_STATUS_FAN;
					//				status->fan_speed = fanSpeedValue.iFanSpeed*100/fanSpeedInfo.iMaxRPM;
					//			}
					//		}
					//		else
					//		{
					//			status->flag |= GPU_STATUS_FAN;
					//			status->fan_speed = fanSpeedValue.iFanSpeed;
					//		}
					//	}
					//}
					
					break;
				}
			}

			// Get usage
			ADLODParameters overdriveParameters = {0};
			overdriveParameters.iSize = sizeof (ADLODParameters);
			ADLPMActivity activity = {0};
			activity.iSize = sizeof (ADLPMActivity);

			if (ADL_OK == ADL_Overdrive5_ODParameters_Get (gpu_devices[gpu_index].amd.id, &overdriveParameters) &&
				overdriveParameters.iActivityReportingSupported &&
				ADL_OK == ADL_Overdrive5_CurrentActivity_Get (gpu_devices[gpu_index].amd.id, &activity))
			{
				status->flag |= GPU_STATUS_USE;
				status->usage = activity.iActivityPercent;
			}
		}
		if (gpu_devices[gpu_index].amd.version == 6)
		{
			ADLOD6FanSpeedInfo fanSpeedInfo = {0};
			ADLOD6ThermalControllerCaps thermalControllerCaps = {0};

			if (/*!ADL_Overdrive6_FanSpeed_Get ||*/ !ADL_Overdrive6_ThermalController_Caps || !ADL_Overdrive6_Temperature_Get || !ADL_Overdrive6_Capabilities_Get || !ADL_Overdrive6_CurrentStatus_Get)
				return GPU_STATUS_FAILED;

			int thermal_result = ADL_Overdrive6_ThermalController_Caps(gpu_devices[gpu_index].amd.id, &thermalControllerCaps);
	
			// Get Fan Speed
			//if (thermal_result == ADL_OK &&
			//	ADL_OD6_TCCAPS_FANSPEED_CONTROL == (thermalControllerCaps.iCapabilities & ADL_OD6_TCCAPS_FANSPEED_CONTROL) && //Verifies that fan speed controller exists on the GPU.
			//	(ADL_OD6_TCCAPS_FANSPEED_PERCENT_READ == (thermalControllerCaps.iCapabilities & ADL_OD6_TCCAPS_FANSPEED_PERCENT_READ )
			//	|| ADL_OD6_TCCAPS_FANSPEED_RPM_READ == (thermalControllerCaps.iCapabilities & ADL_OD6_TCCAPS_FANSPEED_RPM_READ ) ) &&
			//	ADL_OK == ADL_Overdrive6_FanSpeed_Get (gpu_devices[gpu_index].amd.id, &fanSpeedInfo))
			//	{
			//		if (ADL_OD6_FANSPEED_TYPE_RPM == (fanSpeedInfo.iSpeedType & ADL_OD6_FANSPEED_TYPE_RPM))
			//		{
			//			if (fanSpeedInfo.iFanSpeedRPM >= thermalControllerCaps.iFanMinRPM && fanSpeedInfo.iFanSpeedRPM <= thermalControllerCaps.iFanMaxRPM)
			//			{
			//				status->flag |= GPU_STATUS_FAN;
			//				status->fan_speed = fanSpeedInfo.iFanSpeedRPM*100/thermalControllerCaps.iFanMaxRPM;
			//			}
			//		}
			//		else
			//		{
			//			status->flag |= GPU_STATUS_FAN;
			//			status->fan_speed = fanSpeedInfo.iFanSpeedPercent;
			//		}
			//	}
			// Get Temperature
			if (thermal_result == ADL_OK && ADL_OD6_TCCAPS_THERMAL_CONTROLLER == (thermalControllerCaps.iCapabilities & ADL_OD6_TCCAPS_THERMAL_CONTROLLER) && ADL_OK == ADL_Overdrive6_Temperature_Get (gpu_devices[gpu_index].amd.id, &status->temperature)) //Verifies that thermal controller exists on the GPU.
			{	
				status->flag |= GPU_STATUS_TEMPERATURE;
				status->temperature /= 1000;
			}
			// Get usage
			ADLOD6Capabilities od6Capabilities = {0};
			ADLOD6CurrentStatus currentStatus = {0};
			if (ADL_OK == ADL_Overdrive6_Capabilities_Get (gpu_devices[gpu_index].amd.id, &od6Capabilities) &&
				(od6Capabilities.iCapabilities & ADL_OD6_CAPABILITY_GPU_ACTIVITY_MONITOR) == ADL_OD6_CAPABILITY_GPU_ACTIVITY_MONITOR &&
				ADL_OK == ADL_Overdrive6_CurrentStatus_Get (gpu_devices[gpu_index].amd.id, &currentStatus))
			{
				status->flag |= GPU_STATUS_USE;
				status->usage = currentStatus.iActivityPercent;
			}
		}
	}

	return status->flag;
}

#include <Shlobj.h>
PRIVATE BOOL init_cuda()
{
	if(hcuda) return TRUE;// If loaded -> do nothing

	// Check cuda API
	hcuda = LoadLibrary("nvcuda.dll");
	if(hcuda)
	{
		int driver_version;	
		cuDriverGetVersion = (tcuDriverGetVersion*)GetProcAddress(hcuda, "cuDriverGetVersion");
		cuDriverGetVersion(&driver_version);
		if(driver_version < 4000)
		{
			FreeLibrary(hcuda);
			return FALSE;
		}

		cuInit 					= (tcuInit*)				GetProcAddress(hcuda, "cuInit");
		cuDeviceGet				= (tcuDeviceGet*)			GetProcAddress(hcuda, "cuDeviceGet");
		cuDeviceGetCount		= (tcuDeviceGetCount*)		GetProcAddress(hcuda, "cuDeviceGetCount");
		cuDeviceGetName			= (tcuDeviceGetName*)		GetProcAddress(hcuda, "cuDeviceGetName");
		cuDeviceGetAttribute	= (tcuDeviceGetAttribute*)	GetProcAddress(hcuda, "cuDeviceGetAttribute");
		cuCtxCreate				= (tcuCtxCreate*)			GetProcAddress(hcuda, "cuCtxCreate");
		cuMemAlloc				= (tcuMemAlloc*)			GetProcAddress(hcuda, "cuMemAlloc");
		cuMemFree				= (tcuMemFree*)				GetProcAddress(hcuda, "cuMemFree");
		cuMemcpyHtoD			= (tcuMemcpyHtoD*)			GetProcAddress(hcuda, "cuMemcpyHtoD");
		cuMemcpyDtoH			= (tcuMemcpyDtoH*)			GetProcAddress(hcuda, "cuMemcpyDtoH");
		cuLaunchKernel			= (tcuLaunchKernel*)		GetProcAddress(hcuda, "cuLaunchKernel");
		cuCtxDestroy			= (tcuCtxDestroy*)			GetProcAddress(hcuda, "cuCtxDestroy");
		cuModuleLoadData		= (tcuModuleLoadData*)		GetProcAddress(hcuda, "cuModuleLoadData");
		cuModuleUnload			= (tcuModuleUnload*)		GetProcAddress(hcuda, "cuModuleUnload");
		cuModuleGetFunction		= (tcuModuleGetFunction*)	GetProcAddress(hcuda, "cuModuleGetFunction");
		cuCtxSynchronize		= (tcuCtxSynchronize*)		GetProcAddress(hcuda, "cuCtxSynchronize");
		cuCtxPopCurrent			= (tcuCtxPopCurrent*)		GetProcAddress(hcuda, "cuCtxPopCurrent");
		cuCtxPushCurrent		= (tcuCtxPushCurrent*)		GetProcAddress(hcuda, "cuCtxPushCurrent");
		cuFuncSetCacheConfig	= (tcuFuncSetCacheConfig*)	GetProcAddress(hcuda, "cuFuncSetCacheConfig");

		// Check all functions are good
		if (cuInit && cuDeviceGet && cuDeviceGetCount && cuDeviceGetName && cuDeviceGetAttribute && cuCtxCreate && cuMemAlloc &&
			cuMemFree && cuMemcpyHtoD && cuMemcpyDtoH && cuLaunchKernel && cuCtxDestroy && cuModuleLoadData && cuModuleUnload &&
			cuModuleGetFunction && cuCtxSynchronize &&  cuCtxPushCurrent && cuCtxPopCurrent && cuFuncSetCacheConfig && cuInit(0) == CUDA_SUCCESS)
		{
			// Try to load aditional data about Nvidia devices
			if (!hnvml)
			{
				hnvml = LoadLibrary("nvml.dll");
				if (!hnvml)
				{
					TCHAR path[MAX_PATH];
					SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, path);
					strcat(path, "\\NVIDIA Corporation\\NVSMI\\nvml.dll");
					hnvml = LoadLibrary(path);
				}
					
				if (hnvml)
				{
					pnvmlInit = (tnvmlInit*)GetProcAddress(hnvml, "nvmlInit");
					pnvmlDeviceGetCount = (tnvmlDeviceGetCount*)GetProcAddress(hnvml, "nvmlDeviceGetCount");
					pnvmlDeviceGetHandleByIndex = (tnvmlDeviceGetHandleByIndex*)GetProcAddress(hnvml, "nvmlDeviceGetHandleByIndex");
					pnvmlDeviceGetName = (tnvmlDeviceGetName*)GetProcAddress(hnvml, "nvmlDeviceGetName");
					pnvmlDeviceGetFanSpeed = (tnvmlDeviceGetFanSpeed*)GetProcAddress(hnvml, "nvmlDeviceGetFanSpeed");
					pnvmlDeviceGetTemperature = (tnvmlDeviceGetTemperature*)GetProcAddress(hnvml, "nvmlDeviceGetTemperature");

					if (!pnvmlInit || !pnvmlDeviceGetCount || !pnvmlDeviceGetHandleByIndex || !pnvmlDeviceGetName || !pnvmlDeviceGetFanSpeed || !pnvmlDeviceGetTemperature || pnvmlInit() != NVML_SUCCESS)
					{
						FreeLibrary(hnvml);
						hnvml = NULL;
					}
				}
			}
			return TRUE;
		}
		else
			return FALSE;
	}

	return FALSE;
}
PRIVATE int init_amdadl()
{
	if (hamdadl) return TRUE;

	hamdadl = LoadLibrary("atiadlxx.dll");
	if (hamdadl == NULL)
		// A 32 bit calling application on 64 bit OS will fail to LoadLibrary.
		// Try to load the 32 bit library (atiadlxy.dll) instead
		hamdadl = LoadLibrary("atiadlxy.dll");

	if (hamdadl)
	{
		ADL_MAIN_CONTROL_CREATE ADL_Main_Control_Create = (ADL_MAIN_CONTROL_CREATE) GetProcAddress(hamdadl,"ADL_Main_Control_Create");
		ADL_Adapter_NumberOfAdapters_Get = (ADL_ADAPTER_NUMBEROFADAPTERS_GET) GetProcAddress(hamdadl,"ADL_Adapter_NumberOfAdapters_Get");
		ADL_Adapter_AdapterInfo_Get = (ADL_ADAPTER_ADAPTERINFO_GET) GetProcAddress(hamdadl,"ADL_Adapter_AdapterInfo_Get");
		ADL_Overdrive_Caps = (ADL_OVERDRIVE_CAPS)GetProcAddress(hamdadl, "ADL_Overdrive_Caps");
		// Overdrive 5
		ADL_Overdrive5_ThermalDevices_Enum = (ADL_OVERDRIVE5_THERMALDEVICES_ENUM) GetProcAddress (hamdadl, "ADL_Overdrive5_ThermalDevices_Enum");
		ADL_Overdrive5_Temperature_Get = (ADL_OVERDRIVE5_TEMPERATURE_GET) GetProcAddress (hamdadl, "ADL_Overdrive5_Temperature_Get");
		//ADL_Overdrive5_FanSpeed_Get = (ADL_OVERDRIVE5_FANSPEED_GET) GetProcAddress (hamdadl, "ADL_Overdrive5_FanSpeed_Get");
		//ADL_Overdrive5_FanSpeedInfo_Get = (ADL_OVERDRIVE5_FANSPEEDINFO_GET ) GetProcAddress (hamdadl, "ADL_Overdrive5_FanSpeedInfo_Get");
		ADL_Overdrive5_ODParameters_Get = (ADL_OVERDRIVE5_ODPARAMETERS_GET) GetProcAddress (hamdadl, "ADL_Overdrive5_ODParameters_Get");	
		ADL_Overdrive5_CurrentActivity_Get = (ADL_OVERDRIVE5_CURRENTACTIVITY_GET) GetProcAddress (hamdadl, "ADL_Overdrive5_CurrentActivity_Get");
		// Overdrive 6
		//ADL_Overdrive6_FanSpeed_Get = (ADL_OVERDRIVE6_FANSPEED_GET) GetProcAddress(hamdadl,"ADL_Overdrive6_FanSpeed_Get");
		ADL_Overdrive6_ThermalController_Caps = (ADL_OVERDRIVE6_THERMALCONTROLLER_CAPS)GetProcAddress (hamdadl, "ADL_Overdrive6_ThermalController_Caps");
		ADL_Overdrive6_Temperature_Get = (ADL_OVERDRIVE6_TEMPERATURE_GET)GetProcAddress (hamdadl, "ADL_Overdrive6_Temperature_Get");
		ADL_Overdrive6_Capabilities_Get = (ADL_OVERDRIVE6_CAPABILITIES_GET)GetProcAddress(hamdadl, "ADL_Overdrive6_Capabilities_Get");
		ADL_Overdrive6_CurrentStatus_Get = (ADL_OVERDRIVE6_CURRENTSTATUS_GET)GetProcAddress(hamdadl, "ADL_Overdrive6_CurrentStatus_Get");

		if (!ADL_Main_Control_Create || !ADL_Adapter_NumberOfAdapters_Get || !ADL_Adapter_AdapterInfo_Get || !ADL_Overdrive_Caps)
			goto error_out;

		// Initialize ADL. The second parameter is 1, which means:
        // retrieve adapter information only for adapters that are physically present and enabled in the system
        if ( ADL_OK != ADL_Main_Control_Create (ADL_Main_Memory_Alloc, 1) )
			goto error_out;

		return TRUE;
	}
error_out:
	if (hamdadl)
	{
		FreeLibrary(hamdadl);
		hamdadl = NULL;
	}
	return FALSE;
}
#endif
PRIVATE void get_device_info_extended(int gpu_index)
{
	char buffer_str[1024];

	// Defaults values
	gpu_devices[gpu_index].flags = 0;
	gpu_devices[gpu_index].vendor = OCL_VENDOR_UNKNOW;
	gpu_devices[gpu_index].vendor_icon = 19;// Device icon based on device vendor
	gpu_devices[gpu_index].cores = 1;
	gpu_devices[gpu_index].l1_cache_size = 8;
	gpu_devices[gpu_index].l2_cache_size = 16;
	gpu_devices[gpu_index].l3_cache_size = 0;
	gpu_devices[gpu_index].memory_type[0] = 0;
	gpu_devices[gpu_index].memory_frequency = 0;
	gpu_devices[gpu_index].opencl_version[0] = 0;
	gpu_devices[gpu_index].driver_version[0] = 0;
	strcpy(gpu_devices[gpu_index].name, "GPU");
	gpu_devices[gpu_index].max_clock_frequency = 0;
	gpu_devices[gpu_index].global_memory_size = 0;
	gpu_devices[gpu_index].local_memory_size = 0;
#ifdef __ANDROID__
	gpu_devices[gpu_index].NUM_KEYS_OPENCL_DIVIDER = 8;
	gpu_devices[gpu_index].flags |= GPU_FLAG_HAD_UNIFIED_MEMORY;

	gpu_devices[gpu_index].lm_work_group_size = 32;
#else
	gpu_devices[gpu_index].NUM_KEYS_OPENCL_DIVIDER = 1;

	gpu_devices[gpu_index].flags |= GPU_FLAG_HAD_LM_UNROll;
	gpu_devices[gpu_index].lm_work_group_size = 64;
#endif
	gpu_devices[gpu_index].flags |= GPU_FLAG_LM_REQUIRE_WORKGROUP;
	gpu_devices[gpu_index].flags |= GPU_FLAG_LM_USE_SHARED_MEMORY;
	gpu_devices[gpu_index].compiler_options = "";
	gpu_devices[gpu_index].lm_compiler_options = "";

	// Driver version
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DRIVER_VERSION, sizeof(gpu_devices[gpu_index].driver_version), gpu_devices[gpu_index].driver_version, NULL);
	// OpenCl version
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_VERSION, sizeof(buffer_str), buffer_str, NULL);
	strstr(strstr(buffer_str, " ")+1, " ")[0] = 0;// select only opencl version
	strcpy(gpu_devices[gpu_index].opencl_version, buffer_str);
	// GPU Name
	cl_device_type gpu_type;
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_TYPE, sizeof(gpu_type), &gpu_type, NULL);
	if (gpu_type == CL_DEVICE_TYPE_CPU)
	{
		// Eliminate the frequency if exist
		char* freq = strstr(current_cpu.brand, "GHz");
		if (freq)
		{
			freq--;
			char* last = freq + 4;
			while (*freq == '.' || (*freq >= '0' && *freq <= '9'))
				freq--;

			// Copy brand
			strncpy(gpu_devices[gpu_index].name, current_cpu.brand, freq - current_cpu.brand);
			strcpy(gpu_devices[gpu_index].name + (freq - current_cpu.brand), last);
		}
	}
	else
		pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_NAME, sizeof(gpu_devices[gpu_index].name), gpu_devices[gpu_index].name, NULL);
	// Frequency
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(cl_uint), &gpu_devices[gpu_index].max_clock_frequency, NULL);
	// Memory
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_GLOBAL_MEM_SIZE	, sizeof(cl_ulong), &gpu_devices[gpu_index].global_memory_size, NULL);
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_LOCAL_MEM_SIZE		, sizeof(cl_ulong), &gpu_devices[gpu_index].local_memory_size, NULL);
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_MAX_MEM_ALLOC_SIZE	, sizeof(cl_ulong), &gpu_devices[gpu_index].max_mem_alloc_size, NULL);
	// Compute Units
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cl_uint), &gpu_devices[gpu_index].cores, NULL);
	// Vector
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT , sizeof(cl_uint), &gpu_devices[gpu_index].vector_int_size, NULL);
	if (gpu_type == CL_DEVICE_TYPE_CPU)
	{
#ifdef __ANDROID__
		if (current_cpu.capabilites[CPU_CAP_NEON])
			gpu_devices[gpu_index].vector_int_size = 8;
#else
		if (current_cpu.capabilites[CPU_CAP_SSE2])
			gpu_devices[gpu_index].vector_int_size = 4;
		if (current_cpu.capabilites[CPU_CAP_AVX])
			gpu_devices[gpu_index].vector_int_size = 8;
		if (current_cpu.capabilites[CPU_CAP_AVX2])
			gpu_devices[gpu_index].vector_int_size = 16;
#endif
	}
	// Max Work Group Size
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), &gpu_devices[gpu_index].max_work_group_size, NULL);
	// TODO: check that gpu_devices[gpu_index].max_work_group_size is a power of 2
	// Used for Intel
	cl_bool has_unified_memory;
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_HOST_UNIFIED_MEMORY, sizeof(cl_bool), &has_unified_memory, NULL);
	if (has_unified_memory)
		gpu_devices[gpu_index].flags |= GPU_FLAG_HAD_UNIFIED_MEMORY;
	else
		GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_HAD_UNIFIED_MEMORY);

	// Vendor specific stuff
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_VENDOR, sizeof(gpu_devices[gpu_index].vendor_string), gpu_devices[gpu_index].vendor_string, NULL);

	// Cache
	pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_GLOBAL_MEM_CACHE_SIZE, sizeof(cl_ulong), &gpu_devices[gpu_index].l2_cache_size, NULL);
	gpu_devices[gpu_index].l2_cache_size /= 1024;

//#define __ANDROID__ 1
#ifdef __ANDROID__
    if(gpu_devices[gpu_index].max_clock_frequency < 10)
        gpu_devices[gpu_index].max_clock_frequency = 200;// By default 200MHz
	if (strstr(gpu_devices[gpu_index].vendor_string, "QUALCOMM"))//Checked
	{
		gpu_devices[gpu_index].vendor_icon = 20;
		gpu_devices[gpu_index].vendor = OCL_VENDOR_QUALCOMM;
		gpu_devices[gpu_index].NUM_KEYS_OPENCL_DIVIDER = 4;
		gpu_devices[gpu_index].flags |= GPU_FLAG_HAD_LM_UNROll;
		GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_LM_REQUIRE_WORKGROUP);
		//gpu_devices[gpu_index].lm_compiler_options = "-qcom-sched-rule=2";

		// Try to read the max GPU clock in a configuration file
		// Mali: /sys/class/misc/mali0/device/clock
		FILE* gpu_freq = fopen("/sys/class/kgsl/kgsl-3d0/max_gpuclk", "r");
		if(gpu_freq)
		{
			fgets(buffer_str, sizeof(buffer_str), gpu_freq);
			fclose(gpu_freq);

			cl_uint freq = atoll(buffer_str)/1000000;
			if(freq)
				gpu_devices[gpu_index].max_clock_frequency = __max(gpu_devices[gpu_index].max_clock_frequency, freq);
		}

		// Make name more friendly
		pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_VERSION, sizeof(buffer_str), buffer_str, NULL);
		char* andreno_version = strstr(buffer_str, "Adreno");
		if(andreno_version)
		{
			remove_str(andreno_version, "(TM)");
			if(atoi(andreno_version+6))
				strcpy(gpu_devices[gpu_index].name, andreno_version);
		}

		remove_str(gpu_devices[gpu_index].name, "QUALCOMM ");
		remove_str(gpu_devices[gpu_index].name, "(TM)");

		buffer_str[0] = 0;
		pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DRIVER_VERSION, sizeof(buffer_str), buffer_str, NULL);
		char* build_date = strstr(buffer_str, "Date: ");
        if (build_date)
        {
            strcpy(gpu_devices[gpu_index].driver_version, "Build ");
            memcpy(gpu_devices[gpu_index].driver_version+6, build_date+6, 8);
            gpu_devices[gpu_index].driver_version[14] = 0;
        }
	}
#else
	if(strstr(gpu_devices[gpu_index].vendor_string, "Advanced Micro Devices"))//Checked
	{
		gpu_devices[gpu_index].vendor = OCL_VENDOR_AMD;
		gpu_devices[gpu_index].vendor_icon = 16;// Device icon based on device vendor
		gpu_devices[gpu_index].flags |= GPU_FLAG_NATIVE_BITSELECT;
		gpu_devices[gpu_index].flags |= GPU_FLAG_HAD_LM_UNROll;
		gpu_devices[gpu_index].compiler_options = "-fno-bin-source -fno-bin-llvmir -fno-bin-amdil";
		gpu_devices[gpu_index].lm_compiler_options = gpu_devices[gpu_index].compiler_options;
		if(pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_EXTENSIONS, sizeof(buffer_str), buffer_str, NULL) == CL_SUCCESS && strstr(buffer_str, "cl_amd_media_ops"))
			gpu_devices[gpu_index].flags |= GPU_FLAG_SUPPORT_AMD_OPS;
		//if(pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_EXTENSIONS, sizeof(buffer_str), buffer_str, NULL) == CL_SUCCESS && strstr(buffer_str, "cl_amd_media_ops2"))
		//	gpu_devices[gpu_index].support_amd_bfe = TRUE;

		// Support Status
		if (init_amdadl())
		{
			LPAdapterInfo lpAdapterInfo = NULL;
			int num_adapters;

			if (pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_BOARD_NAME_AMD, sizeof(buffer_str), buffer_str, NULL) != CL_SUCCESS)
				goto error_out;
			
			// Obtain the number of adapters for the system
			if ( ADL_OK != ADL_Adapter_NumberOfAdapters_Get ( &num_adapters ) )
				goto error_out;

			if ( 0 < num_adapters )
			{
				lpAdapterInfo = (LPAdapterInfo)malloc ( sizeof (AdapterInfo) * num_adapters );
				memset ( lpAdapterInfo, 0, sizeof (AdapterInfo) * num_adapters );

				// Get the AdapterInfo structure for all adapters in the system
				ADL_Adapter_AdapterInfo_Get (lpAdapterInfo, sizeof (AdapterInfo) * num_adapters);
			}

			// Looking for first present and active adapter in the system
			gpu_devices[gpu_index].amd.id = -1;
			for (int i = 0; i < num_adapters; i++ )
				if (lpAdapterInfo[i].iVendorID == AMDVENDORID && !strcmp(buffer_str, lpAdapterInfo[i].strAdapterName))
				{
					// If the GPU was already added
					cl_bool already_added = FALSE;
					for (int j = 0; j < gpu_index; j++)
						if (gpu_devices[j].amd.id == lpAdapterInfo[i].iAdapterIndex)
						{
							already_added = TRUE;
							break;
						}
				
					if (!already_added)
					{
						gpu_devices[gpu_index].amd.id = lpAdapterInfo[i].iAdapterIndex;
						break;
					}
				}

			//Overdrive 5 APIs should be used if returned version indicates 5. Overdrive 6 APIs are used if 6 is returned.
			//Overdrive 5 is supported on legacy ASICs. Newer ASICs (CIK+) should report Overdrive 6
			int overdrive_supported, overdrive_enabled;
			if ( ADL_OK != ADL_Overdrive_Caps(gpu_devices[gpu_index].amd.id, &overdrive_supported, &overdrive_enabled, &gpu_devices[gpu_index].amd.version) || !overdrive_supported)
				goto error_out;
		
			if (gpu_devices[gpu_index].amd.version == 5 || gpu_devices[gpu_index].amd.version == 6)
				gpu_devices[gpu_index].flags |= GPU_FLAG_SUPPORT_STATUS_INFO;

error_out:
			free(lpAdapterInfo);
		}

		if(strstr(gpu_devices[gpu_index].name, "Verde"))
		{
			gpu_devices[gpu_index].l1_cache_size = 16;
			gpu_devices[gpu_index].l2_cache_size = 512;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
			gpu_devices[gpu_index].memory_frequency = 1125;
			GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_LM_USE_SHARED_MEMORY);
		}
		else if(strstr(gpu_devices[gpu_index].name, "Pitcairn"))
		{
			gpu_devices[gpu_index].l1_cache_size = 16;
			gpu_devices[gpu_index].l2_cache_size = 512;
			gpu_devices[gpu_index].memory_frequency = 1200;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
			GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_LM_USE_SHARED_MEMORY);
		}
		else if(strstr(gpu_devices[gpu_index].name, "Tahiti"))
		{
			gpu_devices[gpu_index].l1_cache_size = 16;
			gpu_devices[gpu_index].l2_cache_size = 768;
			gpu_devices[gpu_index].memory_frequency = gpu_devices[gpu_index].cores == 28 ? 1250 : 1375;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
			GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_LM_USE_SHARED_MEMORY);
		}
		/////
		else if(strstr(gpu_devices[gpu_index].name, "Barts"))
		{
			gpu_devices[gpu_index].l2_cache_size = 512;
			gpu_devices[gpu_index].memory_frequency =  gpu_devices[gpu_index].cores == 12 ? 1000 : 1050;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
		}
		else if(strstr(gpu_devices[gpu_index].name, "Blackcomb"))
		{
			gpu_devices[gpu_index].l2_cache_size = 512;
			gpu_devices[gpu_index].memory_frequency = 900;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
		}
		else if(strstr(gpu_devices[gpu_index].name, "Cayman"))
		{
			gpu_devices[gpu_index].l2_cache_size = 512;
			gpu_devices[gpu_index].memory_frequency = (gpu_devices[gpu_index].cores == 22 || gpu_devices[gpu_index].cores == 48) ? 1250 : 1375;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
		}
		//////////////////
		else if(strstr(gpu_devices[gpu_index].name, "Turks"))
		{
			gpu_devices[gpu_index].l2_cache_size = 256;
			if (gpu_devices[gpu_index].global_memory_size <= 1024 * 1024 * 1024)// Less than or EQ 1GB
			{
				strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
				gpu_devices[gpu_index].memory_frequency = 1000;
			}
			else
			{
				strcpy(gpu_devices[gpu_index].memory_type, "DDR3");
				gpu_devices[gpu_index].memory_frequency = 900;
			}
		}
		else if(strstr(gpu_devices[gpu_index].name, "Whistler"))
		{
			gpu_devices[gpu_index].l2_cache_size = 256;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
			gpu_devices[gpu_index].memory_frequency = 800;// Exist other but...
		}
		///////////////////
		else if(strstr(gpu_devices[gpu_index].name, "Caicos"))
		{
			gpu_devices[gpu_index].l2_cache_size = 128;
			if(gpu_devices[gpu_index].global_memory_size <= 1024*1024*512)// Less than or EQ 512MB
				strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
			else
				strcpy(gpu_devices[gpu_index].memory_type, "DDR3");
			gpu_devices[gpu_index].memory_frequency = 800;
		}
		else if (strstr(gpu_devices[gpu_index].name, "Seymour"))
		{
			gpu_devices[gpu_index].l2_cache_size = 128;
			if (gpu_devices[gpu_index].global_memory_size <= 1024 * 1024 * 512)// Less than or EQ 512MB
			{
				strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
				gpu_devices[gpu_index].memory_frequency = 800;
			}
			else
			{
				strcpy(gpu_devices[gpu_index].memory_type, "DDR3");
				gpu_devices[gpu_index].memory_frequency = 900;
			}
		}
		///////////
		else if(strstr(gpu_devices[gpu_index].name, "Ontario"))
		{
			gpu_devices[gpu_index].l2_cache_size = 64;
			strcpy(gpu_devices[gpu_index].memory_type, "DDR3");
			gpu_devices[gpu_index].memory_frequency = 533;
		}
		else if(strstr(gpu_devices[gpu_index].name, "Zacate"))
		{
			gpu_devices[gpu_index].l2_cache_size = 64;
			gpu_devices[gpu_index].memory_frequency = 533;
			strcpy(gpu_devices[gpu_index].memory_type, "DDR3");
		}
		//////////
		else if(strstr(gpu_devices[gpu_index].name, "Redwood"))
		{
			gpu_devices[gpu_index].l2_cache_size = 128;
			gpu_devices[gpu_index].memory_frequency = 1000;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
		}
		else if(strstr(gpu_devices[gpu_index].name, "Juniper"))
		{
			gpu_devices[gpu_index].l2_cache_size = 256;
			gpu_devices[gpu_index].memory_frequency = 1150;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
		}
		else if(strstr(gpu_devices[gpu_index].name, "Cypress"))
		{
			gpu_devices[gpu_index].l2_cache_size = 512;
			gpu_devices[gpu_index].memory_frequency = 1000;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
		}
		else if(strstr(gpu_devices[gpu_index].name, "Hemlock"))
		{
			gpu_devices[gpu_index].l2_cache_size = 1024;
			gpu_devices[gpu_index].memory_frequency = 1000;
			strcpy(gpu_devices[gpu_index].memory_type, "GDDR5");
		}
		/////////////
		else if(strstr(gpu_devices[gpu_index].name, "Cedar"))
		{
			gpu_devices[gpu_index].l2_cache_size = 64;
			gpu_devices[gpu_index].memory_frequency = 800;
			strcpy(gpu_devices[gpu_index].memory_type, "DDR3");
		}
	}
	else if(strstr(gpu_devices[gpu_index].vendor_string, "NVIDIA"))// Checked
	{
		cl_uint minor_cc;

		gpu_devices[gpu_index].vendor = OCL_VENDOR_NVIDIA;
		gpu_devices[gpu_index].vendor_icon = 17;// Device icon based on device vendor
		gpu_devices[gpu_index].l1_cache_size = gpu_devices[gpu_index].l2_cache_size;

		if( pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof(cl_uint), &gpu_devices[gpu_index].major_cc, NULL) == CL_SUCCESS &&
			pclGetDeviceInfo(gpu_devices[gpu_index].cl_id, CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV, sizeof(cl_uint), &minor_cc, NULL) == CL_SUCCESS)
			if(gpu_devices[gpu_index].major_cc < 2)
			{
				gpu_devices[gpu_index].l1_cache_size = 0;
				gpu_devices[gpu_index].l2_cache_size = 0;
			}

		// For good parallel instructions execution
		if (gpu_devices[gpu_index].major_cc == 2 && minor_cc == 0)
			gpu_devices[gpu_index].vector_int_size = 2;

		if (gpu_devices[gpu_index].major_cc < 3)
			GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_HAD_LM_UNROll);
		else
			GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_LM_USE_SHARED_MEMORY);

		// Check cuda API for more data
		if(init_cuda())
		{
			int driver_version;
			cuDriverGetVersion(&driver_version);
			// Use lop3 instruction to reduce gate counts
			if (driver_version >= 7050 && gpu_devices[gpu_index].major_cc >= 5)
				gpu_devices[gpu_index].flags |= GPU_FLAG_NVIDIA_LOP3;

			int device_count, i, j;
			uint32_t nvml_device_count = 0;
			cuDeviceGetCount(&device_count);
			if (hnvml)
				pnvmlDeviceGetCount(&nvml_device_count);

			// Iterate over all cuda devices
			for(i = 0; i < device_count; i++)
			{
				CUdevice cuda_device;
				int device_already_added = FALSE;
				cuDeviceGet(&cuda_device, i);
				
				// Check if device was already selected
				for (j = 0; j < gpu_index; j++)
					if (gpu_devices[j].vendor == OCL_VENDOR_NVIDIA && cuda_gpu_devices[j] == cuda_device)
					{
						device_already_added = TRUE;
						break;
					}

				if(device_already_added) continue;

				// Check if the name is the same
				cuDeviceGetName(buffer_str, sizeof(buffer_str), cuda_device);
				if(!strcmp(buffer_str, gpu_devices[gpu_index].name))
				{
					int val;
					if(gpu_devices[gpu_index].major_cc >= 2)
					{
						cuda_gpu_devices[gpu_index] = cuda_device;
						gpu_devices[gpu_index].flags |= GPU_FLAG_SUPPORT_PTX;
					}

					if (cuDeviceGetAttribute(&val, CU_DEVICE_ATTRIBUTE_MEMORY_CLOCK_RATE, cuda_device) == CUDA_SUCCESS)
					{
						gpu_devices[gpu_index].memory_frequency = val / 1000;
						sprintf(gpu_devices[gpu_index].memory_type, "%s", val >= 1000000 ? "GDDR5" : "DDR3");
					}
					if(cuDeviceGetAttribute(&val, CU_DEVICE_ATTRIBUTE_L2_CACHE_SIZE, cuda_device) == CUDA_SUCCESS)
						gpu_devices[gpu_index].l2_cache_size = val/1024;

					// Nvidia get status
					for (i = 0; i < (int)nvml_device_count; i++)
					{
						nvmlDevice_t nvml_device;
						int device_already_added = FALSE;
						pnvmlDeviceGetHandleByIndex(i, &nvml_device);

						// Check if device was already selected
						for (j = 0; j < gpu_index; j++)
							if (gpu_devices[j].vendor == OCL_VENDOR_NVIDIA && gpu_devices[j].nv.id == nvml_device)
							{
								device_already_added = TRUE;
								break;
							}

						if (device_already_added) continue;

						// Check if the name is the same
						pnvmlDeviceGetName(nvml_device, buffer_str, sizeof(buffer_str));
						if (!strcmp(buffer_str, gpu_devices[gpu_index].name))
						{
							gpu_devices[gpu_index].nv.id = nvml_device;
							gpu_devices[gpu_index].flags |= GPU_FLAG_SUPPORT_STATUS_INFO;
							break;
						}
					}
					break;
				}
			}
		}
		else
		{
			GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_HAD_LM_UNROll);
			gpu_devices[gpu_index].flags |= GPU_FLAG_LM_USE_SHARED_MEMORY;
		}
	}
	else if(strstr(gpu_devices[gpu_index].vendor_string, "Intel"))// Checked
	{
		gpu_devices[gpu_index].vendor = OCL_VENDOR_INTEL;
		gpu_devices[gpu_index].vendor_icon = 18;// Device icon based on device vendor
		gpu_devices[gpu_index].l3_cache_size = current_cpu.l3_cache_size;

		GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_HAD_LM_UNROll);
		GPU_SET_FLAG_DISABLE(gpu_devices[gpu_index].flags, GPU_FLAG_LM_USE_SHARED_MEMORY);
		gpu_devices[gpu_index].NUM_KEYS_OPENCL_DIVIDER = 16;

		if (gpu_type == CL_DEVICE_TYPE_CPU)
			gpu_devices[gpu_index].NUM_KEYS_OPENCL_DIVIDER *= 2;
		gpu_devices[gpu_index].lm_work_group_size = 16;

		// Make name more friendly
		remove_str(gpu_devices[gpu_index].name, "(R)");
		remove_str(gpu_devices[gpu_index].name, "Graphics ");
		//remove_str(gpu_devices[gpu_index].name, "Intel");
	}
#endif
}
PUBLIC int use_cpu_as_gpu = FALSE;
PRIVATE void find_all_gpus()
{
	cl_platform_id platform[16];
	cl_uint num_platforms, num_devices, p;
	cl_bool bool_param;
	uint32_t i,j;
	char exts[1024];
	cl_device_id gpus_id[MAX_NUMBER_GPUS_SUPPORTED];

	num_gpu_devices = 0;

	// Get platform and devices.
	if(pclGetPlatformIDs(LENGHT(platform), platform, &num_platforms ) == CL_SUCCESS)
		for(p = 0; p < num_platforms; p++)
			if (pclGetDeviceIDs(platform[p], CL_DEVICE_TYPE_ALL, MAX_NUMBER_GPUS_SUPPORTED - num_gpu_devices, gpus_id + num_gpu_devices, &num_devices) == CL_SUCCESS)
				num_gpu_devices += num_devices;

	// Copy the ids
	for (i = 0; i < num_gpu_devices; i++)
		gpu_devices[i].cl_id = gpus_id[i];

	// Check all devices are "good" devices
	for(i = 0; i < num_gpu_devices; i++)
	{
		int erase = FALSE;
		cl_device_type gpu_type;
		pclGetDeviceInfo(gpu_devices[i].cl_id, CL_DEVICE_TYPE, sizeof(gpu_type), &gpu_type, NULL);
		if (gpu_type == CL_DEVICE_TYPE_CPU && !use_cpu_as_gpu)
			erase = TRUE;
		if (pclGetDeviceInfo(gpu_devices[i].cl_id, CL_DEVICE_AVAILABLE, sizeof(bool_param), &bool_param, NULL) != CL_SUCCESS || !bool_param)
			erase = TRUE;
		if( pclGetDeviceInfo(gpu_devices[i].cl_id, CL_DEVICE_COMPILER_AVAILABLE, sizeof(bool_param), &bool_param, NULL) != CL_SUCCESS || !bool_param)
			erase = TRUE;
		if( pclGetDeviceInfo(gpu_devices[i].cl_id, CL_DEVICE_ENDIAN_LITTLE, sizeof(bool_param), &bool_param, NULL) != CL_SUCCESS || !bool_param)
			erase = TRUE;

		// Check if support atomics
		if( pclGetDeviceInfo(gpu_devices[i].cl_id, CL_DEVICE_VERSION, sizeof(exts), exts, NULL) != CL_SUCCESS)
			erase = TRUE;
		else
		{
			// OpenCl version > 1.0 support atomic
			if (!isdigit(exts[7]) || !isdigit(exts[9]) || (exts[7] == '1' && exts[9] == '0'))
				erase = TRUE; 
			else// OpenCL 1.0 check the extensions
			{
				pclGetDeviceInfo(gpu_devices[i].cl_id, CL_DEVICE_PROFILE, sizeof(exts), exts, NULL);

				if (!strcmp(exts, "EMBEDDED_PROFILE") && !(pclGetDeviceInfo(gpu_devices[i].cl_id, CL_DEVICE_EXTENSIONS, sizeof(exts), exts, NULL) == CL_SUCCESS && 
					strstr(exts, "cl_khr_global_int32_base_atomics") && strstr(exts, "cl_khr_local_int32_base_atomics")))
					erase = TRUE;
			}
		}

		if (erase)
		{
			// Erase the device moving the next devices
			for(j = i+1; j < num_gpu_devices; j++)
				gpu_devices[j-1] = gpu_devices[j];

			num_gpu_devices--;
			i--;// Check again
			continue;
		}
	}

	// Get GPU info
	for(i = 0; i < num_gpu_devices; i++)
		get_device_info_extended(i);
}
PUBLIC void init_opencl()
{
	if (!hOpenCL)
		hOpenCL = LoadLibrary(OPENCL_DLL);
	if(hOpenCL)
	{
		pclGetPlatformIDs			= (clGetPlatformIDsFunc)			GetProcAddress(hOpenCL, "clGetPlatformIDs");
		pclGetDeviceIDs				= (clGetDeviceIDsFunc)				GetProcAddress(hOpenCL, "clGetDeviceIDs");
		pclGetDeviceInfo			= (clGetDeviceInfoFunc)				GetProcAddress(hOpenCL, "clGetDeviceInfo");
		pclCreateContext			= (clCreateContextFunc)				GetProcAddress(hOpenCL, "clCreateContext");
		pclCreateCommandQueue		= (clCreateCommandQueueFunc)		GetProcAddress(hOpenCL, "clCreateCommandQueue");
		pclCreateProgramWithSource  = (clCreateProgramWithSourceFunc)	GetProcAddress(hOpenCL, "clCreateProgramWithSource");
		pclBuildProgram				= (clBuildProgramFunc)				GetProcAddress(hOpenCL, "clBuildProgram");
		pclCreateKernel				= (clCreateKernelFunc)				GetProcAddress(hOpenCL, "clCreateKernel");
		pclCreateBuffer				= (clCreateBufferFunc)				GetProcAddress(hOpenCL, "clCreateBuffer");
		pclSetKernelArg				= (clSetKernelArgFunc)				GetProcAddress(hOpenCL, "clSetKernelArg");
		pclEnqueueNDRangeKernel		= (clEnqueueNDRangeKernelFunc)		GetProcAddress(hOpenCL, "clEnqueueNDRangeKernel");
		pclFinish					= (clFinishFunc)					GetProcAddress(hOpenCL, "clFinish");
		pclFlush					= (clFinishFunc)					GetProcAddress(hOpenCL, "clFlush");
		pclReleaseMemObject			= (clReleaseMemObjectFunc)			GetProcAddress(hOpenCL, "clReleaseMemObject");
		pclReleaseKernel			= (clReleaseKernelFunc)				GetProcAddress(hOpenCL, "clReleaseKernel");
		pclReleaseProgram			= (clReleaseProgramFunc)			GetProcAddress(hOpenCL, "clReleaseProgram");
		pclReleaseCommandQueue		= (clReleaseCommandQueueFunc)		GetProcAddress(hOpenCL, "clReleaseCommandQueue");
		pclReleaseContext			= (clReleaseContextFunc)			GetProcAddress(hOpenCL, "clReleaseContext");
		pclEnqueueReadBuffer		= (clEnqueueReadBufferFunc)			GetProcAddress(hOpenCL, "clEnqueueReadBuffer");
		pclEnqueueWriteBuffer		= (clEnqueueWriteBufferFunc)		GetProcAddress(hOpenCL, "clEnqueueWriteBuffer");
		pclEnqueueCopyBuffer		= (clEnqueueCopyBufferFunc)			GetProcAddress(hOpenCL, "clEnqueueCopyBuffer");

		pclGetEventProfilingInfo	= (clGetEventProfilingInfoFunc)		GetProcAddress(hOpenCL, "clGetEventProfilingInfo");
		pclReleaseEvent				= (clReleaseEventFunc)				GetProcAddress(hOpenCL, "clReleaseEvent");
		pclGetProgramInfo			= (clGetProgramInfoFunc)			GetProcAddress(hOpenCL, "clGetProgramInfo");
		pclCreateProgramWithBinary  = (clCreateProgramWithBinaryFunc)	GetProcAddress(hOpenCL, "clCreateProgramWithBinary");
#ifdef _DEBUG
		pclGetProgramBuildInfo		= (clGetProgramBuildInfoFunc)		GetProcAddress(hOpenCL, "clGetProgramBuildInfo");
#endif

		if( pclGetPlatformIDs && pclGetDeviceIDs && pclGetDeviceInfo && pclCreateContext && pclCreateCommandQueue && pclGetProgramInfo &&
			pclCreateProgramWithSource && pclBuildProgram && pclCreateKernel && pclCreateBuffer && pclFlush && pclGetEventProfilingInfo &&
			pclSetKernelArg && pclEnqueueNDRangeKernel && pclFinish && pclReleaseMemObject && pclReleaseKernel && pclReleaseEvent && pclEnqueueCopyBuffer &&
			pclReleaseProgram && pclReleaseCommandQueue && pclReleaseContext && pclEnqueueReadBuffer && pclEnqueueWriteBuffer && pclCreateProgramWithBinary)
			find_all_gpus();
	}
}

PUBLIC void create_opencl_param(OpenCL_Param* result, cl_uint gpu_index, generate_key_funtion* gen, cl_uint size_ouput, int use_ptx)
{
	cl_int code;

	result->max_work_group_size = gpu_devices[gpu_index].max_work_group_size;
	result->use_ptx = use_ptx && (gpu_devices[gpu_index].flags & GPU_FLAG_SUPPORT_PTX);

#ifndef __ANDROID__
	if(result->use_ptx)
		result->cu_id = cuda_gpu_devices[gpu_index];
	else
#endif
		result->id = gpu_devices[gpu_index].cl_id;

	// Create the OpenCl context
#ifndef __ANDROID__
	if(result->use_ptx)
		code = cuCtxCreate(&result->cu_context, CU_CTX_LMEM_RESIZE_TO_MAX | CU_CTX_SCHED_YIELD, result->cu_id);
	else
#endif
		result->context = pclCreateContext( NULL, 1, &result->id, NULL, NULL, &code);
	// Note: CUDA_SUCCESS equivalent to CL_SUCCESS
	if (code == CL_SUCCESS)
	{
		if(!result->use_ptx)
			result->queue = pclCreateCommandQueue( result->context, result->id, 0, &code );
		if (code == CL_SUCCESS)
		{
			// Quick approximation of good NUM_KEYS_OPENCL
			cl_uint base_val = gpu_devices[gpu_index].cores*gpu_devices[gpu_index].max_clock_frequency/64;
			// Calculate next power of 2 of base_val
			cl_uint next_pwd_2 = base_val-1;
			next_pwd_2 |= next_pwd_2 >> 1;
			next_pwd_2 |= next_pwd_2 >> 2;
			next_pwd_2 |= next_pwd_2 >> 4;
			next_pwd_2 |= next_pwd_2 >> 8;
			next_pwd_2 |= next_pwd_2 >> 16;
			next_pwd_2++;
			if(!next_pwd_2) next_pwd_2++;
			// Approximate base_val to a power of 2
			result->NUM_KEYS_OPENCL = 1024 * ((next_pwd_2 - base_val) > (base_val - (next_pwd_2>>1)) ? (next_pwd_2>>1) : next_pwd_2);
			result->NUM_KEYS_OPENCL /= gpu_devices[gpu_index].NUM_KEYS_OPENCL_DIVIDER;

			result->gen = gen;
			result->output = (cl_uint*)malloc(size_ouput);
		}
		else
		{
			pclReleaseContext(result->context);
			free(result);
		}
	}
	else
	{
		free(result);
	}
}
PUBLIC void release_opencl_param(OpenCL_Param* param)
{
	if(param)
	{
		cl_uint i;

		// Release memory objects
		for(i = 0; i < LENGHT(param->mems); i++)
		{
#ifndef __ANDROID__
			if( param->use_ptx && param->cu_mems[i])	cuMemFree(param->cu_mems[i]);
#endif
			if(!param->use_ptx && param->mems[i])		pclReleaseMemObject(param->mems[i]);
		}

		// Release kernels
		if(!param->use_ptx)
			for(i = 0; i < LENGHT(param->kernels); i++)
				if(param->kernels[i])
					pclReleaseKernel(param->kernels[i]);

		// Release all kernels used by rules
		if (param->rules.kernels)
		{
			for (i = 0; i < param->rules.num_kernels; i++)
				if (param->rules.kernels[i])
					pclReleaseKernel(param->rules.kernels[i]);
			free(param->rules.kernels);

			if (param->rules.work_group_sizes)
				free(param->rules.work_group_sizes);

#ifndef OCL_RULES_ALL_IN_GPU
			pclReleaseProgram(param->rules.program);

			for (int len = 0; len < LENGHT(param->rules.binaries); len++)
				if (param->rules.binaries[len])
					free(param->rules.binaries[len]);
#endif
		}
		// Release all programs used by rules
		/*if (param->rules_programs)
		{
			for (i = 0; i < param->num_rules_programs; i++)
				pclReleaseProgram(param->rules_programs[i]);
			free(param->rules_programs);
		}*/

		// Release program
#ifndef __ANDROID__
		if( param->use_ptx && param->cu_module)	cuModuleUnload(param->cu_module);
#endif
		if(!param->use_ptx && param->program)	pclReleaseProgram(param->program);

		// Release Command queue
		if(!param->use_ptx && param->queue)	pclReleaseCommandQueue(param->queue);

		// Release context
#ifndef __ANDROID__
		if( param->use_ptx && param->cu_context)	cuCtxDestroy(param->cu_context);
#endif
		if(!param->use_ptx && param->context)		pclReleaseContext(param->context);

		if(param->output) free(param->output);

		free(param);
	}
}
PUBLIC int build_opencl_program(OpenCL_Param* param, const char* source, char* compiler_options)
{
	cl_int code;
	//int64_t init = get_milliseconds();

	// Perform runtime source compilation, and obtain kernel entry point.
#ifndef __ANDROID__
	if(param->use_ptx)
		code = cuModuleLoadData(&param->cu_module, source);
	else
#endif
		param->program = pclCreateProgramWithSource( param->context, 1, &source, NULL, &code );
	if (code != CL_SUCCESS)
		return FALSE;
	
	// Build program
	if(!param->use_ptx)
		// For Nvidia GPUs: "-cl-nv-verbose"
		if (pclBuildProgram(param->program, 1, &param->id, compiler_options, NULL, NULL) != CL_SUCCESS)
		{
#ifdef _DEBUG

#ifdef __ANDROID__
#define DEBUG_DIR "/sdcard/"
#else
#define DEBUG_DIR "C:\\Users\\alain\\Desktop\\"
#endif
			FILE* errors = fopen(DEBUG_DIR"build_errors.txt","w");
			int size_log = 10*1024*1024;
			char* log = (char*)malloc(size_log);
			pclGetProgramBuildInfo(param->program, param->id, CL_PROGRAM_BUILD_LOG, size_log, (void*)log, NULL);

			fwrite(log, 1, strlen(log), errors);
			fclose(errors);
			free(log);

			FILE* code = fopen(DEBUG_DIR"source_code.c","w");
			fwrite(source, 1, strlen(source), code);
			fclose(code);
#endif
			hs_log(HS_LOG_DEBUG, "GPU compilation failed!", "error");
			return FALSE;
		}
#ifdef _DEBUG
		else
		{
			//// Save build Log
			//FILE* build_log = fopen(DEBUG_DIR"build_log.txt", "w");
			//int size_log = 4 * 1024 * 1024;
			//char* log = (char*)malloc(size_log);
			//pclGetProgramBuildInfo(param->program, param->id, CL_PROGRAM_BUILD_LOG, size_log, (void*)log, NULL);

			//fwrite(log, 1, strlen(log), build_log);
			//fclose(build_log);
			//free(log);

			//// Save PTX code for Nvidia GPUs
			//size_t binary_size;
			//unsigned char* binary_code[1];
			//pclGetProgramInfo(param->program, CL_PROGRAM_BINARY_SIZES, sizeof(size_t), &binary_size, NULL);
			//binary_code[0] = (char*)malloc(binary_size);
			//pclGetProgramInfo(param->program, CL_PROGRAM_BINARIES, sizeof(binary_code), &binary_code, NULL);

			//FILE* binary_file = fopen("C:\\Users\\alain\\Desktop\\code_asm.ptx", "w");
			//fwrite(binary_code[0], 1, binary_size, binary_file);
			//fclose(binary_file);
			//free(binary_code[0]);
		}
#endif
	
	//int64_t duration = get_milliseconds() - init;
	//hs_log(HS_LOG_INFO, "Test Suite", "Build time: %i ms", (int)duration);

	return TRUE;
}

PUBLIC int create_opencl_mem(OpenCL_Param* param, uint32_t index, cl_mem_flags flag, size_t size, void* host_ptr)
{
#ifndef __ANDROID__
	if(param->use_ptx)
		return (CUDA_SUCCESS == cuMemAlloc(&param->cu_mems[index], size));
	else
#endif
	{
		cl_int error_code;
		param->mems[index] = pclCreateBuffer(param->context, flag, size, host_ptr, &error_code);
		return (CL_SUCCESS == error_code);
	}
}
PUBLIC int create_kernel(OpenCL_Param* param, uint32_t index, char* kernel_name)
{
	cl_int code;
#ifndef __ANDROID__
	if(param->use_ptx)
		code = cuModuleGetFunction(param->cu_kernels+index, param->cu_module, kernel_name);
	else
#endif
		param->kernels[index] = pclCreateKernel( param->program, kernel_name, &code );
	return code;
}
PUBLIC void cl_write_buffer(OpenCL_Param* param, uint32_t index, size_t size, void* ptr)
{
#ifndef __ANDROID__
	if(param->use_ptx)
		cuMemcpyHtoD(param->cu_mems[index], ptr, size);
	else
#endif
		pclEnqueueWriteBuffer(param->queue, param->mems[index], CL_FALSE, 0, size, ptr, 0, NULL, NULL);
}

#include "attack.h"

PUBLIC void change_value_proportionally(cl_uint* value, cl_uint duration)
{
	if (duration >= OCL_NORMAL_KERNEL_TIME)
	{
		cl_uint floor_value = floor_power_2(duration / OCL_NORMAL_KERNEL_TIME);
		cl_uint ceil_value = floor_value * 2;

		cl_uint multipler = floor_value;
		if (abs(OCL_NORMAL_KERNEL_TIME - duration / floor_value) > abs(OCL_NORMAL_KERNEL_TIME - duration / ceil_value))
			multipler = ceil_value;

		value[0] /= multipler;
	}
	else
	{
		cl_uint multipler = 32;
		if(duration)
		{
			cl_uint floor_value = floor_power_2(OCL_NORMAL_KERNEL_TIME / duration);
			cl_uint ceil_value = floor_value * 2;

			multipler = floor_value;
			if (abs(OCL_NORMAL_KERNEL_TIME - duration * floor_value) > abs(OCL_NORMAL_KERNEL_TIME - duration * ceil_value))
				multipler = ceil_value;
		}
			
		value[0] *= multipler;
	}
}
PUBLIC cl_ulong ocl_calculate_best_work_group(OpenCL_Param* param, cl_kernel* kernel, cl_uint max_keys, int* kernel_param, int kernel_param_index, cl_bool depend_workgroup, cl_bool change_param)
{
	cl_uint zero = 0;
	// Select best work_group
	if (change_param && !kernel_param)
		while (param->NUM_KEYS_OPENCL >= max_keys)
			param->NUM_KEYS_OPENCL /= 2;

	size_t num_work_items = param->NUM_KEYS_OPENCL;
	int kernel_index = 0;

	// Time related
	cl_ulong init, duration, best_duration = INT_MAX;
	
	cl_event kernel_event;
	cl_command_queue prof_queue = pclCreateCommandQueue(param->context, param->id, CL_QUEUE_PROFILING_ENABLE, NULL);

	if (kernel_param && kernel_param_index >= 0)
		pclSetKernelArg(kernel[kernel_index], kernel_param_index, sizeof(int), (void*)kernel_param);

	// Warm up
	pclFinish(param->queue);
	pclFinish(prof_queue);
	int bad_execution = FALSE;
	
	if (CL_SUCCESS != pclEnqueueNDRangeKernel(prof_queue, kernel[kernel_index], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, &kernel_event))
		bad_execution = TRUE;
	if (CL_SUCCESS != pclFinish(prof_queue))
		bad_execution = TRUE;

	pclEnqueueWriteBuffer(prof_queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, sizeof(cl_uint), &zero, 0, NULL, NULL);

	while (bad_execution && param->max_work_group_size >= OCL_MIN_WORKGROUP_SIZE)
	{
		param->max_work_group_size /= 2;
		if (depend_workgroup)
			kernel_index++;
		bad_execution = FALSE;

		if (CL_SUCCESS != pclEnqueueNDRangeKernel(prof_queue, kernel[kernel_index], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, &kernel_event))
			bad_execution = TRUE;
		if (CL_SUCCESS != pclFinish(prof_queue))
			bad_execution = TRUE;

		pclEnqueueWriteBuffer(prof_queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, sizeof(cl_uint), &zero, 0, NULL, NULL);
	}

	if (!bad_execution)
	{
		pclGetEventProfilingInfo(kernel_event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &init, NULL);
		pclGetEventProfilingInfo(kernel_event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &duration, NULL);
		pclReleaseEvent(kernel_event);
		duration -= init;
		duration /= 1000000;
	}
	else
		duration = OCL_NORMAL_KERNEL_TIME;

	if (duration > (OCL_NORMAL_KERNEL_TIME * 4 / 3))
		hs_log(HS_LOG_WARNING, "calculate_best_work_group", "Warm-up kernel duration: %ums", (cl_uint)duration);
	
	// Select a good num_work_items
	if (change_param)
	{
		if (kernel_param)
		{
			change_value_proportionally(kernel_param, (cl_uint)duration);
			kernel_param[0] = __min(kernel_param[0], (int)max_keys);

			if (kernel_param_index >= 0)
				pclSetKernelArg(kernel[kernel_index], kernel_param_index, sizeof(int), (void*)kernel_param);
		}
		else
		{
			change_value_proportionally(&param->NUM_KEYS_OPENCL, (cl_uint)duration);

			while (param->NUM_KEYS_OPENCL >= max_keys)
				param->NUM_KEYS_OPENCL /= 2;
			num_work_items = param->NUM_KEYS_OPENCL;
		}
	}

	size_t best_work_group = param->max_work_group_size;
	if (param->max_work_group_size < OCL_MIN_WORKGROUP_SIZE)
	{
		best_duration = duration * 4;
		hs_log(HS_LOG_WARNING, "calculate_best_work_group", "Very small workgroup: %u", (cl_uint)param->max_work_group_size);
	}
	for (size_t work_group = param->max_work_group_size; work_group >= OCL_MIN_WORKGROUP_SIZE; work_group /= 2)
	{
		size_t warm_num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_work_items / 4, work_group);
		// Warm-up
		if (CL_SUCCESS != pclEnqueueNDRangeKernel(prof_queue, kernel[kernel_index], 1, NULL, &warm_num_work_items, &work_group, 0, NULL, NULL))
			continue;
		if (CL_SUCCESS != pclEnqueueWriteBuffer(prof_queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, sizeof(cl_uint), &zero, 0, NULL, NULL))
			continue;

		if (CL_SUCCESS != pclEnqueueNDRangeKernel(prof_queue, kernel[kernel_index], 1, NULL, &num_work_items, &work_group, 0, NULL, &kernel_event))
			continue;
		if (CL_SUCCESS != pclFinish(prof_queue))
			continue;
		pclGetEventProfilingInfo(kernel_event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &init, NULL);
		pclGetEventProfilingInfo(kernel_event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &duration, NULL);
		pclReleaseEvent(kernel_event);
		duration -= init;
		duration /= 250000;

		if (duration < best_duration)
		{
			best_duration = duration;
			best_work_group = work_group;
		}
		pclEnqueueWriteBuffer(prof_queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, sizeof(cl_uint), &zero, 0, NULL, NULL);

		if (depend_workgroup)
			kernel_index++;
	}
	param->max_work_group_size = best_work_group;
	best_duration /= 4;
	// Convert to miliseconds
	//duration.QuadPart = duration.QuadPart * 1000 / timmer_freq.QuadPart;
	// Select a good num_work_items
	if (change_param)
	{
		if (kernel_param)
		{
			change_value_proportionally(kernel_param, (cl_uint)best_duration);
			kernel_param[0] = __min(kernel_param[0], (int)max_keys);
		}
		else
		{
			change_value_proportionally(&param->NUM_KEYS_OPENCL, (cl_uint)best_duration);
			while (param->NUM_KEYS_OPENCL >= max_keys)
				param->NUM_KEYS_OPENCL /= 2;
		}
	}

	if (best_duration > (OCL_NORMAL_KERNEL_TIME * 4 / 3) || best_duration < (OCL_NORMAL_KERNEL_TIME / 2))
		hs_log(HS_LOG_WARNING, "calculate_best_work_group", "Final kernel duration: %ums", (cl_uint)best_duration);

	//hs_log(HS_LOG_DEBUG, "calculate_best_work_group", "duration: %ums\nkeys:%u\nwork_group_size:%u", (cl_uint)best_duration, param->NUM_KEYS_OPENCL, param->max_work_group_size);

	// TODO: If used in low priority
	//param->NUM_KEYS_OPENCL /= 2;

	pclReleaseCommandQueue(prof_queue);

	return best_duration;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common opencl charset non-salted
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Get the number of 32 bits registers needed to represent the charset params
PUBLIC cl_uint get_number_of_32regs(cl_uint num_chars, cl_uint key_lenght, cl_uint* bits_by_char)
{
	_BitScanReverse(bits_by_char, ceil_power_2(num_chars));

	cl_uint chars_in_reg = 32 / bits_by_char[0];

	return (key_lenght + chars_in_reg-1) / chars_in_reg;
}
PRIVATE void generate_kernel_params(char* source, cl_uint key_lenght)
{
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
	cl_uint bits_by_char;
	cl_uint num_param_regs = get_number_of_32regs(num_char_in_charset, key_lenght-1, &bits_by_char);

	for (cl_uint i = 0; i < num_param_regs; i++)
		sprintf(source + strlen(source), "uint current_key%u,", i);
#else
	sprintf(source + strlen(source), "__constant uchar* current_key __attribute__((max_constant_size(%u))),", __max(2, key_lenght));
#endif

	strcat(source, "__global uint* restrict output");

	if (num_passwords_loaded > 1)
		strcat(source, ",const __global uint* restrict cbg_table,const __global uint* restrict binary_values,const __global ushort* restrict cbg_filter");
}
PUBLIC void ocl_charset_load_buffer_be(char* source, cl_uint key_lenght, cl_uint* vector_size, DivisionParams div_param, char* nt_buffer[])
{
	cl_uint i;
	// TODO: TEST this: Reduce vector size
	//if (vector_size <= 3)
	{
		*vector_size = 1;
	}
	//else
	//	vector_size /= 2;

	// Begin function code
	sprintf(source + strlen(source), "uint indx,nt_buffer0=0;");

#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
	cl_uint bits_by_char;
	_BitScanReverse(&bits_by_char, ceil_power_2(num_char_in_charset));
	cl_uint chars_in_reg = 32 / bits_by_char;
#endif

	for (i = 0; i < key_lenght / 4; i++)
		for (cl_uint j = 0; j < 4; j++)
			if (i || j)
			{
				cl_uint key_index = 4 * i + j;
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
				key_index--;
				sprintf(source + strlen(source), "max_number+=(current_key%i>>%uu)&%uu;", key_index / chars_in_reg, (key_index%chars_in_reg)*bits_by_char, ceil_power_2(num_char_in_charset) - 1);
#else
				sprintf(source + strlen(source), "max_number+=current_key[%i];", key_index);
#endif
				// Perform division
				if (div_param.magic)sprintf(source + strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
				else				sprintf(source + strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

				if (j)
					sprintf(source + strlen(source), "nt_buffer%u+=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<%uu;", i, 24 - 8 * j);
				else
					sprintf(source + strlen(source), "uint nt_buffer%u=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<24u;", i);

				sprintf(source + strlen(source), "max_number=indx;");
			}

	if (key_lenght & 3)
	{
		for (cl_uint j = 0; j < (key_lenght & 3); j++)
			if (i || j)
			{
				cl_uint key_index = 4 * i + j;
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
				key_index--;
				sprintf(source + strlen(source), "max_number+=(current_key%i>>%uu)&%uu;", key_index / chars_in_reg, (key_index%chars_in_reg)*bits_by_char, ceil_power_2(num_char_in_charset) - 1);
#else
				sprintf(source + strlen(source), "max_number+=current_key[%i];", key_index);
#endif
				// Perform division
				if (div_param.magic)sprintf(source + strlen(source), "indx=mul_hi(max_number+%iU,%uU)>>%iU;", (int)div_param.sum_one, div_param.magic, (int)div_param.shift);// Normal division
				else				sprintf(source + strlen(source), "indx=max_number>>%iU;", (int)div_param.shift);// Power of two division

				if (j)
					sprintf(source + strlen(source), "nt_buffer%u+=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<%uu;", i, 24 - 8 * j);
				else
					sprintf(source + strlen(source), "uint nt_buffer%u=((uint)charset[max_number-NUM_CHAR_IN_CHARSET*indx])<<24u;", i);

				sprintf(source + strlen(source), "max_number=indx;");
			}

		sprintf(source + strlen(source), "nt_buffer%u+=%uu;", i, 0x80 << (24 - 8 * (key_lenght & 3)));
	}
	else
		nt_buffer[i] = "+0x80000000u";

	for (i = key_lenght / 4 + 1; i < 7; i++)
		nt_buffer[i] = "";
}


PRIVATE char* ocl_gen_charset_code_common(GPUDevice* gpu, ocl_write_header_func* ocl_write_header, int BINARY_SIZE, DivisionParams* div_param, cl_uint max_num_kernels)
{
	char* source = (char*)malloc(1024 * 64 * max_num_kernels);

	//Initial values
	ocl_write_header(source, gpu, /*ntlm_size_bit_table*/0);
	sprintf(source + strlen(source), "#define NUM_CHAR_IN_CHARSET %uu\n", num_char_in_charset);

	strcat(source, "__constant uchar charset[]={");

	// Fill charset
	for (cl_uint i = 0; i < num_char_in_charset; i++)
		sprintf(source + strlen(source), "%s%uU", i ? "," : "", (cl_uint)charset[i]);
	// XOR fast
	if (!is_charset_consecutive(charset))
	{
		for (cl_uint i = 0; i < num_char_in_charset; i += gpu->vector_int_size)
		{
			sprintf(source + strlen(source), ",%uU", i ? (cl_uint)(charset[i] ^ charset[i - gpu->vector_int_size]) : (cl_uint)(charset[0]));

			for (cl_uint j = 1; j < gpu->vector_int_size; j++)
				sprintf(source + strlen(source), ",%uU", i ? (cl_uint)(charset[(i + j) % num_char_in_charset] ^ charset[i + j - gpu->vector_int_size]) : (cl_uint)(charset[j]));
		}
	}
	strcat(source, "};\n");

	div_param[0] = get_div_params(num_char_in_charset);

	return source;
}
PRIVATE char* ocl_gen_charset_code(cl_uint output_size, GPUDevice* gpu, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_with_lenght_func* ocl_gen_kernel_with_lenght, int BINARY_SIZE, cl_uint workgroup, cl_bool require_workgroup)
{
	DivisionParams div_param;
	char* str_comp[] = { ".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf" };
	if (gpu->vector_int_size == 1)str_comp[0] = "";

	char* source = ocl_gen_charset_code_common(gpu, ocl_write_header, BINARY_SIZE, &div_param, __max(1, max_lenght - current_key_lenght + 1));
	
	// Generate code for all lengths in range
	for (cl_uint i = current_key_lenght; i <= max_lenght; i++)
	{
		// Function definition
		if (require_workgroup)
			sprintf(source + strlen(source), "\n__attribute__((reqd_work_group_size(%i, 1, 1))) ", workgroup);
		
		sprintf(source + strlen(source), "\n__kernel void crypt%u(", i);

		generate_kernel_params(source, i);

		// Begin function code
		sprintf(source + strlen(source), "){uint max_number=get_global_id(0);");

		ocl_gen_kernel_with_lenght(source + strlen(source), i, gpu->vector_int_size, /*ntlm_size_bit_table*/0, output_size, div_param, str_comp, /*value_map_collision*/0, workgroup);
	}

	return source;
}
PRIVATE char* ocl_gen_charset_code_many_kernels(cl_uint output_size, GPUDevice* gpu, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_with_lenght_func** ocl_gen_kernel_with_lenght, cl_uint num_gen_kernels, int BINARY_SIZE, cl_uint workgroup)
{
	DivisionParams div_param;
	char* str_comp[] = { ".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf" };
	if (gpu->vector_int_size == 1)str_comp[0] = "";

	char* source = ocl_gen_charset_code_common(gpu, ocl_write_header, BINARY_SIZE, &div_param, num_gen_kernels);

	// Generate code for all lengths in range
	for (cl_uint i = 0; i < num_gen_kernels; i++)
	{
		// Function definition
		sprintf(source + strlen(source), "\n__kernel void crypt%u(", i);

		generate_kernel_params(source, max_lenght);

		// Begin function code
		sprintf(source + strlen(source), "){uint max_number=get_global_id(0);");

		ocl_gen_kernel_with_lenght[i](source + strlen(source), max_lenght, gpu->vector_int_size, /*ntlm_size_bit_table*/0, output_size, div_param, str_comp, /*value_map_collision*/0, workgroup);
	}

	return source;
}
PRIVATE char* ocl_gen_charset_code_depend_workgroup(cl_uint output_size, GPUDevice* gpu, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_with_lenght_func* ocl_gen_kernel_with_lenght, int BINARY_SIZE, cl_uint max_work_group_size)
{
	DivisionParams div_param;
	cl_uint workgroup_map[32];
	cl_uint count_workgroup = 0;
	char* str_comp[] = { ".s0", ".s1", ".s2", ".s3", ".s4", ".s5", ".s6", ".s7", ".s8", ".s9", ".sa", ".sb", ".sc", ".sd", ".se", ".sf" };
	if (gpu->vector_int_size == 1)str_comp[0] = "";

	// Count the possible number of workgroup
	for (cl_uint workgroup = max_work_group_size; workgroup >= OCL_MIN_WORKGROUP_SIZE; count_workgroup++, workgroup /= 2)
		workgroup_map[count_workgroup] = workgroup;

	char* source = ocl_gen_charset_code_common(gpu, ocl_write_header, BINARY_SIZE, &div_param, __max(1, count_workgroup));

	// Generate code for all lengths in range
	for (cl_uint i = 0; i < count_workgroup; i++)
	{
		// Function definition
		sprintf(source + strlen(source), "\n__attribute__((reqd_work_group_size(%i, 1, 1))) __kernel void crypt%u(", workgroup_map[i], i);

		generate_kernel_params(source, max_lenght);

		// Begin function code
		sprintf(source + strlen(source), "){uint max_number=get_global_id(0);");

		ocl_gen_kernel_with_lenght(source + strlen(source), max_lenght, gpu->vector_int_size, /*ntlm_size_bit_table*/0, output_size, div_param, str_comp, /*value_map_collision*/0, workgroup_map[i]);
	}

	return source;
}

PRIVATE void ocl_charset_work(OpenCL_Param* param)
{
	unsigned char buffer[MAX_KEY_LENGHT_SMALL + 2 * sizeof(cl_uint)];
	cl_uint num_found = 0;
	int is_consecutive = is_charset_consecutive(charset);
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
	// Params compresed
	cl_uint bits_by_char, chars_in_reg;
	_BitScanReverse(&bits_by_char, ceil_power_2(num_char_in_charset));
	chars_in_reg = 32 / bits_by_char;
	cl_uint max_j = 33 - bits_by_char;
#endif

	HS_SET_PRIORITY_GPU_THREAD;

	while (continue_attack && param->gen(buffer, param->NUM_KEYS_OPENCL, param->thread_id))
	{
		cl_uint key_lenght = ((cl_uint*)buffer)[8];
		cl_uint num_keys_filled = ((cl_uint*)buffer)[9];
		size_t num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_keys_filled, param->max_work_group_size);// Convert to multiple of work_group_size

#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
		// Set registers params
		cl_uint num_param_regs = (key_lenght + chars_in_reg - 2) / chars_in_reg;
		cl_uint key_index = 1;
		for (cl_uint i = 0; i < num_param_regs; i++)
		{
			cl_uint key_param = buffer[key_index]; key_index++;

			for (cl_uint j = bits_by_char; j < max_j && key_index < key_lenght; j += bits_by_char, key_index++)
				key_param |= buffer[key_index] << j;

			pclSetKernelArg(param->kernels[key_lenght], i, sizeof(cl_uint), (void*)&key_param);
		}
#else
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_CURRENT_KEY], CL_FALSE, 0, key_lenght, buffer, 0, NULL, NULL);
#endif
		// TODO: Check if there is some problem
		/*if (result != CL_SUCCESS)
			OCL_REPORT_ERROR("pclEnqueueWriteBuffer");*/
		pclEnqueueNDRangeKernel(param->queue, param->kernels[key_lenght], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		//if (result != CL_SUCCESS)
		//	OCL_REPORT_ERROR("pclEnqueueNDRangeKernel");
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);
		//if (result != CL_SUCCESS)
		//	OCL_REPORT_ERROR("pclEnqueueReadBuffer");

		// GPU found some passwords
		if (num_found)
		{
			// TODO: manage this case
			if (num_found > (cl_uint)param->param0)
				num_found = param->param0;
			ocl_charset_process_found(param, &num_found, is_consecutive, buffer, key_lenght);
		}

		report_keys_processed(num_keys_filled*num_char_in_charset);
	}

	release_opencl_param(param);
	finish_thread();
}
PRIVATE int ocl_charset_init_common(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE
	, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_with_lenght_func** ocl_gen_kernel_with_lenght, cl_uint num_gen_kernels, void* ocl_empty_hash, cl_uint local_bytes_needed, cl_uint keys_opencl_divider)
{
	//																						Max surpluss because OCL_MULTIPLE_WORKGROUP_SIZE
	cl_uint output_size = 2 * sizeof(cl_uint)* (__min(num_passwords_loaded, 10000000) + ((cl_uint)gpu_devices[gpu_index].max_work_group_size)*num_char_in_charset);

	create_opencl_param(param, gpu_index, gen, output_size, FALSE);
	if (!param)	return FALSE;

	// Do not allow blank in GPU
	if (current_key_lenght == 0)
	{
		unsigned char* bin = (unsigned char*)binary_values;

		for (cl_uint i = 0; i < num_passwords_loaded; i++, bin += BINARY_SIZE)
			if (!memcmp(bin, ocl_empty_hash, BINARY_SIZE))
				password_was_found(i, "");

		current_key_lenght = 1;
		report_keys_processed(1);
	}

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL = param->NUM_KEYS_OPENCL * 4 * __max(1, 120 / num_char_in_charset) / keys_opencl_divider;
	if (num_passwords_loaded == 1) param->NUM_KEYS_OPENCL *= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint)*__min(param->NUM_KEYS_OPENCL, (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size / (2 * 2 * sizeof(cl_uint))));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Create memory objects
#ifndef HS_OCL_CURRENT_KEY_AS_REGISTERS
	if(!create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_ONLY, MAX_KEY_LENGHT, NULL))
	{
		release_opencl_param(param);
		return FALSE;
	}
#endif
	if(!create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, sizeof(cl_uint)+output_size, NULL)) { release_opencl_param(param); return FALSE; }

	if (num_passwords_loaded > 1)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			if(!create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(cbg_mask + 1ull), cbg_table))				{ release_opencl_param(param); return FALSE; }
			if(!create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_ushort)*(cbg_mask + 1ull), cbg_filter))		{ release_opencl_param(param); return FALSE; }
			if(!create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values))	{ release_opencl_param(param); return FALSE; }
		}
		else
		{
			if(!create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY, sizeof(cl_uint)*(cbg_mask + 1ull), NULL))			{ release_opencl_param(param); return FALSE; }
			if(!create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY, sizeof(cl_ushort)*(cbg_mask + 1ull), NULL))	{ release_opencl_param(param); return FALSE; }
			if(!create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL))	{ release_opencl_param(param); return FALSE; }
		}
	}

	// Copy data to GPU
	unsigned char zero[MAX_KEY_LENGHT_SMALL];
	memset(zero, 0, MAX_KEY_LENGHT_SMALL);
#ifndef HS_OCL_CURRENT_KEY_AS_REGISTERS
	cl_write_buffer(param, GPU_CURRENT_KEY, MAX_KEY_LENGHT, zero);
#endif
	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), zero);
	if (num_passwords_loaded > 1 && !(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
	{
		cl_write_buffer(param, GPU_TABLE, sizeof(cl_uint)* (cbg_mask + 1ull), cbg_table);
		cl_write_buffer(param, GPU_BIT_TABLE, sizeof(cl_ushort)* (cbg_mask+1ull), cbg_filter);
		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE*num_passwords_loaded, binary_values);

		pclFinish(param->queue);
	}

	// Generate code
	param->param0 = output_size / 2 / sizeof(cl_uint);
	char* source = NULL;

	if (num_gen_kernels > 1)
	{
		source = ocl_gen_charset_code_many_kernels(param->param0, &gpu_devices[gpu_index], ocl_write_header, ocl_gen_kernel_with_lenght, num_gen_kernels, BINARY_SIZE, (cl_uint)param->max_work_group_size);
	}
	else
	{
		if (local_bytes_needed)
		{
			if (param->max_work_group_size*local_bytes_needed >= gpu_devices[gpu_index].local_memory_size)
				param->max_work_group_size = floor_power_2((cl_uint)((gpu_devices[gpu_index].local_memory_size - 1) / local_bytes_needed));
			source = ocl_gen_charset_code_depend_workgroup(param->param0, &gpu_devices[gpu_index], ocl_write_header, *ocl_gen_kernel_with_lenght, BINARY_SIZE, (cl_uint)param->max_work_group_size);// Generate opencl code
		}
		else
			source = ocl_gen_charset_code(param->param0, &gpu_devices[gpu_index], ocl_write_header, *ocl_gen_kernel_with_lenght, BINARY_SIZE, (cl_uint)param->max_work_group_size, CL_FALSE);// Generate opencl code
	}

	//size_t len = strlen(source);
	//{// Uncomment this to view opencl code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	cl_uint min_i = 0, max_i = 0;
	if (num_gen_kernels > 1)
	{
		max_i = num_gen_kernels;
	}
	else
	{
		if (local_bytes_needed)
		{
			for (cl_uint workgroup = (cl_uint)param->max_work_group_size; workgroup >= OCL_MIN_WORKGROUP_SIZE; max_i++, workgroup /= 2);
		}
		else
		{
			min_i = current_key_lenght;
			max_i = max_lenght + 1;
		}
	}

	// Crypt by length
	for (cl_uint i = min_i; i < max_i; i++)
	{
		char name_buffer[16];
		sprintf(name_buffer, "crypt%u", i);
		cl_int code = create_kernel(param, i, name_buffer);
		if (code != CL_SUCCESS)
		{
			release_opencl_param(param);
			return FALSE;
		}

		// Set OpenCL kernel params
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
		cl_uint bits_by_char;
		cl_uint key_lenght = (num_gen_kernels > 1 || local_bytes_needed) ? max_lenght : i;
		cl_uint num_param_regs = get_number_of_32regs(num_char_in_charset, key_lenght-1, &bits_by_char);
		for (cl_uint j = 0; j < num_param_regs; j++)
			pclSetKernelArg(param->kernels[i], j, sizeof(cl_uint), (void*)zero);
#else
		cl_uint num_param_regs = 1;
		pclSetKernelArg(param->kernels[i], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
#endif

		pclSetKernelArg(param->kernels[i], num_param_regs, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

		if (num_passwords_loaded > 1)
		{
			pclSetKernelArg(param->kernels[i], num_param_regs+1, sizeof(cl_mem), (void*)&param->mems[GPU_TABLE]);
			pclSetKernelArg(param->kernels[i], num_param_regs+2, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
			pclSetKernelArg(param->kernels[i], num_param_regs+3, sizeof(cl_mem), (void*)&param->mems[GPU_BIT_TABLE]);
		}
	}

	// Select best work_group
	if (num_gen_kernels <= 1)
		ocl_calculate_best_work_group(param, param->kernels + (local_bytes_needed ? 0 : max_lenght), UINT_MAX / num_char_in_charset, NULL, 0, local_bytes_needed, CL_TRUE);
	pclFinish(param->queue);

	free(source);
	*gpu_crypt = ocl_charset_work;

	return TRUE;
}

PRIVATE int ocl_charset_init_second_test(OpenCL_Param* param, cl_uint gpu_index, int BINARY_SIZE, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_with_lenght_func* ocl_gen_kernel_with_lenght, cl_bool require_workgroup)
{
	// Release kernels
	for (cl_uint i = 0; i < LENGHT(param->kernels); i++)
		if (param->kernels[i])
		{
			pclReleaseKernel(param->kernels[i]);
			param->kernels[i] = 0;
		}

	// Now the normal kernels
	char* source = ocl_gen_charset_code(param->param0, &gpu_devices[gpu_index], ocl_write_header, ocl_gen_kernel_with_lenght, BINARY_SIZE, (cl_uint)param->max_work_group_size, require_workgroup);// Generate opencl code

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Crypt by lenght
	for (cl_uint i = current_key_lenght; i <= max_lenght; i++)
	{
		char name_buffer[16];
		sprintf(name_buffer, "crypt%u", i);
		cl_int code = create_kernel(param, i, name_buffer);
		if (code != CL_SUCCESS)
		{
			release_opencl_param(param);
			return FALSE;
		}

		// Set OpenCL kernel params
#ifdef HS_OCL_CURRENT_KEY_AS_REGISTERS
		cl_uint bits_by_char;
		cl_uint num_param_regs = get_number_of_32regs(num_char_in_charset, i-1, &bits_by_char);
#else
		cl_uint num_param_regs = 1;
		pclSetKernelArg(param->kernels[i], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
#endif

		pclSetKernelArg(param->kernels[i], num_param_regs, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

		if (num_passwords_loaded > 1)
		{
			pclSetKernelArg(param->kernels[i], num_param_regs+1, sizeof(cl_mem), (void*)&param->mems[GPU_TABLE]);
			pclSetKernelArg(param->kernels[i], num_param_regs+2, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
			pclSetKernelArg(param->kernels[i], num_param_regs+3, sizeof(cl_mem), (void*)&param->mems[GPU_BIT_TABLE]);
		}
	}

	free(source);
	return TRUE;
}

PUBLIC int ocl_charset_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE
	, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_with_lenght_func* ocl_gen_kernel_with_lenght, void* ocl_empty_hash, cl_uint local_bytes_needed, cl_uint keys_opencl_divider)
{
	if (!ocl_charset_init_common(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_header, &ocl_gen_kernel_with_lenght, 1, ocl_empty_hash, local_bytes_needed, keys_opencl_divider))
		return FALSE;

	if (local_bytes_needed)
		return ocl_charset_init_second_test(param, gpu_index, BINARY_SIZE, ocl_write_header, ocl_gen_kernel_with_lenght, CL_TRUE);

	return TRUE;
}

// Select the best implementation of the provided
typedef struct OclImplementationParams
{
	size_t max_work_group_size;
	cl_ulong duration;
}
OclImplementationParams;
PUBLIC int ocl_charset_kernels_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_with_lenght_func** ocl_gen_kernel_with_lenght, void* ocl_empty_hash, cl_uint keys_opencl_divider)
{
	cl_uint num_gen_kernels = 0;
	for (; ocl_gen_kernel_with_lenght[num_gen_kernels]; num_gen_kernels++);

	// Generate kernels code
	if (!ocl_charset_init_common(param, gpu_index, gen, gpu_crypt, BINARY_SIZE, ocl_write_header, ocl_gen_kernel_with_lenght, num_gen_kernels, ocl_empty_hash, CL_FALSE, keys_opencl_divider))
		return FALSE;

	// Find what kernel implementation is best
	OclImplementationParams* implementation_params = (OclImplementationParams*)malloc(sizeof(OclImplementationParams)*num_gen_kernels);
	cl_uint zero = 0;

	if (param->max_work_group_size > 256)
	{
		param->max_work_group_size = 256;
	}
	size_t max_work_group_size = param->max_work_group_size;
	pclFinish(param->queue);
	for (cl_uint i = 0; i < num_gen_kernels; i++)
	{
		size_t num_work_items = param->NUM_KEYS_OPENCL / 2;
		param->max_work_group_size = max_work_group_size;

		// Warm-up
		pclEnqueueNDRangeKernel(param->queue, param->kernels[i], 1, NULL, &num_work_items, &max_work_group_size, 0, NULL, NULL);
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, sizeof(cl_uint), &zero, 0, NULL, NULL);

		implementation_params[i].duration = ocl_calculate_best_work_group(param, param->kernels+i, UINT_MAX / num_char_in_charset, NULL, 0, CL_FALSE, i==0);

		// Get good timespan
		if (i == 0)
		{
			cl_ulong init, duration;
			cl_event kernel_event;
			cl_command_queue prof_queue = pclCreateCommandQueue(param->context, param->id, CL_QUEUE_PROFILING_ENABLE, NULL);
			num_work_items = param->NUM_KEYS_OPENCL;

			pclEnqueueNDRangeKernel(prof_queue, param->kernels[i], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, &kernel_event);
			pclFinish(prof_queue);

			pclGetEventProfilingInfo(kernel_event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &init, NULL);
			pclGetEventProfilingInfo(kernel_event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &duration, NULL);
			pclReleaseEvent(kernel_event);
			duration -= init;
			duration /= 1000000;

			pclEnqueueWriteBuffer(prof_queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, sizeof(cl_uint), &zero, 0, NULL, NULL);
			implementation_params[i].duration = duration;

			pclReleaseCommandQueue(prof_queue);
		}

		implementation_params[i].max_work_group_size = param->max_work_group_size;
	}
	int best_index = 0;
	cl_ulong best_duration = implementation_params[0].duration;
	for (cl_uint i = 1; i < num_gen_kernels; i++)
		if (best_duration > implementation_params[i].duration)
		{
			best_duration = implementation_params[i].duration;
			best_index = i;
		}

	change_value_proportionally(&param->NUM_KEYS_OPENCL, (cl_uint)best_duration);
	param->max_work_group_size = implementation_params[best_index].max_work_group_size;

	ocl_charset_init_second_test(param, gpu_index, BINARY_SIZE, ocl_write_header, ocl_gen_kernel_with_lenght[best_index], CL_FALSE);

	//hs_log(HS_LOG_INFO, "SHA1 Best Implementation", "index: %i\nduration: %ums\nworkgroup: %u", best_index, (cl_uint)best_duration, (cl_uint)param->max_work_group_size);

	free(implementation_params);
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common opencl (UTF8 and PHRASES) non-salted
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define NTLM_MAX_KEY_LENGHT 27

#include <ctype.h>
PUBLIC void ocl_convert_2_big_endian(char* source, char* data, char* W)
{
	if (data[0] == 0)// Empty
	{
		sprintf(source + strlen(source), "%s=0;", W);
	}
	else if (isdigit(data[1]))// Constant
	{
		uint32_t x;
		int is_hex = !strncmp(data, "+0x", 3) || !strncmp(data, "+0X", 3);
		sscanf(data+1, is_hex ? "%x" : "%u", &x);

		x = ROTATE(x, 16U); x = ((x & 0x00FF00FF) << 8) + ((x >> 8) & 0x00FF00FF);
		sprintf(source + strlen(source), "%s=%uu;", W, x);
	}
	else// Variable
	{
		sprintf(source + strlen(source),
			"%s=rotate(%s,16u);"
			"%s=((%s&0x00FF00FF)<<8u)+((%s>>8u)&0x00FF00FF);"
			, W, data + 1
			, W, W, W);
	}	
}

PRIVATE void ocl_work(OpenCL_Param* param)
{
	cl_uint num_found = 0;
	int use_buffer = 1;
	int result, num_keys_filled;
	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer1 = malloc(kernel2common->get_buffer_size(param));
	void* buffer2 = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer1, 0, kernel2common->get_buffer_size(param));
	memset(buffer2, 0, kernel2common->get_buffer_size(param));

	result = param->gen(buffer1, param->NUM_KEYS_OPENCL, param->thread_id);
	while (continue_attack && result)
	{
		size_t num_work_items = kernel2common->process_buffer(use_buffer ? buffer1 : buffer2, result, param, &num_keys_filled);// Convert to multiple of work_group_size

		// Do actual hashing
		pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_found, 0, NULL, NULL);
		pclFlush(param->queue);
		// Generate keys in the CPU concurrently with GPU processing
		result = param->gen(use_buffer ? buffer2 : buffer1, param->NUM_KEYS_OPENCL, param->thread_id);
		use_buffer ^= 1;
		pclFinish(param->queue);

		// GPU found some passwords
		if (num_found)
			ocl_common_process_found(param, &num_found, kernel2common->get_key, use_buffer ? buffer2 : buffer1, num_work_items, num_keys_filled);

		report_keys_processed(num_keys_filled);
	}

	free(buffer1);
	free(buffer2);
	release_opencl_param(param);

	finish_thread();
}
PUBLIC int ocl_common_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE
	, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_func* ocl_gen_kernel, oclKernel2Common* ocl_kernel_provider, cl_uint keys_multipler, ocl_begin_rule_funtion* ocl_load)
{
	cl_uint output_size = 2 * sizeof(cl_uint) * __min(10000000, num_passwords_loaded);

	create_opencl_param(param, gpu_index, gen, output_size, FALSE);

	param->additional_param = ocl_kernel_provider;

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= keys_multipler;

	while (param->NUM_KEYS_OPENCL >= gpu_devices[gpu_index].max_mem_alloc_size / 32)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint)*param->NUM_KEYS_OPENCL;
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Generate code
	char* source = (char*)malloc(1024 * 32);

	// Write the definitions needed by the opencl implementation
	ocl_write_header(source, &gpu_devices[gpu_index], /*ntlm_size_bit_table*/0);
	// Kernel needed to convert from * to the common format
	ocl_kernel_provider->gen_kernel(source, param->NUM_KEYS_OPENCL);

	// Write the kernel
	ocl_gen_kernel(source, "crypt", ocl_load, NULL, NULL, NULL, NTLM_MAX_KEY_LENGHT, param->NUM_KEYS_OPENCL, FALSE, NULL, gpu_devices[gpu_index].vector_int_size);
	//{// Uncomment this to view code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(source, 1, strlen(source), code);
	//	fclose(code);
	//}

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Kernels
	cl_int code = create_kernel(param, KERNEL_PROCESS_KEY_INDEX, "process_key");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Generate kernels by lenght
	code = create_kernel(param, 0, "crypt");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Create memory objects
	if (!create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL * param->NUM_KEYS_OPENCL, NULL)) { release_opencl_param(param); return FALSE; }
	if (!create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, sizeof(cl_uint)+output_size, NULL))						{ release_opencl_param(param); return FALSE; }

	if (num_passwords_loaded > 1)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			if (!create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(cbg_mask + 1ull), cbg_table))				{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_ushort)*(cbg_mask + 1ull), cbg_filter))		{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values))	{ release_opencl_param(param); return FALSE; }
		}
		else
		{
			if (!create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY, sizeof(cl_uint)*(cbg_mask + 1ull), NULL))		{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY, sizeof(cl_ushort)*(cbg_mask + 1ull), NULL))	{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL)) { release_opencl_param(param); return FALSE; }
		}
	}
	ocl_kernel_provider->setup_params(param, &gpu_devices[gpu_index]);

	// Set OpenCL kernel params
	pclSetKernelArg(param->kernels[0], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[0], 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

	if (num_passwords_loaded > 1)
	{
		pclSetKernelArg(param->kernels[0], 2, sizeof(cl_mem), (void*)&param->mems[GPU_TABLE]);
		pclSetKernelArg(param->kernels[0], 3, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
		pclSetKernelArg(param->kernels[0], 4, sizeof(cl_mem), (void*)&param->mems[GPU_BIT_TABLE]);
	}

	// Copy data to GPU
	memset(source, 0, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint));
	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), source);
	if (num_passwords_loaded > 1 && !(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
	{
		// Create and initialize bitmaps
		cl_write_buffer(param, GPU_TABLE, sizeof(cl_uint)* (cbg_mask + 1ull), cbg_table);
		cl_write_buffer(param, GPU_BIT_TABLE, sizeof(cl_ushort)* (cbg_mask + 1ull), cbg_filter);
		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE*num_passwords_loaded, binary_values);

		pclFinish(param->queue);
	}

	pclFinish(param->queue);
	free(source);

	// Find working workgroup
	size_t num_work_items = param->NUM_KEYS_OPENCL;
	int bad_execution = FALSE;
	cl_uint zero = 0;

	int64_t init_kernel = get_milliseconds(), duration_kernel;
	if (CL_SUCCESS != pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
		bad_execution = TRUE;
	if (CL_SUCCESS != pclFinish(param->queue))
		bad_execution = TRUE;
	duration_kernel = get_milliseconds() - init_kernel;
	if (!bad_execution && duration_kernel > (OCL_NORMAL_KERNEL_TIME * 4 / 3))
		hs_log(HS_LOG_WARNING, "UTF8 to long", "UTF8 kernel duration: %ums", (cl_uint)duration_kernel);

	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), &zero);

	while (bad_execution && param->max_work_group_size >= OCL_MIN_WORKGROUP_SIZE)
	{
		param->max_work_group_size /= 2;
		bad_execution = FALSE;

		init_kernel = get_milliseconds();
		if (CL_SUCCESS != pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
			bad_execution = TRUE;
		if (CL_SUCCESS != pclFinish(param->queue))
			bad_execution = TRUE;
		duration_kernel = get_milliseconds() - init_kernel;
		if (!bad_execution && duration_kernel > (OCL_NORMAL_KERNEL_TIME * 4 / 3))
			hs_log(HS_LOG_WARNING, "UTF8 to long", "UTF8 kernel duration: %ums", (cl_uint)duration_kernel);

		cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), &zero);
	}
	
	pclFinish(param->queue);

	*gpu_crypt = ocl_work;
	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Phrases opencl optimizations
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define WORD_POS_MASK		0x07ffffff
#define GET_WORD_POS(x)		(word_pos[(x)] & WORD_POS_MASK)
#define GET_WORD_LEN(x)		(word_pos[(x)] >> 27)

extern uint32_t* word_pos;
extern unsigned char* words;
extern uint32_t num_words;

PRIVATE void ocl_phrases_work(OpenCL_Param* param)
{
	cl_uint num_found;
	cl_uint sentence[MAX_KEY_LENGHT_SMALL + 2];

	HS_SET_PRIORITY_GPU_THREAD;

	while (continue_attack && param->gen(sentence, param->NUM_KEYS_OPENCL, param->thread_id))
	{
		cl_uint num_keys_filled = sentence[0];
		size_t num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_keys_filled, param->max_work_group_size);// Convert to multiple of work_group_size

		// TODO: Check if there is some problem
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_CURRENT_KEY], CL_FALSE, 0, (sentence[1] + 1)*sizeof(cl_uint), sentence + 1, 0, NULL, NULL);
		pclEnqueueNDRangeKernel(param->queue, param->kernels[0], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);

		// GPU found some passwords
		if (num_found)
			ocl_common_process_found(param, &num_found, kernels2common[PHRASES_INDEX_IN_KERNELS].get_key, sentence, num_work_items, num_keys_filled);

		report_keys_processed(num_keys_filled);
	}

	release_opencl_param(param);
	finish_thread();
}
PUBLIC int ocl_phrases_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE, ocl_gen_phrases_kernel_func* ocl_gen_kernel_phrases, cl_uint keys_multipler)
{
	cl_uint output_size = 2 * sizeof(cl_uint)*(__min(10000000, num_passwords_loaded) + (cl_uint)gpu_devices[gpu_index].max_work_group_size);

	create_opencl_param(param, gpu_index, gen, output_size, FALSE);

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL *= keys_multipler;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = 2 * sizeof(cl_uint)*__min(param->NUM_KEYS_OPENCL, (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size / 2 / sizeof(cl_uint)));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// The size is: (position of last element) + (length of last element) + a plus to ensure correct read by uint------------------
	cl_uint size_words = GET_WORD_POS(num_words - 1) + GET_WORD_LEN(num_words - 1) + 4;

	// Create words aligned to 4 bytes
	cl_uint size_new_word = size_words + 3 * num_words;
	unsigned char* new_words = (unsigned char*)malloc(size_new_word);
	cl_uint* new_word_pos = (cl_uint*)malloc(num_words*sizeof(cl_uint));
	cl_uint new_pos = 0;
	memset(new_words, 0, size_new_word);
	for (cl_uint i = 0; i < num_words; i++)
	{
		cl_uint len = GET_WORD_LEN(i);
		memcpy(new_words + new_pos, words + GET_WORD_POS(i), len);
		new_word_pos[i] = new_pos / 4 + (len << 27) + MAX_KEY_LENGHT_SMALL;
		new_pos += ((len + 3) / 4) * 4;
		// If bigger than GPU memory
		if (new_pos >= gpu_devices[gpu_index].max_mem_alloc_size)
		{
			num_words = i;
			new_pos -= ((len + 3) / 4) * 4;
			break;
		}
	}
	size_new_word = new_pos;

	// Params needed
	if (!create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_ONLY, MAX_KEY_LENGHT_SMALL*sizeof(cl_uint) + size_new_word + sizeof(cl_uint)*num_words, NULL)) { release_opencl_param(param); return FALSE; }
	// Write to gpu memory
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_CURRENT_KEY], CL_FALSE, MAX_KEY_LENGHT_SMALL*sizeof(cl_uint), size_new_word, new_words, 0, NULL, NULL);
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_CURRENT_KEY], CL_FALSE, MAX_KEY_LENGHT_SMALL*sizeof(cl_uint) + size_new_word, sizeof(cl_uint)*num_words, new_word_pos, 0, NULL, NULL);
	pclFinish(param->queue);

	free(new_words);
	free(new_word_pos);
	//-----------------------------------------------------------------------------------------------------------------------------------
	// Generate code
	char* source = ocl_gen_kernel_phrases("crypt", FALSE, gpu_devices + gpu_index, /*ntlm_size_bit_table*/0, size_new_word);
	// Uncomment this to view code
	//size_t len = strlen(source);
	//FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//fwrite(source, 1, len, code);
	//fclose(code);

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Generate kernels by lenght
	if (create_kernel(param, 0, "crypt") != CL_SUCCESS)
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Create memory objects
	if (!create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, sizeof(cl_uint) + output_size, NULL)) { release_opencl_param(param); return FALSE; }

	if (num_passwords_loaded > 1)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			if (!create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(cbg_mask + 1ull), cbg_table))				{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_ushort)*(cbg_mask + 1ull), cbg_filter))		{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values))	{ release_opencl_param(param); return FALSE; }
		}
		else
		{
			if (!create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY, sizeof(cl_uint)*(cbg_mask + 1ull), NULL))		{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY, sizeof(cl_ushort)*(cbg_mask + 1ull), NULL))	{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL)) { release_opencl_param(param); return FALSE; }
		}
	}

	// Set OpenCL kernel params
	pclSetKernelArg(param->kernels[0], 0, sizeof(cl_mem), &param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[0], 1, sizeof(cl_mem), &param->mems[GPU_OUTPUT]);

	if (num_passwords_loaded > 1)
	{
		pclSetKernelArg(param->kernels[0], 2, sizeof(cl_mem), &param->mems[GPU_TABLE]);
		pclSetKernelArg(param->kernels[0], 3, sizeof(cl_mem), &param->mems[GPU_BINARY_VALUES]);
		pclSetKernelArg(param->kernels[0], 4, sizeof(cl_mem), &param->mems[GPU_BIT_TABLE]);
	}

	// Copy data to GPU
	memset(source, 0, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint));
	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), source);
	if (num_passwords_loaded > 1 && !(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
	{
		// Create and initialize bitmaps
		cl_write_buffer(param, GPU_TABLE, sizeof(cl_uint)* (cbg_mask + 1ull), cbg_table);
		cl_write_buffer(param, GPU_BIT_TABLE, sizeof(cl_ushort)* (cbg_mask + 1ull), cbg_filter);
		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE*num_passwords_loaded, binary_values);

		pclFinish(param->queue);
	}

	pclFinish(param->queue);
	free(source);

	// Find working workgroup
	// Hack: For NVIDIA and AMD there is a bug preventing NUM_KEYS_OPENCL greater than 24 bits
	cl_ulong duration = ocl_calculate_best_work_group(param, param->kernels, (num_passwords_loaded==1) ? UINT_MAX : 0x1000000, NULL, 0, CL_FALSE, CL_TRUE);
	if (duration < OCL_NORMAL_KERNEL_TIME/2)
		param->NUM_KEYS_OPENCL = ((param->NUM_KEYS_OPENCL-1)<<1) & (~((cl_uint)param->max_work_group_size-1));

	*gpu_crypt = ocl_phrases_work;
	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common opencl Rules non-salted
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
extern int current_rules_count;
extern int* rules_remapped;
extern int provider_index;
void rules_calculate_key_space(uint32_t num_keys_original, int64_t num_keys_in_memory, uint32_t thread_id);
void rules_report_remain_key_space(int64_t pnum_keys_in_memory, uint32_t thread_id);

PRIVATE char* ocl_gen_rules_code(GPUDevice* gpu, OpenCL_Param* param, int kernel2common_index, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_func* ocl_gen_kernel,
	cl_uint ntlm_size_bit_table, void* salt_param, int BINARY_SIZE, int FORMAT_BUFFER, cl_uint common_NUM_KEYS_OPENCL, cl_uint ordered_NUM_KEYS_OPENCL
#ifndef OCL_RULES_ALL_IN_GPU
	, int current_lenght
#endif
){
#ifdef OCL_RULES_ALL_IN_GPU
	char* base_source = (char*)malloc(1024 * 32 * __max(1, current_rules_count)*(NTLM_MAX_KEY_LENGHT + 1));
#else
	char* base_source = (char*)malloc(1024 * 32 * __max(1, current_rules_count));
#endif
	base_source[0] = 0;

	// Write the definitions needed by the opencl implementation
	ocl_write_header(base_source, gpu, ntlm_size_bit_table);

#ifndef OCL_RULES_ALL_IN_GPU
	if (current_lenght < 0)
#endif
	{
		// Kernel needed to convert from * to the common format
		kernels2common[kernel2common_index].gen_kernel(base_source, common_NUM_KEYS_OPENCL);
		// Kernel needed to convert from common format to the ordered by lenght format
		ocl_gen_kernel_common_2_ordered(base_source, common_NUM_KEYS_OPENCL, ordered_NUM_KEYS_OPENCL, NTLM_MAX_KEY_LENGHT);
	}
#ifndef OCL_RULES_ALL_IN_GPU
	else
#endif
	{
		char* source = base_source;
		// This is because AMD compiler do not support __constant vars inside a kernel
		ocl_write_code** constants_written = (ocl_write_code**)malloc(current_rules_count*sizeof(ocl_write_code*));
		int num_constants_written = 0;

		// Generate one kernel for each rule
	#ifdef OCL_RULES_ALL_IN_GPU
		for (cl_uint lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
	#else
		cl_uint lenght = current_lenght;
	#endif
		{
			for (int i = 0; i < current_rules_count; i++)
			{
				char kernel_name[12];
				char found_param[64];
				int* need_param_ptr = NULL;

				if (rules[rules_remapped[i]].ocl.max_param_value)
					need_param_ptr = &param->param0;

				// If needed to use constants -> write it only once
				if (rules[rules_remapped[i]].ocl.setup_constants)
				{
					int constants_already_written = FALSE, j;
					// Check if was written before
					for (j = 0; j < num_constants_written; j++)
						if (rules[rules_remapped[i]].ocl.setup_constants == constants_written[j])
						{
							constants_already_written = TRUE;
							break;
						}
					if (!constants_already_written)
					{
						constants_written[num_constants_written] = rules[rules_remapped[i]].ocl.setup_constants;
						num_constants_written++;
						rules[rules_remapped[i]].ocl.setup_constants(source);
					}
				}
				// Write the kernel
				sprintf(kernel_name, "ru_%il%i", i, lenght);
				sprintf(found_param, "(%uu+%s)", (rules_remapped[i] << 22) + (lenght << 27), rules[rules_remapped[i]].ocl.found_param);
				//sprintf(source + strlen(source), "\n__attribute__((work_group_size_hint(64, 1, 1))) ");
				ocl_gen_kernel(source + strlen(source), kernel_name, rules[rules_remapped[i]].ocl.begin[FORMAT_BUFFER], rules[rules_remapped[i]].ocl.end, found_param, need_param_ptr, lenght, ordered_NUM_KEYS_OPENCL, ntlm_size_bit_table, salt_param, gpu->vector_int_size);
			}
		}
		free(constants_written);
	}

	//{// Uncomment this to view code
	//	FILE* code = fopen("C:\\Users\\alain\\Desktop\\opencl_code.c","w");
	//	fwrite(base_source, 1, strlen(base_source), code);
	//	fclose(code);
	//}

	return base_source;
}

PRIVATE void oclru_check_binary_present(OpenCL_Param* param, cl_uint lenght)
{
#ifndef OCL_RULES_ALL_IN_GPU
	cl_int code, status;

	// Release resources
	for (cl_uint i = 0; i < param->rules.num_kernels; i++)
		if (param->rules.kernels[i])
		{
			pclReleaseKernel(param->rules.kernels[i]);
			param->rules.kernels[i] = NULL;
		}

	if (param->rules.program)
		pclReleaseProgram(param->rules.program);

	// Load program
	param->rules.program = pclCreateProgramWithBinary(param->context, 1, &param->id, param->rules.binaries_size+lenght, (unsigned char const **)(param->rules.binaries+lenght), &status, &code);
	if (code != CL_SUCCESS || status != CL_SUCCESS)
		hs_log(HS_LOG_ERROR, "Test Suite", "Error loading rules binary: lenght=%i", lenght);

	code = pclBuildProgram(param->rules.program, 1, &param->id, gpu_devices[param->rules.gpu_index].compiler_options, NULL, NULL);
	if (code != CL_SUCCESS)
		hs_log(HS_LOG_ERROR, "Test Suite", "Error building rules binary: lenght=%i", lenght);
	// Load kernels
	for (int i = 0; i < current_rules_count; i++)
	{
		char name_buffer[12];
		sprintf(name_buffer, "ru_%il%i", i, lenght);
		param->rules.kernels[i + lenght*current_rules_count] = pclCreateKernel(param->rules.program, name_buffer, &code);
		if (code != CL_SUCCESS)
			hs_log(HS_LOG_ERROR, "Test Suite", "Error with rule: %s code: %i", name_buffer, code);

		pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 0, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);
		pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

		if(num_diff_salts > 1)
		{
			pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 2, sizeof(cl_mem), (void*) &param->mems[GPU_BINARY_VALUES]);
			pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 3, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_VALUES]);
			pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 4, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_INDEX]);
			pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 5, sizeof(cl_mem), (void*) &param->mems[GPU_SAME_SALT_NEXT]);
		}
		if (!FORMAT_USE_SALT && num_passwords_loaded > 1)
		{
			pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 2, sizeof(cl_mem), (void*)&param->mems[GPU_TABLE]);
			pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 3, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
			pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 4, sizeof(cl_mem), (void*)&param->mems[GPU_SAME_HASH_NEXT]);
			pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 5, sizeof(cl_mem), (void*)&param->mems[GPU_BIT_TABLE]);
		}
	}
#endif
}
#define MAX_SALTS_IN_KERNEL_OTHER	64
cl_uint* ocl_dcc_shrink_salts_size(char salt_values_str[11][20], cl_uint* num_salt_diff_parts);
PRIVATE void ocl_protocol_rules_work(OpenCL_Param* param)
{
	cl_uint gpu_num_keys_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint gpu_pos_ordered_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint num_found = 0;
	cl_uint zero = 0;
	int num_keys_filled;

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	// Size in uint
	for (cl_uint i = 0, j = 32; i <= NTLM_MAX_KEY_LENGHT; i++)
	{
		gpu_pos_ordered_by_len[i] = j;
		j += (i + 3) / 4 * param->NUM_KEYS_OPENCL;
	}

	cl_uint num_keys_to_read = param->NUM_KEYS_OPENCL;
	int result = param->gen(buffer, num_keys_to_read, param->thread_id);
	int64_t num_keys_in_memory = 0;
	while (continue_attack && result)
	{
		// Enqueue the process_key kernel
		size_t num_work_items = kernel2common->process_buffer(buffer, result, param, &num_keys_filled);

		// Convert to ordered by lenght
		pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 2, sizeof(cl_uint), (void*)&num_keys_filled);
		while (CL_INVALID_WORK_GROUP_SIZE == pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_ORDERED_INDEX], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
			param->max_work_group_size /= 2;
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
		num_keys_to_read = 0;
		num_keys_in_memory = 0;
		// Calculate the number of keys in memory
		for (int lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
			for (int i = 0; i < current_rules_count; i++)
			{
				int64_t multipler = rules[rules_remapped[i]].multipler;
				if (rules[rules_remapped[i]].depend_key_lenght)
					multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

				num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
			}
		rules_calculate_key_space(num_keys_filled, num_keys_in_memory, param->thread_id);

		for (int lenght = 0; continue_attack && lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		{
			if (gpu_num_keys_by_len[lenght] >= param->NUM_KEYS_OPENCL / 4 * 3)
			{
				oclru_check_binary_present(param, lenght);

				// Do actual hashing
				for (int i = 0; continue_attack && i < current_rules_count; i++)
				{
					size_t work_group_size_rl = param->rules.work_group_sizes[i + lenght*current_rules_count];
					size_t num_work_items_len = OCL_MULTIPLE_WORKGROUP_SIZE(gpu_num_keys_by_len[lenght], work_group_size_rl);// Convert to multiple of work_group_size

					if (rules[rules_remapped[i]].ocl.max_param_value)
					{
						// Some params
						int64_t multipler = rules[rules_remapped[i]].multipler / rules[rules_remapped[i]].ocl.max_param_value;
						int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
						if (rules[rules_remapped[i]].depend_key_lenght)
							max_param_value = lenght + rules[rules_remapped[i]].key_lenght_sum;
						multipler *= gpu_num_keys_by_len[lenght];

						for (int j = 0; continue_attack && j < max_param_value; j++)
						{
							pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param
							cl_int code = pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
							if (code != CL_SUCCESS)
								hs_log(HS_LOG_ERROR, "Test Suite", "Enqueue error: %i", code);
							// For kernels with large params to behave properly
							if ((j & 0xf) == 0xf)
								pclFinish(param->queue);
							else
								pclFlush(param->queue);

							num_keys_in_memory -= multipler;
							rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
							report_keys_processed(multipler);
						}
					}
					else
					{
						cl_int code = pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
						if (code != CL_SUCCESS)
							hs_log(HS_LOG_ERROR, "Test Suite", "Enqueue error: %i", code);
						pclFlush(param->queue);

						int64_t multipler = rules[rules_remapped[i]].multipler;
						if (rules[rules_remapped[i]].depend_key_lenght)
							multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);
						multipler *= gpu_num_keys_by_len[lenght];

						num_keys_in_memory -= multipler;
						rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
						report_keys_processed(multipler);
					}
				}

				pclEnqueueWriteBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_FALSE, lenght*sizeof(cl_uint), sizeof(cl_uint), &zero, 0, NULL, NULL);
			}
			// Find fullest lenght
			else if (gpu_num_keys_by_len[lenght] > num_keys_to_read)
			{
				num_keys_to_read = gpu_num_keys_by_len[lenght];
			}
		}
		// Next block of keys
		if (continue_attack)
		{
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_found, 0, NULL, NULL);
			pclFlush(param->queue);

			// Generate keys in the CPU concurrently with GPU processing
			// Calculate the free space left in the fullest lenght
			num_keys_to_read = param->NUM_KEYS_OPENCL - num_keys_to_read;
			num_keys_to_read &= ~(param->max_work_group_size - 1);// Make it a multiple of work_group_size
			result = param->gen(buffer, num_keys_to_read, param->thread_id);

			pclFinish(param->queue);
			// GPU found some passwords
			if (num_found)
				ocl_rules_process_found(param, &num_found, gpu_num_keys_by_len, gpu_pos_ordered_by_len, param->NUM_KEYS_OPENCL);
		}
	}

	// Get the last passwords from memory
	pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
	num_keys_in_memory = 0;
	// Calculate the number of keys in memory
	for (int lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		for (int i = 0; i < current_rules_count; i++)
		{
			int64_t multipler = rules[rules_remapped[i]].multipler;
			if (rules[rules_remapped[i]].depend_key_lenght)
				multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

			num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
		}
	rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);

	for (int lenght = 0; /*continue_attack &&*/ lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		if (gpu_num_keys_by_len[lenght])
		{
			oclru_check_binary_present(param, lenght);

			// Do actual hashing
			for (int i = 0; /*continue_attack &&*/ i < current_rules_count; i++)
			{
				size_t work_group_size_rl = param->rules.work_group_sizes[i + lenght*current_rules_count];
				size_t num_work_items_len = OCL_MULTIPLE_WORKGROUP_SIZE(gpu_num_keys_by_len[lenght], work_group_size_rl);// Convert to multiple of work_group_size

				if (rules[rules_remapped[i]].ocl.max_param_value)
				{
					// Some params
					int64_t multipler = rules[rules_remapped[i]].multipler / rules[rules_remapped[i]].ocl.max_param_value;
					int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
					if (rules[rules_remapped[i]].depend_key_lenght)
						max_param_value = lenght + rules[rules_remapped[i]].key_lenght_sum;
					multipler *= gpu_num_keys_by_len[lenght];

					for (int j = 0; /*continue_attack &&*/ j < max_param_value; j++)
					{
						pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param
						cl_int code = pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
						if (code != CL_SUCCESS)
							hs_log(HS_LOG_ERROR, "Test Suite", "Enqueue error: %i", code);
						// For kernels with large params to behave properly
						if ((j & 0xf) == 0xf)
							pclFinish(param->queue);
						else
							pclFlush(param->queue);

						num_keys_in_memory -= multipler;
						rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
						report_keys_processed(multipler);
					}
				}
				else
				{
					cl_int code = pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
					if (code != CL_SUCCESS)
						hs_log(HS_LOG_ERROR, "Test Suite", "Enqueue error: %i", code);
					pclFlush(param->queue);

					int64_t multipler = rules[rules_remapped[i]].multipler;
					if (rules[rules_remapped[i]].depend_key_lenght)
						multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);
					multipler *= gpu_num_keys_by_len[lenght];

					num_keys_in_memory -= multipler;
					rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
					report_keys_processed(multipler);
				}

				pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);
				// GPU found some passwords
				if (num_found)
					ocl_rules_process_found(param, &num_found, gpu_num_keys_by_len, gpu_pos_ordered_by_len, param->NUM_KEYS_OPENCL);
			}
		}

	free(buffer);
	release_opencl_param(param);

	finish_thread();
}
PRIVATE void ocl_dcc_protocol_rules_work(OpenCL_Param* param)
{
	cl_uint gpu_num_keys_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint gpu_pos_ordered_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint num_found = 0;
	cl_uint zero = 0;
	cl_uint num_iterations = (num_diff_salts + MAX_SALTS_IN_KERNEL_OTHER - 1) / MAX_SALTS_IN_KERNEL_OTHER;
	int num_keys_filled;

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	// Size in uint
	for (cl_uint i = 0, j = 32; i <= NTLM_MAX_KEY_LENGHT; i++)
	{
		gpu_pos_ordered_by_len[i] = j;
		j += (i + 3) / 4 * param->NUM_KEYS_OPENCL;
	}

	cl_uint num_keys_to_read = param->NUM_KEYS_OPENCL;
	int result = param->gen(buffer, num_keys_to_read, param->thread_id);
	int64_t num_keys_in_memory = 0;
	while (continue_attack && result)
	{
		// Enqueue the process_key kernel
		size_t num_work_items = kernel2common->process_buffer(buffer, result, param, &num_keys_filled);

		// Convert to ordered by lenght
		pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 2, sizeof(cl_uint), (void*)&num_keys_filled);
		while (CL_INVALID_WORK_GROUP_SIZE == pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_ORDERED_INDEX], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
			param->max_work_group_size /= 2;
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
		num_keys_to_read = 0;
		num_keys_in_memory = 0;
		// Calculate the number of keys in memory
		for (int lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
			for (int i = 0; i < current_rules_count; i++)
			{
				int64_t multipler = rules[rules_remapped[i]].multipler;
				if (rules[rules_remapped[i]].depend_key_lenght)
					multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

				num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
			}
		rules_calculate_key_space(num_keys_filled, num_keys_in_memory, param->thread_id);

		for (int lenght = 0; continue_attack && lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
			if (gpu_num_keys_by_len[lenght] >= param->NUM_KEYS_OPENCL/4*3)
			{
				oclru_check_binary_present(param, lenght);

				// Do actual hashing
				for (int i = 0; continue_attack && i < current_rules_count; i++)
				{
					size_t work_group_size_rl = param->rules.work_group_sizes[i + lenght*current_rules_count];
					size_t num_work_items_len = OCL_MULTIPLE_WORKGROUP_SIZE(gpu_num_keys_by_len[lenght], work_group_size_rl);// Convert to multiple of work_group_size

					if (rules[rules_remapped[i]].ocl.max_param_value)
					{
						// Some params
						int64_t multipler = rules[rules_remapped[i]].multipler / rules[rules_remapped[i]].ocl.max_param_value;
						int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
						if (rules[rules_remapped[i]].depend_key_lenght)
							max_param_value = lenght + rules[rules_remapped[i]].key_lenght_sum;
						multipler *= gpu_num_keys_by_len[lenght];

						int64_t num_keys_by_batch = multipler * 16 / num_iterations;
						multipler -= num_keys_by_batch*(num_iterations / 16);

						for (int j = 0; continue_attack && j < max_param_value; j++)
						{
							pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param

							for (cl_uint current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
							{
								if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
									pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], (num_diff_salts < num_passwords_loaded) ? 6 : 4, sizeof(current_salt_index), (void*)&current_salt_index);

								pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
								// For large different salts to behave properly
								if (((current_salt_index / MAX_SALTS_IN_KERNEL_OTHER) & 0xf) == 0xf)
								{
									num_keys_in_memory -= num_keys_by_batch;
									rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
									report_keys_processed(num_keys_by_batch);
									pclFinish(param->queue);
								}
								else
									pclFlush(param->queue);
							}

							// For kernels with large params to behave properly
							if ((j & 0xf) == 0xf)
								pclFinish(param->queue);
							else
								pclFlush(param->queue);

							num_keys_in_memory -= multipler;
							rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
							report_keys_processed(multipler);
						}
					}
					else
					{
						int64_t multipler = rules[rules_remapped[i]].multipler;
						if (rules[rules_remapped[i]].depend_key_lenght)
							multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);
						multipler *= gpu_num_keys_by_len[lenght];

						int64_t num_keys_by_batch = multipler * 16 / num_iterations;
						multipler -= num_keys_by_batch*(num_iterations / 16);

						for (cl_uint current_salt_index = 0; continue_attack && current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
						{
							if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
								pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], (num_diff_salts < num_passwords_loaded) ? 6 : 4, sizeof(current_salt_index), (void*)&current_salt_index);

							pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);

							// For large different salts to behave properly
							if (((current_salt_index / MAX_SALTS_IN_KERNEL_OTHER) & 0xf) == 0xf)
							{
								num_keys_in_memory -= num_keys_by_batch;
								rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
								report_keys_processed(num_keys_by_batch);
								pclFinish(param->queue);
							}
							else
								pclFlush(param->queue);
						}

						num_keys_in_memory -= multipler;
						rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
						report_keys_processed(multipler);
					}
				}

				pclEnqueueWriteBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_FALSE, lenght*sizeof(cl_uint), sizeof(cl_uint), &zero, 0, NULL, NULL);
			}
			// Find fullest lenght
			else if (gpu_num_keys_by_len[lenght] > num_keys_to_read)
			{
				num_keys_to_read = gpu_num_keys_by_len[lenght];
			}
		// Next block of keys
		if (continue_attack)
		{
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_found, 0, NULL, NULL);
			pclFlush(param->queue);

			// Generate keys in the CPU concurrently with GPU processing
			// Calculate the free space left in the fullest lenght
			num_keys_to_read = param->NUM_KEYS_OPENCL - num_keys_to_read;
			num_keys_to_read &= ~(param->max_work_group_size - 1);// Make it a multiple of work_group_size
			result = param->gen(buffer, num_keys_to_read, param->thread_id);

			pclFinish(param->queue);
			// GPU found some passwords
			if (num_found)
				ocl_rules_process_found(param, &num_found, gpu_num_keys_by_len, gpu_pos_ordered_by_len, param->NUM_KEYS_OPENCL);
		}
	}

	// Get the last passwords from memory
	pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
	num_keys_in_memory = 0;
	// Calculate the number of keys in memory
	for (int lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		for (int i = 0; i < current_rules_count; i++)
		{
			int64_t multipler = rules[rules_remapped[i]].multipler;
			if (rules[rules_remapped[i]].depend_key_lenght)
				multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

			num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
		}
	rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);

	for (int lenght = 0; /*continue_attack &&*/ lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		if (gpu_num_keys_by_len[lenght])
		{
			oclru_check_binary_present(param, lenght);

			// Do actual hashing
			for (int i = 0; /*continue_attack &&*/ i < current_rules_count; i++)
			{
				size_t work_group_size_rl = param->rules.work_group_sizes[i + lenght*current_rules_count];
				size_t num_work_items_len = OCL_MULTIPLE_WORKGROUP_SIZE(gpu_num_keys_by_len[lenght], work_group_size_rl);// Convert to multiple of work_group_size

				if (rules[rules_remapped[i]].ocl.max_param_value)
				{
					// Some params
					int64_t multipler = rules[rules_remapped[i]].multipler / rules[rules_remapped[i]].ocl.max_param_value;
					int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
					if (rules[rules_remapped[i]].depend_key_lenght)
						max_param_value = lenght + rules[rules_remapped[i]].key_lenght_sum;
					multipler *= gpu_num_keys_by_len[lenght];

					int64_t num_keys_by_batch = multipler * 16 / num_iterations;
					multipler -= num_keys_by_batch*(num_iterations / 16);

					for (int j = 0; /*continue_attack &&*/ j < max_param_value; j++)
					{
						pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param

						for (cl_uint current_salt_index = 0; /*continue_attack &&*/ current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
						{
							if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
								pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], (num_diff_salts < num_passwords_loaded) ? 6 : 4, sizeof(current_salt_index), (void*)&current_salt_index);

							pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
							// For large different salts to behave properly
							if (((current_salt_index / MAX_SALTS_IN_KERNEL_OTHER) & 0xf) == 0xf)
							{
								num_keys_in_memory -= num_keys_by_batch;
								rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
								report_keys_processed(num_keys_by_batch);
								pclFinish(param->queue);
							}
							else
								pclFlush(param->queue);
						}
						// For kernels with large params to behave properly
						if ((j & 0xf) == 0xf)
							pclFinish(param->queue);
						else
							pclFlush(param->queue);

						num_keys_in_memory -= multipler;
						rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
						report_keys_processed(multipler);
					}
				}
				else
				{
					int64_t multipler = rules[rules_remapped[i]].multipler;
					if (rules[rules_remapped[i]].depend_key_lenght)
						multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);
					multipler *= gpu_num_keys_by_len[lenght];

					int64_t num_keys_by_batch = multipler * 16 / num_iterations;
					multipler -= num_keys_by_batch*(num_iterations / 16);

					for (cl_uint current_salt_index = 0; /*continue_attack &&*/ current_salt_index < num_diff_salts; current_salt_index += MAX_SALTS_IN_KERNEL_OTHER)
					{
						if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
							pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], (num_diff_salts < num_passwords_loaded) ? 6 : 4, sizeof(current_salt_index), (void*)&current_salt_index);

						pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
						// For large different salts to behave properly
						if (((current_salt_index / MAX_SALTS_IN_KERNEL_OTHER) & 0xf) == 0xf)
						{
							num_keys_in_memory -= num_keys_by_batch;
							rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
							report_keys_processed(num_keys_by_batch);
							pclFinish(param->queue);
						}
						else
							pclFlush(param->queue);
					}

					num_keys_in_memory -= multipler;
					rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
					report_keys_processed(multipler);
				}
			}

			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);
			// GPU found some passwords
			if (num_found)
				ocl_rules_process_found(param, &num_found, gpu_num_keys_by_len, gpu_pos_ordered_by_len, param->NUM_KEYS_OPENCL);
		}

	free(buffer);
	release_opencl_param(param);

	finish_thread();
}
PUBLIC int ocl_rules_init(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_func* ocl_gen_kernel, int FORMAT_BUFFER, cl_uint keys_opencl_divider)
{
	int kernel2common_index;
	cl_uint gpu_key_buffer_lenght = 0;
	cl_uint output_size = 3 * sizeof(cl_uint)*num_passwords_loaded;
	int multipler = 0;
	
	// Optimize parts
	union{
		cl_uint num_salt_diff_parts;
		cl_uint ntlm_size_bit_table;
	} Part;
	char salt_values_str[11][20];
	cl_uint* small_salts_values = NULL;

	// Find a compatible generate_key_funtion function for a given key_provider
	for (int i = 0; i < LENGHT(key_providers[provider_index].impls); i++)
		for (kernel2common_index = 0; kernel2common_index < (int)num_kernels2common; kernel2common_index++)
			if (key_providers[provider_index].impls[i].protocol == kernels2common[kernel2common_index].protocol)
			{
				gen = key_providers[provider_index].impls[i].generate;
				goto out;
			}
out:
	create_opencl_param(param, gpu_index, gen, output_size, FALSE);

	// Count the possible number of generated keys
	for (int i = 0; i < current_rules_count; i++)
		multipler += rules[rules_remapped[i]].multipler;

	// Size in bytes
	for (int i = 1; i <= NTLM_MAX_KEY_LENGHT; i++)
		gpu_key_buffer_lenght += (i + 3) / 4 * sizeof(cl_uint);

	// Set appropriate number of candidates
	if (FORMAT_USE_SALT)
	{
		param->NUM_KEYS_OPENCL /= 4;
		param->NUM_KEYS_OPENCL *= multipler < 95 ? 64 : 1;
		if (num_diff_salts <= 32 && param->NUM_KEYS_OPENCL < UINT_MAX / 2) param->NUM_KEYS_OPENCL *= 2;
		if (num_diff_salts <= 16 && param->NUM_KEYS_OPENCL < UINT_MAX / 2) param->NUM_KEYS_OPENCL *= 2;
		if (num_diff_salts <= 4 && param->NUM_KEYS_OPENCL < UINT_MAX / 2) param->NUM_KEYS_OPENCL *= 2;
		if (num_diff_salts <= 2 && param->NUM_KEYS_OPENCL < UINT_MAX / 2) param->NUM_KEYS_OPENCL *= 2;
	}
	else
	{
#ifdef __ANDROID__
		param->NUM_KEYS_OPENCL *= multipler < 95 ? 16 : 1;
#else
		param->NUM_KEYS_OPENCL *= multipler < 95 ? 64 : 4;
#endif
	}
	param->NUM_KEYS_OPENCL /= keys_opencl_divider;
	while (param->NUM_KEYS_OPENCL >= (gpu_devices[gpu_index].max_mem_alloc_size - MAX_KEY_LENGHT_SMALL * sizeof(cl_uint)) / gpu_key_buffer_lenght)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && multipler*param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		// Reserve to output at maximum half the MAX_MEM_ALLOC_SIZE
		output_size = __min(3 * sizeof(cl_uint)*multipler*param->NUM_KEYS_OPENCL, (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size/2));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	if (FORMAT_USE_SALT)
	{
		// Find similar "salts parts" and optimize it---------------------------------
		small_salts_values = ocl_dcc_shrink_salts_size(salt_values_str, &Part.num_salt_diff_parts);
	}
	else
		Part.ntlm_size_bit_table = 0;

	// Generate code
#ifdef OCL_RULES_ALL_IN_GPU
	char* source = ocl_gen_rules_code(&gpu_devices[gpu_index], param, kernel2common_index, ocl_write_header, ocl_gen_kernel, Part.ntlm_size_bit_table, salt_values_str, BINARY_SIZE, FORMAT_BUFFER, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL);
#else
	char* source = ocl_gen_rules_code(&gpu_devices[gpu_index], param, kernel2common_index, ocl_write_header, ocl_gen_kernel, Part.ntlm_size_bit_table, salt_values_str, BINARY_SIZE, FORMAT_BUFFER, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL, -1);
#endif

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Crypt by length
	cl_int code = create_kernel(param, KERNEL_PROCESS_KEY_INDEX, "process_key");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return FALSE;
	}
	code = create_kernel(param, KERNEL_ORDERED_INDEX, "common2ordered");
	if (code != CL_SUCCESS)
	{
		release_opencl_param(param);
		return FALSE;
	}

#ifndef OCL_RULES_ALL_IN_GPU
	for (int len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
	{
		free(source);
		source = ocl_gen_rules_code(&gpu_devices[gpu_index], param, kernel2common_index, ocl_write_header, ocl_gen_kernel, Part.ntlm_size_bit_table,
			salt_values_str, BINARY_SIZE, FORMAT_BUFFER, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL, len);

		param->rules.program = pclCreateProgramWithSource( param->context, 1, (char const **)(&source), NULL, &code );
		// Build program
		if(pclBuildProgram(param->rules.program, 1, &param->id, gpu_devices[gpu_index].compiler_options, NULL, NULL ) == CL_SUCCESS)
		{
			pclGetProgramInfo(param->rules.program, CL_PROGRAM_BINARY_SIZES, sizeof(size_t), &param->rules.binaries_size[len], NULL);
			param->rules.binaries[len] = malloc(param->rules.binaries_size[len]);
			unsigned char* buffers[1] = { param->rules.binaries[len] };
			cl_int code = pclGetProgramInfo(param->rules.program, CL_PROGRAM_BINARIES, sizeof( buffers ), &buffers, NULL);
			if(code != CL_SUCCESS)
				code++;
		}
		else
		{
			release_opencl_param(param);
			return FALSE;
		}
		pclReleaseProgram(param->rules.program);
		param->rules.program = NULL;
	}
#endif

	// Create rules kernels
	param->rules.num_kernels = current_rules_count*(NTLM_MAX_KEY_LENGHT + 1);
	param->rules.kernels = (cl_kernel*)calloc(param->rules.num_kernels, sizeof(cl_kernel));
	param->rules.work_group_sizes = (size_t*)malloc(sizeof(size_t)*param->rules.num_kernels);

#ifdef OCL_RULES_ALL_IN_GPU
	for (int len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
		for (int i = 0; i < current_rules_count; i++)
		{
			char name_buffer[12];
			sprintf(name_buffer, "ru_%il%i", i, len);
			param->rules.kernels[i + len*current_rules_count] = pclCreateKernel(param->program, name_buffer, &code);
			if (code != CL_SUCCESS)
			{
				release_opencl_param(param);
				return FALSE;
			}
		}
#endif

	// Create memory objects
	if (!create_opencl_mem(param, GPU_ORDERED_KEYS, CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint)+param->NUM_KEYS_OPENCL*gpu_key_buffer_lenght, NULL))	{ release_opencl_param(param); return FALSE; }
	if (!create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL*param->NUM_KEYS_OPENCL, NULL))											{ release_opencl_param(param); return FALSE; }
	if (!create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, sizeof(cl_uint)+output_size, NULL))																{ release_opencl_param(param); return FALSE; }

	if(num_diff_salts > 1)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
			create_opencl_mem(param, GPU_SALT_INDEX	   , CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
		}
		else
		{
			create_opencl_mem(param, GPU_BINARY_VALUES , CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SALT_INDEX	   , CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
		create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY, sizeof(cl_uint)*Part.num_salt_diff_parts*num_diff_salts, NULL);
	}
	if (!FORMAT_USE_SALT && num_passwords_loaded > 1)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			if (!create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*(cbg_mask + 1ull), cbg_table))				{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_ushort)*(cbg_mask + 1ull), cbg_filter))		{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values))	{ release_opencl_param(param); return FALSE; }
		}
		else
		{
			if (!create_opencl_mem(param, GPU_TABLE, CL_MEM_READ_ONLY, sizeof(cl_uint)*(cbg_mask + 1ull), NULL))		{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BIT_TABLE, CL_MEM_READ_ONLY, sizeof(cl_ushort)*(cbg_mask + 1ull), NULL))	{ release_opencl_param(param); return FALSE; }
			if (!create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL)) { release_opencl_param(param); return FALSE; }
		}
	}

	// Set OpenCL kernel params
	kernels2common[kernel2common_index].setup_params(param, &gpu_devices[gpu_index]);

	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 1, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);

#ifdef OCL_RULES_ALL_IN_GPU
	for (int len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
		for (int i = 0; i < current_rules_count; i++)
		{
			pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 0, sizeof(cl_mem), (void*)&param->mems[GPU_ORDERED_KEYS]);
			pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 1, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);

			if(num_diff_salts > 1)
			{
				pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 2, sizeof(cl_mem), (void*) &param->mems[GPU_BINARY_VALUES]);
				pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 3, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_VALUES]);
				pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 4, sizeof(cl_mem), (void*) &param->mems[GPU_SALT_INDEX]);
				pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 5, sizeof(cl_mem), (void*) &param->mems[GPU_SAME_SALT_NEXT]);
			}
			if (num_diff_salts==0 && num_passwords_loaded > 1)
			{
				pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 2, sizeof(cl_mem), (void*)&param->mems[GPU_TABLE]);
				pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 3, sizeof(cl_mem), (void*)&param->mems[GPU_BINARY_VALUES]);
				pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 4, sizeof(cl_mem), (void*)&param->mems[GPU_BIT_TABLE]);
			}
		}
#endif

	// Copy data to GPU
	memset(source, 0, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint));
	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), source);
	cl_write_buffer(param, GPU_ORDERED_KEYS, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint), source);
	if(num_diff_salts > 1)
	{
		if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
		{
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_BINARY_VALUES] , CL_FALSE, 0, BINARY_SIZE*num_passwords_loaded, binary_values, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX]	   , CL_FALSE, 0, 4*num_passwords_loaded, salt_index, 0, NULL, NULL);
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, 4*num_passwords_loaded, same_salt_next, 0, NULL, NULL);
		}
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, sizeof(cl_uint)*Part.num_salt_diff_parts*num_diff_salts, small_salts_values, 0, NULL, NULL);
	}
	if (!FORMAT_USE_SALT && num_passwords_loaded > 1 && !(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
	{
		// Create and initialize bitmaps
		cl_write_buffer(param, GPU_TABLE, sizeof(cl_uint)* (cbg_mask + 1ull), cbg_table);
		cl_write_buffer(param, GPU_BIT_TABLE, sizeof(cl_ushort)* (cbg_mask + 1ull), cbg_filter);
		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE*num_passwords_loaded, binary_values);

		pclFinish(param->queue);
	}

	pclFinish(param->queue);
	free(source);
	free(small_salts_values);

	// Find working workgroup
#define RULE_NUM_WORK_ITEMS_DIVIDER	16
	int64_t init = get_milliseconds();
	size_t num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(param->NUM_KEYS_OPENCL / RULE_NUM_WORK_ITEMS_DIVIDER, param->max_work_group_size);
	size_t max_work_group_size = param->max_work_group_size;
	cl_uint zero = 0;
	for (int len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
	{
		oclru_check_binary_present(param, len);

		for (int i = 0; i < current_rules_count; i++)
		{
			cl_kernel kernel = param->rules.kernels[i + len*current_rules_count];
			int bad_execution = FALSE;
			int rule_tryed = TRUE;

			if (rules[rules_remapped[i]].ocl.max_param_value)
			{
				int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
				if (rules[rules_remapped[i]].depend_key_lenght)
					max_param_value = len + rules[rules_remapped[i]].key_lenght_sum;

				if (max_param_value <= 0)
					rule_tryed = FALSE;
			}

			if (rule_tryed)
			{
				if (num_diff_salts > MAX_SALTS_IN_KERNEL_OTHER)
					pclSetKernelArg(kernel, (num_diff_salts < num_passwords_loaded) ? 6 : 4, sizeof(zero), (void*)&zero);

				if (rules[rules_remapped[i]].ocl.max_param_value)
					pclSetKernelArg(kernel, param->param0, sizeof(cl_uint), &zero);//additional param

				pclFinish(param->queue);

				int64_t init_kernel = get_milliseconds(), duration_kernel;
				if (CL_SUCCESS != pclEnqueueNDRangeKernel(param->queue, kernel, 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
					bad_execution = TRUE;
				if (CL_SUCCESS != pclFinish(param->queue))
					bad_execution = TRUE;
				duration_kernel = (get_milliseconds() - init_kernel)*RULE_NUM_WORK_ITEMS_DIVIDER;
				if (!bad_execution && duration_kernel > (OCL_NORMAL_KERNEL_TIME * 4 / 3))
					hs_log(HS_LOG_WARNING, "Rules to long", "Rules kernel duration: %ums", (cl_uint)duration_kernel);

				cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), &zero);

				while (bad_execution && param->max_work_group_size >= OCL_MIN_WORKGROUP_SIZE)
				{
					param->max_work_group_size /= 2;
					bad_execution = FALSE;
					pclFinish(param->queue);

					init_kernel = get_milliseconds();
					if (CL_SUCCESS != pclEnqueueNDRangeKernel(param->queue, kernel, 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
						bad_execution = TRUE;
					if (CL_SUCCESS != pclFinish(param->queue))
						bad_execution = TRUE;
					duration_kernel = (get_milliseconds() - init_kernel)*RULE_NUM_WORK_ITEMS_DIVIDER;
					if (!bad_execution && duration_kernel > (OCL_NORMAL_KERNEL_TIME * 4 / 3))
						hs_log(HS_LOG_WARNING, "Rules to long", "Rules kernel duration: %ums", (cl_uint)duration_kernel);

					cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), &zero);
				}

				param->rules.work_group_sizes[i + len*current_rules_count] = param->max_work_group_size;
				param->max_work_group_size = max_work_group_size;
			}
		}
	}
	pclFinish(param->queue);

	int64_t duration = get_milliseconds() - init;
	if (duration > 2000)
		hs_log(HS_LOG_WARNING, "Test Suite", "Rule check good workgroup: %i ms", (int)duration);

	*gpu_crypt = FORMAT_USE_SALT ? ocl_dcc_protocol_rules_work : ocl_protocol_rules_work;
	param->additional_param = kernels2common + kernel2common_index;
#ifndef OCL_RULES_ALL_IN_GPU
	param->rules.gpu_index = gpu_index;
#endif
	return TRUE;
}

// Fast Salted
PRIVATE void ocl_ssha_protocol_rules_work(OpenCL_Param* param)
{
	cl_uint zero = 0;
	int num_keys_filled;
	cl_uint gpu_num_keys_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint gpu_offsets_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint gpu_pos_ordered_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint num_found = 0;

	// Size in uint
	for (cl_uint i = 0, j = 32; i <= NTLM_MAX_KEY_LENGHT; i++)
	{
		gpu_pos_ordered_by_len[i] = j;
		j += (i + 3) / 4 * param->param1 * 2;
	}
	memset(gpu_num_keys_by_len, 0, sizeof(gpu_num_keys_by_len));
	memset(gpu_offsets_by_len, 0, sizeof(gpu_offsets_by_len));

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	int result = param->gen(buffer, param->param1, param->thread_id);
	int64_t num_keys_in_memory = 0;
	cl_uint min_keys_crypt = param->NUM_KEYS_OPENCL / num_diff_salts;
	cl_uint rest_keys_crypt = param->NUM_KEYS_OPENCL % num_diff_salts;
	while (continue_attack && result)
	{
		// Process common
		size_t num_work_items = kernel2common->process_buffer(buffer, result, param, &num_keys_filled);

		// Convert to ordered by lenght
		pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 2, sizeof(cl_uint), (void*)&num_keys_filled);
		while (CL_INVALID_WORK_GROUP_SIZE == pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_ORDERED_INDEX], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
			param->max_work_group_size /= 2;
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
		num_keys_in_memory = 0;
		// Calculate the number of keys in memory
		for (int lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
			for (int i = 0; i < current_rules_count; i++)
			{
				int64_t multipler = rules[rules_remapped[i]].multipler;
				if (rules[rules_remapped[i]].depend_key_lenght)
					multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

				num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
			}
		rules_calculate_key_space(num_keys_filled, num_keys_in_memory, param->thread_id);

		for (int lenght = 0; continue_attack && lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		{
			cl_uint num_keys_complete_proccessed_total = 0;// The total of keys completly proccessed
			cl_uint current_num_keys = gpu_num_keys_by_len[lenght];
			cl_uint current_offsets_by_len = gpu_offsets_by_len[lenght];

			while (continue_attack && (current_num_keys * num_diff_salts - current_offsets_by_len) >= param->NUM_KEYS_OPENCL)
			{
				oclru_check_binary_present(param, lenght);

				// Take into account in the offset the already proccessed keys
				cl_uint current_offset = current_offsets_by_len + num_keys_complete_proccessed_total*num_diff_salts;

				cl_uint new_rest = rest_keys_crypt + current_offsets_by_len;
				cl_uint num_keys_complete_proccessed = min_keys_crypt;
				if (new_rest >= num_diff_salts)
				{
					num_keys_complete_proccessed++;
					new_rest -= num_diff_salts;
				}				

				// Do actual hashing
				for (int i = 0; continue_attack && i < current_rules_count; i++)
				{
					size_t work_group_size_rl = param->rules.work_group_sizes[i + lenght*current_rules_count];
					size_t num_work_items_len = param->NUM_KEYS_OPENCL;

					if (rules[rules_remapped[i]].ocl.max_param_value)
					{
						// Some param
						int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
						if (rules[rules_remapped[i]].depend_key_lenght)
							max_param_value = lenght + rules[rules_remapped[i]].key_lenght_sum;

						for (int j = 0; continue_attack && j < max_param_value; j++)
						{
							pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param
							pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 4, sizeof(current_offset), &current_offset);
							pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);		
						}
					}
					else
					{
						pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 4, sizeof(current_offset), (void*)&current_offset);
						pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
					}
				}
				pclFinish(param->queue);

				if (continue_attack)
				{
					num_keys_complete_proccessed_total += num_keys_complete_proccessed;
					current_num_keys -= num_keys_complete_proccessed;
					current_offsets_by_len = new_rest;

					int64_t num_keys_complete_proccessed_rules = 0;
					for (int i = 0; i < current_rules_count; i++)
					{
						int64_t multipler = rules[rules_remapped[i]].multipler;
						if (rules[rules_remapped[i]].depend_key_lenght)
							multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

						num_keys_complete_proccessed_rules += ((int64_t)num_keys_complete_proccessed) * multipler;
					}
					report_keys_processed(num_keys_complete_proccessed_rules);
					num_keys_in_memory -= num_keys_complete_proccessed_rules;
					rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
				}
			}
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);
			// GPU found some passwords
			if (num_found)
				ocl_rules_process_found(param, &num_found, gpu_num_keys_by_len, gpu_pos_ordered_by_len, param->param1 * 2);

			if (continue_attack && num_keys_complete_proccessed_total)
			{
				gpu_num_keys_by_len[lenght] = current_num_keys;
				gpu_offsets_by_len[lenght] = current_offsets_by_len;

				if (num_keys_complete_proccessed_total)
				{
					cl_uint len = (lenght + 3) / 4;
					//__kernel void move_to_begin(__global uint* keys, uint base_pos, uint len, uint offset, uint count)
					pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 1, sizeof(cl_uint), gpu_pos_ordered_by_len + lenght);
					pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 2, sizeof(cl_uint), &len);
					pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 3, sizeof(cl_uint), &num_keys_complete_proccessed_total);
					pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 4, sizeof(cl_uint), gpu_num_keys_by_len + lenght);
					size_t num_work_items_move = OCL_MULTIPLE_WORKGROUP_SIZE(gpu_num_keys_by_len[lenght], param->max_work_group_size);
					pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 1, NULL, &num_work_items_move, &param->max_work_group_size, 0, NULL, NULL);

					pclEnqueueWriteBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_FALSE, lenght*sizeof(cl_uint), sizeof(cl_uint), gpu_num_keys_by_len + lenght, 0, NULL, NULL);
				}
			}
		}

		// Next block of keys
		if (continue_attack)
			result = param->gen(buffer, param->param1, param->thread_id);
	}

	// Get the last passwords from memory
	pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);
	num_keys_in_memory = 0;
	// Calculate the number of keys in memory
	for (int lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		for (int i = 0; i < current_rules_count; i++)
		{
			int64_t multipler = rules[rules_remapped[i]].multipler;
			if (rules[rules_remapped[i]].depend_key_lenght)
				multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

			num_keys_in_memory += gpu_num_keys_by_len[lenght] * multipler;
		}
	rules_report_remain_key_space(num_keys_in_memory, param->thread_id);

	for (int lenght = 0; /*continue_attack &&*/ lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
	{
		cl_uint num_keys_complete_proccessed_total = 0;// The total of keys completly proccessed

		while (gpu_num_keys_by_len[lenght])
		{
			oclru_check_binary_present(param, lenght);

			// Take into account in the offset the already proccessed keys
			cl_uint current_offset = gpu_offsets_by_len[lenght] + num_keys_complete_proccessed_total*num_diff_salts;

			cl_uint new_rest = rest_keys_crypt + gpu_offsets_by_len[lenght];
			cl_uint num_keys_complete_proccessed = min_keys_crypt;
			if (new_rest >= num_diff_salts)
			{
				num_keys_complete_proccessed++;
				new_rest -= num_diff_salts;
			}

			cl_uint remaining_items = gpu_num_keys_by_len[lenght] * num_diff_salts - gpu_offsets_by_len[lenght];
			size_t num_work_items_len = param->NUM_KEYS_OPENCL;
			if (remaining_items <= param->NUM_KEYS_OPENCL)
				num_work_items_len = OCL_MULTIPLE_WORKGROUP_SIZE(remaining_items, param->max_work_group_size);

			// Do actual hashing
			for (int i = 0; /*continue_attack &&*/ i < current_rules_count; i++)
			{
				size_t work_group_size_rl = param->rules.work_group_sizes[i + lenght*current_rules_count];

				if (rules[rules_remapped[i]].ocl.max_param_value)
				{
					// Some params
					int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
					if (rules[rules_remapped[i]].depend_key_lenght)
						max_param_value = lenght + rules[rules_remapped[i]].key_lenght_sum;

					for (int j = 0; /*continue_attack &&*/ j < max_param_value; j++)
					{
						pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], param->param0, sizeof(cl_uint), &j);//additional param
						pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 4, sizeof(current_offset), &current_offset);
						pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
					}
				}
				else
				{
					pclSetKernelArg(param->rules.kernels[i + lenght*current_rules_count], 4, sizeof(current_offset), &current_offset);
					pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[i + lenght*current_rules_count], 1, NULL, &num_work_items_len, &work_group_size_rl, 0, NULL, NULL);
				}
			}

			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_found, 0, NULL, NULL);
			// GPU found some passwords
			if (num_found)
				ocl_rules_process_found(param, &num_found, gpu_num_keys_by_len, gpu_pos_ordered_by_len, param->param1 * 2);

			if (remaining_items <= param->NUM_KEYS_OPENCL)
			{
				num_keys_complete_proccessed_total += gpu_num_keys_by_len[lenght];
				gpu_num_keys_by_len[lenght] = 0;
				new_rest = 0;
			}
			else
			{
				if (num_keys_complete_proccessed)
				{
					num_keys_complete_proccessed_total += num_keys_complete_proccessed;
					gpu_num_keys_by_len[lenght] -= num_keys_complete_proccessed;
				}
				gpu_offsets_by_len[lenght] = new_rest;
			}
		}

		int64_t num_keys_complete_proccessed_rules = 0;
		for (int i = 0; i < current_rules_count; i++)
		{
			int64_t multipler = rules[rules_remapped[i]].multipler;
			if (rules[rules_remapped[i]].depend_key_lenght)
				multipler = multipler / RULE_LENGHT_COMMON * __max(0, lenght + rules[rules_remapped[i]].key_lenght_sum);

			num_keys_complete_proccessed_rules += ((int64_t)num_keys_complete_proccessed_total) * multipler;
		}
		report_keys_processed(num_keys_complete_proccessed_rules);
	}

	free(buffer);
	release_opencl_param(param);

	finish_thread();
}
PUBLIC int ocl_rules_init_ssha(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, int BINARY_SIZE, int SALT_SIZE, ocl_write_header_func* ocl_write_header, ocl_gen_kernel_func* ocl_gen_kernel, int FORMAT_BUFFER, cl_uint keys_opencl_divider)
{
	int kernel2common_index;
	cl_uint gpu_key_buffer_lenght = 0;
	cl_uint output_size = 3 * sizeof(cl_uint)*num_passwords_loaded;
	int multipler = 0;

	// Find a compatible generate_key_funtion function for a given key_provider
	for (int i = 0; i < LENGHT(key_providers[provider_index].impls); i++)
		for (kernel2common_index = 0; kernel2common_index < (int)num_kernels2common; kernel2common_index++)
			if (key_providers[provider_index].impls[i].protocol == kernels2common[kernel2common_index].protocol)
			{
				gen = key_providers[provider_index].impls[i].generate;
				goto out;
			}
out:
	create_opencl_param(param, gpu_index, gen, output_size, FALSE);

	// Count the possible number of generated keys
	for (int i = 0; i < current_rules_count; i++)
		multipler += rules[rules_remapped[i]].multipler;

	// Size in bytes
	for (int i = 1; i <= NTLM_MAX_KEY_LENGHT; i++)
		gpu_key_buffer_lenght += (i + 3) / 4 * sizeof(cl_uint);

	// Set appropriate number of candidates
	param->NUM_KEYS_OPENCL /= 4;
	param->NUM_KEYS_OPENCL /= keys_opencl_divider;

	// The minimum workable num_work_items for the GPU to be in use
	param->param1 = __max((param->NUM_KEYS_OPENCL + num_diff_salts - 1) / num_diff_salts, gpu_devices[gpu_index].cores * 64 / gpu_devices[gpu_index].NUM_KEYS_OPENCL_DIVIDER);

	if (param->param1*gpu_key_buffer_lenght >= (gpu_devices[gpu_index].max_mem_alloc_size - MAX_KEY_LENGHT_SMALL * sizeof(cl_uint)))
		param->param1 = (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size - MAX_KEY_LENGHT_SMALL * sizeof(cl_uint) - 1) / 2 / gpu_key_buffer_lenght;

	// The output size take into consideration the possible found keys
	if (num_passwords_loaded > 1 && multipler*param->param1 > num_passwords_loaded)
	{
		// Reserve to output at maximum half the MAX_MEM_ALLOC_SIZE
		output_size = __min(3 * sizeof(cl_uint)*multipler*param->param1, (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size / 2));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Generate code
#ifdef OCL_RULES_ALL_IN_GPU
	char* source = ocl_gen_rules_code(&gpu_devices[gpu_index], param, kernel2common_index, ocl_write_header, ocl_gen_kernel, 0, NULL, BINARY_SIZE, FORMAT_BUFFER, param->param1, param->param1*2);
#else
	char* source = ocl_gen_rules_code(&gpu_devices[gpu_index], param, kernel2common_index, ocl_write_header, ocl_gen_kernel, 0, NULL, BINARY_SIZE, FORMAT_BUFFER, param->param1, param->param1*2, -1);
#endif
	sprintf(source + strlen(source),
			"\n__kernel void move_to_begin(__global uint* keys, uint base_pos, uint len, uint offset, uint count)"
			"{"
				"uint idx=get_global_id(0);"
				"if(idx>=count)return;"

				"for(uint i=0;i<len;i++)"
					"keys[base_pos+i*%uu+idx]=keys[base_pos+i*%uu+idx+offset];"
			"}\n", 2 * param->param1, 2 * param->param1);

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Crypt by length
	create_kernel(param, KERNEL_PROCESS_KEY_INDEX, "process_key");
	create_kernel(param, KERNEL_ORDERED_INDEX, "common2ordered");
	create_kernel(param, KERNEL_RULE_MOVE_TO_BEGIN, "move_to_begin");

#ifndef OCL_RULES_ALL_IN_GPU
	for (int len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
	{
		cl_int code;
		free(source);
		source = ocl_gen_rules_code(&gpu_devices[gpu_index], param, kernel2common_index, ocl_write_header, ocl_gen_kernel, 0, NULL, BINARY_SIZE, FORMAT_BUFFER, param->param1, param->param1 * 2, len);

		param->rules.program = pclCreateProgramWithSource(param->context, 1, (char const **)(&source), NULL, &code);
		// Build program
		if (pclBuildProgram(param->rules.program, 1, &param->id, gpu_devices[gpu_index].compiler_options, NULL, NULL) == CL_SUCCESS)
		{
			pclGetProgramInfo(param->rules.program, CL_PROGRAM_BINARY_SIZES, sizeof(size_t), &param->rules.binaries_size[len], NULL);
			param->rules.binaries[len] = malloc(param->rules.binaries_size[len]);
			unsigned char* buffers[1] = { param->rules.binaries[len] };
			code = pclGetProgramInfo(param->rules.program, CL_PROGRAM_BINARIES, sizeof(buffers), &buffers, NULL);
			if (code != CL_SUCCESS)
				code++;
		}
		else
		{
			release_opencl_param(param);
			return FALSE;
		}
		pclReleaseProgram(param->rules.program);
		param->rules.program = NULL;
	}
#endif

	// Create rules kernels
	param->rules.num_kernels = current_rules_count*(NTLM_MAX_KEY_LENGHT + 1);
	param->rules.kernels = (cl_kernel*)calloc(param->rules.num_kernels, sizeof(cl_kernel));
	param->rules.work_group_sizes = (size_t*)malloc(sizeof(size_t)*param->rules.num_kernels);

#ifdef OCL_RULES_ALL_IN_GPU
	for (int len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
		for (int i = 0; i < current_rules_count; i++)
		{
			cl_int code;
			char name_buffer[12];
			sprintf(name_buffer, "ru_%il%i", i, len);
			param->rules.kernels[i + len*current_rules_count] = pclCreateKernel(param->program, name_buffer, &code);
			if (code != CL_SUCCESS)
			{
				release_opencl_param(param);
				return FALSE;
			}
		}
#endif

	// Create memory objects
	create_opencl_mem(param, GPU_ORDERED_KEYS, CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint) + param->param1*2*gpu_key_buffer_lenght, NULL);
	create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL*param->param1, NULL);
	create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, sizeof(cl_uint) + output_size, NULL);
	create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY, sizeof(cl_uint)*SALT_SIZE*num_diff_salts, NULL);
	create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);

	if (num_diff_salts < num_passwords_loaded)
	{
		if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
		{
			create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, salt_index);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(cl_uint)*num_passwords_loaded, same_salt_next);
		}
		else
		{
			create_opencl_mem(param, GPU_SALT_INDEX, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
			create_opencl_mem(param, GPU_SAME_SALT_NEXT, CL_MEM_READ_ONLY, sizeof(cl_uint)*num_passwords_loaded, NULL);
		}
	}

	// Set OpenCL kernel params
	kernels2common[kernel2common_index].setup_params(param, &gpu_devices[gpu_index]);

	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 0, sizeof(cl_mem), &param->mems[GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 1, sizeof(cl_mem), &param->mems[GPU_ORDERED_KEYS]);

	pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 0, sizeof(cl_mem), &param->mems[GPU_ORDERED_KEYS]);

#ifdef OCL_RULES_ALL_IN_GPU
	for (int len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
		for (int i = 0; i < current_rules_count; i++)
		{
			pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 0, sizeof(cl_mem), &param->mems[GPU_ORDERED_KEYS]);
			pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 1, sizeof(cl_mem), &param->mems[GPU_OUTPUT]);
			pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 2, sizeof(cl_mem), &param->mems[GPU_BINARY_VALUES]);
			pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 3, sizeof(cl_mem), &param->mems[GPU_SALT_VALUES]);

			if (num_diff_salts < num_passwords_loaded)
			{
				pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 5, sizeof(cl_mem), &param->mems[GPU_SALT_INDEX]);
				pclSetKernelArg(param->rules.kernels[i + len*current_rules_count], 6, sizeof(cl_mem), &param->mems[GPU_SAME_SALT_NEXT]);
			}
		}
#endif

	// Copy data to GPU
	memset(source, 0, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint));
	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), source);
	cl_write_buffer(param, GPU_ORDERED_KEYS, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint), source);
	{
		// Facilitate cache
		cl_uint* bin = (cl_uint*)binary_values;
		cl_uint* my_binary_values = (cl_uint*)malloc(BINARY_SIZE * num_passwords_loaded);
		for (cl_uint i = 0; i < num_passwords_loaded; i++)
		{
			my_binary_values[i + 0 * num_passwords_loaded] = bin[5 * i + 0];
			my_binary_values[i + 1 * num_passwords_loaded] = bin[5 * i + 1];
			my_binary_values[i + 2 * num_passwords_loaded] = bin[5 * i + 2];
			my_binary_values[i + 3 * num_passwords_loaded] = bin[5 * i + 3];
			my_binary_values[i + 4 * num_passwords_loaded] = bin[5 * i + 4];
		}

		cl_write_buffer(param, GPU_BINARY_VALUES, BINARY_SIZE * num_passwords_loaded, my_binary_values);
		pclFinish(param->queue);
		free(my_binary_values);
	}
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, sizeof(cl_uint)*SALT_SIZE*num_diff_salts, salts_values, 0, NULL, NULL);
	if (num_diff_salts < num_passwords_loaded && !(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
	{
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_INDEX], CL_FALSE, 0, sizeof(cl_uint) * num_passwords_loaded, salt_index, 0, NULL, NULL);
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SAME_SALT_NEXT], CL_FALSE, 0, sizeof(cl_uint) * num_passwords_loaded, same_salt_next, 0, NULL, NULL);
	}

	pclFinish(param->queue);
	free(source);

	// Find working workgroup
#define RULE_NUM_WORK_ITEMS_DIVIDER	16
	int64_t init = get_milliseconds();
	size_t num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(param->NUM_KEYS_OPENCL / RULE_NUM_WORK_ITEMS_DIVIDER, param->max_work_group_size);
	size_t max_work_group_size = param->max_work_group_size;
	cl_uint zero = 0;
	for (int len = 0; len <= NTLM_MAX_KEY_LENGHT; len++)
	{
		oclru_check_binary_present(param, len);

		for (int i = 0; i < current_rules_count; i++)
		{
			cl_kernel kernel = param->rules.kernels[i + len*current_rules_count];
			int bad_execution = FALSE;
			int rule_tryed = TRUE;

			if (rules[rules_remapped[i]].ocl.max_param_value)
			{
				int max_param_value = rules[rules_remapped[i]].ocl.max_param_value;
				if (rules[rules_remapped[i]].depend_key_lenght)
					max_param_value = len + rules[rules_remapped[i]].key_lenght_sum;

				if (max_param_value <= 0)
					rule_tryed = FALSE;
			}

			if (rule_tryed)
			{
				pclSetKernelArg(kernel, 4, sizeof(zero), (void*)&zero);

				if (rules[rules_remapped[i]].ocl.max_param_value)
					pclSetKernelArg(kernel, param->param0, sizeof(cl_uint), &zero);//additional param

				pclFinish(param->queue);

				int64_t init_kernel = get_milliseconds(), duration_kernel;
				if (CL_SUCCESS != pclEnqueueNDRangeKernel(param->queue, kernel, 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
					bad_execution = TRUE;
				if (CL_SUCCESS != pclFinish(param->queue))
					bad_execution = TRUE;
				duration_kernel = (get_milliseconds() - init_kernel)*RULE_NUM_WORK_ITEMS_DIVIDER;
				if (!bad_execution && duration_kernel > (OCL_NORMAL_KERNEL_TIME * 4 / 3))
					hs_log(HS_LOG_WARNING, "Rules to long", "Rules kernel duration: %ums", (cl_uint)duration_kernel);

				cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), &zero);

				while (bad_execution && param->max_work_group_size >= OCL_MIN_WORKGROUP_SIZE)
				{
					param->max_work_group_size /= 2;
					bad_execution = FALSE;
					pclFinish(param->queue);

					init_kernel = get_milliseconds();
					if (CL_SUCCESS != pclEnqueueNDRangeKernel(param->queue, kernel, 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
						bad_execution = TRUE;
					if (CL_SUCCESS != pclFinish(param->queue))
						bad_execution = TRUE;
					duration_kernel = (get_milliseconds() - init_kernel)*RULE_NUM_WORK_ITEMS_DIVIDER;
					if (!bad_execution && duration_kernel > (OCL_NORMAL_KERNEL_TIME * 4 / 3))
						hs_log(HS_LOG_WARNING, "Rules to long", "Rules kernel duration: %ums", (cl_uint)duration_kernel);

					cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), &zero);
				}

				param->rules.work_group_sizes[i + len*current_rules_count] = param->max_work_group_size;
				param->max_work_group_size = max_work_group_size;
			}
		}
	}
	pclFinish(param->queue);

	int64_t duration = get_milliseconds() - init;
	if (duration > 2000)
		hs_log(HS_LOG_WARNING, "Test Suite", "Rule check good workgroup: %i ms", (int)duration);

	*gpu_crypt = ocl_ssha_protocol_rules_work;
	param->additional_param = kernels2common + kernel2common_index;
#ifndef OCL_RULES_ALL_IN_GPU
	param->rules.gpu_index = gpu_index;
#endif
	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common opencl salted slow
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PRIVATE void ocl_slow_hashes_get_key(void* buffer, unsigned char* out_key, cl_uint key_index, size_t num_work_items)
{
	OpenCL_Param* param = (OpenCL_Param*)buffer;
	cl_uint len;
	pclEnqueueReadBuffer(param->queue, param->mems[GPU_RULE_SLOW_TRANSFORMED_KEYS], CL_FALSE, (7 * param->NUM_KEYS_OPENCL * 2 + key_index)*sizeof(cl_uint), sizeof(cl_uint), &len, 0, NULL, NULL);
	pclFinish(param->queue);
	len >>= 4;

	for (cl_uint i = 0; i < (len + 3) / 4; i++)
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_RULE_SLOW_TRANSFORMED_KEYS], CL_FALSE, (i * param->NUM_KEYS_OPENCL * 2 + key_index)*sizeof(cl_uint), sizeof(cl_uint), out_key + i * 4, 0, NULL, NULL);
		
	pclFinish(param->queue);
	out_key[len] = 0;
}

PRIVATE void ocl_rule_work_slow_hashes(OpenCL_Param* param)
{
	int num_keys_filled, zero = 0;
	uint32_t num_keys_transformed = 0;

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	ocl_slow_work_body_func* ocl_work_body = (ocl_slow_work_body_func*)param->additional_param1;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	int result = param->gen(buffer, param->NUM_KEYS_OPENCL, param->thread_id);
	int output_need_refresh = TRUE;
	while (continue_attack && result)
	{
		// Process common
		size_t num_work_items = kernel2common->process_buffer(buffer, result, param, &num_keys_filled);

		// Calculate the number of keys in memory
		int64_t num_keys_in_memory = 0;
		for (int i = 0; i < current_rules_count; i++)
			num_keys_in_memory += num_keys_filled * rules[rules_remapped[i]].multipler;
		rules_calculate_key_space(num_keys_filled, num_keys_in_memory, param->thread_id);
		cl_int rule_param = 0;

		// Foreach rule
		for (int rule_index = 0; continue_attack && rule_index < current_rules_count;)
		{
			if (output_need_refresh)
			{
				pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_keys_transformed, 0, NULL, NULL);
				output_need_refresh = FALSE;
			}
			if (rules[rules_remapped[rule_index]].multipler > 1)
				pclSetKernelArg(param->rules.kernels[rule_index], 4, sizeof(rule_param), (void*)&rule_param);
			pclSetKernelArg(param->rules.kernels[rule_index], 3, sizeof(num_keys_filled), (void*)&num_keys_filled);
			pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[rule_index], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &num_keys_transformed, 0, NULL, NULL);
			pclFinish(param->queue);

			// Calculate cycle state
			rule_param++;
			if (rules[rules_remapped[rule_index]].depend_key_lenght)
			{
				if (rule_param >= (27 + rules[rules_remapped[rule_index]].key_lenght_sum) * rules[rules_remapped[rule_index]].multipler / RULE_LENGHT_COMMON)
				{
					rule_index++;
					rule_param = 0;
				}
			}
			else if (rule_param >= rules[rules_remapped[rule_index]].multipler)
			{
				rule_index++;
				rule_param = 0;
			}

			if (num_keys_transformed < param->NUM_KEYS_OPENCL)
				continue;

			// Execute DCC2 format
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &zero, 0, NULL, NULL);
			ocl_work_body(param, param->NUM_KEYS_OPENCL, param, ocl_slow_hashes_get_key);
			output_need_refresh = TRUE;

			// Handle keys that remains
			num_keys_in_memory -= param->NUM_KEYS_OPENCL;
			rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
			num_keys_transformed -= param->NUM_KEYS_OPENCL;
			if (num_keys_transformed)
			{
				size_t move_num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_keys_transformed, param->max_work_group_size);
				pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 1, sizeof(num_keys_transformed), (void*)&num_keys_transformed);
				pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 1, NULL, &move_num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			}
		}

		if (continue_attack)
			result = param->gen(buffer, param->NUM_KEYS_OPENCL, param->thread_id);
	}

	// Last keys
	if (continue_attack && num_keys_transformed)
	{
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &zero, 0, NULL, NULL);
		rules_calculate_key_space(0, num_keys_transformed, param->thread_id);
		ocl_work_body(param, num_keys_transformed, param, ocl_slow_hashes_get_key);
	}

	free(buffer);
	release_opencl_param(param);

	finish_thread();
}
PRIVATE void ocl_work_slow_hashes(OpenCL_Param* param)
{
	int num_keys_filled;

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	ocl_slow_work_body_func* ocl_work_body = (ocl_slow_work_body_func*)param->additional_param1;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	int result = param->gen(buffer, param->NUM_KEYS_OPENCL, param->thread_id);
	while (continue_attack && result)
	{
		// Process common
		size_t num_work_items = kernel2common->process_buffer(buffer, result, param, &num_keys_filled);
		
		ocl_work_body(param, num_keys_filled, buffer, kernel2common->get_key);

		if (continue_attack)
			result = param->gen(buffer, param->NUM_KEYS_OPENCL, param->thread_id);
	}

	free(buffer);
	release_opencl_param(param);

	finish_thread();
}
PUBLIC int ocl_init_slow_hashes(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, oclKernel2Common* ocl_kernel_provider, int use_rules, cl_uint size_big_chunk
	, int BINARY_SIZE, int SALT_SIZE, ocl_gen_kernels_func* ocl_gen_kernels, ocl_slow_work_body_func* ocl_work_body, cl_uint num_keys_divider)
{
	//cl_int code;
	cl_uint output_size = 2 * sizeof(cl_uint)*num_passwords_loaded;

	create_opencl_param(param, gpu_index, gen, output_size, FALSE);
	param->additional_param  = ocl_kernel_provider;
	param->additional_param1 = ocl_work_body;

	param->NUM_KEYS_OPENCL /= num_keys_divider;
	if (param->NUM_KEYS_OPENCL < param->max_work_group_size)
	{
		param->max_work_group_size = param->NUM_KEYS_OPENCL = __max(OCL_MIN_WORKGROUP_SIZE, param->NUM_KEYS_OPENCL);
	}

	while ((size_big_chunk*sizeof(cl_uint)*param->NUM_KEYS_OPENCL) > gpu_devices[gpu_index].max_mem_alloc_size)
		param->NUM_KEYS_OPENCL /= 2;

	// The output size take into consideration the possible found keys
	if (param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = __min(2 * sizeof(cl_uint)*param->NUM_KEYS_OPENCL, (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size / 2));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Generate code
	char* source = ocl_gen_kernels(&gpu_devices[gpu_index], ocl_kernel_provider, param, use_rules ? 2 : 1);

	if (use_rules)
	{
		// This is because AMD compiler do not support __constant vars inside a kernel
		ocl_write_code** constants_written = (ocl_write_code**)malloc(current_rules_count*sizeof(ocl_write_code*));
		int num_constants_written = 0;

		// Generate one kernel for each rule
		for (int i = 0; i < current_rules_count; i++)
		{
			char rule_name[12];

			// If needed to use constants -> write it only once
			if (rules[rules_remapped[i]].ocl.setup_constants)
			{
				int constants_already_written = FALSE, j;
				// Check if was written before
				for (j = 0; j < num_constants_written; j++)
					if (rules[rules_remapped[i]].ocl.setup_constants == constants_written[j])
					{
						constants_already_written = TRUE;
						break;
					}
				if (!constants_already_written)
				{
					constants_written[num_constants_written] = rules[rules_remapped[i]].ocl.setup_constants;
					num_constants_written++;
					rules[rules_remapped[i]].ocl.setup_constants(source);
				}
			}
			// Write the kernel
			sprintf(rule_name, "rule_%i", i);
			rules[rules_remapped[i]].ocl.common_implementation(source, rule_name, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL * 2);
		}

		free(constants_written);

		sprintf(source + strlen(source),
			"\n__kernel void move_to_begin(__global uint* keys, uint count)"
			"{"
				"uint idx=get_global_id(0);"
				"if(idx>=count)return;"

				"uint len=keys[7u*%uu+idx+%uu];"
				"keys[7u*%uu+idx]=len;"
				"len=(len>>6u)+1u;"

				"for(uint i=0;i<len;i++)"
					"keys[i*%uu+idx]=keys[i*%uu+idx+%uu];"
			"}", param->NUM_KEYS_OPENCL * 2, param->NUM_KEYS_OPENCL, param->NUM_KEYS_OPENCL * 2, param->NUM_KEYS_OPENCL * 2, param->NUM_KEYS_OPENCL * 2, param->NUM_KEYS_OPENCL);
	}

	//size_t len = strlen(source);
	
	// Perform runtime source compilation
	if(!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Crypt Kernels
	create_kernel(param, KERNEL_PROCESS_KEY_INDEX, "process_key");
	if (use_rules)
	{
		param->rules.num_kernels = current_rules_count;
		param->rules.kernels = (cl_kernel*)malloc(sizeof(cl_kernel)*current_rules_count);
		// Generate one kernel for each rule
		for (int i = 0; i < current_rules_count; i++)
		{
			cl_int code;
			char rule_name[12];

			// Write the kernel
			sprintf(rule_name, "rule_%i", i);
			param->rules.kernels[i] = pclCreateKernel(param->program, rule_name, &code);
			if (code != CL_SUCCESS)
			{
				release_opencl_param(param);
				return FALSE;
			}
		}
		create_kernel(param, KERNEL_RULE_MOVE_TO_BEGIN, "move_to_begin");
	}

	// Create memory objects
	// ipad+opad+sha1+crypt_result
	int big_buffer_index = GPU_CURRENT_KEY;
	if (use_rules)
	{
		create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL*param->NUM_KEYS_OPENCL, NULL);
		create_opencl_mem(param, GPU_RULE_SLOW_TRANSFORMED_KEYS, CL_MEM_READ_WRITE, 2 * MAX_KEY_LENGHT_SMALL*param->NUM_KEYS_OPENCL, NULL);

		big_buffer_index = GPU_RULE_SLOW_BUFFER;
	}
	create_opencl_mem(param, big_buffer_index, CL_MEM_READ_WRITE, size_big_chunk*sizeof(cl_uint)*param->NUM_KEYS_OPENCL, NULL);
	create_opencl_mem(param,    GPU_OUTPUT   , CL_MEM_READ_WRITE, sizeof(cl_uint)+output_size, NULL);
	if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
	{
		create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
		create_opencl_mem(param, GPU_SALT_VALUES  , CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, SALT_SIZE*num_diff_salts, salts_values);
	}
	else
	{
		create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
		create_opencl_mem(param, GPU_SALT_VALUES  , CL_MEM_READ_ONLY, SALT_SIZE*num_diff_salts, NULL);
	}

	ocl_kernel_provider->setup_params(param, &gpu_devices[gpu_index]);

	// Set OpenCL kernel params
	if (use_rules)
	{
		for (int i = 0; i < current_rules_count; i++)
		{
			pclSetKernelArg(param->rules.kernels[i], 0, sizeof(cl_mem), (void*)&param->mems[GPU_CURRENT_KEY]);
			pclSetKernelArg(param->rules.kernels[i], 1, sizeof(cl_mem), (void*)&param->mems[GPU_RULE_SLOW_TRANSFORMED_KEYS]);
			pclSetKernelArg(param->rules.kernels[i], 2, sizeof(cl_mem), (void*)&param->mems[GPU_OUTPUT]);
		}

		pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 0, sizeof(cl_mem), (void*)&param->mems[GPU_RULE_SLOW_TRANSFORMED_KEYS]);
	}

	// Copy data to GPU
	memset(source, 0, MAX_KEY_LENGHT_SMALL);
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, sizeof(cl_uint), source, 0, NULL, NULL);
	if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
	{
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_BINARY_VALUES], CL_FALSE, 0, BINARY_SIZE*num_passwords_loaded, binary_values, 0, NULL, NULL);
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES]  , CL_FALSE, 0, SALT_SIZE*num_diff_salts, salts_values, 0, NULL, NULL);
	}
	pclFinish(param->queue);

	free(source);
	
	*gpu_crypt = use_rules ? ocl_rule_work_slow_hashes : ocl_work_slow_hashes;
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Common opencl salted slow ordered (md5crypt,...)
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
PUBLIC void ocl_slow_ordered_found(OpenCL_Param* param, cl_uint* num_found, cl_uint gpu_max_num_keys, cl_uint gpu_base_pos, cl_uint lenght)
{
	// Keys found
	unsigned char key[MAX_KEY_LENGHT_SMALL];

	pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 4, 2 * sizeof(cl_uint)*num_found[0], param->output, 0, NULL, NULL);

	// Iterate all found passwords
	for (cl_uint i = 0; i < num_found[0]; i++)
	{
		cl_uint key_index = param->output[2 * i];
		cl_uint hash_index = param->output[2 * i + 1];

		if (hash_index < num_passwords_loaded && !((is_foundBit[hash_index >> 5] >> (hash_index & 31)) & 1) && key_index < gpu_max_num_keys)
		{
			// Get the cleartext of the original key
			for (cl_uint j = 0; j < (lenght + 3) / 4; j++)
				pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_FALSE, 4 * (gpu_base_pos + key_index + j*param->param1*2), sizeof(cl_uint), key + 4 * j, 0, NULL, NULL);

			pclFinish(param->queue);
			key[lenght] = 0;
			password_was_found(hash_index, key);
		}
	}

	num_found[0] = 0;
	pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, sizeof(cl_uint), num_found, 0, NULL, NULL);
}
PRIVATE void ocl_rule_work_slow_hashes_ordered(OpenCL_Param* param)
{
	cl_uint zero = 0;
	int num_keys_filled;
	cl_uint gpu_num_keys_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint gpu_offsets_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint gpu_pos_ordered_by_len[NTLM_MAX_KEY_LENGHT + 1];

	// Size in uint
	for (cl_uint i = 0, j = 32; i <= NTLM_MAX_KEY_LENGHT; i++)
	{
		gpu_pos_ordered_by_len[i] = j;
		j += (i + 3) / 4 * param->param1 * 2;
	}
	memset(gpu_num_keys_by_len, 0, sizeof(gpu_num_keys_by_len));
	memset(gpu_offsets_by_len, 0, sizeof(gpu_offsets_by_len));

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	ocl_slow_ordered_work_body_func* ocl_work_body = (ocl_slow_ordered_work_body_func*)param->additional_param1;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	int result = param->gen(buffer, param->param1, param->thread_id);
	int64_t num_keys_in_memory = 0;
	cl_uint num_keys_transformed = 0;
	cl_uint min_keys_crypt = param->NUM_KEYS_OPENCL / num_diff_salts;
	cl_uint rest_keys_crypt = param->NUM_KEYS_OPENCL % num_diff_salts;
	while (continue_attack && result)
	{
		// Process common
		size_t num_work_items = kernel2common->process_buffer(buffer, result, param, &num_keys_filled);

		// Calculate num_keys_in_memory
		num_keys_in_memory = 0;
		for (int i = 0; i < current_rules_count; i++)
			num_keys_in_memory += ((int64_t)num_keys_filled) * rules[rules_remapped[i]].multipler;
		for (cl_uint lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
			num_keys_in_memory += gpu_num_keys_by_len[lenght];
		rules_calculate_key_space(num_keys_filled, num_keys_in_memory, param->thread_id);

		cl_int rule_param = 0;
		// Foreach rule
		for (int rule_index = 0; continue_attack && rule_index < current_rules_count;)
		{
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &zero, 0, NULL, NULL);

			if (rules[rules_remapped[rule_index]].multipler > 1)
				pclSetKernelArg(param->rules.kernels[rule_index], 4, sizeof(rule_param), &rule_param);
			pclSetKernelArg(param->rules.kernels[rule_index], 3, sizeof(num_keys_filled), &num_keys_filled);
			pclEnqueueNDRangeKernel(param->queue, param->rules.kernels[rule_index], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_OUTPUT], CL_TRUE, 0, 4, &num_keys_transformed, 0, NULL, NULL);

			// Calculate cycle state
			rule_param++;
			if (rules[rules_remapped[rule_index]].depend_key_lenght)
			{
				// TODO: Make this generic
				if (rule_param >= (15 + rules[rules_remapped[rule_index]].key_lenght_sum) * rules[rules_remapped[rule_index]].multipler / RULE_LENGHT_COMMON)
				{
					rule_index++;
					rule_param = 0;
				}
			}
			else if (rule_param >= rules[rules_remapped[rule_index]].multipler)
			{
				rule_index++;
				rule_param = 0;
			}
			if (num_keys_transformed == 0)
				continue;

			// Convert to ordered by lenght
			size_t ordered_num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(num_keys_transformed, param->max_work_group_size);
			pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 2, sizeof(cl_uint), &num_keys_transformed);
			while (CL_INVALID_WORK_GROUP_SIZE == pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_ORDERED_INDEX], 1, NULL, &ordered_num_work_items, &param->max_work_group_size, 0, NULL, NULL))
				param->max_work_group_size /= 2;
			pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);

			// Execute format
			pclEnqueueWriteBuffer(param->queue, param->mems[GPU_OUTPUT], CL_FALSE, 0, 4, &zero, 0, NULL, NULL);
			for (cl_uint lenght = 0; continue_attack && lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
			{
				cl_uint num_keys_complete_proccessed_total = 0;// The total of keys completly proccessed

				while ((gpu_num_keys_by_len[lenght] * num_diff_salts - gpu_offsets_by_len[lenght]) >= param->NUM_KEYS_OPENCL)
				{
					// Take into account in the offset the already proccessed keys
					cl_uint current_offset = gpu_offsets_by_len[lenght] + num_keys_complete_proccessed_total*num_diff_salts;

					cl_uint new_rest = rest_keys_crypt + gpu_offsets_by_len[lenght];
					cl_uint num_keys_complete_proccessed = min_keys_crypt;
					if (new_rest >= num_diff_salts)
					{
						num_keys_complete_proccessed++;
						new_rest -= num_diff_salts;
					}
					num_keys_complete_proccessed_total += num_keys_complete_proccessed;
					gpu_num_keys_by_len[lenght] -= num_keys_complete_proccessed;
					gpu_offsets_by_len[lenght] = new_rest;

					ocl_work_body(param, lenght, num_keys_complete_proccessed_total + (new_rest ? 1 : 0), gpu_pos_ordered_by_len[lenght], current_offset, param->NUM_KEYS_OPENCL);
				}

				if (num_keys_complete_proccessed_total)
				{
					cl_uint len = (lenght + 3) / 4;
					//__kernel void move_to_begin(__global uint* keys, uint base_pos, uint len, uint offset, uint count)
					pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 1, sizeof(cl_uint), gpu_pos_ordered_by_len + lenght);
					pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 2, sizeof(cl_uint), &len);
					pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 3, sizeof(cl_uint), &num_keys_complete_proccessed_total);
					pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 4, sizeof(cl_uint), gpu_num_keys_by_len + lenght);
					size_t num_work_items_move = OCL_MULTIPLE_WORKGROUP_SIZE(gpu_num_keys_by_len[lenght], param->max_work_group_size);
					pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 1, NULL, &num_work_items_move, &param->max_work_group_size, 0, NULL, NULL);

					pclEnqueueWriteBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_FALSE, lenght*sizeof(cl_uint), sizeof(cl_uint), gpu_num_keys_by_len + lenght, 0, NULL, NULL);
					report_keys_processed(num_keys_complete_proccessed_total);
				}
			}

			// Calculate num_keys_in_memory
			num_keys_in_memory = rule_param ? ((int64_t)num_keys_filled) * (rules[rules_remapped[rule_index]].multipler - rule_param) : 0;
			for (int i = rule_index + 1; i < current_rules_count; i++)
				num_keys_in_memory += ((int64_t)num_keys_filled) * rules[rules_remapped[i]].multipler;
			for (cl_uint lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
				num_keys_in_memory += gpu_num_keys_by_len[lenght];
			rules_calculate_key_space(0, num_keys_in_memory, param->thread_id);
		}

		// More keys
		if (continue_attack)
			result = param->gen(buffer, param->param1, param->thread_id);
	}

	num_keys_in_memory = 0;
	// Calculate the number of keys in memory
	for (cl_uint lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		num_keys_in_memory += gpu_num_keys_by_len[lenght];
	rules_report_remain_key_space(num_keys_in_memory, param->thread_id);

	// Process the remaining in memory
	for (cl_uint lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
	{
		cl_uint num_keys_complete_proccessed_total = 0;// The total of keys completly proccessed

		while (gpu_num_keys_by_len[lenght])
		{
			// Take into account in the offset the already proccessed keys
			cl_uint current_offset = gpu_offsets_by_len[lenght] + num_keys_complete_proccessed_total*num_diff_salts;

			cl_uint new_rest = rest_keys_crypt + gpu_offsets_by_len[lenght];
			cl_uint num_keys_complete_proccessed = min_keys_crypt;
			if (new_rest >= num_diff_salts)
			{
				num_keys_complete_proccessed++;
				new_rest -= num_diff_salts;
			}

			cl_uint remaining_items = gpu_num_keys_by_len[lenght] * num_diff_salts - gpu_offsets_by_len[lenght];
			size_t num_work_items = param->NUM_KEYS_OPENCL;
			if (remaining_items <= param->NUM_KEYS_OPENCL)
				num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(remaining_items, param->max_work_group_size);

			if (remaining_items <= param->NUM_KEYS_OPENCL)
			{
				num_keys_complete_proccessed_total += gpu_num_keys_by_len[lenght];
				gpu_num_keys_by_len[lenght] = 0;
				new_rest = 0;
			}
			else
			{
				if (num_keys_complete_proccessed)
				{
					num_keys_complete_proccessed_total += num_keys_complete_proccessed;
					gpu_num_keys_by_len[lenght] -= num_keys_complete_proccessed;
				}
				gpu_offsets_by_len[lenght] = new_rest;
			}

			ocl_work_body(param, lenght, num_keys_complete_proccessed_total + (new_rest ? 1 : 0), gpu_pos_ordered_by_len[lenght], current_offset, num_work_items);
		}
		report_keys_processed(num_keys_complete_proccessed_total);
	}

	free(buffer);
	release_opencl_param(param);

	finish_thread();
}
PRIVATE void ocl_work_slow_hashes_ordered(OpenCL_Param* param)
{
	cl_uint zero = 0;
	int num_keys_filled;
	cl_uint gpu_num_keys_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint gpu_offsets_by_len[NTLM_MAX_KEY_LENGHT + 1];
	cl_uint gpu_pos_ordered_by_len[NTLM_MAX_KEY_LENGHT + 1];
	
	// Size in uint
	for (cl_uint i = 0, j = 32; i <= NTLM_MAX_KEY_LENGHT; i++)
	{
		gpu_pos_ordered_by_len[i] = j;
		j += (i + 3) / 4 * param->param1 * 2;
	}
	memset(gpu_num_keys_by_len, 0, sizeof(gpu_num_keys_by_len));
	memset(gpu_offsets_by_len, 0, sizeof(gpu_offsets_by_len));

	oclKernel2Common* kernel2common = (oclKernel2Common*)param->additional_param;
	ocl_slow_ordered_work_body_func* ocl_work_body = (ocl_slow_ordered_work_body_func*)param->additional_param1;
	void* buffer = malloc(kernel2common->get_buffer_size(param));

	HS_SET_PRIORITY_GPU_THREAD;
	memset(buffer, 0, kernel2common->get_buffer_size(param));

	int result = param->gen(buffer, param->param1, param->thread_id);

	cl_uint min_keys_crypt = param->NUM_KEYS_OPENCL / num_diff_salts;
	cl_uint rest_keys_crypt = param->NUM_KEYS_OPENCL % num_diff_salts;
	while (continue_attack && result)
	{
		// Process common
		size_t num_work_items = kernel2common->process_buffer(buffer, result, param, &num_keys_filled);

		// Convert to ordered by lenght
		pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 2, sizeof(cl_uint), &num_keys_filled);
		while (CL_INVALID_WORK_GROUP_SIZE == pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_ORDERED_INDEX], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL))
			param->max_work_group_size /= 2;
		pclEnqueueReadBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_TRUE, 0, (NTLM_MAX_KEY_LENGHT + 1) * sizeof(cl_uint), &gpu_num_keys_by_len, 0, NULL, NULL);

		for (cl_uint lenght = 0; continue_attack && lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
		{
			cl_uint num_keys_complete_proccessed_total = 0;// The total of keys completly proccessed

			while ((gpu_num_keys_by_len[lenght] * num_diff_salts - gpu_offsets_by_len[lenght]) >= param->NUM_KEYS_OPENCL)
			{
				// Take into account in the offset the already proccessed keys
				cl_uint current_offset = gpu_offsets_by_len[lenght] + num_keys_complete_proccessed_total*num_diff_salts;

				cl_uint new_rest = rest_keys_crypt + gpu_offsets_by_len[lenght];
				cl_uint num_keys_complete_proccessed = min_keys_crypt;
				if (new_rest >= num_diff_salts)
				{
					num_keys_complete_proccessed++;
					new_rest -= num_diff_salts;
				}
				num_keys_complete_proccessed_total += num_keys_complete_proccessed;
				gpu_num_keys_by_len[lenght] -= num_keys_complete_proccessed;
				gpu_offsets_by_len[lenght] = new_rest;

				ocl_work_body(param, lenght, num_keys_complete_proccessed_total + (new_rest ? 1 : 0), gpu_pos_ordered_by_len[lenght], current_offset, param->NUM_KEYS_OPENCL);
			}

			if (num_keys_complete_proccessed_total)
			{
				cl_uint len = (lenght + 3) / 4;
				//__kernel void move_to_begin(__global uint* keys, uint base_pos, uint len, uint offset, uint count)
				pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 1, sizeof(cl_uint), gpu_pos_ordered_by_len + lenght);
				pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 2, sizeof(cl_uint), &len);
				pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 3, sizeof(cl_uint), &num_keys_complete_proccessed_total);
				pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 4, sizeof(cl_uint), gpu_num_keys_by_len + lenght);
				num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(gpu_num_keys_by_len[lenght], param->max_work_group_size);
				pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 1, NULL, &num_work_items, &param->max_work_group_size, 0, NULL, NULL);

				pclEnqueueWriteBuffer(param->queue, param->mems[GPU_ORDERED_KEYS], CL_FALSE, lenght*sizeof(cl_uint), sizeof(cl_uint), gpu_num_keys_by_len + lenght, 0, NULL, NULL);
				report_keys_processed(num_keys_complete_proccessed_total);
			}
		}

		// More keys
		if (continue_attack)
			result = param->gen(buffer, param->param1, param->thread_id);
	}

	// Process the remaining in memory
	for (cl_uint lenght = 0; lenght <= NTLM_MAX_KEY_LENGHT; lenght++)
	{
		cl_uint num_keys_complete_proccessed_total = 0;// The total of keys completly proccessed

		while (gpu_num_keys_by_len[lenght])
		{
			// Take into account in the offset the already proccessed keys
			cl_uint current_offset = gpu_offsets_by_len[lenght] + num_keys_complete_proccessed_total*num_diff_salts;

			cl_uint new_rest = rest_keys_crypt + gpu_offsets_by_len[lenght];
			cl_uint num_keys_complete_proccessed = min_keys_crypt;
			if (new_rest >= num_diff_salts)
			{
				num_keys_complete_proccessed++;
				new_rest -= num_diff_salts;
			}

			cl_uint remaining_items = gpu_num_keys_by_len[lenght] * num_diff_salts - gpu_offsets_by_len[lenght];
			size_t num_work_items = param->NUM_KEYS_OPENCL;
			if (remaining_items <= param->NUM_KEYS_OPENCL)
				num_work_items = OCL_MULTIPLE_WORKGROUP_SIZE(remaining_items, param->max_work_group_size);

			if (remaining_items <= param->NUM_KEYS_OPENCL)
			{
				num_keys_complete_proccessed_total += gpu_num_keys_by_len[lenght];
				gpu_num_keys_by_len[lenght] = 0;
				new_rest = 0;
			}
			else
			{
				if (num_keys_complete_proccessed)
				{
					num_keys_complete_proccessed_total += num_keys_complete_proccessed;
					gpu_num_keys_by_len[lenght] -= num_keys_complete_proccessed;
				}
				gpu_offsets_by_len[lenght] = new_rest;
			}

			ocl_work_body(param, lenght, num_keys_complete_proccessed_total + (new_rest ? 1 : 0), gpu_pos_ordered_by_len[lenght], current_offset, num_work_items);
		}
		report_keys_processed(num_keys_complete_proccessed_total);
	}

	free(buffer);
	release_opencl_param(param);

	finish_thread();
}
PUBLIC int ocl_init_slow_hashes_ordered(OpenCL_Param* param, cl_uint gpu_index, generate_key_funtion* gen, gpu_crypt_funtion** gpu_crypt, oclKernel2Common* ocl_kernel_provider, int use_rules, cl_uint size_big_chunk
	, int BINARY_SIZE, int SALT_SIZE, ocl_gen_kernels_func* ocl_gen_kernels, ocl_slow_ordered_work_body_func* ocl_work_body, cl_uint num_keys_divider, cl_uint MAX_KEY_LENGHT)
{
	//cl_int code;
	cl_uint output_size = 2 * sizeof(cl_uint)*num_passwords_loaded;

	create_opencl_param(param, gpu_index, gen, output_size, FALSE);
	param->additional_param = ocl_kernel_provider;
	param->additional_param1 = ocl_work_body;

	param->NUM_KEYS_OPENCL /= num_keys_divider;
	if (param->NUM_KEYS_OPENCL < param->max_work_group_size)
	{
		param->max_work_group_size = param->NUM_KEYS_OPENCL = __max(OCL_MIN_WORKGROUP_SIZE, param->NUM_KEYS_OPENCL);
	}

	// Permit to be used as buffer for keys
	size_big_chunk = __max(8u, size_big_chunk);
	while ((size_big_chunk*sizeof(cl_uint)*param->NUM_KEYS_OPENCL) > gpu_devices[gpu_index].max_mem_alloc_size)
		param->NUM_KEYS_OPENCL /= 2;

	cl_uint gpu_key_buffer_lenght = 0;
	// Size in bytes
	for (cl_uint i = 1; i <= MAX_KEY_LENGHT; i++)
		gpu_key_buffer_lenght += (i + 3) / 4 * sizeof(cl_uint);

	// The minimum workable num_work_items for the GPU to be in use
	param->param1 = __max((param->NUM_KEYS_OPENCL + num_diff_salts - 1) / num_diff_salts, gpu_devices[gpu_index].cores * 64 / gpu_devices[gpu_index].NUM_KEYS_OPENCL_DIVIDER);

	if(2 * param->param1*gpu_key_buffer_lenght >= (gpu_devices[gpu_index].max_mem_alloc_size - MAX_KEY_LENGHT_SMALL * sizeof(cl_uint)))
		param->param1 = (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size - MAX_KEY_LENGHT_SMALL * sizeof(cl_uint) - 1) / 2 / gpu_key_buffer_lenght;

	// The output size take into consideration the possible found keys
	if (param->NUM_KEYS_OPENCL > num_passwords_loaded)
	{
		output_size = __min(2 * sizeof(cl_uint)*param->NUM_KEYS_OPENCL, (cl_uint)(gpu_devices[gpu_index].max_mem_alloc_size / 2));
		free(param->output);
		param->output = (cl_uint*)malloc(output_size);
	}

	// Generate code
	char* source = ocl_gen_kernels(&gpu_devices[gpu_index], ocl_kernel_provider, param, use_rules);
	// Kernel needed to convert from common format to the ordered by lenght format
	ocl_gen_kernel_common_2_ordered(source + strlen(source), param->param1, 2 * param->param1, MAX_KEY_LENGHT);

	if (use_rules)
	{
		// This is because AMD compiler do not support __constant vars inside a kernel
		ocl_write_code** constants_written = (ocl_write_code**)malloc(current_rules_count*sizeof(ocl_write_code*));
		int num_constants_written = 0;

		// Generate one kernel for each rule
		for (int i = 0; i < current_rules_count; i++)
		{
			char rule_name[12];

			// If needed to use constants -> write it only once
			if (rules[rules_remapped[i]].ocl.setup_constants)
			{
				int constants_already_written = FALSE, j;
				// Check if was written before
				for (j = 0; j < num_constants_written; j++)
					if (rules[rules_remapped[i]].ocl.setup_constants == constants_written[j])
					{
						constants_already_written = TRUE;
						break;
					}
				if (!constants_already_written)
				{
					constants_written[num_constants_written] = rules[rules_remapped[i]].ocl.setup_constants;
					num_constants_written++;
					rules[rules_remapped[i]].ocl.setup_constants(source);
				}
			}
			// Write the kernel
			sprintf(rule_name, "rule_%i", i);
			rules[rules_remapped[i]].ocl.common_implementation(source, rule_name, param->param1, param->param1);
		}

		free(constants_written);
	}
	sprintf(source + strlen(source),
			"\n__kernel void move_to_begin(__global uint* keys, uint base_pos, uint len, uint offset, uint count)"
			"{"
				"uint idx=get_global_id(0);"
				"if(idx>=count)return;"

				"for(uint i=0;i<len;i++)"
					"keys[base_pos+i*%uu+idx]=keys[base_pos+i*%uu+idx+offset];"
			"}", 2 * param->param1, 2 * param->param1);
	//size_t len = strlen(source);

	// Perform runtime source compilation
	if (!build_opencl_program(param, source, gpu_devices[gpu_index].compiler_options))
	{
		release_opencl_param(param);
		return FALSE;
	}

	// Crypt Kernels
	create_kernel(param, KERNEL_PROCESS_KEY_INDEX, "process_key");
	create_kernel(param, KERNEL_ORDERED_INDEX, "common2ordered");
	create_kernel(param, KERNEL_RULE_MOVE_TO_BEGIN, "move_to_begin");
	if (use_rules)
	{
		param->rules.num_kernels = current_rules_count;
		param->rules.kernels = (cl_kernel*)malloc(sizeof(cl_kernel)*current_rules_count);
		// Generate one kernel for each rule
		for (int i = 0; i < current_rules_count; i++)
		{
			cl_int code;
			char rule_name[12];

			// Write the kernel
			sprintf(rule_name, "rule_%i", i);
			param->rules.kernels[i] = pclCreateKernel(param->program, rule_name, &code);
			if (code != CL_SUCCESS)
			{
				release_opencl_param(param);
				return FALSE;
			}
		}
	}

	// Create memory objects
	if (use_rules)
		create_opencl_mem(param, GPU_RULE_SLOW_TRANSFORMED_KEYS, CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL * param->param1, NULL);

	create_opencl_mem(param, GPU_CURRENT_KEY, CL_MEM_READ_WRITE, size_big_chunk*sizeof(cl_uint)*param->NUM_KEYS_OPENCL, NULL);
	create_opencl_mem(param, GPU_OUTPUT, CL_MEM_READ_WRITE, sizeof(cl_uint) + output_size, NULL);
	create_opencl_mem(param, GPU_ORDERED_KEYS, CL_MEM_READ_WRITE, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint) + 2 * param->param1 * gpu_key_buffer_lenght, NULL);
	if (gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY)
	{
		create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, BINARY_SIZE*num_passwords_loaded, binary_values);
		create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, SALT_SIZE*num_diff_salts, salts_values);
	}
	else
	{
		create_opencl_mem(param, GPU_BINARY_VALUES, CL_MEM_READ_ONLY, BINARY_SIZE*num_passwords_loaded, NULL);
		create_opencl_mem(param, GPU_SALT_VALUES, CL_MEM_READ_ONLY, SALT_SIZE*num_diff_salts, NULL);
	}

	ocl_kernel_provider->setup_params(param, &gpu_devices[gpu_index]);
	// Order params
	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 0, sizeof(cl_mem), &param->mems[use_rules ? GPU_RULE_SLOW_TRANSFORMED_KEYS : GPU_CURRENT_KEY]);
	pclSetKernelArg(param->kernels[KERNEL_ORDERED_INDEX], 1, sizeof(cl_mem), &param->mems[GPU_ORDERED_KEYS]);

	pclSetKernelArg(param->kernels[KERNEL_RULE_MOVE_TO_BEGIN], 0, sizeof(cl_mem), &param->mems[GPU_ORDERED_KEYS]);

	// Set OpenCL kernel params
	if (use_rules)
		for (int i = 0; i < current_rules_count; i++)
		{
			pclSetKernelArg(param->rules.kernels[i], 0, sizeof(cl_mem), &param->mems[GPU_CURRENT_KEY]);
			pclSetKernelArg(param->rules.kernels[i], 1, sizeof(cl_mem), &param->mems[GPU_RULE_SLOW_TRANSFORMED_KEYS]);
			pclSetKernelArg(param->rules.kernels[i], 2, sizeof(cl_mem), &param->mems[GPU_OUTPUT]);
		}

	// Copy data to GPU
	memset(source, 0, MAX_KEY_LENGHT_SMALL* sizeof(cl_uint));
	cl_write_buffer(param, GPU_OUTPUT, sizeof(cl_uint), source);
	cl_write_buffer(param, GPU_ORDERED_KEYS, MAX_KEY_LENGHT_SMALL * sizeof(cl_uint), source);
	if (!(gpu_devices[gpu_index].flags & GPU_FLAG_HAD_UNIFIED_MEMORY))
	{
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_BINARY_VALUES], CL_FALSE, 0, BINARY_SIZE*num_passwords_loaded, binary_values, 0, NULL, NULL);
		pclEnqueueWriteBuffer(param->queue, param->mems[GPU_SALT_VALUES], CL_FALSE, 0, SALT_SIZE*num_diff_salts, salts_values, 0, NULL, NULL);
	}
	pclFinish(param->queue);

	free(source);

	*gpu_crypt = use_rules ? ocl_rule_work_slow_hashes_ordered : ocl_work_slow_hashes_ordered;

	return TRUE;
}
////////////////////////////////////////////////////////////////////////////////////////
// Select best work_group/implementation
////////////////////////////////////////////////////////////////////////////////////////
PUBLIC void ocl_best_workgroup_pbkdf2(OpenCL_Param* param, int KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE, int KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC)
{
	if (param->NUM_KEYS_OPENCL < param->max_work_group_size)
	{
		param->max_work_group_size = param->NUM_KEYS_OPENCL;
	}
	size_t initial_workgroup_size = param->max_work_group_size;
	int scalar_param = 128;
	ocl_calculate_best_work_group(param, param->kernels + KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE, 2048, &scalar_param, 1, FALSE, CL_TRUE);
	size_t scalar_workgroup = param->max_work_group_size;

#ifndef HS_OCL_REDUCE_REGISTER_USE
	param->max_work_group_size = initial_workgroup_size;
	int vector_param = 128;
	param->NUM_KEYS_OPENCL /= 2;
	if (param->NUM_KEYS_OPENCL < param->max_work_group_size)
		param->max_work_group_size = param->NUM_KEYS_OPENCL;
	ocl_calculate_best_work_group(param, param->kernels + KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC, 2048, &vector_param, 1, FALSE, CL_TRUE);
	size_t vector_workgroup = param->max_work_group_size;
	param->NUM_KEYS_OPENCL *= 2;

	// Compare the scalar and vector version
	int64_t init, scalar_duration, vector_duration;
	size_t num_work_items = param->NUM_KEYS_OPENCL;
	
	int kernel_param = __min(scalar_param, vector_param);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE], 1, sizeof(int), (void*)&kernel_param);
	pclSetKernelArg(param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC], 1, sizeof(int), (void*)&kernel_param);
	// Warm up
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE], 1, NULL, &num_work_items, &scalar_workgroup, 0, NULL, NULL);
	pclFinish(param->queue);
	// Get scalar timespan
	init = get_milliseconds();
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE], 1, NULL, &num_work_items, &scalar_workgroup, 0, NULL, NULL);
	pclFinish(param->queue);
	scalar_duration = get_milliseconds() - init;

	// Warm up
	num_work_items /= 2;
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC], 1, NULL, &num_work_items, &vector_workgroup, 0, NULL, NULL);
	pclFinish(param->queue);
	// Get vector timespan
	init = get_milliseconds();
	pclEnqueueNDRangeKernel(param->queue, param->kernels[KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC], 1, NULL, &num_work_items, &vector_workgroup, 0, NULL, NULL);
	pclFinish(param->queue);
	vector_duration = get_milliseconds() - init;

	if (vector_duration < scalar_duration)
	{
		vector_param = CLIP_RANGE(vector_param, 2, 2048);
		param->param0 = OCL_SLOW_COMBINE_PARAM_KERNEL_INDEX(vector_param, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE_VEC);
		param->max_work_group_size = vector_workgroup;
	}
	else
#endif
	{
		scalar_param = CLIP_RANGE(scalar_param, 2, 2048);
		param->param0 = OCL_SLOW_COMBINE_PARAM_KERNEL_INDEX(scalar_param, KERNEL_INDEX_PBKDF2_HMAC_SHA1_CYCLE);
		param->max_work_group_size = scalar_workgroup;
	}

//#ifndef HS_OCL_REDUCE_REGISTER_USE
//	hs_log(HS_LOG_DEBUG, "Slow format", "UseVector:%i\nduration:%ums\nParam:%u\nkeys:%u\nwork_group_size:%u", (cl_uint)(vector_duration < scalar_duration), (cl_uint)__min(vector_duration, scalar_duration), OCL_SLOW_GET_CYCLE_PARAM(param->param0), param->NUM_KEYS_OPENCL, param->max_work_group_size);
//#else
//	hs_log(HS_LOG_DEBUG, "Slow format", "Param:%u\nkeys:%u\nwork_group_size:%u", GET_CYCLE_PARAM(param->param0), param->NUM_KEYS_OPENCL, param->max_work_group_size);
//#endif
}

PUBLIC const char* md5_array_body =
			/* Round 1 */
			"a+=bs(d,c,b)+W[0]+0xd76aa478;a=rotate(a,7u)+b;"
			"d+=bs(c,b,a)+W[1]+0xe8c7b756;d=rotate(d,12u)+a;"
			"c+=bs(b,a,d)+W[2]+0x242070db;c=rotate(c,17u)+d;"
			"b+=bs(a,d,c)+W[3]+0xc1bdceee;b=rotate(b,22u)+c;"
			"a+=bs(d,c,b)+W[4]+0xf57c0faf;a=rotate(a,7u)+b;"
			"d+=bs(c,b,a)+W[5]+0x4787c62a;d=rotate(d,12u)+a;"
			"c+=bs(b,a,d)+W[6]+0xa8304613;c=rotate(c,17u)+d;"
			"b+=bs(a,d,c)+W[7]+0xfd469501;b=rotate(b,22u)+c;"
			"a+=bs(d,c,b)+W[8]+0x698098d8;a=rotate(a,7u)+b;"
			"d+=bs(c,b,a)+W[9]+0x8b44f7af;d=rotate(d,12u)+a;"
			"c+=bs(b,a,d)+W[10]+0xffff5bb1;c=rotate(c,17u)+d;"
			"b+=bs(a,d,c)+W[11]+0x895cd7be;b=rotate(b,22u)+c;"
			"a+=bs(d,c,b)+W[12]+0x6b901122;a=rotate(a,7u)+b;"
			"d+=bs(c,b,a)+W[13]+0xfd987193;d=rotate(d,12u)+a;"
			"c+=bs(b,a,d)+W[14]+0xa679438e;c=rotate(c,17u)+d;"
			"b+=bs(a,d,c)+W[15]+0x49b40821;b=rotate(b,22u)+c;"
			/* Round 2 */
			"a+=bs(c,b,d)+W[1]+0xf61e2562;a=rotate(a,5u)+b;"
			"d+=bs(b,a,c)+W[6]+0xc040b340;d=rotate(d,9u)+a;"
			"c+=bs(a,d,b)+W[11]+0x265e5a51;c=rotate(c,14u)+d;"
			"b+=bs(d,c,a)+W[0]+0xe9b6c7aa;b=rotate(b,20u)+c;"
			"a+=bs(c,b,d)+W[5]+0xd62f105d;a=rotate(a,5u)+b;"
			"d+=bs(b,a,c)+W[10]+0x02441453;d=rotate(d,9u)+a;"
			"c+=bs(a,d,b)+W[15]+0xd8a1e681;c=rotate(c,14u)+d;"
			"b+=bs(d,c,a)+W[4]+0xe7d3fbc8;b=rotate(b,20u)+c;"
			"a+=bs(c,b,d)+W[9]+0x21e1cde6;a=rotate(a,5u)+b;"
			"d+=bs(b,a,c)+W[14]+0xc33707d6;d=rotate(d,9u)+a;"
			"c+=bs(a,d,b)+W[3]+0xf4d50d87;c=rotate(c,14u)+d;"
			"b+=bs(d,c,a)+W[8]+0x455a14ed;b=rotate(b,20u)+c;"
			"a+=bs(c,b,d)+W[13]+0xa9e3e905;a=rotate(a,5u)+b;"
			"d+=bs(b,a,c)+W[2]+0xfcefa3f8;d=rotate(d,9u)+a;"
			"c+=bs(a,d,b)+W[7]+0x676f02d9;c=rotate(c,14u)+d;"
			"b+=bs(d,c,a)+W[12]+0x8d2a4c8a;b=rotate(b,20u)+c;"
			/* Round 3 */
			"a+=(b^c^d)+W[5]+0xfffa3942;a=rotate(a,4u)+b;"
			"d+=(a^b^c)+W[8]+0x8771f681;d=rotate(d,11u)+a;"
			"c+=(d^a^b)+W[11]+0x6d9d6122;c=rotate(c,16u)+d;"
			"b+=(c^d^a)+W[14]+0xfde5380c;b=rotate(b,23u)+c;"
			"a+=(b^c^d)+W[1]+0xa4beea44;a=rotate(a,4u)+b;"
			"d+=(a^b^c)+W[4]+0x4bdecfa9;d=rotate(d,11u)+a;"
			"c+=(d^a^b)+W[7]+0xf6bb4b60;c=rotate(c,16u)+d;"
			"b+=(c^d^a)+W[10]+0xbebfbc70;b=rotate(b,23u)+c;"
			"a+=(b^c^d)+W[13]+0x289b7ec6;a=rotate(a,4u)+b;"
			"d+=(a^b^c)+W[0]+0xeaa127fa;d=rotate(d,11u)+a;"
			"c+=(d^a^b)+W[3]+0xd4ef3085;c=rotate(c,16u)+d;"
			"b+=(c^d^a)+W[6]+0x04881d05;b=rotate(b,23u)+c;"
			"a+=(b^c^d)+W[9]+0xd9d4d039;a=rotate(a,4u)+b;"
			"d+=(a^b^c)+W[12]+0xe6db99e5;d=rotate(d,11u)+a;"
			"c+=(d^a^b)+W[15]+0x1fa27cf8;c=rotate(c,16u)+d;"
			"b+=(c^d^a)+W[2]+0xc4ac5665;b=rotate(b,23u)+c;"
			/* Round 4 */
			"a+=(c^(b|~d))+W[0]+0xf4292244;a=rotate(a,6u)+b;"
			"d+=(b^(a|~c))+W[7]+0x432aff97;d=rotate(d,10u)+a;"
			"c+=(a^(d|~b))+W[14]+0xab9423a7;c=rotate(c,15u)+d;"
			"b+=(d^(c|~a))+W[5]+0xfc93a039;b=rotate(b,21u)+c;"
			"a+=(c^(b|~d))+W[12]+0x655b59c3;a=rotate(a,6u)+b;"
			"d+=(b^(a|~c))+W[3]+0x8f0ccc92;d=rotate(d,10u)+a;"
			"c+=(a^(d|~b))+W[10]+0xffeff47d;c=rotate(c,15u)+d;"
			"b+=(d^(c|~a))+W[1]+0x85845dd1;b=rotate(b,21u)+c;"
			"a+=(c^(b|~d))+W[8]+0x6fa87e4f;a=rotate(a,6u)+b;"
			"d+=(b^(a|~c))+W[15]+0xfe2ce6e0;d=rotate(d,10u)+a;"
			"c+=(a^(d|~b))+W[6]+0xa3014314;c=rotate(c,15u)+d;"
			"b+=(d^(c|~a))+W[13]+0x4e0811a1;b=rotate(b,21u)+c;"
			"a+=(c^(b|~d))+W[4]+0xf7537e82;a=rotate(a,6u)+b;"
			"d+=(b^(a|~c))+W[11]+0xbd3af235;d=rotate(d,10u)+a;"
			"c+=(a^(d|~b))+W[2]+0x2ad7d2bb;c=rotate(c,15u)+d;"
			"b+=(d^(c|~a))+W[9]+0xeb86d391;b=rotate(b,21u)+c;";
PUBLIC const char* sha1_array_body =
						 "E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W[0];B=rotate(B,30u);"
						 "D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W[1];A=rotate(A,30u);"
						 "C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W[2];E=rotate(E,30u);"
						 "B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W[3];D=rotate(D,30u);"
						 "A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W[4];C=rotate(C,30u);"
						 "E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W[5];B=rotate(B,30u);"
						 "D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W[6];A=rotate(A,30u);"
						 "C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W[7];E=rotate(E,30u);"
						 "B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W[8];D=rotate(D,30u);"
						 "A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W[9];C=rotate(C,30u);"
						 "E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W[10];B=rotate(B,30u);"
						 "D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W[11];A=rotate(A,30u);"
						 "C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W[12];E=rotate(E,30u);"
						 "B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W[13];D=rotate(D,30u);"
						 "A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W[14];C=rotate(C,30u);"
						 "E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W[15];B=rotate(B,30u);"
		"DCC2_R(0,13,8,2);D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W[0];A=rotate(A,30u);"
		"DCC2_R(1,14,9,3);C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W[1];E=rotate(E,30u);"
		"DCC2_R(2,15,10,4);B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W[2];D=rotate(D,30u);"
		"DCC2_R(3,0,11,5);A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W[3];C=rotate(C,30u);"

		"DCC2_R(4,1,12,6);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W[4];B=rotate(B,30u);"
		"DCC2_R(5,2,13,7);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W[5];A=rotate(A,30u);"
		"DCC2_R(6,3,14,8);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W[6];E=rotate(E,30u);"
		"DCC2_R(7,4,15,9);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W[7];D=rotate(D,30u);"
		"DCC2_R(8,5,0,10);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W[8];C=rotate(C,30u);"
		"DCC2_R(9,6,1,11);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W[9];B=rotate(B,30u);"
		"DCC2_R(10,7,2,12);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W[10];A=rotate(A,30u);"
		"DCC2_R(11,8,3,13);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W[11];E=rotate(E,30u);"
		"DCC2_R(12,9,4,14);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W[12];D=rotate(D,30u);"
		"DCC2_R(13,10,5,15);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W[13];C=rotate(C,30u);"
		"DCC2_R(14,11,6,0);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W[14];B=rotate(B,30u);"
		"DCC2_R(15,12,7,1);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W[15];A=rotate(A,30u);"
		"DCC2_R(0,13,8,2);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W[0];E=rotate(E,30u);"
		"DCC2_R(1,14,9,3);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W[1];D=rotate(D,30u);"
		"DCC2_R(2,15,10,4);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W[2];C=rotate(C,30u);"
		"DCC2_R(3,0,11,5);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W[3];B=rotate(B,30u);"
		"DCC2_R(4,1,12,6);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W[4];A=rotate(A,30u);"
		"DCC2_R(5,2,13,7);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W[5];E=rotate(E,30u);"
		"DCC2_R(6,3,14,8);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W[6];D=rotate(D,30u);"
		"DCC2_R(7,4,15,9);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W[7];C=rotate(C,30u);"

		"DCC2_R(8,5,0,10);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W[8];B=rotate(B,30u);"
		"DCC2_R(9,6,1,11);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W[9];A=rotate(A,30u);"
		"DCC2_R(10,7,2,12);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W[10];E=rotate(E,30u);"
		"DCC2_R(11,8,3,13);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W[11];D=rotate(D,30u);"
		"DCC2_R(12,9,4,14);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W[12];C=rotate(C,30u);"
		"DCC2_R(13,10,5,15);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W[13];B=rotate(B,30u);"
		"DCC2_R(14,11,6,0);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W[14];A=rotate(A,30u);"
		"DCC2_R(15,12,7,1);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W[15];E=rotate(E,30u);"
		"DCC2_R(0,13,8,2);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W[0];D=rotate(D,30u);"
		"DCC2_R(1,14,9,3);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W[1];C=rotate(C,30u);"
		"DCC2_R(2,15,10,4);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W[2];B=rotate(B,30u);"
		"DCC2_R(3,0,11,5);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W[3];A=rotate(A,30u);"
		"DCC2_R(4,1,12,6);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W[4];E=rotate(E,30u);"
		"DCC2_R(5,2,13,7);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W[5];D=rotate(D,30u);"
		"DCC2_R(6,3,14,8);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W[6];C=rotate(C,30u);"
		"DCC2_R(7,4,15,9);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W[7];B=rotate(B,30u);"
		"DCC2_R(8,5,0,10);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W[8];A=rotate(A,30u);"
		"DCC2_R(9,6,1,11);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W[9];E=rotate(E,30u);"
		"DCC2_R(10,7,2,12);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W[10];D=rotate(D,30u);"
		"DCC2_R(11,8,3,13);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W[11];C=rotate(C,30u);"
															   
		"DCC2_R(12,9,4,14);E+=rotate(A,5u)+(B^C^D)+CONST4+W[12];B=rotate(B,30u);"
		"DCC2_R(13,10,5,15);D+=rotate(E,5u)+(A^B^C)+CONST4+W[13];A=rotate(A,30u);"
		"DCC2_R(14,11,6,0);C+=rotate(D,5u)+(E^A^B)+CONST4+W[14];E=rotate(E,30u);"
		"DCC2_R(15,12,7,1);B+=rotate(C,5u)+(D^E^A)+CONST4+W[15];D=rotate(D,30u);"
		"DCC2_R(0,13,8,2);A+=rotate(B,5u)+(C^D^E)+CONST4+W[0];C=rotate(C,30u);"
		"DCC2_R(1,14,9,3);E+=rotate(A,5u)+(B^C^D)+CONST4+W[1];B=rotate(B,30u);"
		"DCC2_R(2,15,10,4);D+=rotate(E,5u)+(A^B^C)+CONST4+W[2];A=rotate(A,30u);"
		"DCC2_R(3,0,11,5);C+=rotate(D,5u)+(E^A^B)+CONST4+W[3];E=rotate(E,30u);"
		"DCC2_R(4,1,12,6);B+=rotate(C,5u)+(D^E^A)+CONST4+W[4];D=rotate(D,30u);"
		"DCC2_R(5,2,13,7);A+=rotate(B,5u)+(C^D^E)+CONST4+W[5];C=rotate(C,30u);"
		"DCC2_R(6,3,14,8);E+=rotate(A,5u)+(B^C^D)+CONST4+W[6];B=rotate(B,30u);"
		"DCC2_R(7,4,15,9);D+=rotate(E,5u)+(A^B^C)+CONST4+W[7];A=rotate(A,30u);"
		"DCC2_R(8,5,0,10);C+=rotate(D,5u)+(E^A^B)+CONST4+W[8];E=rotate(E,30u);"
		"DCC2_R(9,6,1,11);B+=rotate(C,5u)+(D^E^A)+CONST4+W[9];D=rotate(D,30u);"
		"DCC2_R(10,7,2,12);A+=rotate(B,5u)+(C^D^E)+CONST4+W[10];C=rotate(C,30u);"
		"DCC2_R(11,8,3,13);E+=rotate(A,5u)+(B^C^D)+CONST4+W[11];B=rotate(B,30u);"
		"DCC2_R(12,9,4,14);D+=rotate(E,5u)+(A^B^C)+CONST4+W[12];A=rotate(A,30u);"
		"DCC2_R(13,10,5,15);C+=rotate(D,5u)+(E^A^B)+CONST4+W[13];E=rotate(E,30u);"
		"DCC2_R(14,11,6,0);B+=rotate(C,5u)+(D^E^A)+CONST4+W[14];D=rotate(D,30u);"
		"DCC2_R(15,12,7,1);A+=rotate(B,5u)+(C^D^E)+CONST4+W[15];C=rotate(C,30u);";

PUBLIC const char* sha1_process_sha1_body =
				"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+W0;B=rotate(B,30u);"
				"D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W1;A=rotate(A,30u);"
				"C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W2;E=rotate(E,30u);"
				"B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W3;D=rotate(D,30u);"
				"A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W4;C=rotate(C,30u);"
				"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+0x80000000;B=rotate(B,30u);"

				"W0=rotate(W2^W0,1u);"
				"W1=rotate(W3^W1,1u);"
				"W2=rotate(0x2A0^W4^W2,1u);"
				"W3=rotate(W0^0x80000000^W3,1u);"
				"W4=rotate(W1^W4,1u);"
				"W5=rotate(W2^0x80000000,1u);"
				"W6=rotate(W3,1u);"
				"W7=rotate(W4^0x2A0,1u);"
				"W8=rotate(W5^W0,1u);"
				"W9=rotate(W6^W1,1u);"
				"W10=rotate(W7^W2,1u);"
				"W11=rotate(W8^W3,1u);"
				"W12=rotate(W9^W4,1u);"
				"W13=rotate(W10^W5^0x2A0,1u);"
				"W14=rotate(W11^W6^W0,1u);"
				"W15=rotate(W12^W7^W1^0x2A0,1u);"

				"D+=rotate(E,5u)+bs(C,B,A)+SQRT_2;A=rotate(A,30u);"
				"C+=rotate(D,5u)+bs(B,A,E)+SQRT_2;E=rotate(E,30u);"
				"B+=rotate(C,5u)+bs(A,E,D)+SQRT_2;D=rotate(D,30u);"
				"A+=rotate(B,5u)+bs(E,D,C)+SQRT_2;C=rotate(C,30u);"
				"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2;B=rotate(B,30u);"
				"D+=rotate(E,5u)+bs(C,B,A)+SQRT_2;A=rotate(A,30u);"
				"C+=rotate(D,5u)+bs(B,A,E)+SQRT_2;E=rotate(E,30u);"
				"B+=rotate(C,5u)+bs(A,E,D)+SQRT_2;D=rotate(D,30u);"
				"A+=rotate(B,5u)+bs(E,D,C)+SQRT_2;C=rotate(C,30u);"
				"E+=rotate(A,5u)+bs(D,C,B)+SQRT_2+0x2A0;B=rotate(B,30u);"
				"D+=rotate(E,5u)+bs(C,B,A)+SQRT_2+W0;A=rotate(A,30u);"
				"C+=rotate(D,5u)+bs(B,A,E)+SQRT_2+W1;E=rotate(E,30u);"
				"B+=rotate(C,5u)+bs(A,E,D)+SQRT_2+W2;D=rotate(D,30u);"
				"A+=rotate(B,5u)+bs(E,D,C)+SQRT_2+W3;C=rotate(C,30u);"

								 "E+=rotate(A,5u)+(B^C^D)+SQRT_3+W4;B=rotate(B,30u);"
								 "D+=rotate(E,5u)+(A^B^C)+SQRT_3+W5;A=rotate(A,30u);"
								 "C+=rotate(D,5u)+(E^A^B)+SQRT_3+W6;E=rotate(E,30u);"
								 "B+=rotate(C,5u)+(D^E^A)+SQRT_3+W7;D=rotate(D,30u);"
								 "A+=rotate(B,5u)+(C^D^E)+SQRT_3+W8;C=rotate(C,30u);"
								 "E+=rotate(A,5u)+(B^C^D)+SQRT_3+W9;B=rotate(B,30u);"
								 "D+=rotate(E,5u)+(A^B^C)+SQRT_3+W10;A=rotate(A,30u);"
								 "C+=rotate(D,5u)+(E^A^B)+SQRT_3+W11;E=rotate(E,30u);"
								 "B+=rotate(C,5u)+(D^E^A)+SQRT_3+W12;D=rotate(D,30u);"
								 "A+=rotate(B,5u)+(C^D^E)+SQRT_3+W13;C=rotate(C,30u);"
								 "E+=rotate(A,5u)+(B^C^D)+SQRT_3+W14;B=rotate(B,30u);"
								 "D+=rotate(E,5u)+(A^B^C)+SQRT_3+W15;A=rotate(A,30u);"

				"DCC2_R(0,13,8,2);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W0;E=rotate(E,30u);"
				"DCC2_R(1,14,9,3);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W1;D=rotate(D,30u);"
				"DCC2_R(2,15,10,4);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W2;C=rotate(C,30u);"
				"DCC2_R(3,0,11,5);E+=rotate(A,5u)+(B^C^D)+SQRT_3+W3;B=rotate(B,30u);"
				"DCC2_R(4,1,12,6);D+=rotate(E,5u)+(A^B^C)+SQRT_3+W4;A=rotate(A,30u);"
				"DCC2_R(5,2,13,7);C+=rotate(D,5u)+(E^A^B)+SQRT_3+W5;E=rotate(E,30u);"
				"DCC2_R(6,3,14,8);B+=rotate(C,5u)+(D^E^A)+SQRT_3+W6;D=rotate(D,30u);"
				"DCC2_R(7,4,15,9);A+=rotate(B,5u)+(C^D^E)+SQRT_3+W7;C=rotate(C,30u);"

				"DCC2_R(8,5,0,10);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W8;B=rotate(B,30u);"
				"DCC2_R(9,6,1,11);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W9;A=rotate(A,30u);"
				"DCC2_R(10,7,2,12);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W10;E=rotate(E,30u);"
				"DCC2_R(11,8,3,13);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W11;D=rotate(D,30u);"
				"DCC2_R(12,9,4,14);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W12;C=rotate(C,30u);"
				"DCC2_R(13,10,5,15);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W13;B=rotate(B,30u);"
				"DCC2_R(14,11,6,0);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W14;A=rotate(A,30u);"
				"DCC2_R(15,12,7,1);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W15;E=rotate(E,30u);"
				"DCC2_R(0,13,8,2);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W0;D=rotate(D,30u);"
				"DCC2_R(1,14,9,3);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W1;C=rotate(C,30u);"
				"DCC2_R(2,15,10,4);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W2;B=rotate(B,30u);"
				"DCC2_R(3,0,11,5);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W3;A=rotate(A,30u);"
				"DCC2_R(4,1,12,6);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W4;E=rotate(E,30u);"
				"DCC2_R(5,2,13,7);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W5;D=rotate(D,30u);"
				"DCC2_R(6,3,14,8);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W6;C=rotate(C,30u);"
				"DCC2_R(7,4,15,9);E+=rotate(A,5u)+MAJ(B,C,D)+CONST3+W7;B=rotate(B,30u);"
				"DCC2_R(8,5,0,10);D+=rotate(E,5u)+MAJ(A,B,C)+CONST3+W8;A=rotate(A,30u);"
				"DCC2_R(9,6,1,11);C+=rotate(D,5u)+MAJ(E,A,B)+CONST3+W9;E=rotate(E,30u);"
				"DCC2_R(10,7,2,12);B+=rotate(C,5u)+MAJ(D,E,A)+CONST3+W10;D=rotate(D,30u);"
				"DCC2_R(11,8,3,13);A+=rotate(B,5u)+MAJ(C,D,E)+CONST3+W11;C=rotate(C,30u);"
																  
				"DCC2_R(12,9,4,14);E+=rotate(A,5u)+(B^C^D)+CONST4+W12;B=rotate(B,30u);"
				"DCC2_R(13,10,5,15);D+=rotate(E,5u)+(A^B^C)+CONST4+W13;A=rotate(A,30u);"
				"DCC2_R(14,11,6,0);C+=rotate(D,5u)+(E^A^B)+CONST4+W14;E=rotate(E,30u);"
				"DCC2_R(15,12,7,1);B+=rotate(C,5u)+(D^E^A)+CONST4+W15;D=rotate(D,30u);"
				"DCC2_R(0,13,8,2);A+=rotate(B,5u)+(C^D^E)+CONST4+W0 ;C=rotate(C,30u);"
				"DCC2_R(1,14,9,3);E+=rotate(A,5u)+(B^C^D)+CONST4+W1 ;B=rotate(B,30u);"
				"DCC2_R(2,15,10,4);D+=rotate(E,5u)+(A^B^C)+CONST4+W2 ;A=rotate(A,30u);"
				"DCC2_R(3,0,11,5);C+=rotate(D,5u)+(E^A^B)+CONST4+W3 ;E=rotate(E,30u);"
				"DCC2_R(4,1,12,6);B+=rotate(C,5u)+(D^E^A)+CONST4+W4 ;D=rotate(D,30u);"
				"DCC2_R(5,2,13,7);A+=rotate(B,5u)+(C^D^E)+CONST4+W5 ;C=rotate(C,30u);"
				"DCC2_R(6,3,14,8);E+=rotate(A,5u)+(B^C^D)+CONST4+W6 ;B=rotate(B,30u);"
				"DCC2_R(7,4,15,9);D+=rotate(E,5u)+(A^B^C)+CONST4+W7 ;A=rotate(A,30u);"
				"DCC2_R(8,5,0,10);C+=rotate(D,5u)+(E^A^B)+CONST4+W8 ;E=rotate(E,30u);"
				"DCC2_R(9,6,1,11);B+=rotate(C,5u)+(D^E^A)+CONST4+W9 ;D=rotate(D,30u);"
				"DCC2_R(10,7,2,12);A+=rotate(B,5u)+(C^D^E)+CONST4+W10;C=rotate(C,30u);"
				"DCC2_R(11,8,3,13);E+=rotate(A,5u)+(B^C^D)+CONST4+W11;B=rotate(B,30u);"
				"DCC2_R(12,9,4,14);D+=rotate(E,5u)+(A^B^C)+CONST4+W12;A=rotate(A,30u);"
				"DCC2_R(13,10,5,15);C+=rotate(D,5u)+(E^A^B)+CONST4+W13;E=rotate(E,30u);"
				"DCC2_R(14,11,6,0);B+=rotate(C,5u)+(D^E^A)+CONST4+W14;D=rotate(D,30u);"
				"DCC2_R(15,12,7,1);A+=rotate(B,5u)+(C^D^E)+CONST4+W15;C=rotate(C,30u);";

#endif