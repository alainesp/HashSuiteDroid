LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

HS_DIR := ../../../Hash_Suite/
BZ2_DIR:= ../../../Hash_Suite/compress/libbz2/

#LOCAL_CFLAGS :=  -std=c99 -v -pg

LOCAL_MODULE    := HashSuiteNative
LOCAL_SRC_FILES := jni_bridge.cpp $(HS_DIR)common.c $(HS_DIR)sqlite3.c $(HS_DIR)attack.c $(HS_DIR)key_providers.c $(HS_DIR)rules.c $(HS_DIR)hardware.c $(HS_DIR)in_out.c $(HS_DIR)format_DCC.c $(HS_DIR)format_NTLM.c $(HS_DIR)format_LM.c
LOCAL_SRC_FILES += $(HS_DIR)wordlist.c $(HS_DIR)compress/zlib/unzip.c $(HS_DIR)compress/zlib/ioapi.c $(BZ2_DIR)bzlib.c $(BZ2_DIR)decompress.c $(BZ2_DIR)crctable.c $(BZ2_DIR)randtable.c $(BZ2_DIR)huffman.c

ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
    LOCAL_ARM_NEON  := true
    LOCAL_SRC_FILES += $(HS_DIR)arch_neon.S
endif

LOCAL_STATIC_LIBRARIES := cpufeatures
#LOCAL_STATIC_LIBRARIES += android-ndk-profiler
LOCAL_LDLIBS := -lz

include $(BUILD_SHARED_LIBRARY)

$(call import-module,cpufeatures)
#$(call import-module,android-ndk-profiler)
