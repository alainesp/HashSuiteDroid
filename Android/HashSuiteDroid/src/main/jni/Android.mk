LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

HS_DIR := ../../../../../Hash_Suite/
BZ2_DIR:= ../../../../../Hash_Suite/compress/libbz2/
7ZIP_DIR:= ../../../../../Hash_Suite/compress/7z/

#LOCAL_CFLAGS :=  -std=c99
#LOCAL_CFLAGS :=  -std=c99 -v -pg
LOCAL_CPPFLAGS :=  -std=c++14

LOCAL_MODULE := HashSuiteNative

# Hash Suite 'core' files
LOCAL_SRC_FILES := jni_bridge.cpp $(HS_DIR)common.c $(HS_DIR)sqlite3.c $(HS_DIR)attack.c $(HS_DIR)key_providers.c $(HS_DIR)rules.c $(HS_DIR)hardware.c $(HS_DIR)in_out.c  $(HS_DIR)opencl_code.c $(HS_DIR)hash.c
LOCAL_SRC_FILES += $(HS_DIR)cbg_table.cpp $(HS_DIR)in_hashtable.cpp

# Formats
LOCAL_SRC_FILES += $(HS_DIR)format_LM.c $(HS_DIR)format_NTLM.c $(HS_DIR)format_MD5.c $(HS_DIR)format_SHA1.c $(HS_DIR)format_DCC.c $(HS_DIR)format_DCC2.c $(HS_DIR)format_raw_SHA256.c $(HS_DIR)format_raw_SHA512.c
LOCAL_SRC_FILES += $(HS_DIR)format_WPA.c $(HS_DIR)format_BCRYPT.c $(HS_DIR)format_SSHA1.c $(HS_DIR)format_MD5CRYPT.c

# Wordlist support (including compressing wordlists)
LOCAL_SRC_FILES += $(HS_DIR)wordlist.c $(HS_DIR)compress/zlib/unzip.c $(HS_DIR)compress/zlib/ioapi.c $(BZ2_DIR)bzlib.c $(BZ2_DIR)decompress.c $(BZ2_DIR)crctable.c $(BZ2_DIR)randtable.c $(BZ2_DIR)huffman.c
LOCAL_SRC_FILES += $(7ZIP_DIR)7zAlloc.c $(7ZIP_DIR)7zBuf.c $(7ZIP_DIR)7zCrc.c $(7ZIP_DIR)7zCrcOpt.c $(7ZIP_DIR)7zDec.c $(7ZIP_DIR)7zFile.c $(7ZIP_DIR)7zIn.c $(7ZIP_DIR)7zStream.c $(7ZIP_DIR)Bcj2.c $(7ZIP_DIR)Bra.c
LOCAL_SRC_FILES += $(7ZIP_DIR)Bra86.c $(7ZIP_DIR)CpuArch.c $(7ZIP_DIR)Lzma2Dec.c $(7ZIP_DIR)LzmaDec.c $(7ZIP_DIR)Ppmd7.c $(7ZIP_DIR)Ppmd7Dec.c 

ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
    LOCAL_ARM_NEON  := true
    LOCAL_SRC_FILES += $(HS_DIR)arch_neon.S
endif
ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
    LOCAL_ARM_NEON  := true
    LOCAL_SRC_FILES += $(HS_DIR)arch_neon64.S
    LOCAL_CFLAGS :=  -DANDROID_NO_NEON=1
endif

LOCAL_STATIC_LIBRARIES := libcpufeatures
#LOCAL_STATIC_LIBRARIES += android-ndk-profiler
LOCAL_LDLIBS := -lz -ldl
#LOCAL_LDLIBS := -lz -ldl -llog

include $(BUILD_SHARED_LIBRARY)

$(call import-module,android/cpufeatures)
#$(call import-module,android-ndk-profiler)
