# Build ARMv7-A machine code.
APP_ABI := armeabi-v7a arm64-v8a
APP_STL := c++_static

# ASAN
# APP_STL := c++_shared # Or system, or none.
# APP_CFLAGS := -fsanitize=address -fno-omit-frame-pointer
# APP_LDFLAGS := -fsanitize=address