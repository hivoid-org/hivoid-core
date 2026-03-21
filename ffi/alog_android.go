//go:build android
package main

/*
#include <stdlib.h>
#include <android/log.h>

static void android_log(const char* tag, const char* msg) {
    __android_log_print(ANDROID_LOG_INFO, tag, "%s", msg);
}
*/
import "C"
import "unsafe"

// alog لاگ مستقیم به Android logcat
func alog(tag, msg string) {
	ctag := C.CString(tag)
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(ctag))
	defer C.free(unsafe.Pointer(cmsg))
	C.android_log(ctag, cmsg)
}
