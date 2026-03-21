//go:build !android
package main

import "fmt"

// alog لاگ به کنسول برای پلتفرم‌های دسکتاپ
func alog(tag, msg string) {
	fmt.Printf("[%s] %s\n", tag, msg)
}
