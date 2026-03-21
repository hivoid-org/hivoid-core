//go:build !android
package main

import "fmt"

// alog logs to stdout for desktop platforms
func alog(tag, msg string) {
	fmt.Printf("[%s] %s\n", tag, msg)
}
