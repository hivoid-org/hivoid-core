// cmd/server — HiVoid QUIC proxy server
//
// Usage:
//
//	hivoid-server start  --config <server.json>   Start the server
//	hivoid-server stop                             Stop a running server
//	hivoid-server status                           Show running state
package main

import (
	"fmt"
	"os"
)

const usage = `Usage:
  hivoid-server start  --config <server.json>   Start the HiVoid server
  hivoid-server stop                             Stop a running server
  hivoid-server status                           Show running state and uptime

Flags are parsed per-subcommand. Run "hivoid-server <cmd> --help" for details.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}

	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "start":
		runStart(args)
	case "stop":
		runStop(args)
	case "status":
		runStatus(args)
	case "--help", "-h", "-help", "help":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s\n", sub, usage)
		os.Exit(1)
	}
}
