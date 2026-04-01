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

	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/utils"
)

const usage = `Usage:
  hivoid-server version                         Show engine version
  hivoid-server start  --config <server.json>     Start the HiVoid server
  hivoid-server stop                            Stop a running server
  hivoid-server shock                           Force active clients to reconnect (Shock)
  hivoid-server list                            List active clients and sessions
  hivoid-server status                          Show running state and uptime

Flags are parsed per-subcommand. Run "hivoid-server <cmd> --help" for details.`

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("HiVoid Server v%s (Protocol v%d)\n\n", utils.CoreVersion, config.Version)
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}

	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "version":
		fmt.Printf("HiVoid Server v%s (Protocol v%d)\n", utils.CoreVersion, config.Version)
	case "start":
		runStart(args)
	case "stop":
		runStop(args)
	case "shock":
		runShock(args)
	case "list":
		runList(args)
	case "status":
		runStatus(args)
	case "--help", "-h", "-help", "help":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s\n", sub, usage)
		os.Exit(1)
	}
}
