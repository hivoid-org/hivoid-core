// cmd/client — HiVoid client with subcommand dispatch
//
// Usage:
//
//	hivoid-client start  --config <file.json>   Start proxy tunnel
//	hivoid-client stop                          Stop running instance
//	hivoid-client status                        Show running status
//	hivoid-client export --config <file.json>   Print hivoid:// URI
//	hivoid-client export --uri    <hivoid://..> Print expanded JSON
package main

import (
	"fmt"
	"os"

	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/utils"
)

const usage = `Usage:
  hivoid-client version                       Show engine version
  hivoid-client start  --config <file.json>   Start the HiVoid proxy tunnel
  hivoid-client stop                          Stop a running HiVoid instance
  hivoid-client status                        Show running state and uptime
  hivoid-client ping   --config <file.json>   Test latency to server
  hivoid-client export --config <file.json>   Export hivoid:// URI from config
  hivoid-client export --uri    <hivoid://..> Expand URI to pretty JSON

Flags are parsed per-subcommand. Run "hivoid-client <cmd> --help" for details.`

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("HiVoid Client v%s (Protocol %d)\n\n", utils.CoreVersion, config.Version)
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(1)
	}

	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "version":
		fmt.Printf("HiVoid Client v%s (Protocol %d)\n", utils.CoreVersion, config.Version)
	case "start":
		runStart(args)
	case "stop":
		runStop(args)
	case "status":
		runStatus(args)
	case "ping":
		runPing(args)
	case "export":
		runExport(args)
	case "--help", "-h", "-help", "help":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s\n", sub, usage)
		os.Exit(1)
	}
}
