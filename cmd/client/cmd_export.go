package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hivoid-org/hivoid-core/config"
)

// runExport handles `hivoid-client export`.
func runExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to JSON config file")
	uriStr := fs.String("uri", "", "hivoid:// URI to expand into JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hivoid-client export --config <file.json>")
		fmt.Fprintln(os.Stderr, "       hivoid-client export --uri    <hivoid://...>")
		fs.PrintDefaults()
	}
	fs.Parse(args) //nolint:errcheck

	// Mode 1: JSON → URI
	if *configPath != "" {
		cfg, err := config.LoadJSON(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(cfg.URI())
		return
	}

	// Mode 2: URI → pretty JSON
	if *uriStr != "" {
		cfg, err := config.ParseURI(*uriStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "uri parse error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(cfg.PrettyJSON())
		return
	}

	fmt.Fprintln(os.Stderr, "error: --config or --uri is required for 'export'")
	fs.Usage()
	os.Exit(1)
}
