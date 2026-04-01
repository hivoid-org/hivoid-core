package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/hivoid-org/hivoid-core/session"
)

// runList handles `hivoid-server list`.
func runList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hivoid-server list")
		fmt.Fprintln(os.Stderr, "Shows all active sessions and connected clients.")
	}
	fs.Parse(args) //nolint:errcheck

	resp, err := http.Get("http://127.0.0.1:23080/sessions")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to server diagnostic API: %v\n", err)
		fmt.Fprintln(os.Stderr, "Is the HiVoid server running?")
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Server returned error: %d\n", resp.StatusCode)
		os.Exit(1)
	}

	var snapshots []session.SessionSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snapshots); err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding session data: %v\n", err)
		os.Exit(1)
	}

	if len(snapshots) == 0 {
		fmt.Println("No active sessions.")
		return
	}

	fmt.Printf("Active Clients (Grouped by UUID+IP: %d):\n\n", len(snapshots))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	// Header
	fmt.Fprintln(w, "EMAIL\tUUID\tREMOTE IP\tDURATION\tIN / OUT")
	fmt.Fprintln(w, "-----\t----\t---------\t--------\t--------")

	for _, s := range snapshots {
		traffic := fmt.Sprintf("%.1f MB / %.1f MB", float64(s.TrafficIn)/1024/1024, float64(s.TrafficOut)/1024/1024)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			s.Email,
			s.UUID,
			s.RemoteAddr,
			s.Duration,
			traffic,
		)
	}
	w.Flush()
}
