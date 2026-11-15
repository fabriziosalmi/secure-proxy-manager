// Command spm is the Secure Proxy Manager API from a terminal (internal/cli).
package main

import (
	"os"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
