// Command devsecrets writes a complete set of throwaway secret files (keys,
// role passwords, connection strings) for local development and the Compose
// deployment check. Production operators generate their own.
//
// Usage: go run ./tools/devsecrets <dir>
package main

import (
	"fmt"
	"os"

	"github.com/qali-project/qali/tools/internal/secretsdir"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: devsecrets <dir>")
		os.Exit(2)
	}
	if err := secretsdir.Write(os.Args[1], secretsdir.URLs{}); err != nil {
		fmt.Fprintln(os.Stderr, "devsecrets:", err)
		os.Exit(1)
	}
	fmt.Println("devsecrets: wrote", os.Args[1])
}
