package main

import (
	"errors"
	"fmt"
	"os"

	"caeruleus/internal/cli"
)

func main() {
	err := cli.Execute()
	if err == nil {
		return
	}
	// A subcommand can return cli.ExitError to ask for a specific exit
	// code (e.g. `doctor` returns 2 when one of its checks failed). If
	// ExitError carries no wrapped error, the subcommand has already
	// printed everything it wants the user to see - don't add "error:".
	var exitErr *cli.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Err != nil {
			fmt.Fprintln(os.Stderr, "error:", exitErr.Err)
		}
		os.Exit(exitErr.Code)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
