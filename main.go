package main

import (
	"fmt"
	"os"
	"syscall"
)

var appConfig AppConfig
var exitCode int

func main() {
	defer func() {
		os.Exit(exitCode)
	}()

	var err error
	appConfig, err = initializeAppConfig()

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid/incomplete application configuration: %v\n", err)
		os.Exit(1)
	}

	serveAuthCodeFlow()
}

// Initiate a controlled shutdown of the application (allow for gracefull http server teardown)
// ❗This is NOT a blocking function - it will return control to the caller!
func softExit(code int) {
	// For some portability reason the exit code must be in [0-125]
	// Unfortunately this means that my plan for using HTTP status codes falls short
	exitCode = code
	if code > 125 || code < 0 {
		if appConfig.Verbose {
			fmt.Fprintf(os.Stderr, "Replacing desired exit code %v with 125\n", code)
		}
		exitCode = 125
	}
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
}
