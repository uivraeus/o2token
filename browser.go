package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/browser"
)

// The 3rd-party "browser" package provides most of what we need here when it comes to
// executing the proper command for launching an external browser session.
// But what it doesn't support is the ability to control/override the selection of which
// command to run via the BROWSER environment variable, like Python's "webbrowser" does.
// That variable is not a "standard" but (at least) used in VScode's dev-containers and
// quite convenient to support.
// In Python the BROWSER-variable is treated like the PATH-variable, i.e. a list of
// alternatives sorted in precedence order. But here we cut some corners an just handle
// the first entry of that list (if defined).

func launchBrowser(url string) error {
	if appConfig.Verbose {
		fmt.Printf("Launching browser window\n")
	}
	if launchBrowserFromEnv(url) != nil {
		err := browser.OpenURL(url)
		if err != nil {
			retErr := fmt.Errorf("could not launch browser automatically")
			if appConfig.Verbose {
				fmt.Fprintf(os.Stderr, "%v, error: %v\n", retErr, err)
			}
			return retErr
		}
	}
	return nil
}

func launchBrowserFromEnv(url string) error {
	envStr := os.Getenv("BROWSER")
	paths := strings.Split(envStr, string(os.PathListSeparator))
	if len(paths[0]) > 0 {
		if appConfig.Verbose {
			fmt.Printf("Using path from BROWSER env: %v\n", paths[0])
		}
		browserCmd := exec.Command(paths[0], url)
		err := browserCmd.Run()
		if err != nil {
			retErr := fmt.Errorf("could not run command specified via BROWSER env")
			if appConfig.Verbose {
				fmt.Fprintf(os.Stderr, "%v, error: %v\n", retErr, err)
			}
			return retErr
		}
		return nil
	}
	return fmt.Errorf("environment variable BROWSER not defined")
}
