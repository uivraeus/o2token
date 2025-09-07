package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	h "o2token/helpers"
)

const usageMsg = `Usage: jwt [optional flags] <jwt-string>
   or: echo <jwt-string> | jwt [optional flags]`

func main() {
	pureOutputPtr := flag.Bool("pure", false, "show decoded JWT body without any re-formatting or annotations (default false)")

	flag.Parse()

	var jwtStr string

	stat, _ := os.Stdin.Stat()
	isPipe := (stat.Mode() & os.ModeCharDevice) == 0

	if isPipe && flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Error: Cannot accept both piped input and command line argument\n%s\n", usageMsg)
		os.Exit(1)
	}

	if isPipe {
		reader := bufio.NewReader(os.Stdin)
		input, err := io.ReadAll(reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
		jwtStr = strings.TrimSpace(string(input))
	} else if flag.NArg() == 1 {
		jwtStr = flag.Arg(0)
	} else {
		fmt.Fprintln(os.Stderr, usageMsg)
		os.Exit(1)
	}

	if *pureOutputPtr {
		fmt.Println(h.JwtToString(jwtStr))
	} else {
		epochKeys := []string{"iat", "nbf", "exp", "xms_tcdt"} // xms_tcdt is probably azure proprietary
		fmt.Println(h.InjectEpochFieldComments(h.PrettyJson(h.JwtToString(jwtStr)), epochKeys))
	}
}
