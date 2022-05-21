package main

import (
	"flag"
	"fmt"
	"os"

	h "o2token/helpers"
)

func main() {
	pureOutputPtr := flag.Bool("pure", false, "show decoded JWT body without any re-formatting or annotations (default false)")

	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprint(os.Stderr, "Usage: jwt [optional flags] <jwt-string>\n")
		os.Exit(1)
	}

	jwtStr := flag.Arg(0)
	if *pureOutputPtr {
		fmt.Println(h.JwtToString(jwtStr))
	} else {
		epochKeys := []string{"iat", "nbf", "exp", "xms_tcdt"} // xms_tcdt is probably azure proprietary
		fmt.Println(h.InjectEpochFieldComments(h.PrettyJson(h.JwtToString(jwtStr)), epochKeys))
	}
}
