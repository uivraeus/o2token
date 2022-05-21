package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

//"Unstructured object" (e.g. generic json)
type unstruct map[string]interface{}

func launchBrowser(url string) {
	if appConfig.Verbose {
		fmt.Printf("Launching browser window")
	}
	browserCmd := exec.Command("python3", "-m", "webbrowser", "-n", url)
	err := browserCmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't launch browser automatically; %v\n", err)
	}
}

func secondsToFriendlyString(seconds int) string {
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := (seconds % 60)
	hStr := ""
	mStr := ""
	if h > 0 {
		hStr = fmt.Sprintf("%v, ", numToPluralString(h, "hour"))
	}
	if m > 0 || h > 0 {
		mStr = fmt.Sprintf("%v and ", numToPluralString(m, "minute"))
	}
	sStr := numToPluralString(s, "second")
	return fmt.Sprintf("%v%v%v", hStr, mStr, sStr)
}

func numToPluralString(value int, unit string) string {
	str := fmt.Sprintf("%v %v", value, unit)
	if value != 1 {
		str += "s"
	}
	return str
}

// Extract/decode the body part without any kind of authenticity verification
func jwtToString(jwt string) string {
	bodyStr := "<not a JWT>" // default used if we cant interpret the input
	// A jwt shall have three sections separated by "." - we wan't the middle part
	parts := strings.Split(jwt, ".")
	if len(parts) == 3 {
		body, err := base64.StdEncoding.DecodeString(base64UrlToBase64(parts[1]))
		if err == nil {
			bodyStr = string(body)
		}
	}
	return bodyStr
}

func base64UrlToBase64(input string) string {
	// https://stackoverflow.com/a/55389212
	result := strings.ReplaceAll(input, "_", "/")
	result = strings.ReplaceAll(result, "-", "+")
	rem := len(result) % 4
	if rem == 2 {
		result += "=="
	} else if rem == 3 {
		result += "="
	}
	return result
}

func base64ToBase64Url(input string) string {
	result := strings.ReplaceAll(input, "/", "_")
	result = strings.ReplaceAll(result, "+", "-")
	result = strings.ReplaceAll(result, "=", "")
	return result
}

func prettyJson(jsonStr string) string {
	// https://stackoverflow.com/a/29046984
	var pretty bytes.Buffer
	err := json.Indent(&pretty, ([]byte)(jsonStr), "", "  ")

	if err != nil {
		return fmt.Sprintf("Invalid JSON: %v", jsonStr)
	}
	return pretty.String()
}
