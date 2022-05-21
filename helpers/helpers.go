package helpers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//"Unstructured object" (e.g. generic json)
type Unstruct map[string]interface{}

func SecondsToFriendlyString(seconds int) string {
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := (seconds % 60)
	hStr := ""
	mStr := ""
	if h > 0 {
		hStr = fmt.Sprintf("%v, ", NumToPluralString(h, "hour"))
	}
	if m > 0 || h > 0 {
		mStr = fmt.Sprintf("%v and ", NumToPluralString(m, "minute"))
	}
	sStr := NumToPluralString(s, "second")
	return fmt.Sprintf("%v%v%v", hStr, mStr, sStr)
}

func NumToPluralString(value int, unit string) string {
	str := fmt.Sprintf("%v %v", value, unit)
	if value != 1 {
		str += "s"
	}
	return str
}

// Extract/decode the body part without any kind of authenticity verification
func JwtToString(jwt string) string {
	bodyStr := "<not a JWT>" // default used if we cant interpret the input
	// A jwt shall have three sections separated by "." - we wan't the middle part
	parts := strings.Split(jwt, ".")
	if len(parts) == 3 {
		body, err := base64.StdEncoding.DecodeString(Base64UrlToBase64(parts[1]))
		if err == nil {
			bodyStr = string(body)
		}
	}
	return bodyStr
}

func Base64UrlToBase64(input string) string {
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

func Base64ToBase64Url(input string) string {
	result := strings.ReplaceAll(input, "/", "_")
	result = strings.ReplaceAll(result, "+", "-")
	result = strings.ReplaceAll(result, "=", "")
	return result
}

func PrettyJson(jsonStr string) string {
	// https://stackoverflow.com/a/29046984
	var pretty bytes.Buffer
	err := json.Indent(&pretty, ([]byte)(jsonStr), "", "  ")

	if err != nil {
		return fmt.Sprintf("Invalid JSON: %v", jsonStr)
	}
	return pretty.String()
}

// Add jsonc-style comments with epoch interpretation, i.e. time strings
// (fail silent for all kinds of error/non-founds)
func InjectEpochFieldComments(jsonStr string, epochKeys []string) string {
	resultStr := jsonStr
	for _, keyName := range epochKeys {
		parsePattern := fmt.Sprintf(`"%v": (?P<Epoch>\d+),?`, keyName)
		parser := regexp.MustCompile(parsePattern)
		matches := parser.FindStringSubmatch(jsonStr)
		if len(matches) == 2 {
			original := matches[0]
			epoch, err := strconv.ParseInt(matches[1], 10, 64)
			if err == nil {
				dateStr := time.Unix(epoch, 0)
				replaced := fmt.Sprintf("%v //👈 %v", original, dateStr)
				resultStr = strings.Replace(resultStr, original, replaced, 1)
			}
		}
	}
	return resultStr
}
