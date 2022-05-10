package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type OAuthAccessResponse struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// Only a few fields defined here (the ones used by the app)
type OidcMetadata struct {
	AuthEndpoint     string `json:"authorization_endpoint"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserInfoEndpoint string `json:"userinfo_endpoint"`
}

type AppConfig struct {
	AuthEndpoint     string `json:"auth_endpoint"`
	CallbackPath     string `json:"callback_path"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	MetadataEndpoint string `json:"metadata_endpoint"`
	Port             uint   `json:"oauth2_port"`
	Scope            string `json:"scope"`
	State            string `json:"state"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	UserInfo         bool   `json:"userinfo"`
	Verbose          bool   `json:"verbose"`
}

var appConfig AppConfig
var exitCode int

func main() {
	defer func() {
		os.Exit(exitCode)
	}()

	err := initializeAppConfig()

	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid/incomplete application configuration: %v\n", err)
		os.Exit(1)
	}

	serveAuthCodeFlow()
}

func initializeAppConfig() error {
	// General rules;
	// - CLI arguments have precedence over ENV, i.e. those starting with "O2TOKEN_"
	// - specified variables (CLI or ENV) will never be automatically derived

	// Read from CLI or ENV (let ENV show as default if defined - but not for random/secret fields because they show up in --help)
	authEndpointPtr := flag.String("auth_endpoint", parseStringEnvVar("", "O2TOKEN_AUTH_ENDPOINT"), "Authorization endpoint")
	callbackPathPtr := flag.String("callback_path", parseStringEnvVar("/oauth2/callback", "O2TOKEN_CALLBACK_PATH"), "Oauth2 callback path")
	clientIDPtr := flag.String("client_id", parseStringEnvVar("", "O2TOKEN_CLIENT_ID"), "Client (aka application) id ")
	clientSecretPtr := flag.String("client_secret", "", "Client secret (if applicable)")
	metadataEndpointPtr := flag.String("metadata_endpoint", parseStringEnvVar("", "O2TOKEN_METADATA_ENDPOINT"), "IDP base URL")
	portPtr := flag.Uint("port", parseUintEnvVar(8080, "O2TOKEN_PORT"), "Local server port")
	tokenEndpointPtr := flag.String("token_endpoint", parseStringEnvVar("", "O2TOKEN_TOKEN_ENDPOINT"), "Token endpoint")
	statePtr := flag.String("state", parseStringEnvVar("", "O2TOKEN_STATE"), "Oauth2 state string (default <random>)")
	scopePtr := flag.String("scope", parseStringEnvVar("openid,offline_access", "O2TOKEN_SCOPE"), "Access scope")
	verbosePtr := flag.Bool("verbose", parseBoolEnvVar(false, "O2TOKEN_VERBOSE"), "Print progress and decoded/interpreted tokens")
	userInfoPtr := flag.Bool("userinfo", parseBoolEnvVar(false, "O2TOKEN_USERINFO"), "Fetch user info after obtaining the access token")
	userInfoEndpointPtr := flag.String("userinfo_endpoint", parseStringEnvVar("", "O2TOKEN_USERINFO_ENDPOINT"), "User info endpoint")
	flag.Parse()

	// Handle special defaults (random/secrets)
	if *clientSecretPtr == "" {
		secretStr := parseStringEnvVar("", "O2TOKEN_CLIENT_SECRET")
		clientSecretPtr = &secretStr
	}
	if *statePtr == "" {
		randStr := genRandStr()
		statePtr = &randStr
	}

	// Derive unspecified fields based on IDP's metadata
	if len(*metadataEndpointPtr) > 0 {
		if *verbosePtr {
			fmt.Println("Fetching metadata document from IDP")
		}
		idpMeta := fetchMetadataDocument(*metadataEndpointPtr)
		//Only overwrite if specified value is empty
		if len(*authEndpointPtr) == 0 {
			authEndpointPtr = &idpMeta.AuthEndpoint
		}
		if len(*tokenEndpointPtr) == 0 {
			tokenEndpointPtr = &idpMeta.TokenEndpoint
		}
		if len(*userInfoEndpointPtr) == 0 {
			userInfoEndpointPtr = &idpMeta.UserInfoEndpoint
		}
	}

	//Fix scope-string; input supports either " " or "," as separator but when used, it must be " "
	scopeStr := strings.ReplaceAll(*scopePtr, ",", " ")

	appConfig = AppConfig{
		AuthEndpoint:     *authEndpointPtr,
		CallbackPath:     *callbackPathPtr,
		ClientID:         *clientIDPtr,
		ClientSecret:     *clientSecretPtr,
		MetadataEndpoint: *metadataEndpointPtr,
		Port:             *portPtr,
		State:            *statePtr,
		Scope:            scopeStr,
		TokenEndpoint:    *tokenEndpointPtr,
		Verbose:          *verbosePtr,
		UserInfo:         *userInfoPtr,
		UserInfoEndpoint: *userInfoEndpointPtr,
	}

	// Some level of input validation...
	var retVal error
	if appConfig.AuthEndpoint == "" || appConfig.TokenEndpoint == "" {
		retVal = fmt.Errorf("Authorization/Token endpoints not configured")
	} else if appConfig.Port == 0 || appConfig.Port > 65535 {
		retVal = fmt.Errorf("Invalid port configured")
	} else if len(appConfig.CallbackPath) < 2 || appConfig.CallbackPath[0] != '/' {
		retVal = fmt.Errorf("Invalid callback path configured")
	} else if appConfig.ClientID == "" {
		retVal = fmt.Errorf("Client ID not configured")
	} else if appConfig.UserInfo && appConfig.UserInfoEndpoint == "" {
		retVal = fmt.Errorf("UserInfoEndpoint not configured")
	} else if appConfig.State == "" {
		retVal = fmt.Errorf("Empty state string configured")
	}

	if appConfig.Verbose || retVal != nil {
		// temporary hide the secret
		tempSecret := appConfig.ClientSecret
		appConfig.ClientSecret = strings.Repeat("*", len(tempSecret))
		configOutput, _ := json.MarshalIndent(appConfig, "", "  ")
		fmt.Printf("Running with the specified/derived configuration:\n%v\n", string(configOutput))
		appConfig.ClientSecret = tempSecret
	}

	return retVal
}

func parseBoolEnvVar(defaultValue bool, envVar string) bool {
	retVal := defaultValue
	var err error
	envValue := os.Getenv(envVar)
	if len(envValue) > 0 {
		retVal, err = strconv.ParseBool(envValue)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ignoring invalid boolean value for environment variable %v\n", envVar)
			retVal = defaultValue
		}
	}
	return retVal
}

func parseStringEnvVar(defaultValue string, envVar string) string {
	retVal := defaultValue
	envValue := os.Getenv(envVar)
	if len(envValue) > 0 {
		retVal = envValue
	}
	return retVal
}

func parseUintEnvVar(defaultValue uint, envVar string) uint {
	retVal := (uint64)(defaultValue)
	var err error
	envValue := os.Getenv(envVar)
	if len(envValue) > 0 {
		retVal, err = strconv.ParseUint(envValue, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ignoring invalid unsigned integer value for environment variable %v\n", envVar)
			retVal = (uint64)(defaultValue)
		}
	}
	return (uint)(retVal)
}

func genRandStr() string {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	h := func() string {
		v := r.Intn(0x10000)
		return fmt.Sprintf("%04x", v)
	}
	return fmt.Sprintf("%v%v%v%v", h(), h(), h(), h())
}

func fetchMetadataDocument(metadataUrl string) OidcMetadata {
	emtpy := OidcMetadata{}
	httpClient := http.Client{}

	req, err := http.NewRequest(http.MethodGet, metadataUrl, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create request for metadata document: %v", err)
		return emtpy
	}
	req.Header.Set("accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not send request for metadata document: %v", err)
		return emtpy
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Unexpected status code for %v: %v\n", metadataUrl, res.StatusCode)
		return emtpy
	}

	var retVal OidcMetadata
	if err := json.NewDecoder(res.Body).Decode(&retVal); err != nil {
		fmt.Fprintf(os.Stderr, "Could not parse metadata document response: %v", err)
		return emtpy
	}

	return retVal
}

func serveAuthCodeFlow() {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("public"))
	mux.Handle("/", noCache(fs))
	mux.HandleFunc(appConfig.CallbackPath, oauth2Callback)
	mux.HandleFunc("/login", startFlow)

	portStr := fmt.Sprintf(":%v", appConfig.Port)
	server := &http.Server{Addr: portStr, Handler: mux}

	go func() {
		fmt.Fprintf(os.Stderr, "Serving oauth2 authorization code flow at 👉 http://localhost%v/login\n", portStr)
		serveErr := server.ListenAndServe()
		if serveErr != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Unexpected error from HTTP server: %v\n", serveErr)
		}
	}()

	// Setting up signal capturing
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Waiting for SIGINT (kill -2)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Unexpected error when closing server: %v\n", err)
	}
}

// https://stackoverflow.com/questions/33880343/go-webserver-dont-cache-files-using-timestamp
func noCache(h http.Handler) http.Handler {
	var epoch = time.Unix(0, 0).Format(time.RFC1123)
	var noCacheHeaders = map[string]string{
		"Expires":         epoch,
		"Cache-Control":   "no-cache, private, max-age=0",
		"Pragma":          "no-cache",
		"X-Accel-Expires": "0",
	}

	var etagHeaders = []string{
		"ETag",
		"If-Modified-Since",
		"If-Match",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
	}

	fn := func(w http.ResponseWriter, r *http.Request) {
		// Delete any ETag headers that may have been set
		for _, v := range etagHeaders {
			if r.Header.Get(v) != "" {
				r.Header.Del(v)
			}
		}

		// Set our NoCache headers
		for k, v := range noCacheHeaders {
			w.Header().Set(k, v)
		}

		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func startFlow(w http.ResponseWriter, r *http.Request) {
	// Redirect to authorization endpoint
	redirectUri := fmt.Sprintf("http://localhost:%v%v", appConfig.Port, appConfig.CallbackPath)
	scope := url.QueryEscape(appConfig.Scope)
	url := fmt.Sprintf("%v/?client_id=%v&redirect_uri=%v&scope=%v&response_type=code&state=%v", appConfig.AuthEndpoint, appConfig.ClientID, redirectUri, scope, appConfig.State)
	if appConfig.Verbose {
		fmt.Printf("Redirecting user to authorization endpoint:\n%v\n", url)
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func oauth2Callback(w http.ResponseWriter, r *http.Request) {
	if appConfig.Verbose {
		fmt.Printf("Processing callback for authorization code\n")
	}

	// We will be using `httpClient`to redeem the tokens via the back channel
	httpClient := http.Client{}

	// First, we need to get the value of the `code` query param
	err := r.ParseForm()
	if err != nil {
		reportErrorAndSoftExit("could not parse query in callback", err, http.StatusBadRequest, w)
		return
	}
	code := r.FormValue("code")

	// Confirm valid state (the only type of "auth verification" done in this app)
	state := r.FormValue("state")
	if state != appConfig.State {
		err := fmt.Errorf("expected: %v, got: %v", appConfig.State, state)
		reportErrorAndSoftExit("unexpected state parameter value in callback", err, http.StatusBadRequest, w)
		return
	}

	// Next, lets for the HTTP request to call the github oauth endpoint to get our access token
	// Params as form-data in POST: https://golang.cafe/blog/how-to-make-http-url-form-encoded-request-golang.html
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", fmt.Sprintf("http://localhost:%v%v", appConfig.Port, appConfig.CallbackPath))
	data.Set("client_id", appConfig.ClientID)
	data.Set("client_secret", appConfig.ClientSecret)
	data.Set("code", code)

	req, err := http.NewRequest(http.MethodPost, appConfig.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		reportErrorAndSoftExit("could not create HTTP request to redeem tokens", err, http.StatusInternalServerError, w)
		return
	}
	// We set this header since we want the response as JSON
	req.Header.Set("accept", "application/json")

	// Send out the HTTP request
	res, err := httpClient.Do(req)
	if err != nil {
		reportErrorAndSoftExit("could not send HTTP request to redeem tokens", err, http.StatusInternalServerError, w)
		return
	}
	defer res.Body.Close()

	if appConfig.Verbose {
		fmt.Printf("Sent POST request to redeem access/id tokens\n")
	}

	bodyBytes, _ := io.ReadAll(res.Body)

	// if appConfig.Verbose {
	// 	fmt.Printf("\nRaw response body:\n%v\n\n", string(bodyBytes))
	// }

	// Parse the request body into the `OAuthAccessResponse` struct
	var t OAuthAccessResponse
	if err := json.Unmarshal(bodyBytes, &t); err != nil {
		reportErrorAndSoftExit("could not parse JSON response for redeemed tokens", err, http.StatusBadRequest, w)
		return
	}

	// TODO: add actual support
	if appConfig.UserInfo {
		fmt.Fprintf(os.Stderr, "NOTE: support for UserInfo is not in place -> skipping\n")
	}

	// Finally, send a response to redirect the user to the "success" page
	http.Redirect(w, r, "/success.html", http.StatusFound)

	// Print result to stdout
	resultJson, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		reportErrorAndSoftExit("could not format result output", err, 1, nil)
		return
	}
	if appConfig.Verbose {
		fmt.Println("Received response:")
	}
	fmt.Println(string(resultJson))

	if appConfig.Verbose {
		fmt.Printf("\nLogin successful, received tokens expire in %v\n", secondsToFriendlyString(t.ExpiresIn))
		fmt.Printf("\nAccessToken:\n------------\n%v\n", prettyJson(jwtToString(t.AccessToken)))
		fmt.Printf("\nIDoken:\n-------\n%v\n", prettyJson(jwtToString(t.IDToken)))
	}

	// We're done
	softExit(0)
}

func reportErrorAndSoftExit(label string, err error, code int, w http.ResponseWriter) {
	msg := fmt.Sprintf("ERROR: %v: %v", label, err)
	if w != nil {

		w.WriteHeader(code)
		w.Write(([]byte)(msg))
	}
	fmt.Fprintln(os.Stderr, msg)
	softExit(code)
}

func softExit(code int) {
	// For some portability reason the exit code must be in [0-125]
	// Unfortunately this means that my plan for using HTTP status codes falls short
	exitCode = code
	if code > 125 || code < 0 {
		fmt.Fprintf(os.Stderr, "Replacing desired exit code %v with 125\n", code)
		exitCode = 125
	}
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
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

func prettyJson(jsonStr string) string {
	// https://stackoverflow.com/a/29046984
	var pretty bytes.Buffer
	err := json.Indent(&pretty, ([]byte)(jsonStr), "", "  ")

	if err != nil {
		return fmt.Sprintf("Invalid JSON: %v", jsonStr)
	}
	return pretty.String()
}
