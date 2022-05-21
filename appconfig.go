package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

type AppConfig struct {
	AuthEndpoint     string `json:"auth_endpoint"`
	CallbackPath     string `json:"callback_path"`
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	CodeChallenge    string `json:"code_challenge"`
	CodeVerifier     string `json:"code_verifier"`
	MetadataEndpoint string `json:"metadata_endpoint"`
	NoBrowser        bool   `json:"no_browser"`
	Pkce             bool   `json:"pkce"`
	Port             uint   `json:"oauth2_port"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	State            string `json:"state"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserInfoEndpoint string `json:"userinfo_endpoint"`
	UserInfo         bool   `json:"userinfo"`
	Verbose          bool   `json:"verbose"`
}

func initializeAppConfig() (AppConfig, error) {
	// General rules;
	// - CLI arguments have precedence over ENV, i.e. those starting with "O2TOKEN_"
	// - specified variables (CLI or ENV) will never be automatically derived

	// Read from CLI or ENV (let ENV show as default if defined - but not for random/secret fields because they show up in --help)
	authEndpointPtr := flag.String("auth-endpoint", parseStringEnvVar("", "O2TOKEN_AUTH_ENDPOINT"), "Authorization endpoint")
	callbackPathPtr := flag.String("callback-path", parseStringEnvVar("/oauth2/callback", "O2TOKEN_CALLBACK_PATH"), "Oauth2 callback path")
	clientIDPtr := flag.String("client-id", parseStringEnvVar("", "O2TOKEN_CLIENT_ID"), "Client (aka application) id ")
	clientSecretPtr := flag.String("client-secret", "", "Client secret (if applicable)")
	codeChallengePtr := flag.String("code-challenge", "", "PKCE Code Challenge (default <derived from verifier> when PKCE is enabled)")
	codeVerifierPtr := flag.String("code-verifier", "", "PKCE Code Verifier (default <random> when PKCE is enabled)")
	metadataEndpointPtr := flag.String("metadata-endpoint", parseStringEnvVar("", "O2TOKEN_METADATA_ENDPOINT"), "IDP base URL")
	noBrowserPtr := flag.Bool("no-browser", parseBoolEnvVar(false, "O2TOKEN_NO_BROWSER"), "Prevent automatic launch of browser for login URL")
	pkcePtr := flag.Bool("pkce", parseBoolEnvVar(true, "O2TOKEN_PKCE"), "Use Oauth2 with PKCE (S256)")
	portPtr := flag.Uint("port", parseUintEnvVar(8080, "O2TOKEN_PORT"), "Local server port")
	tokenEndpointPtr := flag.String("token-endpoint", parseStringEnvVar("", "O2TOKEN_TOKEN_ENDPOINT"), "Token endpoint")
	refreshTokenPtr := flag.String("refresh-token", parseStringEnvVar("", "O2TOKEN_REFRESH_TOKEN"), "Refresh token to use when requesting new tokens")
	statePtr := flag.String("state", parseStringEnvVar("", "O2TOKEN_STATE"), "Oauth2 state string (default <random>)")
	scopePtr := flag.String("scope", parseStringEnvVar("openid,offline_access", "O2TOKEN_SCOPE"), "Access scope")
	verbosePtr := flag.Bool("verbose", parseBoolEnvVar(false, "O2TOKEN_VERBOSE"), "Print progress and decoded/interpreted tokens")
	userInfoPtr := flag.Bool("userinfo", parseBoolEnvVar(false, "O2TOKEN_USERINFO"), "Fetch user info after obtaining the access token")
	userInfoEndpointPtr := flag.String("userinfo-endpoint", parseStringEnvVar("", "O2TOKEN_USERINFO_ENDPOINT"), "User info endpoint")
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
	if *pkcePtr {
		if *codeVerifierPtr == "" {
			verifierStr := genPkceCodeVerifier()
			codeVerifierPtr = &verifierStr
		}
		if *codeChallengePtr == "" {
			challengeStr := computePkceCodeChallenge(*codeVerifierPtr)
			codeChallengePtr = &challengeStr
		}
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

	config := AppConfig{
		AuthEndpoint:     *authEndpointPtr,
		CallbackPath:     *callbackPathPtr,
		ClientID:         *clientIDPtr,
		CodeChallenge:    *codeChallengePtr,
		CodeVerifier:     *codeVerifierPtr,
		ClientSecret:     *clientSecretPtr,
		MetadataEndpoint: *metadataEndpointPtr,
		NoBrowser:        *noBrowserPtr,
		Pkce:             *pkcePtr,
		Port:             *portPtr,
		RefreshToken:     *refreshTokenPtr,
		State:            *statePtr,
		Scope:            scopeStr,
		TokenEndpoint:    *tokenEndpointPtr,
		Verbose:          *verbosePtr,
		UserInfo:         *userInfoPtr,
		UserInfoEndpoint: *userInfoEndpointPtr,
	}

	// Some level of input validation...
	var retErr error
	if config.AuthEndpoint == "" || config.TokenEndpoint == "" {
		retErr = fmt.Errorf("authorization/token endpoints not configured")
	} else if config.Port == 0 || config.Port > 65535 {
		retErr = fmt.Errorf("invalid port configured")
	} else if len(config.CallbackPath) < 2 || config.CallbackPath[0] != '/' {
		retErr = fmt.Errorf("invalid callback path configured")
	} else if config.ClientID == "" {
		retErr = fmt.Errorf("client ID not configured")
	} else if config.UserInfo && config.UserInfoEndpoint == "" {
		retErr = fmt.Errorf("missing UserInfoEndpoint configuration")
	} else if config.State == "" {
		retErr = fmt.Errorf("empty state string configured")
	}

	if config.Verbose || retErr != nil {
		// temporary hide the secret and most of the refresh token (if provided)
		tempSecret := config.ClientSecret
		tempRefresh := config.RefreshToken
		config.ClientSecret = strings.Repeat("*", len(tempSecret))
		if len(config.RefreshToken) > 15 {
			config.RefreshToken = config.RefreshToken[0:15] + "..."
		}
		configOutput, _ := json.MarshalIndent(config, "", "  ")
		fmt.Printf("Running with the specified/derived configuration:\n%v\n", string(configOutput))
		config.ClientSecret = tempSecret
		config.RefreshToken = tempRefresh
	}

	return config, retErr
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
