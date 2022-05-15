package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type OAuthAccessResponse struct {
	TokenType    string   `json:"token_type"`
	Scope        string   `json:"scope"`
	ExpiresIn    int      `json:"expires_in"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	IDToken      string   `json:"id_token"`
	UserInfo     unstruct `json:"userinfo,omitempty"` // actually not part of the oauth2 token response but added for (output) convenience
}

// Only a few fields defined here (the ones used by the app)
type OidcMetadata struct {
	AuthEndpoint     string `json:"authorization_endpoint"`
	TokenEndpoint    string `json:"token_endpoint"`
	UserInfoEndpoint string `json:"userinfo_endpoint"`
}

func fetchMetadataDocument(metadataUrl string) OidcMetadata {
	empty := OidcMetadata{}
	httpClient := http.Client{}

	req, err := http.NewRequest(http.MethodGet, metadataUrl, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create request for metadata document: %v", err)
		return empty
	}
	req.Header.Set("accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not send request for metadata document: %v", err)
		return empty
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Unexpected status code for %v: %v\n", metadataUrl, res.StatusCode)
		return empty
	}

	var retVal OidcMetadata
	if err := json.NewDecoder(res.Body).Decode(&retVal); err != nil {
		fmt.Fprintf(os.Stderr, "Could not parse metadata document response: %v", err)
		return empty
	}

	return retVal
}

func startFlow(w http.ResponseWriter, r *http.Request) {
	// Redirect to authorization endpoint
	redirectUri := fmt.Sprintf("http://localhost:%v%v", appConfig.Port, appConfig.CallbackPath)
	scope := url.QueryEscape(appConfig.Scope)
	url := fmt.Sprintf("%v?client_id=%v&redirect_uri=%v&scope=%v&response_type=code&state=%v", appConfig.AuthEndpoint, appConfig.ClientID, redirectUri, scope, appConfig.State)
	if appConfig.Verbose {
		fmt.Printf("Redirecting user to authorization endpoint:\n%v\n", url)
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func oauth2CodeCallback(w http.ResponseWriter, r *http.Request) {
	if appConfig.Verbose {
		fmt.Printf("Processing callback for authorization code\n")
	}

	// First, we need to get the value of the `code` query param
	err := r.ParseForm()
	if err != nil {
		reportErrorAndSoftExit("could not parse query in callback", err, http.StatusBadRequest, w)
		return
	}
	code := r.FormValue("code")
	if len(code) == 0 {
		reportErrorAndSoftExit("oath2 flow error", fmt.Errorf("missing 'code' parameter"), http.StatusBadRequest, w)
		return
	}

	// Confirm valid state (the only type of "auth verification" done in this app)
	state := r.FormValue("state")
	if state != appConfig.State {
		err := fmt.Errorf("expected: %v, got: %v", appConfig.State, state)
		reportErrorAndSoftExit("unexpected state parameter value in callback", err, http.StatusBadRequest, w)
		return
	}

	// Next, call the idp oauth2 token endpoint to get our tokens
	tokens, err := redeemTokensWithCode(code)
	if err != nil {
		reportErrorAndSoftExit("oath2 flow error", err, http.StatusInternalServerError, w)
		return
	}

	if appConfig.UserInfo {
		var err error
		tokens.UserInfo, err = fetchUserInfo(tokens.AccessToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: %v\n", err) // no show-stopper; log and continue the flow
		}
	}

	// Finally, send a response to redirect the user to the "success" page
	http.Redirect(w, r, "/success.html", http.StatusFound)

	// Print result to stdout
	err = printTokens(tokens)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Output error: %v\n", err)
		softExit(1)
		return
	}

	// We're done
	softExit(0)
}

func refreshTokens(refreshToken string) error {
	tokens, err := redeemTokensWithRefreshToken(refreshToken)
	if err != nil {
		return fmt.Errorf("could not redeem tokens: %v", err)
	}

	if appConfig.UserInfo {
		var err error
		tokens.UserInfo, err = fetchUserInfo(tokens.AccessToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: %v\n", err) // no show-stopper; log and continue the flow
		}
	}

	// Print result to stdout
	err = printTokens(tokens)
	if err != nil {
		return fmt.Errorf("output error: %v", err)
	}

	return nil
}

func printTokens(tokens OAuthAccessResponse) error {
	resultJson, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("could not format result output: %v", err)
	}
	if appConfig.Verbose {
		fmt.Println("Received response:")
	}
	fmt.Println(string(resultJson))

	if appConfig.Verbose {
		fmt.Printf("\nSuccessful operation, received tokens expire in %v\n", secondsToFriendlyString(tokens.ExpiresIn))
		if len(tokens.AccessToken) > 0 {
			fmt.Printf("\nAccessToken:\n------------\n%v\n", prettyJson(jwtToString(tokens.AccessToken)))
		}
		if len(tokens.IDToken) > 0 {
			fmt.Printf("\nIDoken:\n-------\n%v\n", prettyJson(jwtToString(tokens.IDToken)))
		}
	}
	return nil
}

func redeemTokensWithCode(code string) (OAuthAccessResponse, error) {
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("redirect_uri", fmt.Sprintf("http://localhost:%v%v", appConfig.Port, appConfig.CallbackPath))
	params.Set("client_id", appConfig.ClientID)
	params.Set("client_secret", appConfig.ClientSecret)
	params.Set("code", code)

	return redeemTokens(params)
}

func redeemTokensWithRefreshToken(token string) (OAuthAccessResponse, error) {
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("client_id", appConfig.ClientID)
	params.Set("client_secret", appConfig.ClientSecret)
	params.Set("refresh_token", token)

	return redeemTokens(params)
}

func redeemTokens(params url.Values) (OAuthAccessResponse, error) {
	nothing := OAuthAccessResponse{}

	// Params as form-params in POST: https://golang.cafe/blog/how-to-make-http-url-form-encoded-request-golang.html
	req, err := http.NewRequest(http.MethodPost, appConfig.TokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nothing, fmt.Errorf("could not create HTTP request to redeem tokens: %v", err)
	}

	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("accept", "application/json")

	httpClient := http.Client{}
	res, err := httpClient.Do(req)
	if err != nil {
		return nothing, fmt.Errorf("could not send HTTP request to redeem tokens: %v", err)
	}
	defer res.Body.Close()
	if appConfig.Verbose {
		fmt.Printf("Sent POST request to redeem access/id tokens\n")
	}

	bodyBytes, _ := io.ReadAll(res.Body)
	var tokens OAuthAccessResponse
	if err := json.Unmarshal(bodyBytes, &tokens); err != nil {
		return nothing, fmt.Errorf("could not parse JSON response for redeemed tokens: %v", err)
	}

	if len(tokens.AccessToken) == 0 {
		return nothing, fmt.Errorf("no access token received, raw response: %v", string(bodyBytes))
	}
	return tokens, nil
}

func fetchUserInfo(accessToken string) (unstruct, error) {
	req, err := http.NewRequest(http.MethodGet, appConfig.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create request for userinfo: %v", err)
	}

	req.Header.Set("accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+accessToken)

	httpClient := http.Client{}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not send request for userinfo: %v", err)
	}
	defer res.Body.Close()
	if appConfig.Verbose {
		fmt.Printf("Sent GET request for userinfo\n")
	}

	bodyBytes, _ := io.ReadAll(res.Body)
	var retVal unstruct
	err = json.Unmarshal(bodyBytes, &retVal)
	if err != nil {
		return nil, fmt.Errorf("could not parse userinfo response: %v", err)
	}

	return retVal, nil
}
