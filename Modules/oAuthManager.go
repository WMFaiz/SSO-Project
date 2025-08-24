package Modules

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"Server/Structs"
	"Server/Utils"

	// "golang.org/x/oauth2"
	"github.com/fatih/color"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type NgrokAPI struct {
	Args      string `json:"args"`
	IP        string `json:"ip"`
	Region    string `json:"region"`
	Proto     string `json:"proto"`
	PublicURL string `json:"public_url"`
}

type TopicData struct {
	ID           int    `json:"id"`
	Title        string `json:"title"`
	CreatedAt    string `json:"created_at"`
	Views        int    `json:"views"`
	ReplyCount   int    `json:"reply_count"`
	LastPostedAt string `json:"last_posted_at"`
}

type TopicList struct {
	Topics []TopicData `json:"topics"`
}

type DiscourseResponse struct {
	TopicList TopicList `json:"topic_list"`
}

func getNgrokForwardingURL() (string, error) {
	resp, err := http.Get("http://127.0.0.1:4040/api/tunnels")
	if err != nil {
		return "", fmt.Errorf("failed to contact Ngrok API: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %v", err)
	}

	tunnels := result["tunnels"].([]interface{})
	if len(tunnels) > 0 {
		if tunnel, ok := tunnels[0].(map[string]interface{}); ok {
			if publicURL, ok := tunnel["public_url"].(string); ok {
				return publicURL, nil
			}
		}
	}

	return "", fmt.Errorf("no forwarding URL found")
}

func updateConfigFile(newURL string) error {
	configFilePath := "../sso-auth-service/main.config"

	file, err := os.Open(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	var newLines []string
	scanner := bufio.NewScanner(file)
	mainURLFound := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MAIN_URL=") {
			newLines = append(newLines, "MAIN_URL="+newURL)
			mainURLFound = true
		} else {
			newLines = append(newLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	if !mainURLFound {
		newLines = append(newLines, "MAIN_URL="+newURL)
	}

	err = ioutil.WriteFile(configFilePath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
	if err != nil {
		return fmt.Errorf("failed to write to config file: %v", err)
	}

	return nil
}

// Remove salt and hash to return plain password
func verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Setup OAuth2 Server
func SetupOAuthServer(id string, secret string, domain string) *server.Server {
	clientStore := store.NewClientStore()
	clientStore.Set(id, &models.Client{
		ID:     id,
		Secret: secret,
		Domain: domain,
	})

	tokenStore, err := store.NewMemoryTokenStore()
	if err != nil {
		log.Fatalf("Failed to create memory token store: %v", err)
	}
	manager := manage.NewDefaultManager()
	manager.MapClientStorage(clientStore)
	manager.MapTokenStorage(tokenStore)
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	srv := server.NewServer(server.NewConfig(), manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	return srv
}

func exchangeAuthCodeForTokens(client_id, client_secret, authCode, redirectURI string) error {
	tokenURL := "https://oauth2.googleapis.com/token"
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {client_id},
		"client_secret": {client_secret},
	}

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&TokenResponse); err != nil {
		return err
	}

	return nil
}

func refreshAccessToken(client_id, client_secret, refreshToken string) (string, error) {
	tokenURL := "https://oauth2.googleapis.com/token"
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {client_id},
		"client_secret": {client_secret},
	}

	log.Println("Sending Refresh Token:", refreshToken)

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to request new access token: %v", err)
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(resp.Body)

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}

	if err := json.Unmarshal(responseBody, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse refreshed token response: %v", err)
	}

	if tokenResponse.Error != "" {
		return "", fmt.Errorf("refresh token failed: %s - %s", tokenResponse.Error, tokenResponse.ErrorDesc)
	}

	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("refresh token request succeeded but access token is missing")
	}

	return tokenResponse.AccessToken, nil
}

func fetchUserInfo(accessToken string) (*struct {
	Email string `json:"email"`
}, error) {
	userInfoURL := "https://www.googleapis.com/oauth2/v3/userinfo"
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	userResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer userResp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func WithData(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			http.Error(res, "Unable to parse form", http.StatusBadRequest)
			return
		}
		rememberMe := req.FormValue("rememberme")
		rememberMeBool := false
		if rememberMe == "true" || rememberMe == "1" {
			rememberMeBool = true
		}
		ctx := context.WithValue(req.Context(), "rememberMe", rememberMeBool)
		next.ServeHTTP(res, req.WithContext(ctx))
	})
}

// Will be execute upon running the server
func OAuthAuthenticator() {

	// Check and get url from ngrok
	ngrokURL, err := getNgrokForwardingURL()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Update the config file with the new ngrok URL
	err = updateConfigFile(ngrokURL)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Config updated successfully with Ngrok URL:", ngrokURL)

	//Get Database
	db := Utils.GetDB()

	config_main_url, err := Utils.ConfigManager("MAIN_URL")
	if err != nil {
		fmt.Print("ConfigManager", err)
	}

	config_client_id, err := Utils.ConfigManager("CLIENT_ID")
	if err != nil {
		fmt.Print("ConfigManager", err)
	}
	config_client_secret, err := Utils.ConfigManager("CLIENT_SECRET")
	if err != nil {
		fmt.Print("ConfigManager", err)
	}
	oauth_server := SetupOAuthServer(
		config_client_id,
		config_client_secret,
		config_main_url+"/YOUR_PATH/oauth2/callback-google")

	//Main call method
	http.Handle("/YOUR_PATH/oauth2/tokenization", WithData(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := oauth_server.HandleTokenRequest(w, r); err != nil {
			log.Printf("Error handling token request: %s", err)
			http.Error(w, "Failed to generate token: "+err.Error(), http.StatusInternalServerError)
			return
		}
	})))

	//IF ouath_server throw an error
	oauth_server.SetInternalErrorHandler(func(err error) (res *errors.Response) {
		if err.Error() == "Missing optional field" {
			log.Println("Non-fatal error: Missing optional field, but continuing with the request")
			return nil
		}
		log.Printf("OAuth2 Response Error (1): %v", err)
		return &errors.Response{
			Error:       errors.ErrServerError,
			Description: "An internal server error occurred",
			StatusCode:  http.StatusInternalServerError,
		}
	})
	oauth_server.SetResponseErrorHandler(func(res *errors.Response) {
		log.Printf("Full OAuth2 Response: %+v", res)
		if res.Error != nil {
			log.Printf("OAuth2 Response Error (2): %s", res.Error.Error())
		} else {
			log.Println("OAuth2 Response Error (2): Unknown error occurred")
		}
	})

	//Call this method after it execute /YOUR_PATH/oauth2/tokenization
	oauth_server.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (string, error) {
		rememberMe, ok := ctx.Value("rememberMe").(bool)
		if !ok {
			log.Println("RememberMe value not found in context, defaulting to false")
			rememberMe = false
		}

		var acc_id, encryptedPassword string
		query := "SELECT acc_id, encrypted_password FROM accounts WHERE email = $1"
		err := db.QueryRow(query, username).Scan(&acc_id, &encryptedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Println("User not found in database")
				return "", errors.ErrInvalidGrant
			}
			log.Printf("Database error: %v", err)
			return "", errors.ErrServerError
		}

		if !verifyPassword(password, encryptedPassword) {
			log.Println("Password mismatch")
			return "", errors.ErrInvalidGrant
		}

		jwtToken := ""
		if rememberMe {
			jwtToken, err = Utils.CreateToken30Days(acc_id)
			if err != nil {
				log.Printf("Error creating access token: %v", err)
				return "", errors.ErrInvalidAccessToken
			}
		} else {
			jwtToken, err = Utils.CreateToken(acc_id)
			if err != nil {
				log.Printf("Error creating access token: %v", err)
				return "", errors.ErrInvalidAccessToken
			}
		}

		sqlUpdateQuery := "UPDATE accounts SET wira_token = $1 WHERE email = $2"
		_, err = db.Exec(sqlUpdateQuery, jwtToken, username)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Println("User not found in database")
				return "", errors.ErrInvalidRequest
			} else {
				log.Printf("Database error: %v", err)
				return "", errors.ErrServerError
			}
		}

		userId := Structs.User{
			ID:       acc_id,
			Email:    username,
			JwtToken: jwtToken,
			Status:   "success",
		}
		Structs.UsersStore.Lock()
		Structs.UsersStore.Users[acc_id] = userId
		Structs.UsersStore.Unlock()

		return jwtToken, nil
	})

	//SSO Google
	http.HandleFunc("/YOUR_PATH/oauth2/sso/authorize-google", func(res http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(res, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		redirectURI := config_main_url + "/YOUR_PATH/oauth2/callback-google"
		state := Utils.OriginalGenerateState() + "|origin=authorize-google"

		oauthURL := "https://accounts.google.com/o/oauth2/v2/auth?" +
			"client_id=" + config_client_id +
			"&redirect_uri=" + redirectURI +
			"&response_type=code" +
			"&scope=openid%20profile%20email" +
			"&state=" + url.QueryEscape(state) +
			"&access_type=offline" +
			"&prompt=consent"

		response := map[string]string{
			"oauthURL": oauthURL,
		}

		res.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(res).Encode(response); err != nil {
			log.Println("Error encoding response:", err)
			http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	//SSO Google Electron App
	http.HandleFunc("/YOUR_PATH/oauth2/sso/authorize-google-app", func(res http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(res, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		redirectURI := config_main_url + "/YOUR_PATH/oauth2/callback-google"
		state := Utils.OriginalGenerateState() + "|origin=authorize-google-app"

		oauthURL := "https://accounts.google.com/o/oauth2/v2/auth?" +
			"client_id=" + config_client_id +
			"&redirect_uri=" + redirectURI +
			"&response_type=code" +
			"&scope=openid%20profile%20email" +
			"&state=" + url.QueryEscape(state) +
			"&access_type=offline" +
			"&prompt=consent"

		response := map[string]string{
			"oauthURL": oauthURL,
		}

		res.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(res).Encode(response); err != nil {
			log.Println("Error encoding response:", err)
			http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	//SSO Google Callback
	http.HandleFunc("/YOUR_PATH/oauth2/callback-google", func(res http.ResponseWriter, req *http.Request) {
		status := "success"

		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic: %v", r)
				http.Error(res, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		if req.Method != http.MethodGet {
			http.Error(res, "Method Not Allowed", http.StatusMethodNotAllowed)
			status = "failed"
			return
		}

		query := req.URL.Query()
		authCode := query.Get("code")
		encodedState := query.Get("state")
		_, err := url.QueryUnescape(encodedState)
		if err != nil {
			http.Error(res, "Invalid state parameter", http.StatusBadRequest)
			status = "failed"
			return
		}

		if encodedState == "" {
			http.Error(res, "Missing state parameter", http.StatusBadRequest)
			status = "failed"
			return
		}

		parts := strings.Split(encodedState, "|origin=")
		if len(parts) < 2 {
			http.Error(res, "Invalid state parameter", http.StatusBadRequest)
			status = "failed"
			return
		}
		origin := parts[1]

		if errDesc := query.Get("error_description"); errDesc != "" {
			http.Error(res, "Authorization error: "+errDesc, http.StatusBadRequest)
			status = "failed"
			return
		}

		if authCode == "" {
			http.Error(res, "Missing authorization code", http.StatusBadRequest)
			status = "failed"
			return
		}

		redirectURI := config_main_url + "/YOUR_PATH/oauth2/callback-google"
		exchangeErr := exchangeAuthCodeForTokens(config_client_id, config_client_secret, authCode, redirectURI)
		if exchangeErr != nil {
			log.Printf("Error exchanging authorization code: %v", err)
			http.Error(res, "Failed to exchange authorization code for token: "+err.Error(), http.StatusInternalServerError)
			status = "failed"
			return
		}

		if TokenResponse.AccessToken == "" {
			log.Println("Error: Refresh token is empty.")
			status = "failed"
			http.Error(res, "Refresh token is missing", http.StatusUnauthorized)
			return
		}

		newAccessToken, refreshErr := refreshAccessToken(config_client_id, config_client_secret, TokenResponse.RefreshToken)
		if refreshErr != nil {
			log.Printf("Failed to refresh access token: %v", refreshErr)
			http.Error(res, "Failed to fetch user info", http.StatusInternalServerError)
			status = "failed"
			return
		}

		userInfo, err := fetchUserInfo(newAccessToken)
		if err != nil {
			http.Error(res, "Failed to fetch user info", http.StatusInternalServerError)
			status = "failed"
			return
		}

		if userInfo.Email == "" {
			log.Println("userInfo.Email is empty")
			status = "failed"
			res.Header().Set("Content-Type", "application/json")
			json.NewEncoder(res).Encode(map[string]string{"status": status})
			return
		}

		jwtToken, err := Utils.CreateToken(userInfo.Email)
		if err != nil {
			log.Printf("Error creating access token: %v", err)
			status = "failed"
			return
		}

		sqlUpdateQuery := "UPDATE accounts SET google_token = $1, wira_token = $2 WHERE email = $3"
		_, err = db.Exec(sqlUpdateQuery, authCode, jwtToken, userInfo.Email)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Println("User not found in database")
				status = "failed"
			} else {
				log.Printf("Database error: %v", err)
				status = "failed"
			}
			res.Header().Set("Content-Type", "application/json")
			json.NewEncoder(res).Encode(map[string]string{"status": status})
			return
		}

		var acc_id, username string
		sqlGetQuery := "SELECT acc_id, username FROM accounts WHERE email = $1"
		sqlErr := db.QueryRow(sqlGetQuery, userInfo.Email).Scan(&acc_id, &username)
		if sqlErr != nil {
			if sqlErr == sql.ErrNoRows {
				log.Println("User not found in database")
				return
			}
			log.Printf("Database error: %v", sqlErr)
			return
		}

		if origin == "authorize-google" {
			fmt.Fprintf(res, `
				<script>
					window.opener.postMessage({ email: "%s", acc_id: "%s", username: "%s", status: "%s" }, "http://localhost:8080");
					window.close();
				</script>
			`, userInfo.Email, acc_id, username, status)
		} else if origin == "authorize-google-app" {
			if status == "success" {
				fmt.Fprintf(res, `
				<html>
						<head>
								<title>Project Authorization</title>
								<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
						</head>
						<body>
								<h1>Authorization Success!</h1>
								<p>You may now close this tab.</p>
						</body>
						<script>
								const params = new URLSearchParams({
										email: "%s",
										acc_id: "%s",
										username: "%s",
										code: "%s",
										state: "%s",
										status: "%s",
								});
								const redirectURL = "http://54.173.226.243:9096/YOUR_PATH/oauth2/callback-google?" + params.toString();
								window.location.href = redirectURL;
						</script>
				</html>
			`, userInfo.Email, acc_id, username, authCode, encodedState, status)
			} else if status == "failed" {
				fmt.Fprintf(res, `
					<html>
						<head>
							<title>Project Authorization</title>
							<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
						</head>
						<body>
							<h1>Authorization Failed!</h1>
							<p>You may now close this tab.</p>
						</body>
						<script>
							window.close();
						</script>
					</html>
			`)
			}
		}

		res.Header().Set("Content-Type", "application/json")
		json.NewEncoder(res).Encode(map[string]interface{}{
			"email":    userInfo.Email,
			"acc_id":   acc_id,
			"username": username,
			"code":     authCode,
			"state":    encodedState,
			"status":   status,
		})
	})

	http.HandleFunc("/YOUR_PATH/jwt/check-session", func(res http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(res, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := req.ParseForm(); err != nil {
			http.Error(res, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		email := req.FormValue("email")
		if email == "" {
			http.Error(res, "Email is required", http.StatusBadRequest)
			return
		}

		var wiraToken string
		sqlGetQuery := "SELECT wira_token FROM accounts WHERE email = $1"
		sqlErr := db.QueryRow(sqlGetQuery, email).Scan(&wiraToken)
		if sqlErr != nil {
			if sqlErr == sql.ErrNoRows {
				log.Println("User not found in database")
				http.Error(res, "User not found", http.StatusNotFound)
				return
			}
			log.Printf("Database error: %v", sqlErr)
			http.Error(res, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		token, err := Utils.VerifyToken(wiraToken)
		if err != nil {
			log.Printf("Token verification failed: %v", err)
			http.Error(res, "Invalid token", http.StatusUnauthorized)
			return
		}

		isExpired, err := Utils.IsTokenExpired(token)
		if err != nil {
			log.Printf("Error checking token expiration: %v", err)
			http.Error(res, "Error checking token status", http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"Is_Expired": strconv.FormatBool(isExpired),
		}

		res.Header().Set("Access-Control-Allow-Origin", "*")
		res.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(res).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	// Discourse SSO
	http.HandleFunc("/YOUR_PATH/discourse/authorize/sso", func(res http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(res, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var discourseSecret, err = Utils.ConfigManager("DISCOURSE_CON_SECRET")
		if err != nil {
			fmt.Print("ConfigManager", err)
		}

		log.Println("Step 1: Data extraction from json")
		email := req.FormValue("email")
		username := req.FormValue("username")
		name := req.FormValue("name")
		external_id := req.FormValue("external_id")
		sso := req.FormValue("sso")
		sig := req.FormValue("sig")

		if sso == "" || sig == "" {
			http.Error(res, "Missing SSO parameters", http.StatusBadRequest)
			return
		}

		// Step 2: Verify Signature
		log.Println("Step 2: Verify Signature")
		h := hmac.New(sha256.New, []byte(discourseSecret))
		h.Write([]byte(sso))
		expectedSig := hex.EncodeToString(h.Sum(nil))

		if sig != expectedSig {
			http.Error(res, "Invalid SSO signature", http.StatusUnauthorized)
			return
		}

		// Step 3: Decode the Base64 SSO payload
		log.Println("Step 3: Decode the Base64 SSO payload")
		ssoBytes, err := base64.StdEncoding.DecodeString(sso)
		if err != nil {
			http.Error(res, "Failed to decode SSO", http.StatusInternalServerError)
			return
		}

		ssoPayload, err := url.ParseQuery(string(ssoBytes))
		if err != nil {
			http.Error(res, "Failed to parse SSO payload", http.StatusInternalServerError)
			return
		}

		//Step 4: Extract `return_sso_url` from payload
		log.Println("Step 4: Extract `return_sso_url` from payload")
		returnURL := ssoPayload.Get("return_sso_url")
		if returnURL == "" {
			http.Error(res, "Missing return_sso_url", http.StatusBadRequest)
			return
		}

		// Step 5: Generate Discourse SSO Response
		log.Println("Step 5: Generate Discourse SSO Response")
		responseValues := url.Values{}
		responseValues.Set("nonce", ssoPayload.Get("nonce"))
		responseValues.Set("external_id", external_id)
		responseValues.Set("email", email)
		responseValues.Set("username", username)
		responseValues.Set("name", name)

		// Encode the response
		log.Println("Step 6: Encode the response")
		encodedResponse := base64.StdEncoding.EncodeToString([]byte(responseValues.Encode()))

		// Sign the response
		log.Println("Step 7: Sign the response")
		h = hmac.New(sha256.New, []byte(discourseSecret))
		h.Write([]byte(encodedResponse))
		signedResponse := hex.EncodeToString(h.Sum(nil))

		// Step 6: Redirect Back to Discourse
		log.Println("Step 8: Redirect Back to Discourse")
		redirectURL := fmt.Sprintf("%s?sso=%s&sig=%s", returnURL, url.QueryEscape(encodedResponse), url.QueryEscape(signedResponse))
		// http.Redirect(res, req, redirectURL, http.StatusFound)
		responseJSON := map[string]string{
			"redirect_url": redirectURL,
		}
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		json.NewEncoder(res).Encode(responseJSON)
	})

	color.Blue("OAuth2 server is running on http://127.0.0.1:9096")
	log.Fatal(http.ListenAndServe(":9096", nil))
}

