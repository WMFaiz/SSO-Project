package Controller

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"Server/Structs"

	"github.com/julienschmidt/httprouter"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// "Port": "43887"

type LoginData struct {
	DeviceToken string `json:"devicetoken"`
	Email       string `json:"email"`
	IpAddrs     string `json:"ipaddrs"`
	Method      string `json:"method"`
	Passcode    string `json:"passcode"`
	Password    string `json:"password"`
	Username    string `json:"username"`
	RememberMe  bool   `json:"rememberme"`
}

func (cntrlr *Controller) SaltedHashed(res http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if req.Method == http.MethodOptions {
		res.Header().Set("Access-Control-Allow-Origin", "*")
		res.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		res.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		res.Header().Set("Access-Control-Allow-Credentials", "true")
		res.WriteHeader(http.StatusOK)
		return
	}

	res.Header().Set("Access-Control-Allow-Origin", "*")
	res.Header().Set("Access-Control-Allow-Credentials", "true")

	var rawData map[string]interface{}
	err := json.NewDecoder(req.Body).Decode(&rawData)
	if err != nil {
		http.Error(res, "Failed to decode JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	password, ok := rawData["password"].(string)
	if !ok || password == "" {
		http.Error(res, "Password field is missing or invalid", http.StatusBadRequest)
		return
	}

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(res, "Failed to hash password: "+err.Error(), http.StatusInternalServerError)
		print("", err)
	}

	hashString := string(hashBytes)

	res.WriteHeader(http.StatusOK)
	response := map[string]string{
		"message": hashString,
	}
	json.NewEncoder(res).Encode(response)
}

func (cntrlr *Controller) Logout(res http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	if req.Method == http.MethodOptions {
		res.Header().Set("Access-Control-Allow-Origin", "*")
		res.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		res.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		res.Header().Set("Access-Control-Allow-Credentials", "true")
		res.WriteHeader(http.StatusOK)
		return
	}

	res.Header().Set("Access-Control-Allow-Origin", "*")
	res.Header().Set("Access-Control-Allow-Credentials", "true")

	http.SetCookie(res, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		MaxAge: -1,
	})

	res.WriteHeader(http.StatusOK)
	response := map[string]string{
		"message": "Logged out successfully",
	}
	json.NewEncoder(res).Encode(response)
}

// SSO Login Process
func (cntrlr *Controller) Login(res http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	// db := Utils.GetDB()

	//Setup Header
	//START
	//------------------------
	allowedOrigins := []string{
		"http://localhost:8080",
		"http://192.168.0.2:8080",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
		"https://743b-54-173-226-243.ngrok-free.app",
	}

	origin := req.Header.Get("Origin")
	for _, allowedOrigin := range allowedOrigins {
		if origin == allowedOrigin {
			res.Header().Set("Access-Control-Allow-Origin", origin)
			break
		}
	}

	if req.Method == http.MethodOptions {

		res.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		res.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		res.Header().Set("Access-Control-Allow-Credentials", "true")
		res.WriteHeader(http.StatusOK)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	res.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
	res.Header().Set("Access-Control-Allow-Credentials", "true")

	if req.Method == http.MethodPost {
		res.WriteHeader(http.StatusOK)
	} else {
		res.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(res, `{"error": "Method not allowed"}`)
	}
	//END
	//Setup Header
	//------------------------

	//Data abstraction
	//START
	//------------------------
	var loginData LoginData
	err := json.NewDecoder(req.Body).Decode(&loginData)
	if err != nil {
		http.Error(res, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	//END
	//Data abstraction
	//-------------------------

	//OAuth2 Login Process
	//START
	//-------------------------
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "YOUR_GOOGLE_CLIENT_ID")
	form.Set("client_secret", "YOUR_GOOGLE_CLIENT_SECRET")
	form.Set("devicetoken", loginData.DeviceToken)
	form.Set("email", loginData.Email)
	form.Set("ipaddrs", loginData.IpAddrs)
	form.Set("method", loginData.Method)
	form.Set("passcode", loginData.Passcode)
	form.Set("password", loginData.Password)
	form.Set("username", loginData.Email)
	form.Set("rememberme", strconv.FormatBool(loginData.RememberMe))

	reqOAuth, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:9096/YOUR_PATH/oauth2/tokenization", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(res, "Failed to create OAuth request", http.StatusInternalServerError)
		return
	}
	reqOAuth.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	respOAuth, err := client.Do(reqOAuth)
	if err != nil {
		http.Error(res, "Failed to contact OAuth2 server", http.StatusInternalServerError)
		return
	}
	defer respOAuth.Body.Close()

	if respOAuth.StatusCode != http.StatusOK {
		http.Error(res, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	var oauthResponse map[string]interface{}
	err = json.NewDecoder(respOAuth.Body).Decode(&oauthResponse)
	if err != nil {
		http.Error(res, "Invalid response from OAuth2 server", http.StatusInternalServerError)
		return
	}
	//END
	//OAuth2 Login Process
	//--------------------------

	//START
	//Get User
	//------------------------
	user := Structs.GetUser(loginData.Email, "success")
	displayName := "gm." + strings.Split(loginData.Email, "@")[0]
	clientUsername := "gm." + strings.Split(loginData.Email, "@")[0]
	//END
	//Get User
	//------------------------

	//START
	//Output
	//-----------------------
	data := map[string]interface{}{
		"DisplayName": displayName,
		"Email":       loginData.Email,
		"Token":       user.JwtToken,
		"UserID":      user.ID,
		"Username":    clientUsername,
	}

	dataString, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshalling data: %v", err)
		http.Error(res, "Error generating JSON response", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"data":   string(dataString),
		"status": "success",
	}

	res.WriteHeader(http.StatusOK)
	err = json.NewEncoder(res).Encode(response)
	if err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(res, "Error generating JSON response", http.StatusInternalServerError)
		return
	}
	//END
	//Output
	//-----------------------
}
