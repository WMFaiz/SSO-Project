package Controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/julienschmidt/httprouter"
)

type SessionData struct {
	Email string `json:"email"`
}

func (cntrlr *Controller) CheckSession(res http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	//Setup Header
	//START
	//------------------------
	allowedOrigins := []string{
		"http://localhost:8080",
		"http://192.168.0.2:8080",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
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

	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintln(res, `{"error": "Method not allowed"}`)
		return
	}
	//END
	//Setup Header
	//------------------------

	//Data abstraction
	//START
	//------------------------
	var sessionData SessionData
	err := json.NewDecoder(req.Body).Decode(&sessionData)
	if err != nil {
		http.Error(res, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	//END
	//Data abstraction
	//-------------------------

	//Check Session
	//START
	//-------------------------
	form := url.Values{}
	form.Set("email", sessionData.Email)

	reqSession, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:9096/YOUR_PATH/jwt/check-session", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(res, "Failed to create OAuth request", http.StatusInternalServerError)
		return
	}
	reqSession.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	respSession, err := client.Do(reqSession)
	if err != nil {
		http.Error(res, "Failed to contact OAuth2 server", http.StatusInternalServerError)
		return
	}
	defer respSession.Body.Close()

	if respSession.StatusCode != http.StatusOK {
		http.Error(res, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	//END
	//Check Session
	//--------------------------

	//Read response
	//START
	//-------------------------
	var sessionResponse map[string]interface{}
	err = json.NewDecoder(respSession.Body).Decode(&sessionResponse)
	if err != nil {
		http.Error(res, "Invalid response from OAuth2 server", http.StatusInternalServerError)
		return
	}
	//END
	//Read response
	//-----------------------

	//START
	//Output
	//-----------------------
	response := map[string]interface{}{
		"Is_Expired": sessionResponse,
	}

	res.WriteHeader(http.StatusOK)
	err = json.NewEncoder(res).Encode(response)
	if err != nil {
		http.Error(res, "Error generating JSON response", http.StatusInternalServerError)
		return
	}
	//END
	//Output
	//-----------------------
}
