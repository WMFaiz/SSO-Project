package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func GenerateSSOPayload(nonce, email, externalID, username, name, sharedSecret string) (string, string, error) {
	if nonce == "" || email == "" || externalID == "" || username == "" || name == "" {
		return "", "", fmt.Errorf("missing required SSO fields")
	}

	data := url.Values{}
	data.Set("nonce", nonce)
	data.Set("email", email)
	data.Set("external_id", externalID)
	data.Set("username", username)
	data.Set("name", name)

	payload := base64.StdEncoding.EncodeToString([]byte(data.Encode()))

	h := hmac.New(sha256.New, []byte(sharedSecret))
	h.Write([]byte(payload))
	signature := fmt.Sprintf("%x", h.Sum(nil))

	return payload, signature, nil
}

func SendSSOLogin(discourseURL, payload, signature string) error {
	if discourseURL == "" {
		return fmt.Errorf("discourse URL is empty")
	}

	data := url.Values{}
	data.Set("sso", payload)
	data.Set("sig", signature)

	resp, err := http.Post(discourseURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to send SSO login: %w", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discourse responded with status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Println("SSO login successful:", string(body))
	return nil
}

func main() {
	discourseURL := "https://your.host.org/session/sso_login"
	sharedSecret := "YOUR_DISCOURSE_SHARED_SECRET"
	nonce := "YOUR_NONCE_FROM_DISCOURSE"

	email := "YOUR_EMAIL@gmail.com"
	externalID := "YOUR_GENERATED_EXTERNAL_ID"
	username := "YOUR_ADMIN_USENAME"
	name := "ADMIN"

	payload, signature, err := GenerateSSOPayload(nonce, email, externalID, username, name, sharedSecret)
	if err != nil {
		fmt.Println("Error generating SSO payload:", err)
		return
	}

	if err := SendSSOLogin(discourseURL, payload, signature); err != nil {
		fmt.Println("Error sending SSO login:", err)
		return
	}

	fmt.Println("SSO login flow completed successfully!")
}
