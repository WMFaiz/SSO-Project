package Utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ECDSAPrivateKey *ecdsa.PrivateKey
	ECDSAPublicKey  *ecdsa.PublicKey
)

const (
	privateKeyPath = "ecdsa_private.pem"
	publicKeyPath  = "ecdsa_public.pem"
)

func generateAndSaveKeys() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %v", err)
	}
	pub := &priv.PublicKey

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	privFile, err := os.Create(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %v", err)
	}
	defer privFile.Close()

	privPem := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}
	if err := pem.Encode(privFile, privPem); err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	pubFile, err := os.Create(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %v", err)
	}
	defer pubFile.Close()

	pubPem := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	if err := pem.Encode(pubFile, pubPem); err != nil {
		return fmt.Errorf("failed to encode public key: %v", err)
	}

	return nil
}

func loadKeys() error {
	privBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %v", err)
	}

	privPem, _ := pem.Decode(privBytes)
	if privPem == nil {
		return fmt.Errorf("failed to decode private key")
	}

	priv, err := x509.ParseECPrivateKey(privPem.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	pubBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %v", err)
	}

	pubPem, _ := pem.Decode(pubBytes)
	if pubPem == nil {
		return fmt.Errorf("failed to decode public key")
	}

	pub, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	ECDSAPrivateKey = priv
	ECDSAPublicKey = pub.(*ecdsa.PublicKey)

	return nil
}

// Initialize Secret Key
func init() {
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		log.Println("Keys not found, generating new keys...")
		if err := generateAndSaveKeys(); err != nil {
			log.Fatalf("Error generating keys: %v", err)
		}
	} else {
		log.Println("Loading keys from file...")
		if err := loadKeys(); err != nil {
			log.Fatalf("Error loading keys: %v", err)
		}
	}
}

func CreateToken(userID string) (string, error) {
	string_expiration_date, err := ConfigManager("JWT_TOKEN_EXPIRATION_DATE")
	if err != nil {
		fmt.Printf("Failed to get expiration_date in config file")
		return "", err
	}
	float_expiration_date, err := strconv.ParseFloat(string_expiration_date, 64)
	if err != nil {
		fmt.Println("Error:", err)
		return "", err
	}
	expirationTime := time.Now().Add(time.Duration(float_expiration_date) * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user_id":    userID,
		"expired_in": expirationTime.Unix(),
	})

	tokenString, err := token.SignedString(ECDSAPrivateKey)
	if err != nil {
		log.Printf("Error creating JWT token: %v", err)
		return "", err
	}

	return tokenString, nil
}

func CreateToken30Days(userID string) (string, error) {
	string_expiration_date, err := ConfigManager("JWT_TOKEN_EXPIRATION_DATE_REMEMBERME")
	if err != nil {
		fmt.Printf("Failed to get expiration_date in config file")
		return "", err
	}
	float_expiration_date, err := strconv.ParseFloat(string_expiration_date, 64)
	if err != nil {
		fmt.Println("Error:", err)
		return "", err
	}
	expirationTime := time.Now().Add(time.Duration(float_expiration_date) * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user_id":    userID,
		"expired_in": expirationTime.Unix(),
	})

	tokenString, err := token.SignedString(ECDSAPrivateKey)
	if err != nil {
		log.Printf("Error creating JWT token: %v", err)
		return "", err
	}

	return tokenString, nil
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return ECDSAPublicKey, nil
	})
}

func ExtractClaims(token *jwt.Token) (map[string]interface{}, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("claims are not of type jwt.MapClaims")
	}

	if _, ok := claims["user_id"]; !ok {
		return nil, fmt.Errorf("missing user_id claim")
	}

	if _, ok := claims["expired_in"]; !ok {
		return nil, fmt.Errorf("missing expired_in claim")
	}

	return claims, nil
}

func IsTokenExpired(token *jwt.Token) (bool, error) {
	claims, err := ExtractClaims(token)
	if err != nil {
		return false, err
	}

	expiredIn, ok := claims["expired_in"].(float64)
	if !ok {
		return false, fmt.Errorf("expired_in claim is not a valid timestamp")
	}

	if time.Now().Unix() > int64(expiredIn) {
		return true, nil
	}
	return false, nil
}
