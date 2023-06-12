package util

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	db "github.com/coinbase/baseca/db/sqlc"
	"github.com/coinbase/baseca/internal/authentication"
	"github.com/google/uuid"
)

func GenerateTestUser(t *testing.T, permissions string, length int) (db.User, string) {
	client_id, _ := uuid.NewRandom()
	credentials := generateRandomCredentials(length)
	hashed_credentials, _ := authentication.HashPassword(credentials)
	email := generateRandomEmail()
	username := generateRandomUsername()
	full_name := generateRandomName()

	return db.User{
		Uuid:                client_id,
		Username:            username,
		HashedCredential:    hashed_credentials,
		FullName:            full_name,
		Email:               email,
		Permissions:         permissions,
		CredentialChangedAt: time.Now().UTC(),
		CreatedAt:           time.Now().UTC(),
	}, credentials
}

func generateRandomEmail() string {
	randBytes := make([]byte, 8)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(err)
	}

	// Encode the random bytes using base64 encoding to get an ASCII string
	randStr := base64.URLEncoding.EncodeToString(randBytes)

	// Use the first 10 characters of the base64-encoded string as the email username
	return fmt.Sprintf("%s@coinbase.com", randStr[:10])
}

func generateRandomName() string {
	// Generate random bytes for the first and last name
	firstNameBytes := make([]byte, 6)
	_, err := rand.Read(firstNameBytes)
	if err != nil {
		panic(err)
	}
	lastNameBytes := make([]byte, 6)
	_, err = rand.Read(lastNameBytes)
	if err != nil {
		panic(err)
	}

	// Convert the random bytes to hexadecimal strings
	firstNameHex := hex.EncodeToString(firstNameBytes)[:10]
	lastNameHex := hex.EncodeToString(lastNameBytes)[:10]

	return fmt.Sprintf("%s %s", firstNameHex, lastNameHex)
}

func generateRandomUsername() string {
	// Generate random bytes for the username
	usernameBytes := make([]byte, 8)
	_, err := rand.Read(usernameBytes)
	if err != nil {
		panic(err)
	}

	// Encode the random bytes using base64 encoding to get an ASCII string
	usernameStr := base64.URLEncoding.EncodeToString(usernameBytes)

	// Use the first 10 characters of the base64-encoded string as the username
	return usernameStr[:10]
}

func generateRandomCredentials(length int) string {
	// Generate random bytes for the credentials
	credentialsBytes := make([]byte, length)
	_, err := rand.Read(credentialsBytes)
	if err != nil {
		panic(err)
	}

	// Encode the random bytes using base64 encoding to get an ASCII string
	credentialsStr := base64.URLEncoding.EncodeToString(credentialsBytes)

	// Return the first `length` characters of the base64-encoded string
	return credentialsStr[:length]
}
