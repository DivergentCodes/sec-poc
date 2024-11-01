package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"embed"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed templates/*
var templates embed.FS

// Add a simple in-memory user store
type User struct {
	ID          []byte
	Name        string
	Credentials []webauthn.Credential
	SessionData *webauthn.SessionData
}

var (
	web   *webauthn.WebAuthn
	users = map[string]User{}
)

func main() {
	var err error
	web, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "WebAuthn ID Checker",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
	})
	if err != nil {
		panic(err)
	}

	// Serve static files and templates
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/begin-register", handleBeginRegister)
	http.HandleFunc("/finish-register", handleFinishRegister)
	http.HandleFunc("/begin-auth", handleBeginAuth)
	http.HandleFunc("/finish-auth", handleFinishAuth)

	// Add new handlers
	http.HandleFunc("/list-credentials", handleListCredentials)
	http.HandleFunc("/remove-credential", handleRemoveCredential)

	println("Server running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFS(templates, "templates/index.html"))
	tmpl.Execute(w, nil)
}

func handleBeginRegister(w http.ResponseWriter, r *http.Request) {
	user := User{
		ID:   []byte("test-user"),
		Name: "Test User",
	}

	options, sessionData, err := web.BeginRegistration(
		&user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			RequireResidentKey: &[]bool{true}[0],
			UserVerification:   protocol.VerificationRequired,
		}),
		webauthn.WithConveyancePreference(protocol.PreferDirectAttestation),
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session data in user
	user.SessionData = sessionData
	users["test-user"] = user

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func handleFinishRegister(w http.ResponseWriter, r *http.Request) {
	user, ok := users["test-user"]
	if !ok {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cred, err := web.CreateCredential(&user, *user.SessionData, parsed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Store the credential in the user object
	user.Credentials = append(user.Credentials, *cred)
	users["test-user"] = user // Update the user in our store

	// Format AAGUID as UUID
	aaguid := fmt.Sprintf("%x-%x-%x-%x-%x",
		cred.Authenticator.AAGUID[:4],
		cred.Authenticator.AAGUID[4:6],
		cred.Authenticator.AAGUID[6:8],
		cred.Authenticator.AAGUID[8:10],
		cred.Authenticator.AAGUID[10:])

	response := map[string]interface{}{
		"aaguid":          aaguid,
		"signCount":       cred.Authenticator.SignCount,
		"attestationType": parsed.Response.AttestationObject.Format,
	}

	if parsed.Response.AttestationObject.AttStatement != nil {
		response["attestationStatement"] = parsed.Response.AttestationObject.AttStatement
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleBeginAuth(w http.ResponseWriter, r *http.Request) {
	options, sessionData, err := web.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session data in user (using test-user for now)
	if user, ok := users["test-user"]; ok {
		user.SessionData = sessionData
		users["test-user"] = user
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func handleFinishAuth(w http.ResponseWriter, r *http.Request) {
	parsed, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get user handle from the parsed response
	userHandle := parsed.Response.UserHandle
	if userHandle == nil {
		userHandle = parsed.Response.AuthenticatorData.RPIDHash
	}

	// Find the user
	user, ok := users[string(userHandle)]
	if !ok {
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}

	credential, err := web.ValidateDiscoverableLogin(
		func(rawID, userHandle []byte) (webauthn.User, error) {
			return &user, nil
		},
		*user.SessionData,
		parsed,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Format AAGUID as UUID
	aaguid := fmt.Sprintf("%x-%x-%x-%x-%x",
		credential.Authenticator.AAGUID[:4],
		credential.Authenticator.AAGUID[4:6],
		credential.Authenticator.AAGUID[6:8],
		credential.Authenticator.AAGUID[8:10],
		credential.Authenticator.AAGUID[10:])

	response := map[string]interface{}{
		"value": aaguid,
		"name":  "Unknown",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Implement WebAuthn interfaces for User
func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Name }
func (u *User) WebAuthnIcon() string                       { return "" }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func handleListCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := users["test-user"]
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{}) // Return empty array if no user
		return
	}

	credentials := []map[string]interface{}{}
	for _, cred := range user.Credentials {
		aaguid := fmt.Sprintf("%x-%x-%x-%x-%x",
			cred.Authenticator.AAGUID[:4],
			cred.Authenticator.AAGUID[4:6],
			cred.Authenticator.AAGUID[6:8],
			cred.Authenticator.AAGUID[8:10],
			cred.Authenticator.AAGUID[10:])

		credentials = append(credentials, map[string]interface{}{
			"id":     base64.StdEncoding.EncodeToString(cred.ID),
			"aaguid": aaguid,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(credentials); err != nil {
		http.Error(w, "Failed to encode credentials", http.StatusInternalServerError)
		return
	}
}

func handleRemoveCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CredentialID string `json:"credentialId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	credID, err := base64.StdEncoding.DecodeString(req.CredentialID)
	if err != nil {
		http.Error(w, "Invalid credential ID", http.StatusBadRequest)
		return
	}

	user, ok := users["test-user"]
	if !ok {
		http.Error(w, "User not found", http.StatusBadRequest)
		return
	}

	// Filter out the credential to remove
	newCreds := []webauthn.Credential{}
	for _, cred := range user.Credentials {
		if !bytes.Equal(cred.ID, credID) {
			newCreds = append(newCreds, cred)
		}
	}

	user.Credentials = newCreds
	users["test-user"] = user

	w.WriteHeader(http.StatusOK)
}
