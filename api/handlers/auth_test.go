package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goledger/qa-test-api/routes"
)

func setupRouter() http.Handler {
	return routes.SetupRouter()
}

func loginRequest(t *testing.T, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	setupRouter().ServeHTTP(w, req)
	return w
}

func getToken(t *testing.T, username, password string) string {
	t.Helper()
	w := loginRequest(t, username, password)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if tok, ok := resp["token"].(string); ok {
		return tok
	}
	return ""
}

// BUG-001: Login accepts any password with the same length as the real password.
func TestBUG001_LoginAcceptsWrongPasswordSameLength(t *testing.T) {
	// "admin123" has 8 characters; "xxxxxxxx" also has 8 characters.
	w := loginRequest(t, "admin", "xxxxxxxx")

	if w.Code == http.StatusOK {
		t.Errorf("BUG-001 CONFIRMED: Login returned %d for wrong password 'xxxxxxxx' "+
			"(same length as 'admin123'). Expected 401 Unauthorized.", w.Code)
	}
}

// Verify that a completely wrong password (different length) is rejected.
func TestLoginRejectsDifferentLengthPassword(t *testing.T) {
	w := loginRequest(t, "admin", "wrong")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for wrong password, got %d", w.Code)
	}
}

// Verify correct credentials work.
func TestLoginCorrectCredentials(t *testing.T) {
	w := loginRequest(t, "admin", "admin123")

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for correct credentials, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["token"]; !ok {
		t.Error("Expected token in response")
	}
}

// BUG-002: GET /me exposes password in plain text.
func TestBUG002_ProfileExposesPassword(t *testing.T) {
	token := getToken(t, "admin", "admin123")
	if token == "" {
		t.Skip("Could not obtain token")
	}

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	setupRouter().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if _, hasPassword := resp["password"]; hasPassword {
		t.Errorf("BUG-002 CONFIRMED: GET /me response contains 'password' field: %v. "+
			"Sensitive data should never be returned in API responses.", resp["password"])
	}
}

// BUG-003: DELETE /books is accessible without authentication.
func TestBUG003_DeleteBooksNoAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/books?title=test&author=test", nil)
	w := httptest.NewRecorder()
	setupRouter().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("BUG-003 CONFIRMED: DELETE /books returned %d without auth token. "+
			"Expected 401 Unauthorized. The endpoint is not protected by JWT middleware.", w.Code)
	}
}

// BUG-004: JWT secret is hardcoded as "secret".
func TestBUG004_JWTSecretHardcoded(t *testing.T) {
	// Forge a token using the known hardcoded secret "secret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "admin",
		"role":     "admin",
		"exp":      time.Now().Add(1 * time.Hour).Unix(),
	})
	forgedTokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("Failed to forge token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+forgedTokenString)
	w := httptest.NewRecorder()
	setupRouter().ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("BUG-004 CONFIRMED: Forged JWT token signed with hardcoded secret 'secret' "+
			"was accepted (status %d). The JWT secret must not be hardcoded in source code.", w.Code)
	}
}

// BUG-005: Passwords stored in plain text.
func TestBUG005_PasswordsStoredPlainText(t *testing.T) {
	token := getToken(t, "admin", "admin123")
	if token == "" {
		t.Skip("Could not obtain token")
	}

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	setupRouter().ServeHTTP(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if pw, ok := resp["password"].(string); ok && pw == "admin123" {
		t.Errorf("BUG-005 CONFIRMED: Password returned as plain text 'admin123'. "+
			"Passwords must be hashed (e.g., bcrypt) before storage.")
	}
}

// BUG-006: Pagination offset calculation is wrong.
func TestBUG006_PaginationOffset(t *testing.T) {
	t.Log("BUG-006: GET /books pagination uses offset = page * limit instead of (page-1) * limit. " +
		"For page=1, limit=10, offset is 10 instead of 0, skipping all first-page results. " +
		"Additionally, when no genre filter is set, filteredBooks is nil and always returns empty.")
}

// Register a new user and verify response does not contain password.
func TestRegisterDoesNotLeakPassword(t *testing.T) {
	body, _ := json.Marshal(map[string]string{
		"username": "testuser_register",
		"password": "testpass123",
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	setupRouter().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("Expected 201, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if _, hasPassword := resp["password"]; hasPassword {
		t.Errorf("Register response contains 'password' field — sensitive data leaked.")
	}
}

// BUG-009: POST /books requires auth but createBook() in frontend doesn't send it.
// We verify the API side: POST /books without auth should return 401.
func TestBUG009_CreateBookRequiresAuth(t *testing.T) {
	body, _ := json.Marshal(map[string]interface{}{
		"title":  "Test Book",
		"author": "Test Author",
	})
	req := httptest.NewRequest(http.MethodPost, "/books", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	setupRouter().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("POST /books without auth returned %d, expected 401", w.Code)
	}
}
