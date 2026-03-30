# Bug Report — GoLedger QA Challenge

## How to Run Automated Tests

### API Tests (Go)

```bash
cd api
go test ./handlers/ -v -count=1
```

Tests confirm BUG-001 through BUG-005 and BUG-009 via the Go `testing` package with `httptest`.

### Web Tests (Vitest)

```bash
cd web
npm install
npx vitest run --reporter=verbose
```

Tests confirm BUG-009 through BUG-012 and BUG-016 by analyzing source code for known bug patterns.

---

---

## BUG-001 — Authentication bypass: password comparison only checks length

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-001 |
| **Title**          | Login accepts any password with the same length as the real password |
| **Component**      | API |
| **Endpoint / Page**| `POST /auth/login` |
| **Severity**       | Critical |
| **Description**    | The login handler compares only the **length** of the submitted password against the stored password (`len(req.Password) != len(user.Password)`). It never compares the actual content, so any string with the same number of characters is accepted as valid. |
| **Steps to Reproduce** | 1. Send `POST /auth/login` with `{"username":"admin","password":"xxxxxxxx"}` (8 characters, same length as `admin123`). 2. Observe a `200 OK` response with a valid JWT token. |
| **Expected Behaviour** | The server should reject the request with `401 Unauthorized` because the password content does not match. |
| **Actual Behaviour** | The server returns `200 OK` and issues a valid JWT token. |
| **Proposed Fix**   | Replace the length check on line 32 of `api/handlers/auth.go` with a constant-time comparison: |

```go
// Before (vulnerable):
if len(req.Password) != len(user.Password) {

// After (secure):
if subtle.ConstantTimeCompare([]byte(req.Password), []byte(user.Password)) != 1 {
```

---

## BUG-002 — GET /me endpoint leaks user password in plain text

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-002 |
| **Title**          | Profile endpoint returns the user's password in the JSON response |
| **Component**      | API |
| **Endpoint / Page**| `GET /me` |
| **Severity**       | Critical |
| **Description**    | The `GetProfile` handler serialises the entire `User` struct (which includes the `Password` field with tag `json:"password"`) directly into the response. Any authenticated user can see their own plaintext password. |
| **Steps to Reproduce** | 1. Login via `POST /auth/login` to obtain a JWT token. 2. Send `GET /me` with the `Authorization: Bearer <token>` header. 3. Observe the response contains `"password":"admin123"`. |
| **Expected Behaviour** | The response should never include the password field. |
| **Actual Behaviour** | Response: `{"id":1,"username":"admin","password":"admin123","role":"admin"}` |
| **Proposed Fix**   | Either add `json:"-"` to the Password field in the User model, or return a filtered response in the handler: |

```go
// Option A — hide from all JSON serialisation (api/models/user.go):
Password string `json:"-"`

// Option B — return only safe fields in the handler (api/handlers/auth.go line 83):
c.JSON(http.StatusOK, gin.H{
    "id":       user.ID,
    "username": user.Username,
    "role":     user.Role,
})
```

---

## BUG-003 — DELETE /books endpoint is not protected by authentication

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-003 |
| **Title**          | Anyone can delete books without a valid JWT token |
| **Component**      | API |
| **Endpoint / Page**| `DELETE /books` |
| **Severity**       | Critical |
| **Description**    | The `DELETE /books` route is registered outside the JWT-protected route group in `routes/routes.go` (line 47), so the `AuthRequired()` middleware is never applied. Any unauthenticated user can delete books from the blockchain. |
| **Steps to Reproduce** | 1. Without any Authorization header, send `DELETE /books?title=1984&author=George%20Orwell`. 2. Observe that the server processes the request instead of returning `401 Unauthorized`. |
| **Expected Behaviour** | The server should return `401 Unauthorized` for unauthenticated requests. |
| **Actual Behaviour** | The server processes the delete and returns `200 OK` (or `404` if the book doesn't exist), never asking for authentication. |
| **Proposed Fix**   | Move the route inside the authenticated group in `api/routes/routes.go`: |

```go
// Before (line 47, outside auth group):
r.DELETE("/books", handlers.DeleteBook)

// After (inside the api group with middleware):
api := r.Group("/")
api.Use(middleware.AuthRequired())
{
    api.DELETE("/books", handlers.DeleteBook)
    // ... other protected routes
}
```

---

## BUG-004 — Hardcoded JWT signing secret

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-004 |
| **Title**          | JWT tokens are signed with a hardcoded secret `"secret"` |
| **Component**      | API |
| **Endpoint / Page**| All authenticated endpoints |
| **Severity**       | Critical |
| **Description**    | The JWT signing key is hardcoded as the string `"secret"` in `api/config/config.go` (line 9). Anyone who reads the source code can forge valid JWT tokens for any user. |
| **Steps to Reproduce** | 1. Read the source code and note `const JWTSecret = "secret"`. 2. Use any JWT library to craft a token with `{"username":"admin","role":"admin"}` signed with `"secret"`. 3. Use the forged token to access protected endpoints. |
| **Expected Behaviour** | The JWT secret should be loaded from a secure environment variable and be cryptographically random. |
| **Actual Behaviour** | The secret is the literal string `"secret"`, publicly visible in the source code. |
| **Proposed Fix**   | Load the secret from an environment variable in `api/config/config.go`: |

```go
// Before:
const JWTSecret = "secret"

// After:
var JWTSecret = os.Getenv("JWT_SECRET")

func init() {
    if JWTSecret == "" {
        log.Fatal("JWT_SECRET environment variable is required")
    }
}
```

---

## BUG-005 — Passwords stored in plain text without hashing

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-005 |
| **Title**          | User passwords are stored in plain text in memory |
| **Component**      | API |
| **Endpoint / Page**| `POST /auth/register`, `POST /auth/login` |
| **Severity**       | Critical |
| **Description**    | The `User` model stores passwords as plain text strings. The `Register` handler saves the raw password, and the `Login` handler compares plain text. There is no hashing (bcrypt, argon2, etc.). Hardcoded users in `api/models/user.go` also have plaintext passwords (`admin123`, `pass123`). |
| **Steps to Reproduce** | 1. Read `api/models/user.go` lines 16-17 to see hardcoded credentials. 2. Register a user and observe the password is stored as-is. |
| **Expected Behaviour** | Passwords should be hashed with a strong algorithm (e.g., bcrypt) before storage. |
| **Actual Behaviour** | Passwords are stored and compared as plain text. |
| **Proposed Fix**   | Hash passwords with bcrypt during registration and compare hashes during login: |

```go
import "golang.org/x/crypto/bcrypt"

// Registration:
hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
user := models.AddUser(req.Username, string(hashed), "user")

// Login:
err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
if err != nil {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
    return
}
```

---

## BUG-006 — Pagination returns empty results (multiple logic errors)

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-006 |
| **Title**          | GetBooks pagination always returns an empty array |
| **Component**      | API |
| **Endpoint / Page**| `GET /books` |
| **Severity**       | High |
| **Description**    | The pagination logic in `api/handlers/books.go` (lines 86-95) has multiple bugs: **1)** When no `genre` filter is provided, `filteredBooks` remains `nil`/empty, so the length check on line 87 always evaluates to true and returns `[]`. **2)** The offset formula `page * limit` (line 86) is wrong — for page 1 with limit 5, it calculates offset 5 instead of 0. It should be `(page - 1) * limit`. **3)** The bounds check on line 92 uses `len(books)` instead of `len(filteredBooks)`. **4)** The slice on line 95 reads from the unfiltered `books` array instead of `filteredBooks`. |
| **Steps to Reproduce** | 1. Login and send `GET /books?author=George%20Orwell&page=1&limit=5`. 2. Observe empty array `[]` even though "1984" exists. |
| **Expected Behaviour** | Should return the list of books by George Orwell. |
| **Actual Behaviour** | Returns `[]` (empty array). |
| **Proposed Fix**   | Rewrite the pagination section in `api/handlers/books.go`: |

```go
// When no genre filter, use all books
if genre == "" {
    filteredBooks = make([]map[string]interface{}, len(books))
    for i, b := range books {
        filteredBooks[i] = b.(map[string]interface{})
    }
}

offset := (page - 1) * limit
if offset >= len(filteredBooks) {
    c.JSON(http.StatusOK, []map[string]interface{}{})
    return
}
end := offset + limit
if end > len(filteredBooks) {
    end = len(filteredBooks)
}
c.JSON(http.StatusOK, filteredBooks[offset:end])
```

---

## BUG-007 — UpdateBookTenant uses read-only query endpoint instead of invoke

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-007 |
| **Title**          | Assigning a tenant to a book calls the query endpoint instead of the invoke endpoint |
| **Component**      | API |
| **Endpoint / Page**| `PUT /books/tenant` |
| **Severity**       | High |
| **Description**    | The `UpdateBookTenant` handler in `api/handlers/books.go` (line 199) calls `ccapi.Query()` which sends the request to `/api/query/updateBookTenant`. Since this is a state-changing operation (writing to the blockchain), it should call `ccapi.Invoke()` which targets `/api/invoke/updateBookTenant`. The query endpoint is read-only and will not persist changes. |
| **Steps to Reproduce** | 1. Login and send `PUT /books/tenant` with a valid book and tenant CPF. 2. Observe the operation fails or does not persist. |
| **Expected Behaviour** | The request should go to the invoke endpoint and persist the tenant assignment. |
| **Actual Behaviour** | The request goes to the query endpoint, which cannot perform write operations. |
| **Proposed Fix**   | Change `ccapi.Query` to `ccapi.Invoke` in `api/handlers/books.go` line 199: |

```go
// Before:
result, status, err := ccapi.Query(config.GetCCAPIOrgURL(), "updateBookTenant", params)

// After:
result, status, err := ccapi.Invoke(config.GetCCAPIOrgURL(), http.MethodPut, "updateBookTenant", params)
```

---

## BUG-008 — CORS defaults to wildcard origin

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-008 |
| **Title**          | CORS allows all origins when `CORS_ORIGIN` env var is not set |
| **Component**      | API |
| **Endpoint / Page**| All endpoints |
| **Severity**       | Medium |
| **Description**    | In `api/config/config.go` (line 25), `GetCORSOrigin()` defaults to `"*"` when the `CORS_ORIGIN` environment variable is not set. Combined with `AllowCredentials: true` in the CORS config, this is a security vulnerability that allows any website to make authenticated requests to the API. |
| **Steps to Reproduce** | 1. Start the API without setting `CORS_ORIGIN`. 2. From any external domain, make a request to the API with credentials. |
| **Expected Behaviour** | CORS should default to a restrictive origin (e.g., `http://localhost:3000`) or refuse to start without explicit configuration. |
| **Actual Behaviour** | Any origin is allowed to make credentialed requests. |
| **Proposed Fix**   | Change the default to a safe value or require explicit configuration: |

```go
func GetCORSOrigin() string {
    if origin := os.Getenv("CORS_ORIGIN"); origin != "" {
        return origin
    }
    return "http://localhost:3000"  // safe default
}
```

---

## BUG-009 — createBook() missing Authorization header

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-009 |
| **Title**          | Frontend createBook() function does not send JWT token |
| **Component**      | Web |
| **Endpoint / Page**| Books page — Create New Book form |
| **Severity**       | Critical |
| **Description**    | In `web/src/api.ts` (lines 98-104), the `createBook()` function sends a `POST /books` request with only the `Content-Type` header. Unlike all other authenticated API calls, it does not include the `Authorization: Bearer <token>` header. Since the `POST /books` endpoint requires authentication, book creation always fails with `401 Unauthorized`. |
| **Steps to Reproduce** | 1. Login to the application. 2. Open "+ New Book" form. 3. Fill in title and author, click "Create Book". 4. Observe "An error occurred" error message. 5. In DevTools Network tab, see `401 Unauthorized` on `POST /books`. |
| **Expected Behaviour** | The request should include the Authorization header and create the book successfully. |
| **Actual Behaviour** | Returns `401 Unauthorized` — book is never created. |
| **Proposed Fix**   | Add the Authorization header in `web/src/api.ts` line 100: |

```typescript
// Before:
headers: {
  'Content-Type': 'application/json',
},

// After:
headers: {
  'Content-Type': 'application/json',
  Authorization: `Bearer ${getToken()}`,
},
```

---

## BUG-010 — Prev button always resets to page 1

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-010 |
| **Title**          | Pagination "Prev" button always navigates to page 1 instead of the previous page |
| **Component**      | Web |
| **Endpoint / Page**| Books page — Pagination controls |
| **Severity**       | High |
| **Description**    | In `web/src/pages/BooksPage.tsx` (line 89), `handlePrev()` hardcodes `const prev = 1` instead of calculating `page - 1`. This means clicking "Prev" from any page always jumps back to page 1. |
| **Steps to Reproduce** | 1. Search for an author with multiple pages of results. 2. Click "Next" several times to reach page 4. 3. Click "Prev". 4. Observe you are now on page 1, not page 3. |
| **Expected Behaviour** | Clicking "Prev" from page 4 should go to page 3. |
| **Actual Behaviour** | Clicking "Prev" always goes to page 1. |
| **Proposed Fix**   | Fix the calculation in `web/src/pages/BooksPage.tsx` line 89: |

```typescript
// Before:
const prev = 1;

// After:
const prev = Math.max(1, page - 1);
```

---

## BUG-011 — createPerson() treats HTTP 201 as an error

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-011 |
| **Title**          | Person creation always shows error even when it succeeds |
| **Component**      | Web |
| **Endpoint / Page**| Persons page — Register New Person form |
| **Severity**       | High |
| **Description**    | In `web/src/api.ts` (line 161), `createPerson()` checks `if (res.status !== 200)` to detect errors. However, the API handler returns `201 Created` on success. Since `201 !== 200`, the frontend throws an error even though the person was successfully created on the blockchain. Additionally, the API returns `null` as the response body (Content-Length: 4), so `body` is `null` and accessing `body.error` causes a JavaScript TypeError: "Cannot read properties of null (reading 'error')". |
| **Steps to Reproduce** | 1. Go to Persons page. 2. Fill in a valid CPF (e.g. `52998224725`), Name, and click "Register Person". 3. Observe error "Cannot read properties of null (reading 'error')" even though the API returned `201 Created`. 4. Attempting to register the same CPF again returns `409 Conflict`, proving the first request succeeded. |
| **Expected Behaviour** | Should show success message "Person created successfully!". |
| **Actual Behaviour** | Shows JavaScript TypeError. The person is created on the blockchain but the user sees an error. |
| **Proposed Fix**   | Use `res.ok` and handle null body in `web/src/api.ts` line 161: |

```typescript
// Before:
if (res.status !== 200) throw new Error(body.error ?? 'Failed to create person');

// After:
if (!res.ok) throw new Error(body?.error ?? 'Failed to create person');
```

---

## BUG-014 — CreatePerson API handler returns null body on success

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-014 |
| **Title**          | CreatePerson returns `null` instead of the created person object |
| **Component**      | API |
| **Endpoint / Page**| `POST /persons` |
| **Severity**       | Medium |
| **Description**    | In `api/handlers/persons.go` (line 56), `json.Unmarshal(result, &person)` fails silently because the error is ignored (`//nolint:errcheck`). The CCAPI response format likely wraps the result, so unmarshalling into a flat `map[string]interface{}` fails. The `person` variable remains `nil`, and `c.JSON(http.StatusCreated, nil)` returns `null` (Content-Length: 4) to the client. |
| **Steps to Reproduce** | 1. Send `POST /persons` with valid data. 2. Observe `201 Created` with body `null` instead of the person object. |
| **Expected Behaviour** | Should return the created person object as JSON. |
| **Actual Behaviour** | Returns `null`. |
| **Proposed Fix**   | Check the unmarshal error and handle the CCAPI response format properly: |

```go
// Before:
json.Unmarshal(result, &person) //nolint:errcheck
c.JSON(http.StatusCreated, person)

// After:
if err := json.Unmarshal(result, &person); err != nil {
    c.JSON(http.StatusCreated, json.RawMessage(result))
    return
}
c.JSON(http.StatusCreated, person)
```

---

## BUG-012 — App.tsx passes function reference instead of calling it for initial auth state

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-012 |
| **Title**          | Initial authentication state uses function reference instead of function result |
| **Component**      | Web |
| **Endpoint / Page**| App initialization (`App.tsx`) |
| **Severity**       | Medium |
| **Description**    | In `web/src/App.tsx` (line 12), `useState<boolean>(isTokenPresent)` passes the function `isTokenPresent` as a reference. React's `useState` accepts a function as a lazy initializer, so it does call it — but the intent is ambiguous and the TypeScript type annotation `<boolean>` conflicts with passing a function that returns boolean. This works accidentally but could break with stricter type checking or refactoring. Note: line 14 correctly calls `isTokenPresent()` with parentheses, showing inconsistency. |
| **Steps to Reproduce** | 1. Login and refresh the page. 2. The app may or may not correctly detect the existing token depending on runtime behavior. |
| **Expected Behaviour** | Should explicitly call `isTokenPresent()` for clarity and type safety. |
| **Actual Behaviour** | Works accidentally due to React's lazy initializer pattern, but is inconsistent with line 14. |
| **Proposed Fix**   | Call the function explicitly in `web/src/App.tsx` line 12: |

```typescript
// Before:
const [authenticated, setAuthenticated] = useState<boolean>(isTokenPresent);

// After:
const [authenticated, setAuthenticated] = useState<boolean>(isTokenPresent());
```

---

## BUG-013 — .env file not loaded when running API without Docker

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-013 |
| **Title**          | API does not load .env file, CCAPI connection fails without Docker |
| **Component**      | API |
| **Endpoint / Page**| All CCAPI-proxied endpoints (`/books`, `/persons`, `/libraries`) |
| **Severity**       | High |
| **Description**    | The `main.go` file does not use `godotenv` or any mechanism to load the `.env` file. When running the API without Docker (`go run .`), the environment variables `CCAPI_ORG_URL`, `CCAPI_AUTH_USERNAME`, and `CCAPI_AUTH_PASSWORD` are not set. The API defaults to `http://localhost:80` for the CCAPI URL, causing all blockchain requests to fail with `502 Bad Gateway`. Docker Compose injects the variables via `env_file`, masking this issue. |
| **Steps to Reproduce** | 1. Copy `api/.env.example` to `api/.env` and fill in credentials. 2. Run `cd api && go run .` 3. Login and try to fetch books. 4. Observe `502 Bad Gateway` errors. |
| **Expected Behaviour** | The API should load the `.env` file automatically or clearly document that environment variables must be exported manually. |
| **Actual Behaviour** | All CCAPI requests fail with "failed to reach chaincode API". |
| **Proposed Fix**   | Add `godotenv` to load the `.env` file in `main.go`: |

```go
import "github.com/joho/godotenv"

func main() {
    _ = godotenv.Load() // loads .env if present
    r := routes.SetupRouter()
    log.Println("QA Test API starting on :8080")
    if err := r.Run(":8080"); err != nil {
        log.Fatalf("failed to start server: %v", err)
    }
}
```

---

## BUG-015 — CreateLibrary sends wrong field name to CCAPI

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-015 |
| **Title**          | Library creation fails because the API sends `libraryName` instead of `name` |
| **Component**      | API |
| **Endpoint / Page**| `POST /libraries` |
| **Severity**       | Critical |
| **Description**    | In `api/handlers/libraries.go` (line 25), the handler builds the request payload with the field `"libraryName"`, but the CCAPI transaction `createNewLibrary` expects the field `"name"`. This causes all library creation requests to fail with `400 Bad Request: missing argument 'name'`. |
| **Steps to Reproduce** | 1. Login to the application. 2. Go to the Libraries page. 3. Enter a library name (e.g. "Teste da Silva") and click "Create Library". 4. Observe error: `{"error":"unable to get args: missing argument 'name'","status":400}`. |
| **Expected Behaviour** | The library should be created successfully on the blockchain. |
| **Actual Behaviour** | Always fails with `400 Bad Request` because the CCAPI cannot find the required `name` field. |
| **Proposed Fix**   | Change the field name in `api/handlers/libraries.go` line 25: |

```go
// Before:
params := map[string]interface{}{
    "libraryName": req.Name,
}

// After:
params := map[string]interface{}{
    "name": req.Name,
}
```

---

## BUG-016 — Logout does not remove token from localStorage

| Field              | Details |
|--------------------|---------|
| **ID**             | BUG-016 |
| **Title**          | Logging out does not clear the JWT token, refreshing the page restores the session |
| **Component**      | Web |
| **Endpoint / Page**| All pages — Logout button |
| **Severity**       | High |
| **Description**    | In `web/src/App.tsx` (lines 23-26), the `handleLogout` callback sets `authenticated` to `false` and navigates to the login page, but it never calls `removeToken()` to clear the JWT from `localStorage`. When the user refreshes the page, `isTokenPresent` finds the old token and re-authenticates the user automatically. The `removeToken()` function exists in `api.ts` (line 13) but is never invoked during logout. |
| **Steps to Reproduce** | 1. Login to the application. 2. Click "Logout". 3. Observe you are on the login page. 4. Refresh the browser (F5). 5. Observe you are logged in again without entering credentials. |
| **Expected Behaviour** | After logout, the token should be removed. Refreshing should show the login page. |
| **Actual Behaviour** | The token persists in localStorage, and refreshing restores the authenticated session. |
| **Proposed Fix**   | Call `removeToken()` in the logout handler in `web/src/App.tsx`: |

```typescript
// Before:
const handleLogout = useCallback(() => {
    setAuthenticated(false);
    setCurrentPage('login');
}, []);

// After:
const handleLogout = useCallback(() => {
    removeToken();
    setAuthenticated(false);
    setCurrentPage('login');
}, []);
```
