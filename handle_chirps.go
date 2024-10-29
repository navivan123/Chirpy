package main

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
    "internal/database"
    "net/http"
    "strings"
    "time"
    "github.com/google/uuid"
    "slices"
)

type Chirp struct {
    ID        uuid.UUID `json:"id"`
    Body      string    `json:"body"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    UserID    uuid.UUID `json:"user_id"`
    // AuthID int    `json:"author_id"`
}

type User struct {
    ID           uuid.UUID `json:"id"`
    Email        string    `json:"email"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
    IsRed        bool      `json:"is_chirpy_red"`
    Token        string    `json:"token,omitempty"`
    RefreshToken string    `json:"refresh_token,omitempty"`
}

func (cfg *apiConfig) handleChirpGet(w http.ResponseWriter, r *http.Request) {

    id, err := uuid.Parse(r.PathValue("id"))
    if err != nil {
        handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while converting id string to uuid: %v", err))
        return
    }

    dbChirp, err := cfg.DB.GetChirp(r.Context(), id)
    if err != nil {
        handleChirpError(w, http.StatusNotFound, fmt.Sprintf("Error while fetching Chirps from DB: %v", err))
        return
    }

    handleChirpJSON(w, http.StatusOK, dbChirp)
}

func (cfg *apiConfig) handleChirpsGet(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := cfg.DB.GetChirps(r.Context())
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while fetching Chirps from DB: %v", err))
		return
	}

    if r.URL.Query().Get("sort") == "desc" {
        slices.Reverse(dbChirps)
    }
    handleChirpJSON(w, http.StatusOK, dbChirps)
}

func filterChirp(msg string) string {
	words := strings.Split(msg, " ")

	for i, word := range words {
		if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
			words[i] = "****"
		}
	}

	return strings.Join(words, " ")
}

func (cfg *apiConfig) handleChirpPost(w http.ResponseWriter, r *http.Request) {
	jwtSigned := r.Header.Get("Authorization")

	if len(jwtSigned) < 8 || jwtSigned[0:7] != "Bearer " {
		handleChirpError(w, http.StatusUnauthorized, "Error - Incorrect Authorization Type")
		return
	}
	jwtSigned = jwtSigned[7:]

	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(jwtSigned, &claimsStruct, func(token *jwt.Token) (interface{}, error) { return []byte(cfg.JwtSecret), nil })
	if err != nil {
		handleChirpError(w, http.StatusUnauthorized, fmt.Sprintf("Error - Problem Verifying Token!: %v", err))
		return
	}

	id, err := token.Claims.GetSubject()
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while getting id: %v", err))
		return
	}

    userid, err := uuid.Parse(id)
    if err != nil {
        handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while getting id: %v", err))
        return
    }

    type parameters struct {
        Body   string    `json:"body"`
    }
    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err = decoder.Decode(&params)
    if err != nil {
        handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode Chirp paramters: %v", err))
        return
    }

    if len(params.Body) > 140 {
        handleChirpError(w, http.StatusBadRequest, "Chirp is too long")
        return
    }

    chirp, err := cfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{ Body: filterChirp(params.Body), UserID: userid }) // filterChirp(params.Body) //authID)
    if err != nil {
        handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't create Chirp on DB: %v", err))
        return
    }

    handleChirpJSON(w, http.StatusCreated, Chirp{ID: chirp.ID, Body: chirp.Body, CreatedAt: chirp.CreatedAt, UpdatedAt: chirp.UpdatedAt, UserID: chirp.UserID}) // AuthID: authID})
}

func (cfg *apiConfig) handleChirpDelete(w http.ResponseWriter, r *http.Request) {
	jwtSigned := r.Header.Get("Authorization")

	if len(jwtSigned) < 8 || jwtSigned[0:7] != "Bearer " {
		handleChirpError(w, http.StatusUnauthorized, "Error - Incorrect Authorization Type")
		return
	}
	jwtSigned = jwtSigned[7:]

	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(jwtSigned, &claimsStruct, func(token *jwt.Token) (interface{}, error) { return []byte(cfg.JwtSecret), nil })
	if err != nil {
		handleChirpError(w, http.StatusUnauthorized, fmt.Sprintf("Error - Problem Verifying Token!: %v", err))
		return
	}

	chirpID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while converting id string to uuid: %v", err))
		return
	}

	ids, err := token.Claims.GetSubject()
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while getting id: %v", err))
		return
	}
	authID, err := uuid.Parse(ids)
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while converting id string to uuid: %v", err))
		return
	}

    chirp, err := cfg.DB.GetChirp(r.Context(), chirpID)
    if err != nil {
        handleChirpError(w, http.StatusNotFound, fmt.Sprintf("Error, could not find chirp with that id: %v", err))
        return
    }

    if chirp.UserID != authID {
        handleChirpError(w, http.StatusForbidden, fmt.Sprintf("Error - You are not the author of the chirp!  What are you doing?!: %v", err))
        return
    }

    err = cfg.DB.DeleteChirp(r.Context(), chirpID)

    if err != nil {
        handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while getting Chirp: %v", err))
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handleUserPost(w http.ResponseWriter, r *http.Request) {

	type parameters struct {
		Email string `json:"email"`
		Pass  string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode User paramters: %v", err))
		return
	}

	if params.Pass == "" || params.Email == "" {
		handleChirpError(w, http.StatusInternalServerError, "Error: Please provide username and password!")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(params.Pass), bcrypt.DefaultCost)
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error - Could not Add User to DB: %v", err))
		return
	}

    user, err := cfg.DB.CreateUser(r.Context(), database.CreateUserParams{Email: params.Email, HashedPassword: string(hashed)} ) //, string(hashed))
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't create User on DB: %v", err))
		return
	}

    handleChirpJSON(w, http.StatusCreated, User{ID: user.ID, Email: user.Email, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, IsRed: user.IsChirpyRed})
}

func (cfg *apiConfig) handleReset(w http.ResponseWriter, r *http.Request) {
    if cfg.Platform != "dev" {
        w.WriteHeader(http.StatusForbidden)
        w.Write([]byte("Reset is only allowed in dev environment."))
        return
    }
    cfg.fileserverHits.Store(0)
    cfg.DB.DeleteUsers(r.Context())
    cfg.DB.DeleteChirps(r.Context())
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Hits reset to 0 and database reset to initial state."))
}

func (cfg *apiConfig) handleLoginPost(w http.ResponseWriter, r *http.Request) {

    type parameters struct {
        Email string `json:"email"`
        Pass  string `json:"password"`
        //Exp   int    `json:"expires_in_seconds,omitempty"`
    }

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode User paramters: %v", err))
		return
	}

	dbUser, err := cfg.DB.GetUser(r.Context(), params.Email)
	if err != nil {
		handleChirpError(w, http.StatusNotFound, fmt.Sprintf("Error while fetching Users from DB: %v", err))
		return
	}

    currentTime := time.Now().UTC()
    t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Issuer: "chirpy",
        IssuedAt:  &jwt.NumericDate{currentTime},
        ExpiresAt: &jwt.NumericDate{currentTime.Add(1 * time.Hour)}, //time.Duration(params.Exp) * time.Second)},
        Subject:   dbUser.ID.String()})
    jwtSigned, err := t.SignedString([]byte(cfg.JwtSecret))
    if err != nil {
        handleChirpError(w, http.StatusUnauthorized, fmt.Sprintf("Error - Issue Creating new JWT!  You shall not pass!: %v", err))
        return
    }

    err = bcrypt.CompareHashAndPassword([]byte(dbUser.HashedPassword), []byte(params.Pass))
    if err != nil {
        handleChirpError(w, http.StatusUnauthorized, fmt.Sprintf("Error - Password does not match!: %v", err))
        return
    }

	refreshToken := make([]byte, 32)
    _, err = rand.Read(refreshToken)
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error - Issue generating refresh token!: %v", err))
		return
	}
    rTokenStr := hex.EncodeToString(refreshToken)

    _, err = cfg.DB.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{ UserID: dbUser.ID, Token: rTokenStr, ExpiresAt: currentTime.Add(24 * time.Hour) })
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error - Issue generating refresh token!: %v", err))
		return
	}

    handleChirpJSON(w, http.StatusOK, User{ ID: dbUser.ID,              Email: dbUser.Email, CreatedAt:    dbUser.CreatedAt, UpdatedAt: dbUser.UpdatedAt, 
                                            IsRed: dbUser.IsChirpyRed,  Token: jwtSigned,    RefreshToken: rTokenStr, })
}

func (cfg *apiConfig) handleUserPut(w http.ResponseWriter, r *http.Request) {
	jwtSigned := r.Header.Get("Authorization")

	if len(jwtSigned) < 8 || jwtSigned[0:7] != "Bearer " {
		handleChirpError(w, http.StatusUnauthorized, "Error - Incorrect Authorization Type")
		return
	}
	jwtSigned = jwtSigned[7:]

	claimsStruct := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(jwtSigned, &claimsStruct, func(token *jwt.Token) (interface{}, error) { return []byte(cfg.JwtSecret), nil })
	if err != nil {
		handleChirpError(w, http.StatusUnauthorized, fmt.Sprintf("Error - Problem Verifying Token!: %v", err))
		return
	}

	ids, err := token.Claims.GetSubject()
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while getting id: %v", err))
		return
	}
	id, err := uuid.Parse(ids)
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error while converting id string to uuid: %v", err))
		return
	}

	type parameters struct {
		Email string `json:"email"`
		Pass  string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode User paramters: %v", err))
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(params.Pass), bcrypt.DefaultCost)
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error - Could not Modify User: %v", err))
		return
	}

    _, err = cfg.DB.PutUser(r.Context(), database.PutUserParams{ ID: id, Email: params.Email, HashedPassword: string(hashed) })
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error - Could not Modify User: %v", err))
		return
	}

	handleChirpJSON(w, http.StatusOK, User{ID: id, Email: params.Email})
}

func (cfg *apiConfig) handleRefreshPost(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Token string `json:"token"`
	}

	rToken := r.Header.Get("Authorization")

	if len(rToken) < 8 || rToken[0:7] != "Bearer " {
		handleChirpError(w, http.StatusUnauthorized, "Error - Incorrect Authorization Type")
		return
	}
	rToken = rToken[7:]

    user, err := cfg.DB.GetUserFromRefreshToken(r.Context(), rToken)

    if err != nil {
        handleChirpError(w, http.StatusUnauthorized, fmt.Sprintf("Error while getting User - : %v", err))
        return
    }

	currentTime := time.Now().UTC()
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Issuer: "chirpy",
		IssuedAt:  &jwt.NumericDate{currentTime},
		ExpiresAt: &jwt.NumericDate{currentTime.Add(1 * time.Hour)},
		Subject:   user.ID.String()})
	jwtSigned, err := t.SignedString([]byte(cfg.JwtSecret))
	if err != nil {
		handleChirpError(w, http.StatusUnauthorized, fmt.Sprintf("Error - Issue Creating new JWT!  You shall not pass!: %v", err))
		return
	}

	handleChirpJSON(w, http.StatusOK, response{Token: jwtSigned})

}

func (cfg *apiConfig) handleRevokePost(w http.ResponseWriter, r *http.Request) {
	rToken := r.Header.Get("Authorization")

	if len(rToken) < 8 || rToken[0:7] != "Bearer " {
		handleChirpError(w, http.StatusUnauthorized, "Error - Incorrect Authorization Type")
		return
	}
	rToken = rToken[7:]

	_, err := cfg.DB.RevokeRefreshToken(r.Context(), rToken)
	if err != nil {
		handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Error - Could not Revoke Token: %v", err))
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) handlePolkaWebhooks(w http.ResponseWriter, r *http.Request) {

    rApiKey := r.Header.Get("Authorization")

    if len(rApiKey) < 8 || rApiKey[0:7] != "ApiKey " {
        handleChirpError(w, http.StatusUnauthorized, "Error - Incorrect Authorization Type")
        return
    }
    rApiKey = rApiKey[7:]
    if rApiKey != cfg.PolkaApiKey {
        fmt.Printf("Request API key: %v | Config Api Key %v", rApiKey, cfg.PolkaApiKey)
        handleChirpError(w, http.StatusUnauthorized, "Error - Incorrect Authorization Type")
        return
    }

    type responseData struct {
        UserID string `json:"user_id"`
    }
    type parameters struct {
        Event string       `json:"event"`
        Data  responseData `json:"data"`
    }
    
    decoder := json.NewDecoder(r.Body)
    params := parameters{}
    err := decoder.Decode(&params)
    if err != nil {
        handleChirpError(w, http.StatusInternalServerError, fmt.Sprintf("Couldn't decode User paramters: %v", err))
        return
    }

    if params.Event != "user.upgraded" {
        w.WriteHeader(http.StatusNoContent)
        return
    }
    uid, err := uuid.Parse(params.Data.UserID)
    if err != nil {
        handleChirpError(w, http.StatusNotFound, "User not found!")
        return
    }

    _, err = cfg.DB.UpgradeUser(r.Context(), uid)
    if err != nil {
        handleChirpError(w, http.StatusNotFound, "User not found!")
        return
    }

    w.WriteHeader(http.StatusNoContent)
    return
}

// Write JSON and error JSON to Response Payload

func handleChirpError(w http.ResponseWriter, code int, msg string) {
	type errVals struct {
		Err string `json:"error"`
	}

	handleChirpJSON(w, code, errVals{Err: msg})
}

func handleChirpJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(payload)

	if err != nil {
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(code)
	w.Write(dat)
}
