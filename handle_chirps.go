package main

import (
        "net/http"
        "encoding/json"
	"strings"
        "sort"
        "strconv"
        //"fmt"
)

type Chirp struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

type User struct {
        ID    int    `json:"id"`
        Email string `json:"email"`
}

func (cfg *apiConfig) handleChirpGet(w http.ResponseWriter, r *http.Request) {
        dbChirps, err := cfg.DB.GetChirps()
        if err != nil {
	        handleChirpError(w, http.StatusInternalServerError, "Error while fetching Chirps from DB")
                return
        }
        id, err := strconv.Atoi(r.PathValue("id"))
        if err != nil {
	        handleChirpError(w, http.StatusInternalServerError, "Error while converting id to string")
                return
        }
        chirp := Chirp{}
	for _, dbChirp := range dbChirps {
	        if dbChirp.ID == id {
                        chirp = Chirp{ ID: dbChirp.ID, Body: dbChirp.Body,}
                        break
                }
        }
        if chirp == (Chirp{}) {
                handleChirpError(w, http.StatusNotFound, "Error: Chirp id not found!")
                return
        }

        handleChirpJSON(w, http.StatusOK, chirp)
}

func (cfg *apiConfig) handleChirpsGet(w http.ResponseWriter, r *http.Request) {
        dbChirps, err := cfg.DB.GetChirps()
        if err != nil {
	        handleChirpError(w, http.StatusInternalServerError, "Error while fetching Chirps from DB")
                return
        }
        
        chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, Chirp{
			ID:   dbChirp.ID,
			Body: dbChirp.Body,
		})
	}

	sort.Slice(chirps, func(i, j int) bool {
		return chirps[i].ID < chirps[j].ID
	})

        handleChirpJSON(w, http.StatusOK, chirps)
}

func filterChirp(msg string) string {
	words   := strings.Split(msg, " ")

	for i, word := range(words) {
		if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
			words[i] = "****"
		}
	}

	return strings.Join(words, " ")
}

func (cfg *apiConfig) handleChirpPost(w http.ResponseWriter, r *http.Request) {
    
	type parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
	    handleChirpError(w, http.StatusInternalServerError, "Couldn't decode Chirp paramters")
	    return
	}
	
	if len(params.Body) > 140 {
	    handleChirpError(w, http.StatusBadRequest, "Chirp is too long")
	    return
	}

        chirp, err := cfg.DB.CreateChirp(filterChirp(params.Body))
        if err != nil {
	    handleChirpError(w, http.StatusInternalServerError, "Couldn't create Chirp on DB")
            return    
        }

        handleChirpJSON(w, http.StatusCreated, Chirp{ ID: chirp.ID, Body: chirp.Body })
}

func (cfg *apiConfig) handleUserPost(w http.ResponseWriter, r *http.Request) {
    
	type parameters struct {
		Email string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
	    handleChirpError(w, http.StatusInternalServerError, "Couldn't decode User paramters")
	    return
	}
	
        user, err := cfg.DB.CreateUser(params.Email)
        if err != nil {
	    handleChirpError(w, http.StatusInternalServerError, "Couldn't create User on DB")
            return    
        }

        handleChirpJSON(w, http.StatusCreated, User{ ID: user.ID, Email: user.Email })
}




func handleChirpError(w http.ResponseWriter, code int, msg string) {
    type errVals struct {
         Err string `json:"error"`
    }
    
    handleChirpJSON(w, code, errVals{ Err: msg })
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
