package main

import (
        "net/http"
        "encoding/json"
	"errors"
	"strings"
        "sort"
)

type Chirp struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
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

func (cfg *apiConfig) handleChirpPost(w http.ResponseWriter, r *http.Request){
    
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
	    handleChirpError(w, http.StatusInternalServerError, "Couldn't decode Chirp paramters")
            return    
        }

        handleChirpJSON(w, http.StatusOK, Chirp{ ID: chirp.ID, Body: chirp.Body })
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
