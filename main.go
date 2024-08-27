package main

import (
	"net/http"
	"log"
	"fmt"
	"encoding/json"
	"strings"
        "github.com/navivan123/Chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits int
        DB             *database.DB
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	cfg.fileserverHits += 1
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, req)
	})
}

func (cfg *apiConfig) handleMetrics(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	//w.WriteHeader(http.StatusOK)
	//w.Write([]byte("OK"))
	w.Write([]byte(fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits)))
	//fmt.Fprintf(w, "Hits: %d", cfg.fileserverHits)
}

func (cfg *apiConfig) handleResets(w http.ResponseWriter, req *http.Request) {
	cfg.fileserverHits = 0
	w.WriteHeader(http.StatusOK)
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

func handleChirp(w http.ResponseWriter, r *http.Request){
    
	type parameters struct {
		Body string `json:"body"`
	}
    	type returnVals struct {
	    id int `json:id`
	    Cleaned string `json:"body"`
    	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
	    handleChirpError(w, http.StatusInternalServerError, "Something went wrong")
	    return
	}
	
	if len(params.Body) > 140 {
	    handleChirpError(w, http.StatusBadRequest, "Chirp is too long")
	    return
	}

        response := { id: id, Cleaned: filterChirp(params.Body) }
        id++

        handleChirpJSON(w, http.StatusOK, response)
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


func main() {
	const srcRoot = "."
	const srcPort = "8080"

        db, err := database.NewDB("database.json")
        if err != nil {
                log.Fatal(err)
        }

        apiCfg := apiConfig{ fileserverHits: 0, DB: db,}

	http.StripPrefix("/app", http.FileServer(http.Dir(srcRoot)))

	serveMux := http.NewServeMux()
	serveMux.Handle("GET /app/*", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(srcRoot)))))
	serveMux.HandleFunc("GET /api/reset", apiCfg.handleResets)
	serveMux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)

	

	serveMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))

	})

	serveMux.HandleFunc("POST /api/chirps", apiCfg.handleChirpPost)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.handleChirpsGet)

	httpServ := http.Server{
			Handler: serveMux, 
			Addr: ":" + srcPort,
		}

	log.Printf("Serving index.html on port %s\n", srcPort)
	log.Fatal(httpServ.ListenAndServe())
	// Start the server and check for errors
}
