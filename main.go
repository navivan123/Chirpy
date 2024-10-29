package main

import (
    "net/http"
    "log"
    "fmt"
    "internal/database"
    "github.com/joho/godotenv"
    "os"
    "database/sql"
    "sync/atomic"
)

import _ "github.com/lib/pq"

type apiConfig struct {
    fileserverHits atomic.Int32
    DB             *database.Queries
    Platform       string
    JwtSecret      string
    PolkaApiKey    string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	cfg.fileserverHits.Add(1)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
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

func main() {
    godotenv.Load(".env")
    jwtSecret := os.Getenv("JWT_SECRET")
    apikey    := os.Getenv("POLKA_API_KEY")
    
    dbURL     := os.Getenv("DB_URL")
    if dbURL == "" {
        log.Fatal("DB_URL must be set")
    }

    platform := os.Getenv("PLATFORM")
    if platform == "" {
        log.Fatal("PLATFORM must be set")
    }

    dbp, err := sql.Open("postgres", dbURL)
    if err != nil {
        log.Fatalf("Error opening database: %s", err)
    }

    dbQueries := database.New(dbp)
    
    const srcRoot = "."
    const srcPort = "8080"

    apiCfgPdb := apiConfig { fileserverHits: atomic.Int32{}, DB: dbQueries, JwtSecret: jwtSecret, PolkaApiKey: apikey, Platform: platform,}

    http.StripPrefix("/app", http.FileServer(http.Dir(srcRoot)))

    serveMux := http.NewServeMux()
    serveMux.Handle("GET /app/*", apiCfgPdb.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(srcRoot)))))

    serveMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })

    serveMux.HandleFunc("GET /admin/metrics", apiCfgPdb.handleMetrics)
    serveMux.HandleFunc("DELETE /api/chirps/{id}", apiCfgPdb.handleChirpDelete)
    serveMux.HandleFunc("POST /api/login", apiCfgPdb.handleLoginPost)
    serveMux.HandleFunc("POST /admin/reset", apiCfgPdb.handleReset)
    serveMux.HandleFunc("GET /api/chirps", apiCfgPdb.handleChirpsGet)
    serveMux.HandleFunc("GET /api/chirps/{id}", apiCfgPdb.handleChirpGet)
    serveMux.HandleFunc("POST /api/chirps", apiCfgPdb.handleChirpPost)
    serveMux.HandleFunc("POST /api/users", apiCfgPdb.handleUserPost)
    serveMux.HandleFunc("POST /api/revoke", apiCfgPdb.handleRevokePost)
    serveMux.HandleFunc("POST /api/refresh", apiCfgPdb.handleRefreshPost)
    serveMux.HandleFunc("PUT /api/users", apiCfgPdb.handleUserPut)
    serveMux.HandleFunc("POST /api/polka/webhooks", apiCfgPdb.handlePolkaWebhooks)

	httpServ := http.Server{
			Handler: serveMux, 
			Addr: ":" + srcPort,
		}

	log.Printf("Serving index.html on port %s\n", srcPort)
	log.Fatal(httpServ.ListenAndServe())
	// Start the server and check for errors
}
