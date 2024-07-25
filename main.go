package main

import (
	"net/http"
	"log"
	"fmt"
)

type apiConfig struct {
	fileserverHits int
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

func main() {
	const srcRoot = "."
	const srcPort = "8080"

	apiCfg := apiConfig{}

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

	httpServ := http.Server{
			Handler: serveMux, 
			Addr: ":" + srcPort,
		}

	log.Printf("Serving index.html on port %s\n", srcPort)
	log.Fatal(httpServ.ListenAndServe())
	// Start the server and check for errors
}
