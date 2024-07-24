package main

import (
	"net/http"
	"log"
)

func main() {
	serveMux := http.NewServeMux()
	httpServ := http.Server{Handler: serveMux, Addr: "localhost:8080"}
	
	// Start the server and check for errors
    	if err := httpServ.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        	log.Fatalf("ListenAndServe failed: %v", err)
    	}
}
