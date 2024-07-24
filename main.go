package main

import (
	"net/http"
	"log"
)

func main() {
	const srcRoot = "."
	const srcPort = "8080"

	serveMux := http.NewServeMux()
	serveMux.Handle("/", http.FileServer(http.Dir(srcRoot)))
	httpServ := http.Server{
		Handler: serveMux, 
		Addr: ":" + srcPort,
	}

	log.Printf("Serving index.html on port %s\n", srcPort)
	log.Fatal(httpServ.ListenAndServe())
	// Start the server and check for errors
}
