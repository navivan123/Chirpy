module github.com/navivan123/Chirpy

go 1.22.5

require internal/database v1.0.0

require golang.org/x/crypto v0.26.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/lib/pq v1.10.9 // indirect
)

replace internal/database => ./internal/database
