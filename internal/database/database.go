package database

import (
        "os"
        "errors"
        "sync"
        "encoding/json"
        //"fmt"
)

type DB struct {
	path string
	mu  *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
        Users map[int]User `json:"users"`
}

type Chirp struct {
        ID   int    `json:"id"`
        Body string `json:"body"`
}

type User struct {
        ID    int    `json:"id"`
        Email string `json:"email"`
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
        db := &DB{path: path, mu: &sync.RWMutex{},}
        err := db.ensureDB()
        return db, err
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string) (Chirp, error) {
        dbStructure, err := db.loadDB()
        if err != nil {
                return Chirp{}, err
        }

        id := len(dbStructure.Chirps) + 1
        chirp := Chirp{ ID: id, Body: body }

        dbStructure.Chirps[id] = chirp

        err = db.writeDB(dbStructure)
        if err != nil {
                return Chirp{}, err
        }

        return chirp, nil

}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateUser(email string) (User, error) {
        dbStructure, err := db.loadDB()
        if err != nil {
                return User{}, err
        }

        id := len(dbStructure.Users) + 1
        user := User{ ID: id, Email: email }

        dbStructure.Users[id] = user

        err = db.writeDB(dbStructure)
        if err != nil {
                return User{}, err
        }

        return user, nil

}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
        dbStructure, err := db.loadDB()
        if err != nil {
                return nil, err
        }

        chirps := make([]Chirp, 0, len(dbStructure.Chirps))
        for _, chirp := range dbStructure.Chirps {
                chirps = append(chirps, chirp)
        }


        return chirps, nil
}

func (db *DB) createDB() error {
        dbStructure := DBStructure{ Chirps: map[int]Chirp{}, Users: map[int]User{}}
        return db.writeDB(dbStructure)
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
        _, err := os.ReadFile(db.path)
        if errors.Is(err, os.ErrNotExist) {
                return db.createDB()
        }
        return err
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
        db.mu.RLock()
        defer db.mu.RUnlock()

        dbStructure := DBStructure{}

        data, err := os.ReadFile(db.path)
        if errors.Is(err, os.ErrNotExist) {
                return dbStructure, err
        }

        err = json.Unmarshal(data, &dbStructure)
        if err != nil {
                return dbStructure, err
        }

        return dbStructure, nil
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
        db.mu.Lock()
        defer db.mu.Unlock()

        data, err := json.Marshal(dbStructure)
        if err != nil {
                return err
        }

        err = os.WriteFile(db.path, data, 0600)
        if err != nil {
                return err
        }
        return nil
}
