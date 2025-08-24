package Utils

import (
	"database/sql"
	"log"

	"github.com/fatih/color"
	_ "github.com/lib/pq"
)

var db *sql.DB

func GetDB() *sql.DB {
	if db == nil {
		log.Fatal("Database connection is not initialized. Call DBInitialization first.")
	}
	return db
}

func DBInitialization() {
	var err error
	db, err = sql.Open("postgres", "user=postgres dbname=ProjectLauncher password=123 sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}

	color.Yellow("Database connected")
}

func DBClose() {
	if db != nil {
		err := db.Close()
		if err != nil {
			log.Printf("Failed to close database connection: %v", err)
		} else {
			log.Panicln("Database connection closed")
		}
	}
}

