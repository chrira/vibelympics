package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"
)

//go:embed assets/*
var assets embed.FS

func main() {
	addr := ":8080"
	if v := os.Getenv("PORT"); v != "" {
		addr = ":" + v
	}

	tmpl, err := template.ParseFS(assets, "assets/index.html")
	if err != nil {
		log.Fatalf("parsing template: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			Time string
		}{Time: time.Now().Format(time.RFC1123)}
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("template execute: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	})

	// Static files (CSS / JS) if present
	fs := http.FS(assets)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(fs)))

	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
