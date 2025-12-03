package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"
)

//go:embed assets/*
var assets embed.FS

// Card represents a single card in the memory game
type Card struct {
	ID       int    `json:"id"`
	Emoji    string `json:"emoji"`
	Flipped  bool   `json:"flipped"`
	Matched  bool   `json:"matched"`
}

// GameState represents the current state of the game
type GameState struct {
	Cards     []Card `json:"cards"`
	Flipped   []int  `json:"flipped"`
	Moves     int    `json:"moves"`
	GameOver  bool   `json:"gameOver"`
}

var (
	emojis = []string{"🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼"}
	game   *GameState
)

func main() {
	// Initialize random seed
	rand.Seed(time.Now().UnixNano())

	// Initialize game
	resetGame()

	addr := ":8080"
	if v := os.Getenv("PORT"); v != "" {
		addr = ":" + v
	}

	tmpl, err := template.ParseFS(assets, "assets/index.html")
	if err != nil {
		log.Fatalf("parsing template: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		if err := tmpl.Execute(w, nil); err != nil {
			log.Printf("template execute: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	})

	// API endpoints
	http.HandleFunc("/api/game", handleGameState)
	http.HandleFunc("/api/flip/", handleFlipCard)
	http.HandleFunc("/api/reset", handleResetGame)

	// Static files
	fs := http.FileServer(http.FS(assets))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	log.Printf("Starting server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func resetGame() {
	// Create pairs of cards with emojis
	var cards []Card
	id := 0
	for _, emoji := range emojis {
		// Add two cards with the same emoji
		cards = append(cards, Card{ID: id, Emoji: emoji})
		cards = append(cards, Card{ID: id + 1, Emoji: emoji})
		id += 2
	}

	// Shuffle the cards
	rand.Shuffle(len(cards), func(i, j int) {
		cards[i], cards[j] = cards[j], cards[i]
	})

	// Initialize game state
	game = &GameState{
		Cards:    cards,
		Flipped:  make([]int, 0, 2),
		Moves:    0,
		GameOver: false,
	}
}

func handleGameState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(game)
}

func handleFlipCard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get card ID from URL
	idStr := r.URL.Path[len("/api/flip/"):]
	cardID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid card ID", http.StatusBadRequest)
		return
	}

	// Find the card
	var card *Card
	for i := range game.Cards {
		if game.Cards[i].ID == cardID {
			card = &game.Cards[i]
			break
		}
	}

	if card == nil || card.Matched || card.Flipped || len(game.Flipped) >= 2 {
		http.Error(w, "Invalid move", http.StatusBadRequest)
		return
	}

	// Flip the card
	card.Flipped = true
	game.Flipped = append(game.Flipped, cardID)

	// Check for a match if two cards are flipped
	if len(game.Flipped) == 2 {
		game.Moves++
		var flippedCards [2]*Card
		for i, id := range game.Flipped {
			for j := range game.Cards {
				if game.Cards[j].ID == id {
					flippedCards[i] = &game.Cards[j]
					break
				}
			}
		}

		if flippedCards[0].Emoji == flippedCards[1].Emoji {
			// Match found
			for i := range game.Cards {
				for _, id := range game.Flipped {
					if game.Cards[i].ID == id {
						game.Cards[i].Matched = true
					}
				}
			}

			// Check if game is over
			gameOver := true
			for _, card := range game.Cards {
				if !card.Matched {
					gameOver = false
					break
				}
			}
			game.GameOver = gameOver
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(game)
}

func handleResetGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resetGame()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(game)
}

// Helper function to send JSON response
func sendJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON: %v", err)
	}
}
