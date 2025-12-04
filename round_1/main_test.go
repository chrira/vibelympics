package main

import (
	"testing"
)

func TestResetGame(t *testing.T) {
	// Save original emojis and restore them after the test
	originalEmojis := make([]string, len(emojis))
	copy(originalEmojis, emojis)
	defer func() {
		emojis = originalEmojis
	}()

	// Test with a fixed set of emojis for consistent testing
	testEmojis := []string{"🏡", "🐮", "🐭", "🏔️", "🐰", "🧀", "⏰", "🍫"}
	emojis = testEmojis

	// Call the function we're testing
	resetGame()

	// Check that we have exactly 2 cards per emoji
	expectedCardCount := len(testEmojis) * 2
	if len(game.Cards) != expectedCardCount {
		t.Fatalf("Expected %d cards, got %d", expectedCardCount, len(game.Cards))
	}

	// Count occurrences of each emoji
	emojiCounts := make(map[string]int)
	for _, card := range game.Cards {
		emojiCounts[card.Emoji]++
	}

	// Verify each emoji appears exactly twice
	for _, emoji := range testEmojis {
		count, exists := emojiCounts[emoji]
		if !exists {
			t.Errorf("Emoji %s not found in the cards", emoji)
		} else if count != 2 {
			t.Errorf("Expected emoji %s to appear exactly 2 times, got %d", emoji, count)
		}
	}

	// Verify no unexpected emojis are present
	for emoji, count := range emojiCounts {
		found := false
		for _, testEmoji := range testEmojis {
			if emoji == testEmoji {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Unexpected emoji found in cards: %s (appears %d times)", emoji, count)
		}
	}

	// Verify game state is properly initialized
	if game.Moves != 0 {
		t.Errorf("Expected moves to be 0, got %d", game.Moves)
	}
	if game.GameOver {
		t.Error("Expected game to not be over after reset")
	}
	if len(game.Flipped) != 0 {
		t.Errorf("Expected no flipped cards, got %d", len(game.Flipped))
	}
}

func TestResetGameWithNoEmojis(t *testing.T) {
	// Save original emojis and restore them after the test
	originalEmojis := make([]string, len(emojis))
	copy(originalEmojis, emojis)
	defer func() {
		emojis = originalEmojis
	}()

	// Test with no emojis
	emojis = []string{}

	// Call the function we're testing
	resetGame()

	// Verify no cards were created
	if len(game.Cards) != 0 {
		t.Errorf("Expected 0 cards with no emojis, got %d", len(game.Cards))
	}
}
