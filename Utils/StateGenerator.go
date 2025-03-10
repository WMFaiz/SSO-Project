package Utils

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type StateEntry struct {
	State     string
	UserID    string
	ExpiresAt time.Time
}

var stateStore = struct {
	mu     sync.Mutex
	states map[string]StateEntry
}{
	states: make(map[string]StateEntry),
}

func GenerateState(userID string) string {

	stateStore.mu.Lock()
	defer stateStore.mu.Unlock()

	if entry, exists := stateStore.states[userID]; exists {
		if time.Now().Before(entry.ExpiresAt) {
			stateStore.states[userID] = StateEntry{
				State:     entry.State,
				UserID:    userID,
				ExpiresAt: time.Now().Add(10 * time.Minute),
			}
			return entry.State
		}
		delete(stateStore.states, userID)
	}

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	state := base64.URLEncoding.EncodeToString(b)

	stateStore.mu.Lock()
	defer stateStore.mu.Unlock()
	stateStore.states[state] = StateEntry{
		State:     state,
		UserID:    userID,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	return state
}

func OriginalGenerateState() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	state := base64.URLEncoding.EncodeToString(b)
	return state
}

func ValidateState(userID string) bool {
	stateStore.mu.Lock()
	defer stateStore.mu.Unlock()

	entry, exists := stateStore.states[userID]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return false
	}

	delete(stateStore.states, userID)
	return true
}

func GetState(userID string) string {
	stateStore.mu.Lock()
	defer stateStore.mu.Unlock()

	entry, exists := stateStore.states[userID]
	if !exists {
		return ""
	}

	return entry.State
}
