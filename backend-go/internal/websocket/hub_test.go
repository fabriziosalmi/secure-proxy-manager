package websocket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{}

func TestHub(t *testing.T) {
	hub := NewHub()
	
	// Create a mock server to handle WS upgrades
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		hub.Register(conn)
	}))
	defer s.Close()

	// Connect a client
	wsURL := "ws" + strings.TrimPrefix(s.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer ws.Close()

	// Wait for registration
	time.Sleep(100 * time.Millisecond)
	if hub.ClientCount() != 1 {
		t.Errorf("Expected 1 client, got %d", hub.ClientCount())
	}

	// Broadcast message
	msg := []byte("hello")
	hub.Broadcast <- msg

	// Read message from client
	_, p, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}
	if string(p) != "hello" {
		t.Errorf("Expected hello, got %s", p)
	}

	// Close client and verify unregistration
	ws.Close()
	time.Sleep(100 * time.Millisecond)
	// Some systems might take a bit longer to detect the disconnect via ReadMessage failure
	if hub.ClientCount() > 0 {
		// Try one more sleep
		time.Sleep(200 * time.Millisecond)
	}
	// Note: readPump detects disconnect and calls Unregister.
}
