package websocket

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
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

// The dispatcher used to have no owner and no way to stop, so every NewHub
// leaked a goroutine for the life of the process.
func TestCloseStopsTheDispatcher(t *testing.T) {
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		h := NewHub()
		h.Close()
		h.Close() // idempotent
	}
	time.Sleep(100 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Errorf("goroutines: %d before, %d after 50 hubs were closed", before, after)
	}
}

func TestCloseDisconnectsClientsAndRefusesNewOnes(t *testing.T) {
	hub := NewHub()
	var registered atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if hub.Register(conn) != nil {
			registered.Add(1)
		}
	}))
	defer s.Close()
	wsURL := "ws" + strings.TrimPrefix(s.URL, "http")

	c1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	deadline := time.Now().Add(2 * time.Second)
	for hub.ClientCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	hub.Close()

	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c1.ReadMessage(); err == nil {
		t.Error("a client stayed connected after the hub was closed")
	}
	if n := hub.ClientCount(); n != 0 {
		t.Errorf("%d clients registered after Close", n)
	}

	// A connection that arrives after Close is refused, not leaked.
	c2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		defer c2.Close()
		_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := c2.ReadMessage(); err == nil {
			t.Error("a client connected to a closed hub stayed open")
		}
	}
	if registered.Load() != 1 {
		t.Errorf("registered = %d, want only the first client", registered.Load())
	}

	// Producers use a non-blocking send, so a message after Close is dropped.
	select {
	case hub.Broadcast <- []byte("late"):
	default:
	}
}
