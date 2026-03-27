// Package websocket provides a goroutine-safe WebSocket connection manager.
package websocket

import (
	"sync"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// Client wraps a single WebSocket connection.
type Client struct {
	conn *websocket.Conn
	send chan []byte
}

// Hub manages all active WebSocket clients.
type Hub struct {
	mu         sync.RWMutex
	clients    map[*Client]struct{}
	Broadcast  chan []byte
}

// NewHub creates and starts a Hub.
func NewHub() *Hub {
	h := &Hub{
		clients:   make(map[*Client]struct{}),
		Broadcast: make(chan []byte, 256),
	}
	go h.run()
	return h
}

func (h *Hub) run() {
	for msg := range h.Broadcast {
		h.mu.RLock()
		for c := range h.clients {
			select {
			case c.send <- msg:
			default:
				// Slow client — drop message rather than block.
			}
		}
		h.mu.RUnlock()
	}
}

// Register adds a WebSocket connection to the hub.
func (h *Hub) Register(conn *websocket.Conn) *Client {
	c := &Client{conn: conn, send: make(chan []byte, 64)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	go c.writePump()
	return c
}

// Unregister removes a client from the hub and closes the connection.
func (h *Hub) Unregister(c *Client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
	close(c.send)
}

func (c *Client) writePump() {
	defer func() {
		if r := recover(); r != nil {
			log.Debug().Interface("recover", r).Msg("ws writePump recovered")
		}
	}()
	for msg := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return
		}
	}
}
