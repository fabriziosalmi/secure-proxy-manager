// Package websocket provides a goroutine-safe WebSocket connection manager.
package websocket

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// Client wraps a single WebSocket connection.
type Client struct {
	conn *websocket.Conn
	send chan []byte
	hub  *Hub
}

// Hub manages all active WebSocket clients.
type Hub struct {
	mu        sync.RWMutex
	clients   map[*Client]struct{}
	Broadcast chan []byte
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
	c := &Client{conn: conn, send: make(chan []byte, 64), hub: h}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	go c.writePump()
	go c.readPump() // detect disconnects
	return c
}

// Unregister removes a client from the hub and closes the connection.
func (h *Hub) Unregister(c *Client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
	}
	h.mu.Unlock()
	c.conn.Close()
}

// ClientCount returns the number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (c *Client) writePump() {
	defer func() {
		if r := recover(); r != nil {
			log.Debug().Interface("recover", r).Msg("ws writePump recovered")
		}
		c.hub.Unregister(c) // clean up on exit
	}()
	for msg := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			return
		}
	}
}

// readPump reads pings/pongs and detects disconnects.
func (c *Client) readPump() {
	defer c.hub.Unregister(c)
	c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		return nil
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			break
		}
	}
}
