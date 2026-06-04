// Package websocket provides a goroutine-safe WebSocket connection manager.
package websocket

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const (
	// writeWait is the deadline for a single write (frame) to the peer.
	writeWait = 10 * time.Second
	// pongWait is how long readPump waits for the next read before declaring
	// the connection dead. Reset on every protocol-level pong.
	pongWait = 90 * time.Second
	// pingPeriod is how often writePump sends a protocol-level ping. Must be
	// shorter than pongWait so a pong always lands before the read deadline.
	// Browsers answer protocol pings automatically (the JS WebSocket API does
	// not expose ping/pong), which is what actually keeps the stream alive —
	// there is no application-level heartbeat.
	pingPeriod = (pongWait * 9) / 10 // 81s
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

// writePump is the SOLE writer on the connection (gorilla/websocket forbids
// concurrent writes). It drains broadcast messages from c.send and, on a
// pingPeriod ticker, emits a protocol-level ping to keep the stream alive.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		if r := recover(); r != nil {
			log.Debug().Interface("recover", r).Msg("ws writePump recovered")
		}
		c.hub.Unregister(c) // clean up on exit
	}()
	for {
		select {
		case msg, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub closed the channel during Unregister — say goodbye.
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump detects disconnects and refreshes the read deadline on every
// protocol-level pong (sent automatically by the peer in response to the
// writePump ping). Any inbound application frames are read and discarded —
// this stream is server→client only.
func (c *Client) readPump() {
	defer c.hub.Unregister(c)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			break
		}
	}
}
