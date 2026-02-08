package api

import (
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Origin validation will be configured via allowed_origins setting
		return true
	},
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Validate session token
	token := r.URL.Query().Get("token")
	if token == "" || token != s.wsToken {
		http.Error(w, "invalid or missing token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}
	defer conn.Close()

	log.Info().Msg("WebSocket client connected")

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Info().Msg("WebSocket client disconnected")
			} else {
				log.Error().Err(err).Msg("WebSocket read error")
			}
			return
		}

		// Stub: echo back "not yet implemented" for any message
		_ = message
		resp := `{"id":null,"error":{"code":-1,"message":"not yet implemented"}}`
		if err := conn.WriteMessage(websocket.TextMessage, []byte(resp)); err != nil {
			log.Error().Err(err).Msg("WebSocket write error")
			return
		}
	}
}
