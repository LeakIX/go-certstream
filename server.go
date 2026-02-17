package certstream

import (
	"context"
	"errors"
	"github.com/charmbracelet/log"
	"github.com/gorilla/websocket"
	"net/http"
	"time"
)

type webSocketServer struct {
	listenAddr string
	*Broadcaster
	upgrader websocket.Upgrader
}

func newWebSocketServer(broadcaster *Broadcaster, listenAddr string) (*webSocketServer, error) {
	return &webSocketServer{
		listenAddr:  listenAddr,
		Broadcaster: broadcaster,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true }, // Relaxed for OSS
		},
	}, nil
}

func (wss *webSocketServer) Run(ctx context.Context) error {
	log.Info("Starting certstream WebSocket server", "addr", wss.listenAddr)
	server := &http.Server{Addr: wss.listenAddr}
	router := http.NewServeMux()
	router.HandleFunc("/", wss.handle)
	server.Handler = router
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	// Give the server 10sec to shut down
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	return server.Shutdown(shutdownCtx)
}

func (wss *webSocketServer) handle(w http.ResponseWriter, r *http.Request) {
	conn, err := wss.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	log.Info("client connected", "addr", conn.RemoteAddr().String())
	ch := wss.Broadcaster.Join()
	defer wss.Broadcaster.Leave(ch)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
