package certstream

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/LeakIX/go-certstream/types"
	"github.com/charmbracelet/log"
)

const DefaultLogListUrl = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

type Certstream struct {
	logsWg          sync.WaitGroup
	loglistUrl      string
	LogList         types.LogList
	websocketListen string
	webSocketServer *webSocketServer
	broadcaster     *Broadcaster
}

func NewCertstream(opts ...Option) (*Certstream, error) {
	// Default settings:
	cs := &Certstream{
		loglistUrl:      DefaultLogListUrl,
		websocketListen: ":8080",
		broadcaster:     NewBroadcaster(256),
	}
	// Apply options
	for _, opt := range opts {
		err := opt(cs)
		if err != nil {
			return nil, err
		}
	}
	// Configure socket server
	wsServer, err := newWebSocketServer(cs.broadcaster, cs.websocketListen)
	if err != nil {
		return nil, err
	}
	cs.webSocketServer = wsServer
	return cs, nil
}

func (cs *Certstream) populateLogList() error {
	// Init loglist
	resp, err := http.Get(cs.loglistUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var list types.LogList
	err = json.NewDecoder(resp.Body).Decode(&list)
	if err != nil {
		return err
	}
	cs.LogList = list
	return nil
}

func (cs *Certstream) Run(ctx context.Context) error {
	err := cs.populateLogList()
	if err != nil {
		return err
	}
	cs.logsWg.Add(1)
	go func() {
		defer cs.logsWg.Done()
		if err := cs.webSocketServer.Run(ctx); err != nil {
			log.Error(err)
		}
	}()
	for _, operator := range cs.LogList.Operators {
		for _, log := range operator.Logs {
			cs.logsWg.Add(1)
			go cs.runLogWorker(ctx, log.URL)
		}
	}
	<-ctx.Done()
	cs.logsWg.Wait()
	return ctx.Err()
}

func (cs *Certstream) runLogWorker(ctx context.Context, logUrl string) {
	defer cs.logsWg.Done()
	lw := NewLogWorker(logUrl, cs.broadcaster)
	err := lw.Run(ctx)
	if err != nil {
		log.Error(err)
	}
}
