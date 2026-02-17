package certstream

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/google/certificate-transparency-go/loglist3"
)

const DefaultLogListUrl = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

type Certstream struct {
	logsWg          sync.WaitGroup
	loglistUrl      string
	LogList         loglist3.LogList
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
	var list loglist3.LogList
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
		for _, ctLog := range operator.Logs {
			if ctLog.State != nil && ctLog.State.Usable == nil {
				log.Info("Skipping log", "description", ctLog.Description, "reason", "not_usable")
				continue
			}
			if ctLog.TemporalInterval != nil && ctLog.TemporalInterval.EndExclusive.Before(time.Now()) {
				log.Info("Skipping log", "description", ctLog.Description, "reason", "temporal_interval")

				continue
			}
			cs.logsWg.Add(1)
			go cs.runLogWorker(ctx, ctLog)
		}
	}
	<-ctx.Done()
	cs.logsWg.Wait()
	return ctx.Err()
}

func (cs *Certstream) runLogWorker(ctx context.Context, ctLog *loglist3.Log) {
	defer cs.logsWg.Done()
	lw := NewLogWorker(*ctLog, cs.broadcaster)
	err := lw.Run(ctx)
	if err != nil {
		log.Error(err)
	}
}
