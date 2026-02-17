package certstream

import (
	"context"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/LeakIX/go-certstream/types"
	"github.com/charmbracelet/log"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

type LogWorker struct {
	logUrl              string
	broadcaster         *Broadcaster
	currentIndex        uint64
	rateLimitCorrection time.Duration
}

const maxRateLimitCorrection = 30 * time.Second

func NewLogWorker(logUrl string, broadcaster *Broadcaster) *LogWorker {
	lw := &LogWorker{
		logUrl:              logUrl,
		broadcaster:         broadcaster,
		rateLimitCorrection: 0,
	}
	return lw
}

func (lw *LogWorker) process(ctx context.Context, ctClient *client.LogClient) (err error) {
	sth, err := ctClient.GetSTH(ctx)
	if err != nil {
		return
	}
	if sth.TreeSize <= lw.currentIndex {
		return
	}
	for lw.currentIndex < sth.TreeSize {
		batchSize := uint64(1000)
		if lw.currentIndex+batchSize > sth.TreeSize {
			batchSize = sth.TreeSize - lw.currentIndex
		}
		end := lw.currentIndex + batchSize - 1
	retry_429:
		entries, err := ctClient.GetRawEntries(ctx, int64(lw.currentIndex), int64(end))
		if err != nil {
			if strings.Contains(err.Error(), "429 ") {
				// multiply backoff by 2
				lw.rateLimitCorrection = lw.rateLimitCorrection + 50*time.Millisecond
				if lw.rateLimitCorrection > maxRateLimitCorrection {
					lw.rateLimitCorrection = maxRateLimitCorrection
				}
				log.Info("logworker got rate-limited, correction adapted to " + lw.rateLimitCorrection.String())
				select {
				case <-time.After(lw.rateLimitCorrection):

					goto retry_429
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return err
		}
		for _, entry := range entries.Entries {
			lw.rateLimitCorrection = lw.rateLimitCorrection - time.Millisecond
			if lw.rateLimitCorrection < 0 {
				lw.rateLimitCorrection = 0
			}
			lw.processEntry(lw.currentIndex, &entry)
			lw.currentIndex++
		}
		if lw.rateLimitCorrection > 0 {
			select {
			case <-time.After(lw.rateLimitCorrection):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return
}

func (lw *LogWorker) Run(ctx context.Context) error {
	// Delay start to spread initial load over 10 seconds.
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(time.Duration(1+rand.IntN(10)) * time.Second):
	}
	ctClient, err := client.New(lw.logUrl, http.DefaultClient, jsonclient.Options{UserAgent: "leakix/go-certstream"})
	if err != nil {
		return err
	}
	sth, err := ctClient.GetSTH(ctx)
	if err != nil {
		return err
	}
	lw.currentIndex = sth.TreeSize
	log.Info("connected to ct log", "url", lw.logUrl, "current_index", lw.currentIndex)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := lw.process(ctx, ctClient)
			if err != nil {
				log.Warn(err)
				continue
			}
		}
	}
}

func (lw *LogWorker) processEntry(realIndex uint64, entry *ct.LeafEntry) {
	parsedEntry, err := ct.LogEntryFromLeaf(int64(realIndex), entry)
	if err != nil {
		return
	}
	cert := parsedEntry.X509Cert
	if cert == nil {
		return
	}
	msg := types.CertStreamMessage{
		MessageType: "certificate_update",
	}
	msg.Data.LeafCert.Subject.CN = cert.Subject.CommonName
	msg.Data.LeafCert.Extensions.SubjectAltName = strings.Join(cert.DNSNames, ", ")
	msg.Data.Source.URL = lw.logUrl
	lw.broadcaster.Submit(msg)
}
