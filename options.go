package certstream

type Option func(certstream *Certstream) error

func WithCustomLogList(url string) Option {
	return func(certstream *Certstream) error {
		certstream.loglistUrl = url
		return nil
	}
}

func WithWebSocketListen(addr string) Option {
	return func(certstream *Certstream) error {
		certstream.websocketListen = addr
		return nil
	}
}
