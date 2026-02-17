package types

type CertStreamMessage struct {
	MessageType string `json:"message_type"`
	Data        struct {
		LeafCert struct {
			Subject struct {
				CN string `json:"CN"`
			} `json:"subject"`
			Extensions struct {
				SubjectAltName string `json:"subjectAltName"`
			} `json:"extensions"`
		} `json:"leaf_cert"`
		Source struct {
			URL  string `json:"url"`
			Name string `json:"name"`
		} `json:"source"`
	} `json:"data"`
}
