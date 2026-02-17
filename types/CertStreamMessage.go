package types

import (
	"strings"

	"github.com/google/certificate-transparency-go/x509"
)

type CertStreamMessage struct {
	MessageType string `json:"message_type"`
	Data        struct {
		CertIndex uint64 `json:"cert_index"`
		CertLink  string `json:"cert_link"`
		LeafCert  struct {
			AllDomains []string `json:"all_domains"`
			Subject    struct {
				CN string `json:"CN"`
			} `json:"subject"`
			Extensions CertExtensions `json:"extensions"`
		} `json:"leaf_cert"`
		Source struct {
			URL  string `json:"url"`
			Name string `json:"name"`
		} `json:"source"`
	} `json:"data"`
}

func (csm *CertStreamMessage) AddDomain(domain string) {
	for _, domainTest := range csm.Data.LeafCert.AllDomains {
		if domainTest == domain {
			return
		}
	}
	csm.Data.LeafCert.AllDomains = append(csm.Data.LeafCert.AllDomains, domain)
}

func (csm *CertStreamMessage) AddDomains(domains ...string) {
	for _, domain := range domains {
		csm.AddDomain(domain)
	}
}

type CertExtensions struct {
	SubjectAltName         string `json:"subjectAltName"`
	BasicConstraints       string `json:"basicConstraints,omitempty"`
	KeyUsage               string `json:"keyUsage,omitempty"`
	ExtendedKeyUsage       string `json:"extendedKeyUsage,omitempty"`
	AuthorityKeyIdentifier string `json:"authorityKeyIdentifier,omitempty"`
	SubjectKeyIdentifier   string `json:"subjectKeyIdentifier,omitempty"`
}

func GetExtensions(cert *x509.Certificate) CertExtensions {
	exts := CertExtensions{}

	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, "DNS:"+dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP Address:"+ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, "email:"+email)
	}
	exts.SubjectAltName = strings.Join(sans, ", ")

	if cert.BasicConstraintsValid {
		if cert.IsCA {
			exts.BasicConstraints = "CA:TRUE"
		} else {
			exts.BasicConstraints = "CA:FALSE"
		}
	}

	var ku []string
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		ku = append(ku, "Digital Signature")
	}
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		ku = append(ku, "Content Commitment")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		ku = append(ku, "Key Encipherment")
	}
	exts.KeyUsage = strings.Join(ku, ", ")

	return exts
}
