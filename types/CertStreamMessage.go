package types

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

type CertStreamMessage struct {
	MessageType string `json:"message_type"`
	Data        struct {
		UpdateType string  `json:"update_type"`
		CertIndex  uint64  `json:"cert_index"`
		CertLink   string  `json:"cert_link"`
		Seen       float64 `json:"seen"`
		Source     struct {
			URL  string `json:"url"`
			Name string `json:"name"`
		} `json:"source"`
		LeafCert struct {
			Subject            CertDN         `json:"subject"`
			Issuer             CertDN         `json:"issuer"`
			Extensions         CertExtensions `json:"extensions"`
			NotBefore          int64          `json:"not_before"`
			NotAfter           int64          `json:"not_after"`
			SerialNumber       string         `json:"serial_number"`
			Fingerprint        string         `json:"fingerprint"`
			AllDomains         []string       `json:"all_domains"`
			SignatureAlgorithm string         `json:"signature_algorithm"`
			AsDer              []byte         `json:"as_der,omitempty"`
		} `json:"leaf_cert"`
	} `json:"data"`
}

type CertExtensions struct {
	SubjectAltName         string `json:"subjectAltName"`
	BasicConstraints       string `json:"basicConstraints,omitempty"`
	KeyUsage               string `json:"keyUsage,omitempty"`
	ExtendedKeyUsage       string `json:"extendedKeyUsage,omitempty"`
	AuthorityKeyIdentifier string `json:"authorityKeyIdentifier,omitempty"`
	SubjectKeyIdentifier   string `json:"subjectKeyIdentifier,omitempty"`
}

type CertDN struct {
	Aggregated string  `json:"aggregated"`
	C          *string `json:"C"`
	ST         *string `json:"ST"`
	L          *string `json:"L"`
	O          *string `json:"O"`
	OU         *string `json:"OU"`
	CN         *string `json:"CN"`
}

func (csm *CertStreamMessage) AddDomain(domain string) {
	if domain == "" {
		return
	}
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

func CTX509DNToCertDN(aggregated string) (certDn CertDN) {
	dn, err := ldap.ParseDN(aggregated)
	if err != nil {
		log.Warn(err)
		return
	}
	var clAggregated string
	for _, rdn := range dn.RDNs {
		for _, attr := range rdn.Attributes {
			// Match CaliDog's output:
			value := attr.Value
			clAggregated += fmt.Sprintf("/%s=%s", attr.Type, attr.Value)
			switch attr.Type {
			case "C":
				certDn.C = &value
			case "L":
				certDn.L = &value
			case "CN":
				certDn.CN = &value
			case "ST":
				certDn.ST = &value
			case "OU":
				certDn.OU = &value
			case "O":
				certDn.O = &value
			}
		}
	}
	certDn.Aggregated = clAggregated
	return
}

func CTX509ToCertStreamMessage(ctLog loglist3.Log, realIndex uint64, cert *x509.Certificate) (msg CertStreamMessage) {
	msg.MessageType = "certificate_update"
	msg.Data.UpdateType = "X509Certificate"

	msg.Data.CertIndex = realIndex
	msg.Data.CertLink = fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", strings.TrimSuffix(ctLog.URL, "/"), realIndex, realIndex)

	msg.Data.Seen = float64(time.Now().UnixNano()) / 1e9
	certHash := sha1.Sum(cert.Raw)
	msg.Data.LeafCert.Fingerprint = bytesToFingerprint(certHash[:])
	msg.Data.LeafCert.Extensions = GetExtensions(cert)
	msg.Data.LeafCert.NotBefore = cert.NotBefore.Unix()
	msg.Data.LeafCert.NotAfter = cert.NotAfter.Unix()
	msg.Data.LeafCert.SerialNumber = fmt.Sprintf("%X", cert.SerialNumber)

	// Handle Subject
	msg.Data.LeafCert.Subject = CTX509DNToCertDN(cert.Subject.String())
	msg.Data.LeafCert.Issuer = CTX509DNToCertDN(cert.Issuer.String())

	msg.AddDomain(cert.Subject.CommonName)
	msg.AddDomains(cert.DNSNames...)
	msg.Data.Source.URL = ctLog.URL
	msg.Data.Source.Name = ctLog.Description
	msg.Data.LeafCert.SignatureAlgorithm = getSignatureAlgorithmName(cert.SignatureAlgorithm)
	// TODO: Should be optional, lots of data most people won't use:
	// msg.Data.LeafCert.AsDer = cert.Raw
	return
}

func GetExtensions(cert *x509.Certificate) (exts CertExtensions) {
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

	if len(cert.AuthorityKeyId) > 0 {
		exts.AuthorityKeyIdentifier = "keyid:" + bytesToFingerprint(cert.AuthorityKeyId) + "\n"
	}
	if len(cert.SubjectKeyId) > 0 {
		exts.SubjectKeyIdentifier = bytesToFingerprint(cert.SubjectKeyId)
	}
	return exts
}

func bytesToFingerprint(data []byte) string {
	var b strings.Builder
	b.Grow(len(data)*3 - 1)
	for i, byteVal := range data {
		if i > 0 {
			b.WriteByte(':')
		}
		buf := []byte{0, 0}
		hex.Encode(buf, []byte{byteVal})
		b.Write(buf)
	}
	return strings.ToUpper(b.String())
}

func getSignatureAlgorithmName(sa x509.SignatureAlgorithm) string {
	switch sa {
	case x509.MD2WithRSA:
		return "md2, rsa"
	case x509.MD5WithRSA:
		return "md5, rsa"
	case x509.SHA1WithRSA:
		return "sha1, rsa"
	case x509.SHA256WithRSA:
		return "sha256, rsa"
	case x509.SHA384WithRSA:
		return "sha384, rsa"
	case x509.SHA512WithRSA:
		return "sha512, rsa"
	case x509.DSAWithSHA1:
		return "sha1, dsa"
	case x509.DSAWithSHA256:
		return "sha256, dsa"
	case x509.ECDSAWithSHA1:
		return "sha1, ecdsa"
	case x509.ECDSAWithSHA256:
		return "sha256, ecdsa"
	case x509.ECDSAWithSHA384:
		return "sha384, ecdsa"
	case x509.ECDSAWithSHA512:
		return "sha512, ecdsa"
	case x509.SHA256WithRSAPSS:
		return "sha256, rsa-pss"
	case x509.SHA384WithRSAPSS:
		return "sha384, rsa-pss"
	case x509.SHA512WithRSAPSS:
		return "sha512, rsa-pss"
	case x509.PureEd25519:
		return "ed25519"
	default:
		return "unknown"
	}
}
