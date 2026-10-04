package diagnostics

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"
)

const maxNames = 16

var (
	keyUsages = []struct {
		usage x509.KeyUsage
		name  Text
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "certificate_sign"},
		{x509.KeyUsageCRLSign, "crl_sign"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	extendedUsages = map[x509.ExtKeyUsage]Text{
		x509.ExtKeyUsageAny:             "any",
		x509.ExtKeyUsageServerAuth:      "server_authentication",
		x509.ExtKeyUsageClientAuth:      "client_authentication",
		x509.ExtKeyUsageCodeSigning:     "code_signing",
		x509.ExtKeyUsageEmailProtection: "email_protection",
		x509.ExtKeyUsageTimeStamping:    "time_stamping",
		x509.ExtKeyUsageOCSPSigning:     "ocsp_signing",
	}
)

// Presented describes the chain the installation presents, leaf first, and
// says whether it authenticates the agent, as a client, to whoever trusts the
// authorities the agent trusts at the moment given. A certificate is public,
// so its description holds nothing a copy of it would not.
func Presented(from string, chain [][]byte, trusted []*x509.Certificate, at time.Time) Credential {
	presented := Credential{From: Text(from)}
	var parsed []*x509.Certificate
	for _, encoded := range chain {
		certificate, err := x509.ParseCertificate(encoded)
		if err != nil {
			presented.Unread = Text("the chain holds a block that is not a certificate: " + err.Error())
			return presented
		}
		parsed = append(parsed, certificate)
		presented.Chain = append(presented.Chain, Describe(certificate))
	}
	if len(parsed) == 0 {
		presented.Unread = "the chain holds no certificate"
		return presented
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, authority := range trusted {
		roots.AddCert(authority)
	}
	for _, issuer := range parsed[1:] {
		intermediates.AddCert(issuer)
	}
	moment := at.UTC().Format(time.RFC3339)
	if _, err := parsed[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		presented.Verification = Text(fmt.Sprintf("at %s the chain does not authenticate the agent to whoever trusts the %s the agent trusts: %v", moment, counted(len(trusted)), err))
	} else {
		presented.Verification = Text(fmt.Sprintf("at %s the chain authenticates the agent, as a client, to whoever trusts the %s the agent trusts", moment, counted(len(trusted))))
	}
	return presented
}

func Trusting(from, digest string, authorities []*x509.Certificate) Set {
	held := Set{From: Text(from), Digest: Text(digest)}
	for _, authority := range authorities {
		held.Authorities = append(held.Authorities, Describe(authority))
	}
	return held
}

func Describe(certificate *x509.Certificate) Certificate {
	fingerprint, key := sha256.Sum256(certificate.Raw), sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	described := Certificate{
		Subject:     Text(certificate.Subject.String()),
		Issuer:      Text(certificate.Issuer.String()),
		Serial:      Text(hex.EncodeToString(certificate.SerialNumber.Bytes())),
		Fingerprint: Text(hex.EncodeToString(fingerprint[:])),
		KeyID:       Text(hex.EncodeToString(key[:])),
		Key:         Text(publicKey(certificate)),
		Signature:   Text(certificate.SignatureAlgorithm.String()),
		NotBefore:   certificate.NotBefore.UTC(),
		NotAfter:    certificate.NotAfter.UTC(),
		Authority:   certificate.BasicConstraintsValid && certificate.IsCA,
	}
	for _, held := range keyUsages {
		if certificate.KeyUsage&held.usage != 0 {
			described.Usages = append(described.Usages, held.name)
		}
	}
	for _, usage := range certificate.ExtKeyUsage {
		if name, known := extendedUsages[usage]; known {
			described.Usages = append(described.Usages, name)
		} else {
			described.Usages = append(described.Usages, Text(fmt.Sprintf("extended_usage_%d", usage)))
		}
	}
	for _, usage := range certificate.UnknownExtKeyUsage {
		described.Usages = append(described.Usages, Text(usage.String()))
	}
	var names []Text
	for _, name := range certificate.DNSNames {
		names = append(names, Text(name))
	}
	for _, address := range certificate.IPAddresses {
		names = append(names, Text(address.String()))
	}
	for _, mailbox := range certificate.EmailAddresses {
		names = append(names, Text(mailbox))
	}
	for _, identifier := range certificate.URIs {
		names = append(names, Text(identifier.String()))
	}
	described.Names = names[:min(len(names), maxNames)]
	return described
}

func publicKey(certificate *x509.Certificate) string {
	switch key := certificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + key.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", key.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return certificate.PublicKeyAlgorithm.String()
}

func counted(authorities int) string {
	if authorities == 1 {
		return "1 authority"
	}
	return fmt.Sprintf("%d authorities", authorities)
}
