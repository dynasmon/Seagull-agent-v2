package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"
)

func selfSigned(t testing.TB) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "web-01"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Whatever a file of certificates holds, the chain read from it is exactly
// what it holds, written the one way the agent writes a chain.
func FuzzDecodeChain(f *testing.F) {
	leaf, issuer := selfSigned(f), selfSigned(f)
	written, err := encodeChain([][]byte{leaf, issuer}, MaxChain)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(written)
	f.Add(append(append([]byte{}, written...), '\n'))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: certificateBlock, Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: leaf}))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: keyBlock, Bytes: leaf}))
	f.Fuzz(func(t *testing.T, content []byte) {
		chain, err := decodeChain(content, MaxChain)
		if err != nil {
			if len(err.Error()) > 1<<10 {
				t.Fatalf("a refusal of %d bytes", len(err.Error()))
			}
			return
		}
		again, err := encodeChain(chain, MaxChain)
		if err != nil || !bytes.Equal(again, content) {
			t.Fatalf("a chain of %d certificates read from %d bytes is written as %d: %v", len(chain), len(content), len(again), err)
		}
		for _, certificate := range chain {
			if _, err := x509.ParseCertificate(certificate); err != nil {
				t.Fatalf("a chain holds a block that is not a certificate: %v", err)
			}
		}
	})
}

// Whatever a key file holds, the key read from it is the one the file is named
// after, so a key put in place of another is never used for it.
func FuzzDecodeKey(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	id, err := KeyID(key.Public())
	if err != nil {
		f.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		f.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	otherEncoded, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		f.Fatal(err)
	}
	wider, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		f.Fatal(err)
	}
	widerEncoded, err := x509.MarshalPKCS8PrivateKey(wider)
	if err != nil {
		f.Fatal(err)
	}
	for _, block := range []*pem.Block{{Type: keyBlock, Bytes: encoded}, {Type: keyBlock, Bytes: otherEncoded}, {Type: keyBlock, Bytes: widerEncoded},
		{Type: "EC PRIVATE KEY", Bytes: encoded}} {
		f.Add(pem.EncodeToMemory(block))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		held := slices.Clone(content)
		decoded, err := decode(held, id)
		if err != nil {
			if len(err.Error()) > 1<<10 {
				t.Fatalf("a refusal of %d bytes", len(err.Error()))
			}
			return
		}
		if named, err := KeyID(decoded.Public()); err != nil || named != id || !decoded.Equal(key) {
			t.Fatalf("the file named after key %s held key %s: %v", id, named, err)
		}
	})
}
