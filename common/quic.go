package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

func generateKeyAndCert() ([]byte, []byte, error) {
	// Generate a private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create a template for the certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"LiteProxy"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour), // Valid for 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create a self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Encode the private key to PEM format
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	// Encode the certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return keyPEM, certPEM, nil
}

func GenerateTLSConfig() *tls.Config {
	keyPEM, certPEM, err := generateKeyAndCert()
	if err != nil {
		panic(err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"liteproxy-quic"},
	}
}

func GenerateClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"liteproxy-quic"},
	}
}

var QuicConfig = &quic.Config{
	KeepAlivePeriod:    5 * time.Second,
	MaxIdleTimeout:     15 * time.Second,
	MaxIncomingStreams: 100000,
}

const (
	ErrClientNotFound    quic.StreamErrorCode = 1001
	ErrTargetUnreachable quic.StreamErrorCode = 1002
	ErrNatType           quic.StreamErrorCode = 1003
)

func TranslateStreamError(err error) error {
	// streamErr, ok := err.(*quic.StreamError)
	// if !ok {
	// 	return err
	// }
	// switch streamErr.ErrorCode {
	// case ErrClientNotFound:
	// 	return errors.New("client not found")
	// case ErrTargetUnreachable:
	// 	return errors.New("target unreachable")
	// case ErrNatType:
	// 	return errors.New("maybe unsupported nat type, try again ...")
	// default:
	// 	return err
	// }
	streamStr := err.Error()
	switch {
	case strings.Contains(streamStr, "error code 1001"):
		return errors.New("client not found")
	case strings.Contains(streamStr, "error code 1002"):
		return errors.New("target unreachable")
	case strings.Contains(streamStr, "error code 1003"):
		return errors.New("maybe unsupported nat type, try again ...")
	default:
		return err
	}
}

func TranslateErrorCode(err error) quic.StreamErrorCode {
	streamErr, ok := err.(*quic.StreamError)
	if ok {
		return streamErr.ErrorCode
	}
	return 0
}
