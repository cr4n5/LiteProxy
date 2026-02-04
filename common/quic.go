package common

import (
	"crypto/tls"
	"errors"
	"time"

	"github.com/quic-go/quic-go"
)

func GenerateTLSConfig() *tls.Config {
	keyPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDG6Pgk8DB5MKOg
B1RVaGOO8iMgEvSyUs+WvDyx+q+kRRJIZw8fuMbabawa0qmjg6Z4OdZo0IJ0rkMD
2f2YmvdS6ICWs3o49oMVksLI2P482uJLmYo5tWaFN/08A1seWSPwJrqx3cwt14nd
e7Hr1sxwabug5zrmZY9BH2E1TxSb72fEUOQHLCbmypm9NU3WCLeLaUs/Y84N+skz
OTCCaSxOqanWfU6ofewmsMj97xEO64Tf/u6rqksv4LXK1PxCorG5c8YICGYB0KrR
BSp0MssbCi1Vlg3KgJqAGdOpCH5ZAmoBWbim0ysreAhCYB/Zn4GpPpCLpSg+h6wU
9AefZYl7AgMBAAECggEAGNP1kq7EbiwgZcDkdEYJFKEBZLyDp0qSN3ocMrRcKNX8
9+VH9v6vxjiloId7veRDQC3VUdSiTqwobe+k1DVA+oFOTlaYF/TKh0PVZQ/o1Bxs
3guL5wjPLiu/Q+FrWzi8iqUFmAlbthEkV+1brQNtFfmsqOM+momXaFqMCK/BSSFQ
LuO0Qr1donLZxkq9hixXwtj0BjPDNy8tWsgOlx89kFgdPfulCiYrcNzgOnUa8IUI
A0ZoL/h70cwp/4ZLbW/705VuPk5Pt2mjcTJ57Dh3Fe2B0g9gvcS85z0DNzJO21ob
ABn/JwLuof7DyzcgUIB1CD43W6H2lI+QeTcOD4OfaQKBgQDuAa0+sAraggetoq6z
bIOPnpQ7lf1LtIamPT49wchpcBDoTmhmRrUKB+9EZJ4s5Zk8WopdsqBgPQOvy0n8
XYGBVfc2uClSJDt+9z7SjHM3sVWSWVO9j9IQ4S5UYDfi8+86EsmZvyFQpqq0rZsE
UatnuLUfgfCYHSuHnmC/G5iI1QKBgQDV8qC1vDkkwnaJIqLGJ34l5TyTwvw1leRc
5hndt4bL6o0F5Y/lCjdIURaq6fOe+xmqSVCdf+sOtabWi2ZQPJBxgVq5sW41M/HR
dMzZUVr5nn3GV4dVpic4PsZzetan1v+wq9fRriQxt9drnbD/9jYgZ/WpBKgnPEIg
CWSVSJHxDwKBgQDJ1s4u7Wgm6kLMs7voGUxwzZDz/zzxqMTP0fwor1/gWtNbzrKm
mawKN7RnkdS6SnPrRPU2hLeRJe0sdf/mbv3Wyyp9UyxnpqZ2BANY1xcW0eK529sy
VPdWrUB2+aorY6cq3qftJLOCC/WUh+2AeiocKf4gHDgHKCW0O1Hcf/CZiQKBgQCS
ll3khuVEOXUL+s46JH77Kfh6aUNy15OSzxlz3zYda0RagPI5hOlhxCVaz1bbW8I2
+Wqhry53cqCwKOzeFtEE5BMsXdRb4Y5S68sbLvG9TAlzJy+T0HbYw7InF0gR0W55
NxR1FvK3mfWgR3gpuCFXzML1njo0P8YyuxzOZ92OowKBgBfdJNqljta3ogkUSrwD
3LWgX14SlgQ7H8g2WiCNcDoYJwvBxRE2nVK5uhzNTutRCcLGqasUYEZWDoRG3hCE
wrXkUXHFLtbGpqVxa8fKoS1jNDsezq9NgYl7132oaj09CBpByn84nnIoDf0dzVUZ
Py/n147tIfuEixEzUawreEvA
-----END PRIVATE KEY-----`)
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIURtMN5ZO1T+epaTcfc2GZAEz8n48wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDEyMzE2MDUzN1oXDTM2MDEy
MTE2MDUzN1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAxuj4JPAweTCjoAdUVWhjjvIjIBL0slLPlrw8sfqvpEUS
SGcPH7jG2m2sGtKpo4OmeDnWaNCCdK5DA9n9mJr3UuiAlrN6OPaDFZLCyNj+PNri
S5mKObVmhTf9PANbHlkj8Ca6sd3MLdeJ3Xux69bMcGm7oOc65mWPQR9hNU8Um+9n
xFDkBywm5sqZvTVN1gi3i2lLP2PODfrJMzkwgmksTqmp1n1OqH3sJrDI/e8RDuuE
3/7uq6pLL+C1ytT8QqKxuXPGCAhmAdCq0QUqdDLLGwotVZYNyoCagBnTqQh+WQJq
AVm4ptMrK3gIQmAf2Z+BqT6Qi6UoPoesFPQHn2WJewIDAQABo1MwUTAdBgNVHQ4E
FgQUX0bV3NhqhSKnSqEsUK6idPL+r6kwHwYDVR0jBBgwFoAUX0bV3NhqhSKnSqEs
UK6idPL+r6kwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAAk/Y
a3Hz0rGGtPdIvnryKg6p3Zl6xCQA53idk8XhFLKrQBLBuwToZEPhr1W6SZsAAUgF
VLTM8hfdktIfqjP8c2cHHI5hqrYovzQvVUEqScxXTHeBTcb6KJ4zPEGqH3FtgSbs
ntk6H/Ag4W2KrtfKWxuOR9Se90NM1hgANTn4q96iSHIJVPzC6B+kkApoNqLCu2LN
RUUhqYC1vi9YpJTE4xCV4NgXbH5Z1RDrZbX9KSbEpddQffjImPTykQYaRrAzAHZw
OxEcA0U7f05ZRIqyc0ldHZW1VduKLTfiwe2oCsISGlU3N3TpQQaGvx4ThGgNfbTK
eXD8EjtVzhPE15ppAw==
-----END CERTIFICATE-----`)
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
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
	streamErr, ok := err.(*quic.StreamError)
	if !ok {
		return err
	}
	switch streamErr.ErrorCode {
	case ErrClientNotFound:
		return errors.New("client not found")
	case ErrTargetUnreachable:
		return errors.New("target unreachable")
	case ErrNatType:
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
