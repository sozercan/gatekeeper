package util

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

func GetTLSConfig() (*tls.Config, error) {
	// Load our CA certificate
	clientCACert, err := ioutil.ReadFile("/etc/endpoint-certs/server.crt")
	if err != nil {
		return nil, err
	}

	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(clientCACert)
	if !ok {
		return nil, fmt.Errorf("Failed to append certs to certificate pool")
	}

	// optional client certificate
	certPath := "/etc/endpoint-certs/client.crt"
	keyPath := "/etc/endpoint-certs/client.key"
	if certPath == "" || keyPath == "" {
		return &tls.Config{RootCAs: clientCertPool}, nil
	}

	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		RootCAs:      clientCertPool,
		Certificates: []tls.Certificate{clientCert},
	}, nil
}
