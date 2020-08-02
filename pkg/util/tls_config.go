package util

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	serverCertName = "server.crt"
	clientCertName = "client.crt"
	clientKeyName  = "client.key"
)

func GetTLSConfig(certsDir string) (*tls.Config, error) {
	// Load our CA certificate
	serverCertPath := certsDir + "/" + serverCertName
	clientCACert, err := ioutil.ReadFile(serverCertPath)
	if err != nil {
		return nil, err
	}

	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(clientCACert)
	if !ok {
		return nil, fmt.Errorf("Failed to append certs to certificate pool")
	}

	// optional client certificate
	certPath := certsDir + "/" + clientCertName
	keyPath := certsDir + "/" + clientKeyName
	if !exists(certPath) || !exists(keyPath) {
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

func exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
