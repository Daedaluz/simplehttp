package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"github.com/gorilla/mux"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"os"
	"time"
)

var (
	bind     string
	htdir    string
	secure   bool
	verbose  bool
	vverbose bool
)

func logger(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		log.Printf("%s %s from %s\n", request.Method, request.URL.Path, request.RemoteAddr)
		if verbose || vverbose {
			if vverbose {
				data, _ := httputil.DumpRequest(request, true)
				log.Println("\n" + string(data) + "\n-------------------------------------------------------")
			} else {
				data, _ := httputil.DumpRequest(request, false)
				log.Println("\n" + string(data) + "\n-------------------------------------------------------")
			}
		}
		handler.ServeHTTP(writer, request)

	})
}

func createCertificates() {
	if _, err := os.Stat("/tmp/key.pem"); os.IsNotExist(err) {
		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		pemKeyBin, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			log.Fatal(err)
		}
		keyFile, err := os.Create("/tmp/key.pem")
		if err != nil {
			log.Fatal(err)
		}
		if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: pemKeyBin}); err != nil {
			log.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1337),
			Subject: pkix.Name{
				Country:            []string{"Fantasyland"},
				Organization:       []string{"Dreams Inc"},
				OrganizationalUnit: []string{"Nightmares"},
				StreetAddress:      []string{"NeverEnding St."},
				CommonName:         "Dreamers",
			},
			NotBefore:                   time.Now(),
			NotAfter:                    time.Now().Add(time.Hour * 24 * 180),
			KeyUsage:                    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid:       true,
			EmailAddresses:              []string{"wishes@your.dreams.inc"},
			PermittedDNSDomainsCritical: false,
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
		if err != nil {
			log.Fatal(err)
		}
		certFile, err := os.Create("/tmp/cert.pem")
		if err != nil {
			log.Fatal(err)
		}
		if err = pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		}); err != nil {
			log.Fatal(err)
		}
		certFile.Close()
	}
}

func main() {
	flag.StringVar(&bind, "bind", ":8080", "port")
	flag.StringVar(&htdir, "d", "./", "www root")
	flag.BoolVar(&verbose, "v", false, "Verbose (log verbose)")
	flag.BoolVar(&vverbose, "vv", false, "Verbose (log verbose, body)")
	flag.BoolVar(&secure, "s", false, "Use a dummy ssl cert")
	flag.Parse()

	log.Printf("Starting simple http server on %s in %s", bind, htdir)
	r := mux.NewRouter()
	r.Use(logger)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(htdir)))

	server := http.Server{
		Addr:      bind,
		Handler:   r,
		TLSConfig: nil,
	}

	if secure {
		createCertificates()
		log.Println(server.ListenAndServeTLS("/tmp/cert.pem", "/tmp/key.pem"))
	} else {
		log.Println(server.ListenAndServe())
	}
}
