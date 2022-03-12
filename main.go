/*
 * Copyright (c) 2022 Deomid "rojer" Ryabkov
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/divan/gorilla-xmlrpc/xml"
	"github.com/gorilla/rpc"
	glog "k8s.io/klog/v2"
)

var (
	flagHTTPPort          = flag.Int("http-port", 80, "HTTP port to listen on")
	flagHTTPSPort         = flag.Int("https-port", 443, "HTTPS port to listen on")
	flagCertFile          = flag.String("https-cert-file", "", "TLS certificate file")
	flagkeyFile           = flag.String("https-key-file", "", "TLS key file")
	flagACMEChallengeRoot = flag.String("acme-challenge-root", "", "Directory to serve /.well-known/acme-challenge from")
	flagProfileRoot       = flag.String("profile-root", "", "Serve .ovpn profiles from this location")
)

const svcName = "OpenVPN"

var RPC *rpc.Server

func handleRPC2(w http.ResponseWriter, r *http.Request) {
	// Add dummy service part.
	d, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()
	d = bytes.Replace(d, []byte("<methodName>"), []byte(fmt.Sprintf("<methodName>%s.", svcName)), 1)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(d))
	RPC.ServeHTTP(w, r)
}

func main() {
	var err error
	glog.InitFlags(nil)
	glog.LogToStderr(false) // Can be enabled with --logtostderr/--alsologtostderr.
	flag.Parse()

	if *flagProfileRoot == "" {
		glog.Exitf("--profile-root is required")
	}

	glog.Infof("Starting...")

	pr, err := filepath.Abs(*flagProfileRoot)
	if err != nil {
		glog.Exitf("%s does not exist", *flagProfileRoot)
	}
	if fi, err := os.Stat(pr); err != nil || !fi.Mode().IsDir() {
		glog.Exitf("%s does not exist or is not a directory", *flagProfileRoot)
	}
	svc := NewService(pr)

	var httpMux, httpsMux http.ServeMux
	var tlsConfig *tls.Config
	if *flagCertFile != "" || *flagkeyFile != "" {
		// Check for partial configuration.
		if *flagCertFile == "" || *flagkeyFile == "" {
			glog.Exitf("Failed to load certificate and key: both were not provided")
		}
		tlsConfig = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			NextProtos:               []string{"http/1.1"},
			Certificates:             make([]tls.Certificate, 1),
		}
		glog.Infof("Cert file: %s", *flagCertFile)
		glog.Infof("Key file : %s", *flagkeyFile)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(*flagCertFile, *flagkeyFile)
		if err != nil {
			glog.Exitf("Failed to load certificate and key: %s", err)
		}

		hs := &http.Server{
			Addr:      fmt.Sprintf(":%d", *flagHTTPSPort),
			Handler:   &httpsMux,
			TLSConfig: tlsConfig,
		}
		httpsMux.HandleFunc("/RPC2", handleRPC2)
		httpsMux.Handle("/", svc)

		go func() {
			glog.Infof("Listening on HTTPS port %d ...", *flagHTTPSPort)
			glog.Fatal(hs.ListenAndServeTLS(*flagCertFile, *flagkeyFile))
		}()
	} else {
		glog.Warning("Running without TLS")
		httpMux.Handle("/", svc)
	}

	if *flagACMEChallengeRoot != "" {
		HandleACMEChallenges(*flagACMEChallengeRoot, &httpMux)
	}

	hs := &http.Server{
		Addr:    fmt.Sprintf(":%d", *flagHTTPPort),
		Handler: &httpMux,
	}

	RPC = rpc.NewServer()
	xmlrpcCodec := xml.NewCodec()
	RPC.RegisterCodec(xmlrpcCodec, "text/xml")                          // Should be this
	RPC.RegisterCodec(xmlrpcCodec, "application/x-www-form-urlencoded") // Actually this
	RPC.RegisterService(svc, svcName)
	httpMux.HandleFunc("/RPC2", handleRPC2)

	glog.Infof("Listening on HTTP port %d ...", *flagHTTPPort)
	glog.Fatal(hs.ListenAndServe())
}
