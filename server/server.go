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

package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	glog "k8s.io/klog/v2"
)

func RegisterCmd(parentCmd *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a server",
		RunE:  run,
	}
	f := cmd.Flags()
	f.StringVar(&flagHTTPPort, "http-port", "", "HTTP address andr port to listen on")
	f.StringVar(&flagHTTPSPort, "https-port", "", "HTTPS address and port to listen on")
	f.StringVar(&flagCertFile, "https-cert-file", "", "TLS certificate file")
	f.StringVar(&flagKeyFile, "https-key-file", "", "TLS key file")
	f.StringVar(&flagProfileRoot, "profile-root", "", "Serve .ovpn profiles from this location")
	f.StringVar(&flagACMEChallengeRoot, "acme-challenge-root", "", "Directory to serve /.well-known/acme-challenge from")
	f.StringVar(&flagRealIPHeader, "real-ip-header", "", "When behind a proxy, extract real IP from this header")
	cmd.MarkFlagRequired("profile-root")
	parentCmd.AddCommand(cmd)
}

var (
	flagHTTPPort          string
	flagHTTPSPort         string
	flagCertFile          string
	flagKeyFile           string
	flagProfileRoot       string
	flagACMEChallengeRoot string
	flagRealIPHeader      string
)

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if r.Host != "" {
		w.Header().Set("Location", fmt.Sprintf("https://%s%s", r.Host, r.URL.Path))
		http.Error(w, "Please use HTTPS", http.StatusMovedPermanently)
	} else {
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

func run(cmd *cobra.Command, args []string) error {
	var err error
	glog.LogToStderr(true)

	glog.Infof("Starting...")

	pr, err := filepath.Abs(flagProfileRoot)
	if err != nil {
		return fmt.Errorf("%s does not exist", flagProfileRoot)
	}
	if fi, err := os.Stat(pr); err != nil || !fi.Mode().IsDir() {
		return fmt.Errorf("%s does not exist or is not a directory", flagProfileRoot)
	}

	svc := NewService(pr, flagRealIPHeader)

	var httpServer, httpsServer *http.Server
	if flagHTTPSPort != "" {
		// Check for partial configuration.
		if flagCertFile == "" || flagKeyFile == "" {
			return fmt.Errorf("--https-cert-file and --https-key-file are required for HTTPS")
		}
		tlsConfig := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			NextProtos:               []string{"http/1.1"},
			Certificates:             make([]tls.Certificate, 1),
		}
		glog.Infof("Cert file: %s", flagCertFile)
		glog.Infof("Key  file: %s", flagKeyFile)
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(flagCertFile, flagKeyFile)
		if err != nil {
			return fmt.Errorf("Failed to load certificate and key: %s", err)
		}

		httpsMux := &http.ServeMux{}
		httpsMux.Handle("/", svc)

		addr := flagHTTPSPort
		if !strings.Contains(addr, ":") {
			addr = ":" + addr
		}
		httpsServer = &http.Server{
			Addr:      addr,
			Handler:   httpsMux,
			TLSConfig: tlsConfig,
		}
	}
	if flagHTTPPort != "" {
		httpMux := &http.ServeMux{}
		// If HTTPS is present, then HTTP port only serves ACME challenges
		// and redirects to HTTPS for everything else.
		if httpsServer != nil {
			httpMux.HandleFunc("/", redirectToHTTPS)
		} else {
			httpMux.Handle("/", svc)
		}
		if flagACMEChallengeRoot != "" {
			HandleACMEChallenges(flagACMEChallengeRoot, httpMux)
		}
		addr := flagHTTPPort
		if !strings.Contains(addr, ":") {
			addr = ":" + addr
		}
		httpServer = &http.Server{
			Addr:    addr,
			Handler: httpMux,
		}
	}

	if httpServer == nil && httpsServer == nil {
		return fmt.Errorf("no HTTP or HTTPS port specified")
	}

	resCh := make(chan error)
	if httpServer != nil {
		glog.Infof("HTTP listener on %s", flagHTTPPort)
		go func() {
			resCh <- httpServer.ListenAndServe()
		}()
	}
	if httpsServer != nil {
		glog.Infof("HTTPS listener on %s", flagHTTPSPort)
		go func() {
			resCh <- httpsServer.ListenAndServeTLS(flagCertFile, flagKeyFile)
		}()
	}
	return <-resCh
}
