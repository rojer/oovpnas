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
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	glog "k8s.io/klog/v2"
)

func NewService(profileRoot string) *OpenVPNASService {
	glog.Infof("Serving profiles from %s", profileRoot)
	return &OpenVPNASService{profileRoot: profileRoot}
}

type OpenVPNASService struct {
	profileRoot string
}

type Empty struct{}

type GetSessionRes struct {
	Resp GetSessionResp
}

type GetSessionResp struct {
	Status    int    `xml:"status"`
	SessionID string `xml:"session_id"`
}

func (h *OpenVPNASService) GetSession(r *http.Request, _ *Empty, res *GetSessionRes) error {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return fmt.Errorf("auth required")
	}
	_, err := h.getProfile(user, pass)
	if err == nil {
		res.Resp.Status = 0
		res.Resp.SessionID = fmt.Sprintf("%s/%s", user, pass)
		glog.Infof("GetSession %s", user)
	} else {
		res.Resp.Status = -1
		glog.Infof("GetSession %s: %v", user, err)
	}
	return nil
}

type GetUserloginRes struct {
	Profile string
}

type GetUserloginResp struct {
}

func (h *OpenVPNASService) getLogin(r *http.Request, res *GetUserloginRes, m string) error {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return fmt.Errorf("auth required")
	}
	if user == "SESSION_ID" {
		parts := strings.Split(pass, "/")
		if len(parts) != 2 {
			return fmt.Errorf("invalid pass")
		}
		user, pass = parts[0], parts[1]
	}
	data, err := h.getProfile(user, pass)
	if err != nil {
		glog.Errorf("Error serving profile for %s: %s", user, err)
		return err
	}
	res.Profile = data
	glog.Infof("%s %s", m, user)
	return nil
}

func (h *OpenVPNASService) GetUserlogin(r *http.Request, _ *Empty, res *GetUserloginRes) error {
	return h.getLogin(r, res, "GetUserlogin")
}

func (h *OpenVPNASService) GetAutologin(r *http.Request, _ *Empty, res *GetUserloginRes) error {
	return h.getLogin(r, res, "GetAutologin")
}

type CloseSessionArg struct {
	SessionID string
}

func (h *OpenVPNASService) CloseSession(_ *http.Request, _ *CloseSessionArg, _ *Empty) error {
	return nil
}

func remoteIP(r *http.Request) string {
	parts := strings.Split(r.RemoteAddr, ":")
	return strings.Join(parts[:len(parts)-1], ":")
}

func (h *OpenVPNASService) getProfile(user, pass string) (string, error) {
	if len(pass) < 12 || len(pass) > 64 {
		return "", fmt.Errorf("invalid pass")
	}
	fname := filepath.Join(h.profileRoot, filepath.Base(user)) + ".ovpn"
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		glog.Errorf("Error reading %q: %s", fname, err)
		return "", fmt.Errorf("No such profile %q", user)
	}
	wantPass := fmt.Sprintf("%x", sha256.Sum256(data))
	if !strings.HasPrefix(wantPass, pass) {
		return "", fmt.Errorf("invalid pass")
	}
	return string(data), nil
}

func (h *OpenVPNASService) serveProfile(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="OpenVPN", charset="utf-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	data, err := h.getProfile(user, pass)
	if err != nil {
		glog.Errorf("%s %q: %v", remoteIP(r), user, err)
		w.Header().Set("WWW-Authenticate", `Basic realm="OpenVPN", charset="utf-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
}

func (h *OpenVPNASService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	f := path.Base(r.URL.Path)
	glog.Infof("%s %s", remoteIP(r), r.URL.Path)
	switch {
	case r.URL.Path == "/":
		http.ServeFile(w, r, filepath.Join(h.profileRoot, "index.html"))
	case r.URL.Path == "/rest/GetUserlogin":
		h.serveProfile(w, r)
	case r.URL.Path == "/rest/GetAutologin":
		h.serveProfile(w, r)
	case strings.HasSuffix(f, ".ovpn"):
		if user, _, _ := r.BasicAuth(); f != fmt.Sprintf("%s.ovpn", user) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		h.serveProfile(w, r)
	default:
		user, pass, _ := r.BasicAuth()
		glog.Warningf("%s %s Not Found %s %s", remoteIP(r), r.URL.Path, user, pass)
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}
