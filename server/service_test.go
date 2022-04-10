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
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, content string) {
	require.NoError(t, ioutil.WriteFile(filepath.Join(dir, name), []byte(content), 0644))
}

func TestGetProfile(t *testing.T) {
	proot, err := ioutil.TempDir("", "proot_")
	require.NoError(t, err)
	defer os.RemoveAll(proot)
	writeFile(t, proot, "p1", "foo")
	writeFile(t, proot, "p2.ovpn", "bar")

	for _, c := range []struct {
		user, pass string
		eRes, eErr string
	}{
		{"", "", "", "invalid pass"},
		{"p0", "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9", "", `No such profile "p0"`},
		{"p1", "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9", "", `No such profile "p1"`},
		{"p2", "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9", "bar", ""},
		{"p2", "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9a", "bar", "invalid pass"},
		{"p2", "fcde2b2edba5", "bar", ""},
		{"p2", "FCDE2B2EDBA5", "bar", "invalid pass"},
		{"p2", "fcde2b2edba", "bar", "invalid pass"},
		{"p2", "aaaaaaaaaaaa", "bar", "invalid pass"},
		{"p2", "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fba", "bar", "invalid pass"},
	} {
		s := NewService(proot, "")
		res, err := s.getProfile(c.user, c.pass)
		if c.eErr == "" {
			require.NoErrorf(t, err, "case %+v", c)
			require.Equal(t, c.eRes, res)
		} else {
			require.ErrorContainsf(t, err, c.eErr, "case %+v", c)
			require.Equal(t, "", res)
		}
	}
}

func TestServeProfile(t *testing.T) {
	proot, err := ioutil.TempDir("", "proot_")
	require.NoError(t, err)
	defer os.RemoveAll(proot)
	writeFile(t, proot, "p2.ovpn", "bar")

	s := NewService(proot, "")
	ts := httptest.NewServer(http.HandlerFunc(s.serveProfile))
	defer ts.Close()

	for _, c := range []struct {
		user, pass string
		eRes       int
		eTxt       string
	}{
		{"", "", 401, "Unauthorized\n"},
		{"p1", "", 401, "Unauthorized\n"},
		{"p1", "fcde2b2edba5", 401, "Unauthorized\n"},
		{"p2", "fcde2b2edba5", 200, "bar"},
		{"p1", "fcde2b2edba6", 401, "Unauthorized\n"},
	} {
		req, err := http.NewRequest("GET", ts.URL, nil)
		require.NoError(t, err)
		if c.user != "" {
			req.SetBasicAuth(c.user, c.pass)
		}
		res, err := ts.Client().Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		txt := string(body)
		require.Equalf(t, c.eRes, res.StatusCode, "case %+v", c)
		require.Containsf(t, txt, c.eTxt, "case %+v", c)
		if c.eRes == 401 {
			require.Equalf(t, res.Header.Get("WWW-Authenticate"), `Basic realm="OpenVPN", charset="utf-8"`, "case %+v", c)
		} else {
			require.Equalf(t, res.Header.Get("WWW-Authenticate"), "", "case %+v", c)
		}
	}
}

func TestServeHTTP(t *testing.T) {
	proot, err := ioutil.TempDir("", "proot_")
	require.NoError(t, err)
	defer os.RemoveAll(proot)
	writeFile(t, proot, "index.html", "OHAI")
	writeFile(t, proot, "img.png", "xx")
	writeFile(t, proot, "p2.ovpn", "bar")

	s := NewService(proot, "")
	ts := httptest.NewServer(http.HandlerFunc(s.ServeHTTP))
	defer ts.Close()

	for _, c := range []struct {
		path, user, pass string
		eRes             int
		eTxt             string
	}{
		{"/", "", "", 200, "OHAI"},
		{"/rest/GetUserlogin", "p1", "", 401, "Unauthorized"},
		{"/rest/GetUserlogin", "p2", "fcde2b2edba5", 200, "bar"},
		{"/rest/GetAutologin", "p2", "fcde2b2edba5", 200, "bar"},
		{"/p2.ovpn", "", "", 401, "Unauthorized"},
		{"/p2.ovpn", "p2", "fcde2b2edba5", 200, "bar"},
		{"/p1.ovpn", "p2", "", 400, "Bad Request"},
		{"/img.png", "", "", 200, "xx"},
		{"/../img.png", "", "", 400, "invalid URL path"},
	} {
		req, err := http.NewRequest("GET", ts.URL+c.path, nil)
		require.NoError(t, err)
		if c.user != "" {
			req.SetBasicAuth(c.user, c.pass)
		}
		res, err := ts.Client().Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		txt := string(body)
		require.Equalf(t, c.eRes, res.StatusCode, "case %+v", c)
		require.Containsf(t, txt, c.eTxt, "case %+v", c)
		if c.eRes == 401 {
			require.Equalf(t, `Basic realm="OpenVPN", charset="utf-8"`, res.Header.Get("WWW-Authenticate"), "case %+v", c)
		} else {
			require.Equalf(t, "", res.Header.Get("WWW-Authenticate"), "case %+v", c)
		}
		ct := res.Header.Get("Content-Type")
		switch c.path {
		case "/":
			require.Equalf(t, "text/html; charset=utf-8", ct, "case %+v", c)
		case "/img.png":
			require.Equalf(t, "image/png", ct, "case %+v", c)
		case "/rest/GetAutologin":
			require.Equalf(t, "text/plain; charset=utf-8", ct, "case %+v", c)
		}
	}
}
