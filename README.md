# Open OpenVPN Access Server

## Overview

This server implements some of the APIs of the OpenVPN Access Server.

Currently just the bare minimum required to import profiles via URL is implemented.

## Description

This server serves OpenVPN profiles (`.ovpn` files) to users over HTTP(S) and XMLRPC2 (used by Android and iOS apps).

Files can be retrieved via HTTP(S) by requesting `/PROFILE.ovpn`.

Alternatively, profiles can be reteieved over the XMLRPC2 interface - this is what the Android and iOS apps use for URL imports.

In order to retrieve the file user must authenticate. Name of the profile should be used as the user name and first 12 (or more) characters of the hexadecimal representation of the SHA256 sum of the contents of the profile are the password.
For example, to retrieve `CLIENT1.ovpn` with SHA256 hash `ad81f87be989eb1d41e95f7e1b898181a281a7c61cb9fbd2bab978b84e2b3388` user must use `CLIENT1` as the user name and (at least) `ad81f87be989` as password.

The server also provides the necessary functionality to serve ACME TLS certificate challenges and static content for a simple web interface (any files not ending in `.ovpn` are served without authentication and `index.html` is the index file name).

## Usage Example

```
$ go get github.com/rojer/oovpnas
$ oovpnas --logtostderr --profile-root=/path/to/ovpn/files --acme-challenge-root=/etc/letsencrypt --https-cert-file=/etc/letsencrypt/live/XXX/fullchain.pem --https-key-file=/etc/letsencrypt/live/XXX/privkey.pem
```

### Docker usage
```
$ git clone https://github.com/rojer/oovpnas.git
$ docker-compose up --build --detach
```

## License

Apache 2, see [LICENSE](LICENSE).
