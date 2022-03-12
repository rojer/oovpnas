FROM golang:1.17.8

ENV APP_NAME oovpnas

COPY . /go/src/${APP_NAME}
WORKDIR /go/src/${APP_NAME}

RUN go get ./
RUN go build -o ${APP_NAME}

CMD ./${APP_NAME} --logtostderr --profile-root=/go/src/${APP_NAME}/profiles --acme-challenge-root=/etc/letsencrypt --https-cert-file=/etc/letsencrypt/live/${LETS_ENCRYPT_DOMAIN_NAME}/fullchain.pem --https-key-file=/etc/letsencrypt/live/${LETS_ENCRYPT_DOMAIN_NAME}/privkey.pem

EXPOSE 80
EXPOSE 443
