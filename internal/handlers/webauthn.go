package handlers

import (
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/sirupsen/logrus"
)

var web *webauthn.WebAuthn

func init() {
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Authelia",                       // Display Name for your site
		RPID:          "example.com",                    // Generally the FQDN for your site
		RPOrigin:      "https://login.example.com:8080", // The origin URL for WebAuthn requests
	})
	if err != nil {
		logrus.Panic(err)
	}

	web = w
}
