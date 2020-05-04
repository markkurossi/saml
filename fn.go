//
// fn.go
//
// Copyright (c) 2020 Markku Rossi
//
// All rights reserved.
//

package saml

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"

	api "github.com/markkurossi/cloudsdk/api/auth"
	"github.com/markkurossi/cloudsdk/api/secretmanager"
	"github.com/markkurossi/go-libs/fn"
)

var (
	mux            *http.ServeMux
	projectID      string
	store          *api.ClientStore
	secretManager  *secretmanager.Client
	clientIDSecret []byte
	signatureKey   ed25519.PrivateKey
)

func Fatalf(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	os.Exit(1)
}

func init() {
	mux = http.NewServeMux()
	mux.Handle("/", SAMLHandler())

	id, err := fn.GetProjectID()
	if err != nil {
		Fatalf("GetProjectID: %s\n", err)
	}
	projectID = id

	store, err = api.NewClientStore()
	if err != nil {
		Fatalf("NewClientStore: %s\n", err)
	}
	secretManager, err = secretmanager.NewClient()
	if err != nil {
		Fatalf("NewVault: %s\n", err)
	}
	clientIDSecret, err = secretManager.Get(api.KEY_CLIENT_ID_SECRET, "")
	if err != nil {
		Fatalf("Failed to get secret %s: %s\n", api.KEY_CLIENT_ID_SECRET, err)
	}
	data, err := secretManager.Get(api.KEY_TOKEN_SIGNATURE_KEY, "")
	if err != nil {
		Fatalf("Failed to get secret %s: %s\n",
			api.KEY_TOKEN_SIGNATURE_KEY, err)
	}
	signatureKey = ed25519.PrivateKey(data)
}

func SAML(w http.ResponseWriter, r *http.Request) {
	mux.ServeHTTP(w, r)
}
