package main

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"html/template"
	"idp-server/auth"
	"idp-server/config"
	"idp-server/keys"
	"idp-server/metadata"
	"idp-server/saml"
	"net/http"
	"net/url"
	"os"
)

var (
	privKey *rsa.PrivateKey
	cfg     *config.Config
)

func main() {
	cfg = config.NewConfig()
	privKey = keys.LoadPrivateKey()

	http.HandleFunc("/metadata", metadataHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/auth", authHandler)

	port := os.Getenv("PORT")
	if port == "" {
		// set default port if null
		port = "3001"
	}
	fmt.Printf("IdP Server running on port %s \n", port)
	http.ListenAndServe(":"+port, nil)
}

func metadataHandler(w http.ResponseWriter, r *http.Request) {
	metadata := metadata.GetMetadata(cfg)
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(metadata))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles(cfg.TemplatePath))
	tmpl.Execute(w, struct {
		SAMLRequest string
		RelayState  string
	}{
		SAMLRequest: r.FormValue("SAMLRequest"),
		RelayState:  r.FormValue("RelayState"),
	})
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	samlRequestEncoded := r.FormValue("SAMLRequest")
	relayState := r.FormValue("RelayState")

	// validate user & pass
	if auth.ValidateCredential(username, password) {
		// Decode SAMLRequest
		samlRequestXML, _ := base64.StdEncoding.DecodeString(samlRequestEncoded)
		fmt.Println(string(samlRequestXML))
		// Generate SAML Response
		samlResponse := saml.GenerateResponse(username, privKey, cfg)
		// encode response
		samlResponseEncoded := base64.StdEncoding.EncodeToString([]byte(samlResponse))
		urlFormatString := url.QueryEscape(samlResponseEncoded)

		// Send the SAML response to the SP
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
            <form method="post" action="`+cfg.AssertUrl+`" id="samlForm">
                <input type="hidden" name="SAMLResponse" value="%s">
                <input type="hidden" name="RelayState" value="%s">
            </form>
            <script>
                document.getElementById("samlForm").submit();
            </script>
        `, urlFormatString, relayState)

		// DEBUG SAML RESPONSE XML
		// samlResponseXML, _ := base64.StdEncoding.DecodeString(samlResponseEncoded)
		// fmt.Println(string(samlResponseXML))
	} else {
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusFound)
	}
}
