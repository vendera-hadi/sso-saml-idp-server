package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"idp-server/config"
	"idp-server/utils"
	"time"

	"github.com/beevik/etree"
)

func GenerateResponse(username string, privKey *rsa.PrivateKey, cfg *config.Config) string {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	response := doc.CreateElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	response.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	response.CreateAttr("ID", "_"+utils.GenerateID())
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))
	response.CreateAttr("Destination", "http://localhost:3000/assert")
	response.CreateElement("saml:Issuer").SetText(cfg.EntityID)

	status := response.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

	assertion := response.CreateElement("saml:Assertion")
	assertion.CreateAttr("ID", "_"+utils.GenerateID())
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", time.Now().UTC().Format(time.RFC3339))

	issuer := assertion.CreateElement("saml:Issuer")
	issuer.SetText(cfg.EntityID)

	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nameID.SetText(username)

	subjectConfirmation := subject.CreateElement("saml:SubjectConfirmation")
	subjectConfirmation.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	subjectConfirmationData := subjectConfirmation.CreateElement("saml:SubjectConfirmationData")
	subjectConfirmationData.CreateAttr("InResponseTo", "_"+utils.GenerateID())
	subjectConfirmationData.CreateAttr("NotOnOrAfter", time.Now().UTC().Add(time.Minute*time.Duration(cfg.ResponseLimit)).Format(time.RFC3339))
	subjectConfirmationData.CreateAttr("Recipient", cfg.AssertUrl)

	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", time.Now().UTC().Format(time.RFC3339))
	conditions.CreateAttr("NotOnOrAfter", time.Now().UTC().Add(time.Minute*time.Duration(cfg.ResponseLimit)).Format(time.RFC3339))

	audienceRestriction := conditions.CreateElement("saml:AudienceRestriction")
	audience := audienceRestriction.CreateElement("saml:Audience")
	audience.SetText(cfg.SpEntityID)

	// add username
	attributeStatement := assertion.CreateElement("saml:AttributeStatement")
	attribute := attributeStatement.CreateElement("saml:Attribute")
	attribute.CreateAttr("Name", "Username")
	attributeValue := attribute.CreateElement("saml:AttributeValue")
	attributeValue.SetText(username)

	// MANIPULATE THIS TO PASS ANOTHER ATTRIBUTE VALUES
	// Add Birthdate attribute
	// attribute = attributeStatement.CreateElement("saml:Attribute")
	// attribute.CreateAttr("Name", "Birthdate")
	// attributeValue = attribute.CreateElement("saml:AttributeValue")
	// attributeValue.SetText(birthdate)

	// Add Address attribute
	// attribute = attributeStatement.CreateElement("saml:Attribute")
	// attribute.CreateAttr("Name", "Address")
	// attributeValue = attribute.CreateElement("saml:AttributeValue")
	// attributeValue.SetText(address)

	// Add Picture attribute
	// attribute = attributeStatement.CreateElement("saml:Attribute")
	// attribute.CreateAttr("Name", "Picture")
	// attributeValue = attribute.CreateElement("saml:AttributeValue")
	// attributeValue.SetText(picture)

	authnStatement := assertion.CreateElement("saml:AuthnStatement")
	authnStatement.CreateAttr("AuthnInstant", time.Now().UTC().Format(time.RFC3339))
	authnContext := authnStatement.CreateElement("saml:AuthnContext")
	authnContextClassRef := authnContext.CreateElement("saml:AuthnContextClassRef")
	authnContextClassRef.SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	doc.Indent(2)

	// Sign the SAML response
	signedResponse, err := signResponse(doc, privKey)
	if err != nil {
		panic(err)
	}

	return string(signedResponse)
}

// signResponse signs the SAML response using the IdP's private key and embeds the signature.
func signResponse(doc *etree.Document, key *rsa.PrivateKey) ([]byte, error) {
	response := doc.FindElement("samlp:Response")
	// Create SignedInfo element
	signedInfo := etree.NewElement("ds:SignedInfo")
	signedInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	canonicalizationMethod := signedInfo.CreateElement("ds:CanonicalizationMethod")
	canonicalizationMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

	signatureMethod := signedInfo.CreateElement("ds:SignatureMethod")
	signatureMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

	reference := signedInfo.CreateElement("ds:Reference")
	reference.CreateAttr("URI", "#"+response.SelectAttrValue("ID", ""))

	transforms := reference.CreateElement("ds:Transforms")
	transform := transforms.CreateElement("ds:Transform")
	transform.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
	transform2 := transforms.CreateElement("ds:Transform")
	transform2.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

	digestMethod := reference.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

	// Canonicalize the response and compute digest value
	canonicalResponse, err := utils.Canonicalize(response)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(canonicalResponse))
	digestValue := reference.CreateElement("ds:DigestValue")
	digestValue.SetText(base64.StdEncoding.EncodeToString(hash[:]))

	// Sign the SignedInfo element
	canonicalSignedInfo, err := utils.Canonicalize(signedInfo)
	if err != nil {
		return nil, err
	}
	sigHash := sha256.Sum256([]byte(canonicalSignedInfo))
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sigHash[:])
	if err != nil {
		return nil, err
	}

	// Create Signature element
	signatureElement := response.CreateElement("ds:Signature")
	signatureElement.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	// Append SignedInfo to Signature
	signatureElement.AddChild(signedInfo)

	// Append SignatureValue to Signature
	signatureValueElement := signatureElement.CreateElement("ds:SignatureValue")
	fmt.Println(string(signature))
	signatureValueElement.SetText(base64.StdEncoding.EncodeToString(signature))

	doc.Indent(2)
	return doc.WriteToBytes()
}
