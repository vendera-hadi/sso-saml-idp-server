package utils

import (
	"fmt"
	"time"

	"github.com/beevik/etree"
)

// canonicalize converts the XML element to a canonicalized form for signing.
func Canonicalize(element *etree.Element) (string, error) {
	doc := etree.NewDocument()
	doc.SetRoot(element.Copy())
	doc.WriteSettings = etree.WriteSettings{
		CanonicalEndTags: true,
		CanonicalText:    true,
		CanonicalAttrVal: true,
	}
	doc.Indent(0)
	return doc.WriteToString()
}

func GenerateID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
