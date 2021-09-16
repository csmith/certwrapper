//go:build httpreq
package main

import (
	"fmt"
	"strings"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/httpreq"
)

func (c *CertificateManager) createProvider() (challenge.Provider, error) {
	if strings.ToLower(c.dnsProvider) != "httpreq" {
		return nil, fmt.Errorf("this build of certwrapper only supports `httpreq` as a provider")
	}
	return httpreq.NewDNSProvider()
}
