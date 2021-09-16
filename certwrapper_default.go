//go:build !httpreq
package main

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
)

func (c *CertificateManager) createProvider() (challenge.Provider, error) {
	return dns.NewDNSChallengeProviderByName(c.dnsProvider)
}
