package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"os"
	"time"

	"github.com/csmith/legotapas"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type AcmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration,omitempty"`
	LiveKey      *ecdsa.PrivateKey      `json:"-"`
	Key          []byte                 `json:"key"`
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}
func (u AcmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *AcmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.LiveKey
}

type CertificateManager struct {
	acmeProvider string
	keyType      certcrypto.KeyType
	dnsProvider  string
	client       *lego.Client
	user         *AcmeUser
	domains      []string

	metadataPath    string
	privateKeyPath  string
	certificatePath string
	issuerCertPath  string
}

func NewCertificateManager(keyType certcrypto.KeyType, acmeProvider, dnsProvider, metadataPath, privateKeyPath, certificatePath, issuerCertPath, email string, domains []string) (*CertificateManager, error) {
	c := &CertificateManager{
		acmeProvider: acmeProvider,
		keyType:      keyType,
		dnsProvider:  dnsProvider,
		domains:      domains,

		metadataPath:    metadataPath,
		privateKeyPath:  privateKeyPath,
		certificatePath: certificatePath,
		issuerCertPath:  issuerCertPath,
	}

	if err := c.load(); err != nil {
		return nil, err
	}

	if err := c.createUser(email); err != nil {
		return nil, err
	}

	if err := c.createClient(); err != nil {
		return nil, err
	}

	if err := c.register(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *CertificateManager) load() error {
	user := &AcmeUser{}
	buf, _ := ioutil.ReadFile(c.metadataPath)
	if buf != nil {
		err := json.Unmarshal(buf, user)
		if err != nil {
			return err
		}

		if user.Key != nil {
			liveKey, err := x509.ParseECPrivateKey(user.Key)
			if err != nil {
				return err
			}
			user.LiveKey = liveKey
		}
	}
	c.user = user
	return nil
}

func (c *CertificateManager) save() error {
	data, err := json.Marshal(c.user)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(c.metadataPath, data, 0600)
}

func (c *CertificateManager) createUser(email string) error {
	if c.user == nil || c.user.Key == nil {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}

		marshaled, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return err
		}

		c.user = &AcmeUser{
			LiveKey: privateKey,
			Key:     marshaled,
			Email:   email,
		}
		return c.save()
	}
	return nil
}

func (c *CertificateManager) createClient() error {
	config := lego.NewConfig(c.user)

	config.CADirURL = c.acmeProvider
	config.Certificate.KeyType = c.keyType

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	provider, err := legotapas.CreateProvider(c.dnsProvider)
	if err != nil {
		return err
	}

	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return err
	}

	c.client = client
	return nil
}

func (c *CertificateManager) register() error {
	if c.user.Registration == nil {
		reg, err := c.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
		c.user.Registration = reg
		return c.save()
	}
	return nil
}

func (c *CertificateManager) ObtainCertificate() error {
	request := certificate.ObtainRequest{
		Domains: c.domains,
		Bundle:  true,
	}

	cert, err := c.client.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(c.certificatePath, cert.Certificate, os.FileMode(0600)); err != nil {
		return err
	}

	if err := ioutil.WriteFile(c.privateKeyPath, cert.PrivateKey, os.FileMode(0600)); err != nil {
		return err
	}

	if err := ioutil.WriteFile(c.issuerCertPath, cert.IssuerCertificate, os.FileMode(0600)); err != nil {
		return err
	}

	return nil
}

func (c *CertificateManager) NeedsCertificate() bool {
	b, err := ioutil.ReadFile(c.certificatePath)
	if err != nil {
		return true
	}

	pem, err := certcrypto.ParsePEMCertificate(b)
	if err != nil {
		return true
	}

	return pem.NotAfter.Before(time.Now().AddDate(0, 0, 30))
}

func (c *CertificateManager) getExpiry(cert *certificate.Resource) time.Time {
	pem, err := certcrypto.ParsePEMCertificate(cert.Certificate)
	if err != nil {
		// Ruh roh. Say it's expired so we'll get a new one...
		return time.Time{}
	}

	return pem.NotAfter
}
