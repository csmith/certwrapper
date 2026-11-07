package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/csmith/legotapas/v2"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

type registrationResource struct {
	Body acme.Account `json:"body"`
	URI  string       `json:"uri,omitempty"`
}

func (r *registrationResource) toExtendedAccount() *acme.ExtendedAccount {
	if r == nil {
		return nil
	}
	return &acme.ExtendedAccount{
		Account:  r.Body,
		Location: r.URI,
	}
}

func newRegistrationResource(ea *acme.ExtendedAccount) *registrationResource {
	if ea == nil {
		return nil
	}
	return &registrationResource{
		Body: ea.Account,
		URI:  ea.Location,
	}
}

type AcmeUser struct {
	Email        string                `json:"email"`
	Registration *registrationResource `json:"registration,omitempty"`
	LiveKey      *ecdsa.PrivateKey     `json:"-"`
	Key          []byte                `json:"key"`
}

func (u *AcmeUser) GetEmail() string {
	return u.Email
}
func (u *AcmeUser) GetRegistration() *acme.ExtendedAccount {
	return u.Registration.toExtendedAccount()
}
func (u *AcmeUser) GetPrivateKey() crypto.Signer {
	return u.LiveKey
}

type CertificateManager struct {
	acmeProvider string
	keyType      certcrypto.KeyType
	dnsProvider  challenge.Provider
	client       *lego.Client
	user         *AcmeUser
	domains      []string

	metadataPath    string
	privateKeyPath  string
	certificatePath string
	issuerCertPath  string
}

func NewCertificateManager(
	keyType certcrypto.KeyType,
	acmeProvider, dnsProviderName, metadataPath, privateKeyPath, certificatePath, issuerCertPath, email string,
	domains []string,
) (*CertificateManager, error) {
	dnsProvider, err := legotapas.CreateProvider(dnsProviderName)
	if err != nil {
		return nil, err
	}

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

	return c, nil
}

func (c *CertificateManager) ObtainCertificate() error {
	if err := c.connect(); err != nil {
		return err
	}

	request := certificate.ObtainRequest{
		Domains: c.domains,
		Bundle:  true,
		KeyType: c.keyType,
	}

	cert, err := c.client.Certificate.Obtain(context.Background(), request)
	if err != nil {
		return err
	}

	if err := writeFileAtomic(c.privateKeyPath, cert.PrivateKey); err != nil {
		return err
	}

	if err := writeFileAtomic(c.certificatePath, cert.Certificate); err != nil {
		return err
	}

	return writeFileAtomic(c.issuerCertPath, cert.IssuerCertificate)
}

func (c *CertificateManager) NeedsCertificate() bool {
	cert, err := c.loadCertificate()
	if err != nil {
		return true
	}

	return time.Until(cert.NotAfter) < cert.NotAfter.Sub(cert.NotBefore)/3
}

func (c *CertificateManager) HasValidCertificate() bool {
	cert, err := c.loadCertificate()
	if err != nil {
		return false
	}

	now := time.Now()
	return !now.Before(cert.NotBefore) && now.Before(cert.NotAfter)
}

// connect is deferred until a certificate is needed, as creating the client contacts the ACME
// server and an existing certificate should remain usable while that server is unavailable.
func (c *CertificateManager) connect() error {
	if c.client == nil {
		if err := c.createClient(); err != nil {
			return err
		}
	}

	return c.register()
}

// loadCertificate fails if the private key on disk doesn't match the certificate.
func (c *CertificateManager) loadCertificate() (*x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(c.certificatePath, c.privateKeyPath)
	if err != nil {
		return nil, err
	}

	return pair.Leaf, nil
}

func (c *CertificateManager) load() error {
	user := &AcmeUser{}
	buf, _ := os.ReadFile(c.metadataPath)
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
	return writeFileAtomic(c.metadataPath, data)
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

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	err = client.Challenge.SetDNS01Provider(c.dnsProvider)
	if err != nil {
		return err
	}

	c.client = client
	return nil
}

func (c *CertificateManager) register() error {
	if c.user.Registration == nil {
		opts := registration.RegisterOptions{TermsOfServiceAgreed: true}
		reg, err := c.client.Registration.Register(context.Background(), opts)
		if err != nil {
			return err
		}
		c.user.Registration = newRegistrationResource(reg)
		return c.save()
	}
	return nil
}

// writeFileAtomic replaces path with a new file with 0600 permissions, leaving any existing file
// untouched if the write fails. The path's directory must be writable.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}

	if err := tmp.Sync(); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}
