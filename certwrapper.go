package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/csmith/envflag/v2"
	"github.com/csmith/slogflags"
	"github.com/go-acme/lego/v5/certcrypto"
	legolog "github.com/go-acme/lego/v5/log"
	"golang.org/x/sys/unix"
)

const renewalCheckInterval = time.Hour

var (
	keyType = flag.String(
		"key-type",
		"EC384",
		"Type of private key to use when generating a certificate. One of: "+keyTypeNames()+".",
	)
	acmeEndpoint = flag.String(
		"acme-endpoint",
		"https://acme-v02.api.letsencrypt.org/directory",
		"ACME endpoint to request certificates from.",
	)
	dnsProvider     = flag.String("dns-provider", "", "DNS provider to use. See https://go-acme.github.io/lego/dns/.")
	userPath        = flag.String("user-path", "cert/user.json", "Path to save user registration data.")
	privateKeyPath  = flag.String("private-key-path", "cert/privatekey.pem", "Path to save the private key.")
	certificatePath = flag.String("certificate-path", "cert/certificate.pem", "Path to save the certificate.")
	issuerCertPath  = flag.String("issuer-path", "cert/issuer.pem", "Path to save the issuer's certificate.")
	acmeEmail       = flag.String("acme-email", "", "E-mail address to supply to the ACME server.")
	domains         = flag.String("domains", "", "Comma-separated list of domains to request on the certificate.")
	stripEnv        = flag.String(
		"strip-env",
		"",
		"Comma-separated list of environment variables to withhold from the target, such as DNS provider credentials. "+
			"A trailing * matches any variable starting with the preceding text.",
	)
)

func parseFlags() certcrypto.KeyType {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(
			flag.CommandLine.Output(),
			"Usage: %s [options] /path/to/target [target options]\n\nOptions:\n",
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	envflag.Parse(envflag.WithPrefix("CERTWRAPPER_"))

	// lego logs to stdout by default, which the target shares.
	legolog.SetDefault(slogflags.Logger(slogflags.WithSetDefault(true), slogflags.WithWriter(os.Stderr)))

	kt, err := parseKeyType(*keyType)
	if err != nil {
		usageError("Key type is not supported", "key_type", *keyType)
	}

	if *dnsProvider == "" {
		usageError("DNS provider must be configured")
	}

	if *domains == "" {
		usageError("Domains must be configured")
	}

	if *acmeEmail == "" {
		usageError("ACME e-mail address must be configured")
	}

	return kt
}

func usageError(msg string, args ...any) {
	slog.Error(msg, args...)
	flag.Usage()
	os.Exit(1)
}

// parseKeyType also accepts the names used by certwrapper v4, so existing configuration keeps working.
func parseKeyType(name string) (certcrypto.KeyType, error) {
	legacy := map[string]certcrypto.KeyType{
		"P256": certcrypto.EC256,
		"P384": certcrypto.EC384,
		"2048": certcrypto.RSA2048,
		"3072": certcrypto.RSA3072,
		"4096": certcrypto.RSA4096,
		"8192": certcrypto.RSA8192,
	}
	if kt, ok := legacy[strings.ToUpper(name)]; ok {
		return kt, nil
	}
	return certcrypto.ToKeyType(name)
}

func keyTypeNames() string {
	keyTypes := certcrypto.AllKeyTypes()
	names := make([]string, 0, len(keyTypes))
	for _, kt := range keyTypes {
		names = append(names, string(kt))
	}
	return strings.Join(names, ", ")
}

func main() {
	kt := parseFlags()
	checkFilePermissions()

	cm, err := NewCertificateManager(
		kt,
		*acmeEndpoint,
		*dnsProvider,
		*userPath,
		*privateKeyPath,
		*certificatePath,
		*issuerCertPath,
		*acmeEmail,
		splitDomains(*domains),
	)

	if err != nil {
		slog.Error("Failed to create certificate manager", "error", err)
		os.Exit(2)
	}

	if err := ensureCertificate(cm); err != nil {
		slog.Error("Failed to obtain certificate", "error", err)
		os.Exit(3)
	}

	args := flag.Args()
	if len(args) == 0 {
		usageError("Target command must be specified")
	}

	cmd := exec.CommandContext(context.Background(), args[0], args[1:]...)
	cmd.Env = childEnv(os.Environ(), append(strings.Split(*stripEnv, ","), "CERTWRAPPER_*"))
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		slog.Error("Failed to run application", "error", err)
		os.Exit(4)
	}

	go waitForCommandToExit(cmd)
	go monitorCertificate(cm, cmd)
	proxySignals(cmd)
}

func splitDomains(list string) []string {
	var res []string
	for domain := range strings.SplitSeq(list, ",") {
		if domain = strings.TrimSpace(domain); domain != "" {
			res = append(res, domain)
		}
	}
	return res
}

// childEnv returns environ without the variables matching any of the patterns.
func childEnv(environ, patterns []string) []string {
	// A nil Env makes exec.Cmd inherit the whole environment, so this must never be nil.
	env := []string{}
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.ContainsFunc(patterns, func(pattern string) bool { return envMatches(name, pattern) }) {
			env = append(env, kv)
		}
	}
	return env
}

func envMatches(name, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(name, prefix)
	}
	return pattern != "" && name == pattern
}

func proxySignals(cmd *exec.Cmd) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	for {
		sig := <-sigs
		if err := cmd.Process.Signal(sig); err != nil {
			slog.Error("Failed to signal child process", "error", err)
			os.Exit(7)
		}
	}
}

func waitForCommandToExit(cmd *exec.Cmd) {
	if err := cmd.Wait(); err != nil {
		slog.Error("Application failed", "error", err)
		os.Exit(5)
	}

	os.Exit(0)
}

type certificateRenewer interface {
	NeedsCertificate() bool
	HasValidCertificate() bool
	ObtainCertificate() error
}

// ensureCertificate only returns an error if there's no certificate the child process could use.
func ensureCertificate(cm certificateRenewer) error {
	if !cm.NeedsCertificate() {
		return nil
	}

	err := cm.ObtainCertificate()
	if err != nil && cm.HasValidCertificate() {
		slog.Warn("Failed to renew certificate, using the existing one", "error", err, "retry_in", renewalCheckInterval)
		return nil
	}
	return err
}

func checkCertificate(cm certificateRenewer, reload func() error) {
	if !cm.NeedsCertificate() {
		return
	}

	if err := cm.ObtainCertificate(); err != nil {
		slog.Error("Failed to renew certificate", "error", err, "retry_in", renewalCheckInterval)
		return
	}

	if err := reload(); err != nil {
		slog.Error("Failed to signal child process", "error", err)
		os.Exit(7)
	}
}

func monitorCertificate(cm certificateRenewer, cmd *exec.Cmd) {
	reload := func() error {
		return cmd.Process.Signal(syscall.SIGHUP)
	}

	for range time.Tick(renewalCheckInterval) {
		checkCertificate(cm, reload)
	}
}

func checkFilePermissions() {
	paths := []string{
		*userPath,
		*privateKeyPath,
		*certificatePath,
		*issuerCertPath,
	}
	for i := range paths {
		if err := canReplaceFile(paths[i]); err != nil {
			slog.Error("Unable to replace file", "path", paths[i], "error", err)
			os.Exit(8)
		}
	}
}

func canReplaceFile(path string) error {
	if err := syscall.Access(filepath.Dir(path), unix.W_OK|unix.X_OK); err != nil {
		return err
	}

	mounted, err := isMountPoint(path)
	if err != nil {
		return err
	}
	if mounted {
		return errors.New("the file is a mount point, so it can't be replaced; mount its directory instead")
	}
	return nil
}
