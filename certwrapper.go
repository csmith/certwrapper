package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/peterbourgon/ff/v3"
	"golang.org/x/sys/unix"
)

var (
	keyType         = flag.String("key-type", "P384", "Type of private key to use when generating a certificate.")
	acmeEndpoint    = flag.String("acme-endpoint", "https://acme-v02.api.letsencrypt.org/directory", "ACME endpoint to request certificates from.")
	dnsProvider     = flag.String("dns-provider", "", "DNS provider to use. See https://go-acme.github.io/lego/dns/.")
	userPath        = flag.String("user-path", "cert/user.json", "Path to save user registration data.")
	privateKeyPath  = flag.String("private-key-path", "cert/privatekey.pem", "Path to save the private key.")
	certificatePath = flag.String("certificate-path", "cert/certificate.pem", "Path to save the certificate.")
	issuerCertPath  = flag.String("issuer-path", "cert/issuer.pem", "Path to save the issuer's certificate.")
	acmeEmail       = flag.String("acme-email", "", "E-mail address to supply to the ACME server.")
	domains         = flag.String("domains", "", "Comma-separated list of domains to request on the certificate.")
)

func parseFlags() {
	if err := ff.Parse(flag.CommandLine, os.Args[1:], ff.WithEnvVarPrefix("CERTWRAPPER")); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse flags: %v\n\n", err)
		flag.Usage()
		os.Exit(1)
	}

	if *dnsProvider == "" {
		fmt.Fprintf(os.Stderr, "DNS provider must be configured\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if *domains == "" {
		fmt.Fprintf(os.Stderr, "Domains must be configured\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if *acmeEmail == "" {
		fmt.Fprintf(os.Stderr, "ACME e-mail address must be configured\n\n")
		flag.Usage()
		os.Exit(1)
	}
}

func main() {
	parseFlags()
	checkFilePermissions()

	cm, err := NewCertificateManager(
		certcrypto.KeyType(*keyType),
		*acmeEndpoint,
		*dnsProvider,
		*userPath,
		*privateKeyPath,
		*certificatePath,
		*issuerCertPath,
		*acmeEmail,
		strings.Split(*domains, ","),
	)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create certificate manager: %v\n", err)
		os.Exit(2)
	}

	// See if we need to get a certificate before starting the process
	if cm.NeedsCertificate() {
		if err := cm.ObtainCertificate(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to obtain certificate: %v\n", err)
			os.Exit(3)
		}
	}

	args := flag.Args()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to run application: %v\n", err)
		os.Exit(4)
	}

	go waitForCommandToExit(cmd)
	go monitorCertificate(cm, cmd)
	proxySignals(cmd)
}

func proxySignals(cmd *exec.Cmd) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	for {
		sig := <-sigs
		if err := cmd.Process.Signal(sig); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to signal child process: %v\n", err)
			os.Exit(7)
		}
	}
}

func waitForCommandToExit(cmd *exec.Cmd) {
	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "Application failed: %v\n", err)
		os.Exit(5)
	}

	os.Exit(0)
}

func checkCertificate(cm *CertificateManager, cmd *exec.Cmd) {
	if cm.NeedsCertificate() {
		if err := cm.ObtainCertificate(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to obtain certificate: %v\n", err)
			os.Exit(6)
		}

		if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to signal child process: %v\n", err)
			os.Exit(7)
		}
	}
}

func monitorCertificate(cm *CertificateManager, cmd *exec.Cmd) {
	ticker := time.NewTicker(time.Hour * 24)
	for {
		select {
		case <-ticker.C:
			checkCertificate(cm, cmd)
		}
	}
}

func checkFilePermissions() {
	canWrite := func(p string) bool {
		return syscall.Access(p, unix.W_OK) == nil
	}

	paths := []string {
		*userPath,
		*privateKeyPath,
		*certificatePath,
		*issuerCertPath,
	}
	for i := range paths {
		if !canWrite(paths[i]) {
			fmt.Fprintf(os.Stderr, "Insufficient permissions to write to path: %s", paths[i])
			os.Exit(8)
		}
	}
}
