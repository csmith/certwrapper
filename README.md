# certwrapper

`certwrapper` is a wrapper that requests and maintains a certificate from an ACME server (such as
Let's Encrypt) using a DNS challenge, and then runs another program that will make use of it.
The certificate is refreshed before it is due to expire, and the underlying process is SIGHUP'd.

This is designed to be used by other services that accept PEM certificates but don't have their
own way of requesting ACME certificates; it's a bit nicer than having separate scripts to manage
the process, especially if you're running the service in a container.

Usage: `certwrapper [options] /path/to/target [target options]`

Certwrapper options:

```
  -acme-email string
        E-mail address to supply to the ACME server.
  -acme-endpoint string
        ACME endpoint to request certificates from. (default "https://acme-v02.api.letsencrypt.org/directory")
  -certificate-path string
        Path to save the certificate. (default "cert/certificate.pem")
  -dns-provider string
        DNS provider to use. See https://go-acme.github.io/lego/dns/.
  -domains string
        Comma-separated list of domains to request on the certificate.
  -issuer-path string
        Path to save the issuer's certificate. (default "cert/issuer.pem")
  -key-type string
        Type of private key to use when generating a certificate. (default "P384")
  -private-key-path string
        Path to save the private key. (default "cert/privatekey.pem")
  -user-path string
        Path to save user registration data. (default "cert/user.json")
```

`acme-email`, `domains` and `dns-provider` are required options. Everything else has sensible defaults.

The dns-provider option must be set to one of the providers supported by [Lego](https://go-acme.github.io/lego/dns/).
Configuration for individual providers is done via environment variables, which are documented on the Lego provider
page.

Alternatively, `certwrapper` can be configured using environment variables prefixed with `CERTWRAPPER_`, for
example the `private-key-path` flag can be set using a `CERTWRAPPER_PRIVATE_KEY_PATH` env var. 

certwrapper will connect the target binary's stdin, stderr and stdout to its own. It will also relay any
SIGINT, SIGTERM, SIGHUP, SIGUSR1 and SIGUSR2 signals to the child process.

## Build tags

If you are building certwrapper and know in advance which DNS provider you wish to use, you can use a
build tag to eliminate all of the others. This can significantly reduce the binary size and shave
a second or two off the build times. Supported tags are:

  *  `httpreq`

Trying to use any other provider with one of these builds will result in an error.
