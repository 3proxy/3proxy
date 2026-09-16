# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.9.8   | :white_check_mark: |
| < 0.9.8 | :x:                |

## Hardening a deployment

Configuration is where most of the risk lives. The security recommendations are
kept in [doc/html/securityen.html](doc/html/securityen.html), published at
<https://3proxy.org/securityen.html>: how to run the service, what the
ACLs have to cover, and the settings whose defaults are safe only until
something else is enabled alongside them.

Read it before exposing a service. Recurring points from it:

- Run unprivileged, never suid, and chroot where the platform allows.
- Name the internal and external interfaces explicitly, and limit sources and
  destinations with ACLs rather than relying on defaults.
- Enabling IPv6 makes ACLs written in IPv4 incomplete: the same host is
  reachable through an IPv4-mapped address, and the IPv6 loopback is an
  address of its own.
- Anything that terminates or intercepts TLS holds key material and sees full
  request URLs; both the key and the logs need protecting.

## Reporting a Vulnerability

Report to 3proxy@3proxy.org or via [GitHub security reporting](https://github.com/3proxy/3proxy/security)

For High/Critical patched version is released within 2 weeks

## Verifying downloads

Release binaries and the source tarball are published with SHA256 checksums, an
OpenPGP signature and a GitHub build provenance attestation.

The release signing key is `3proxy-release-key.asc` in the root of this
repository, an RSA-4096 key:

```
pub   rsa4096 2026-08-21 [SC]
      FC12 2144 99FC C7BA 1CFF  6CDC 0312 384E 3A73 940B
uid   3proxy release signing <3proxy@3proxy.org>
```

Import it once:

```
gpg --import 3proxy-release-key.asc
```

Checksums and the checksum file signature:

```
gpg --verify SHA256SUMS-x86_64.asc SHA256SUMS-x86_64
sha256sum -c SHA256SUMS-x86_64
```

The source tarball published with each release is signed as well:

```
gpg --verify SHA256SUMS-src.asc SHA256SUMS-src
sha256sum -c SHA256SUMS-src
gpg --verify 3proxy-0.9.9.tar.gz.asc 3proxy-0.9.9.tar.gz
```

Prefer it over the `Source code (tar.gz)` link GitHub generates automatically:
only the published tarball is signed. It is produced with `git archive` from
the release tag, so it can be regenerated and compared byte for byte.

RPM packages are signed, the signature is checked by rpm itself:

```
sudo rpm --import 3proxy-release-key.asc
rpm -K 3proxy-0.9.9.x86_64.rpm
```

DEB packages are published with a detached signature:

```
gpg --verify 3proxy-0.9.9.x86_64.deb.asc 3proxy-0.9.9.x86_64.deb
```

Build provenance (which workflow, commit and runner produced the file) is
verified with the GitHub CLI:

```
gh attestation verify 3proxy-0.9.9.x86_64.rpm --owner 3proxy
gh attestation verify oci://docker.io/3proxy/3proxy:latest --owner 3proxy
```
