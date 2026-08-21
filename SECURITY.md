# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.9.8   | :white_check_mark: |
| < 0.9.8 | :x:                |

## Reporting a Vulnerability

Report to 3proxy@3proxy.org or via [GitHub security reporting](https://github.com/3proxy/3proxy/security)

For High/Critical patched version is released within 2 weeks

## Verifying downloads

Release binaries are published with SHA256 checksums, an OpenPGP signature and
a GitHub build provenance attestation.

The release signing key is `3proxy-release-key.asc` in the root of this
repository. Import it once:

```
gpg --import 3proxy-release-key.asc
```

Checksums and the checksum file signature:

```
gpg --verify SHA256SUMS-x86_64.asc SHA256SUMS-x86_64
sha256sum -c SHA256SUMS-x86_64
```

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
gh attestation verify oci://docker.io/3proxy/3proxy:lts --owner 3proxy
```

Windows binaries are Authenticode signed in addition to the above.
