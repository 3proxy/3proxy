# 3APA3A 3proxy tiny proxy server

(c) 2002-2025 by Vladimir '3APA3A' Dubrovin <3APA3A@security.nnov.ru>

## Branches

- **Master** (stable) branch - 3proxy 0.9
- **Devel** branch - 3proxy 10 (don't use it)

## Download

Binaries and sources for released (master) versions (Windows, Linux):
https://github.com/z3APA3A/3proxy/releases

Docker images:
https://hub.docker.com/r/3proxy/3proxy

Archive of old versions:
https://github.com/z3APA3A/3proxy-archive

## Documentation

Documentation (man pages and HTML) available with download, on https://3proxy.org/ and in github wiki https://github.com/3proxy/3proxy/wiki

## Windows Installation

Install and start proxy as Windows service:

```bash
3proxy [path_to_config_file] --install
```

Config file should be located in the same directory or may be optionally specified.

Remove the service (should be stopped before via `net stop 3proxy`):

```bash
3proxy --remove
```

## Building on Linux

### With Makefile

```bash
git clone https://github.com/z3apa3a/3proxy
cd 3proxy
ln -s Makefile.Linux Makefile
make
sudo make install
```

### Default Configuration (Linux/Unix)

3proxy uses 2 configuration files:
- `/etc/3proxy/3proxy.cfg` (before-chroot) - This configuration file is executed before chroot and should not be modified.
- `/usr/local/3proxy/conf/3proxy.cfg` symlinked from `/etc/3proxy/conf/3proxy.cfg` (after-chroot) - Main configuration file. Modify this file if required.

All paths in `/usr/local/3proxy/conf/3proxy.cfg` are relative to chroot directory (`/usr/local/3proxy`). For future versions it's planned to move 3proxy chroot directory to `/var`.

Log files are created in `/usr/local/3proxy/logs` symlinked from `/var/log/3proxy`.

By default, socks is started on 0.0.0.0:1080 and proxy on 0.0.0.0:3128 with basic auth, no users are added by default.

### Adding Users

Use `/etc/3proxy/conf/add3proxyuser.sh` script to add users:

```bash
/etc/3proxy/conf/add3proxyuser.sh username password [day_limit] [bandwidth]
```

Parameters:
- `day_limit` - traffic limit in MB per day
- `bandwidth` - bandwidth in bits per second (1048576 = 1Mbps)

Or modify `/etc/3proxy/conf/` files directly.

### With CMake

```bash
git clone https://github.com/z3apa3a/3proxy
cd 3proxy
mkdir build && cd build
cmake ..
cmake --build .
sudo cmake --install .
```

CMake does not use chroot configuration, config file is `/etc/3proxy/3proxy.cfg`

## MacOS X / FreeBSD / *BSD

### With Makefile

```bash
git clone https://github.com/z3apa3a/3proxy
cd 3proxy
ln -s Makefile.FreeBSD Makefile
make
```

Binaries are in `bin/` directory.

### With CMake (recommended)

```bash
git clone https://github.com/z3apa3a/3proxy
cd 3proxy
mkdir build && cd build
cmake ..
cmake --build .
sudo cmake --install .
```

This installs:
- Binaries to `/usr/local/bin/`
- Configuration to `/etc/3proxy/`
- Plugins to `/usr/local/lib/3proxy/`
- rc scripts to `rc.d` for BSD
- launchd plist to `/Library/LaunchDaemons/` for MacOS

### Service Management on macOS

```bash
# Load and start service
sudo launchctl load /Library/LaunchDaemons/org.3proxy.3proxy.plist

# Stop service
sudo launchctl stop org.3proxy.3proxy

# Start service
sudo launchctl start org.3proxy.3proxy

# Unload and disable service
sudo launchctl unload /Library/LaunchDaemons/org.3proxy.3proxy.plist
```

## Features

### 1. General

- IPv4 / IPv6 support for incoming and outgoing connection, can be used as a proxy between IPv4 and IPv6 networks in either direction
- Unix domain sockets support
- HTTP/1.1 Proxy with keep-alive client and server support, transparent proxy support
- HTTPS (CONNECT) proxy (compatible with HTTP/2 / SPDY)
- Anonymous and random client IP emulation for HTTP proxy mode
- FTP over HTTP support
- DNS caching with built-in resolver
- DNS proxy
- DNS over TCP support, redirecting DNS traffic via parent proxy
- SOCKSv4/4.5 Proxy
- SOCKSv5 Proxy
- SOCKSv5 UDP and BIND support (fully compatible with SocksCAP/FreeCAP for UDP)
- Transparent SOCKS redirection for HTTP, POP3, FTP, SMTP
- SNI proxy (based on TLS hostname)
- TLS (SSL) server and client, 3proxy may be used as https:// type proxy or stunnel replacement
- POP3 Proxy
- FTP proxy
- TCP port mapper (port forwarding)
- UDP port mapper (port forwarding)
- SMTP proxy
- Threaded application (no child process)
- Web administration and statistics
- Plugins for functionality extension
- Native 32/64 bit application

### 2. Proxy Chaining and Network Connections

- Can be used as a bridge between client and different proxy type (e.g. convert incoming HTTP proxy request from client to SOCKSv5 request to parent server)
- Connect back proxy support to bypass firewalls
- Parent proxy support for any type of incoming connection
- Username/password authentication for parent proxy(s)
- HTTPS/SOCKS4/SOCKS5 and ip/port redirection parent support
- Random parent selection
- Chain building (multihop proxing)
- Load balancing between few network connections by choosing network interface

### 3. Logging

- Tuneable log format compatible with any log parser
- stdout logging
- File logging
- Syslog logging (Unix)
- ODBC logging
- RADIUS accounting
- Log file rotation
- Automatic log file processing with external archiver (for files)
- Character filtering for log files
- Different log files for different services are supported

### 4. Access Control

- ACL-driven Access control by username, source IP, destination IP/hostname, destination port and destination action (POST, PUT, GET, etc), weekday and daytime
- ACL-driven (user/source/destination/protocol/weekday/daytime or combined) bandwidth limitation for incoming and (!)outgoing traffic
- ACL-driven traffic limitation per day, week or month for incoming and outgoing traffic
- Connection limitation and ratelimiting
- User authentication by username / password
- RADIUS Authentication and Authorization
- User authentication by DNS hostname
- Authentication cache with possibility to limit user to single IP address
- Access control by username/password for SOCKSv5 and HTTP/HTTPS/FTP
- Cleartext or encrypted (crypt/MD5 or NT) passwords
- Connection redirection
- Access control by requested action (CONNECT/BIND, HTTP GET/POST/PUT/HEAD/OTHER)
- All access control entries now support weekday and time limitations
- Hostnames and * templates are supported instead of IP address

### 5. Extensions

- Regular expression filtering (with PCRE2) via PCREPlugin
- Authentication with Windows username/password (cleartext only)
- SSL/TLS decryptions with certificate spoofing
- Transparent redirection support for Linux and *BSD

### 6. Configuration

- Support for configuration files
- Support for includes in configuration files
- Interface binding
- Socket options
- Running as daemon process
- Utility for automated networks list building
- Configuration reload on any file change

**Unix:**
- Support for chroot
- Support for setgid
- Support for setuid
- Support for signals (SIGUSR1 to reload configuration)

**Windows:**
- Support `--install` as service
- Support `--remove` as service
- Support for service START, STOP, PAUSE and CONTINUE commands (on PAUSE no new connection accepted, but active connections still in progress, on CONTINUE configuration is reloaded)

**Windows 95/98/ME:**
- Support `--install` as service
- Support `--remove` as service

### 7. Compilation

- MSVC (static)
- OpenWatcom (static)
- Intel Windows Compiler (msvcrt.dll)
- Windows/gcc (msvcrt.dll)
- Cygwin/gcc (cygwin.dll)
- Unix/gcc
- Unix/ccc
- Solaris
- Mac OS X, iPhone OS
- Linux and derived systems
- Lite version for Windows 95/98/NT/2000/XP/2003
- 32 bit and 64 bit versions for Windows Vista and above, Windows 2008 server and above

## Executables

### 3proxy
Combined proxy server may be used as executable or service (supports installation and removal). It uses config file to read its configuration (see `3proxy.cfg.sample` for details). `3proxy.exe` is all-in-one, it doesn't require all others .exe to work. See `3proxy.cfg.sample` for examples, see `man 3proxy.cfg`

### proxy
HTTP proxy server, binds to port 3128

### ftppr
FTP proxy server, binds to port 21. Please do not mess it with FTP over HTTP proxy used in browsers

### socks
SOCKS 4/5 proxy server, binds to port 1080

### pop3p
POP3 proxy server, binds to port 110. You must specify POP3 username as `username@popserver[:port]` (port is 110 by default).

Example: in Username configuration for your e-mail reader set `someuser@pop.somehost.ru`, to obtain mail for someuser from pop.somehost.ru via proxy.

### smtpp
SMTP proxy server, binds to port 25. You must specify SMTP username as `username@smtpserver[:port]` (port is 25 by default).

Example: in Username configuration for your e-mail reader set `someuser@mail.somehost.ru`, to send mail as someuser via mail.somehost.ru via proxy.

### tcppm
TCP port mapping. Maps some TCP port on local machine to TCP port on remote host.

### tlspr
TLS proxy (SNI proxy) - sniffs hostname from TLS handshake

### udppm
UDP port mapping. Maps some UDP port on local machine to UDP port on remote machine. Only one user simultaneously can use UDP mapping, so it can't be used for public service in large networks. It's OK to use it to map to DNS server in small network or to map Counter-Strike server for single client (you can use few mappings on different ports for different clients in last case).

### mycrypt
Program to obtain crypted password for cleartext. Supports both MD5/crypt and NT password.

```bash
mycrypt password          # produces NT password
mycrypt salt password     # produces MD5/crypt password with salt "salt"
```

---

Run utility with `--help` option for command line reference.

Latest version is available from https://3proxy.org/

Want to donate the project? https://3proxy.org/donations/
