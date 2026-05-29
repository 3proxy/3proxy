Name:           3proxy
Version:        0.9.6
Release:        1%{?dist}
Summary:        3proxy tiny proxy server
License:        GPL/LGPL/Apache/BSD
URL:            https://3proxy.org/
Vendor:         3proxy.org 3proxy@3proxy.org
Prefix:         %{_prefix}
Packager: 	z3APA3A
Source:		https://github.com/%{packager}/%{name}/archive/%{version}.tar.gz

%description
3proxy is lightweight yet powerful proxy server

%prep
%setup -q
ln -s Makefile.Linux Makefile

%build
%if "%{?PAMLIB}" != ""
    make PAMLIB=%{?PAMLIB}
%else
    make
%endif

%install
make DESTDIR=%buildroot install

%clean
make clean


%files
/bin/3proxy
/bin/3proxy_crypt
/bin/3proxy_ftppr
/bin/3proxy_pop3p
/bin/3proxy_proxy
/bin/3proxy_smtpp
/bin/3proxy_socks
/bin/3proxy_tcppm
/bin/3proxy_tlspr
/bin/3proxy_udppm
/bin/add3proxyuser
%config(noreplace) /etc/3proxy/3proxy.cfg
/etc/3proxy/conf
/etc/init.d/3proxy
/usr/lib/systemd/system/3proxy.service
%config(noreplace) /usr/local/3proxy/conf/3proxy.cfg
%config(noreplace) /usr/local/3proxy/conf/bandlimiters
%config(noreplace) /usr/local/3proxy/conf/counters
/usr/local/3proxy/libexec/*.ld.so
/usr/share/man/man5/3proxy.cfg.5
/usr/share/man/man8/*
/var/log/3proxy

%doc doc/*

%pre
if [ -x /usr/sbin/useradd ]; then \
 /usr/bin/getent group proxy >/dev/null || (/usr/sbin/groupadd -f -r proxy || true); \
 /usr/bin/getent passwd proxy >/dev/null || (/usr/sbin/useradd -Mr -s /bin/false -g proxy -c 3proxy proxy || true); \
fi

%post
if [ ! -f /usr/local/3proxy/conf/passwd ]; then \
 touch /usr/local/3proxy/conf/passwd;\
fi
[ -f /bin/add3proxyuser ] && sed -i -e 's|@CMAKE_INSTALL_FULL_BINDIR@|/bin|g' -e 's|@3PROXY_CONFDIR@|/etc/3proxy/conf|g' -e 's|@CRYPT_PREFIX@|3proxy_|g' /bin/add3proxyuser; \
[ -f /etc/init.d/3proxy ] && sed -i -e 's|@CMAKE_INSTALL_FULL_BINDIR@|/bin|g' -e 's|@CMAKE_INSTALL_FULL_SYSCONFDIR@|/etc|g' /etc/init.d/3proxy; \
[ -f /usr/lib/systemd/system/3proxy.service ] && sed -i -e 's|@CMAKE_INSTALL_FULL_BINDIR@|/bin|g' -e 's|@CMAKE_INSTALL_FULL_SYSCONFDIR@|/etc|g' /usr/lib/systemd/system/3proxy.service; \
if [ -d /etc/3proxy ]; then \
 chown -R proxy:proxy /etc/3proxy; \
 chmod -R o-rwx /etc/3proxy; \
fi
if [ -d /usr/local/3proxy ]; then \
 chown -R proxy:proxy /usr/local/3proxy; \
 chmod -R o-rwx /usr/local/3proxy; \
fi
if /bin/systemctl >/dev/null 2>&1; then \
 /usr/sbin/update-rc.d 3proxy disable || true; \
 /usr/sbin/chkconfig 3proxy off || true; \
 /bin/systemctl enable 3proxy.service; \
elif [ -x /usr/sbin/update-rc.d ]; then \
 /usr/sbin/update-rc.d 3proxy defaults; \
 /usr/sbin/update-rc.d 3proxy enable; \
elif [ -x /usr/sbin/chkconfig ]; then \
 /usr/sbin/chkconfig 3proxy on; \
fi

echo ""
echo 3proxy installed.
if /bin/systemctl >/dev/null 2>&1; then \
 /bin/systemctl stop 3proxy.service ; \
 /bin/systemctl start 3proxy.service ; \
 echo use ;\
 echo "  "systemctl start 3proxy.service ;\
 echo to start proxy ;\
 echo "  "systemctl stop 3proxy.service ;\
 echo to stop proxy ;\
elif [ -x /usr/sbin/service ]; then \
 /usr/sbin/service 3proxy stop  || true;\
 /usr/sbin/service 3proxy start  || true;\
 echo "  "service 3proxy start ;\
 echo to start proxy ;\
 echo "  "service 3proxy stop ;\
 echo to stop proxy ;\
fi
echo "  "/bin/add3proxyuser
echo to add users
echo ""
echo Default config uses Google\'s DNS.
echo It\'s recommended to use provider supplied DNS or install local recursor, e.g. pdns-recursor.
echo Configure preferred DNS in /usr/local/3proxy/conf/3proxy.cfg.
echo run \'/bin/add3proxyuser admin password\' to configure \'admin\' user
