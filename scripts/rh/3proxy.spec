Name:           3proxy
Version:        10
Release:        %{devel_version}
Summary:        3proxy tiny proxy server
License:        GPL/LGPL/Apache/BSD
URL:            https://3proxy.org/
Vendor:         3proxy.org 3proxy@3proxy.org
Prefix:         %{_prefix}
Packager: 	z3APA3A
Source:		https://github.com/%{packager}/%{name}/tarball/devel

%description
3proxy is lightweight yet powerful proxy server

%prep
%setup -q -n 3proxy-10-devel
ln -s Makefile.Linux Makefile

%build
make

%install
make DESTDIR=%buildroot install

%clean
make clean


%files
/bin/*
%config(noreplace) /etc/3proxy/3proxy.cfg
%config(noreplace) /etc/3proxy/conf
%config(noreplace) /usr/local/3proxy/conf/*
/etc/init.d/3proxy
/usr/lib/systemd/system/3proxy.service
/usr/local/3proxy/libexec/*
/usr/share/man/man3/*
/usr/share/man/man8/*
/var/log/3proxy

%doc doc/*

%pre
if [ -x /usr/sbin/useradd ]; then \
 /usr/bin/getent group proxy >/dev/null || (/usr/sbin/groupadd -f -r proxy || true); \
 /usr/bin/getent passwd proxy >/dev/null || (/usr/sbin/useradd -UMr -s /bin/false -c 3proxy proxy || true); \
fi

%post
if [ ! -f /usr/local/3proxy/conf/passwd ]; then \
 touch /usr/local/3proxy/conf/passwd;\
fi
chown -R proxy:proxy /usr/local/3proxy
chmod 550  /usr/local/3proxy/
chmod 550  /usr/local/3proxy/conf/
chmod 440  /usr/local/3proxy/conf/*
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
 /bin/systemctl stop 3proxy.service \
 /bin/systemctl start 3proxy.service \
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
echo "  "/usr/local/3proxy/conf/add3proxyuser.sh
echo to add users
echo ""
echo Default config uses Google\'s DNS.
echo It\'s recommended to use provider supplied DNS or install local recursor, e.g. pdns-recursor.
echo Configure preferred DNS in /usr/local/3proxy/conf/3proxy.cfg.
echo run \'/usr/local/3proxy/conf/add3proxyuser.sh admin password\' to configure \'admin\' user
