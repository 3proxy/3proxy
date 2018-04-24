#!/bin/sh
cd ..
cp Makefile.unix Makefile
make
if [ ! -d /usr/local/etc/3proxy/bin ]; then mkdir -p /usr/local/etc/3proxy/bin/; fi
install bin/3proxy /usr/local/bin/3proxy
install bin/mycrypt /usr/local/bin/mycrypt
install scripts/rc.d/proxy.sh /usr/local/etc/rc.d/proxy.sh
install scripts/add3proxyuser.sh /usr/local/etc/3proxy/bin/
if [ -s /usr/local/etc/3proxy/3proxy.cfg ]; then
 echo /usr/local/etc/3proxy/3proxy.cfg already exists
else
 install scripts/3proxy.cfg /usr/local/etc/3proxy/
 if [ ! -d /var/log/3proxy/ ]; then
  mkdir /var/log/3proxy/
 fi
 touch /usr/local/etc/3proxy/passwd
 touch /usr/local/etc/3proxy/counters
 touch /usr/local/etc/3proxy/bandlimiters
 echo Run /usr/local/etc/3proxy/bin/add3proxyuser.sh to add \'admin\' user
fi

