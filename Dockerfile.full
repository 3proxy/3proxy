# 3proxy.full is fully functional 3proxy build based on busibox:glibc
#
#to  build:
# docker build -f Dockerfile.full -t 3proxy.full .
#to run:
# by default 3proxy uses safe chroot environment with chroot to /usr/local/3proxy with uid/gid 65535/65535 and expects
# configuration file to be placed in /usr/local/etc/3proxy.
# Paths in configuration file must be relative to /usr/local/3proxy, that is use /logs instead of 
# /usr/local/3proxy/logs. nserver in chroot is required for DNS resolution. An example:
#
# echo nserver 8.8.8.8 >/path/to/local/config/directory/3proxy.cfg
# echo proxy -p3129 >>/path/to/local/config/directory/3proxy.cfg
# docker run -p 3129:3129 -v /path/to/local/config/directory:/usr/local/3proxy/conf -name 3proxy.full 3proxy.full
#
# /path/to/local/config/directory in this example must conrain 3proxy.cfg
# if you need 3proxy to be executed without chroot with root permissions, replace /etc/3proxy/3proxy.cfg by e.g. mounting config
# dir to /etc/3proxy ot by providing config file /etc/3proxy/3proxy.cfg
# docker run -p 3129:3129 -v /path/to/local/config/directory:/etc/3proxy -name 3proxy.full 3proxy.full
#
# use "log" without pathname in config to log to stdout.
# plugins are located in /usr/local/3proxy/libexec (/libexec for chroot config).


FROM gcc AS buildenv
COPY . 3proxy
RUN cd 3proxy &&\
 echo "">> Makefile.Linux &&\
 echo PLUGINS = StringsPlugin TrafficPlugin PCREPlugin TransparentPlugin SSLPlugin>>Makefile.Linux &&\
 echo LIBS = -l:libcrypto.a -l:libssl.a -ldl >>Makefile.Linux &&\
 make -f Makefile.Linux &&\
 strip bin/3proxy &&\
 strip bin/StringsPlugin.ld.so &&\
 strip bin/TrafficPlugin.ld.so &&\
 strip bin/PCREPlugin.ld.so &&\
 strip bin/TransparentPlugin.ld.so &&\
 strip bin/SSLPlugin.ld.so &&\
 mkdir /usr/local/lib/3proxy &&\
 cp "/lib/`gcc -dumpmachine`"/libdl.so.* /usr/local/lib/3proxy/

FROM busybox:glibc
COPY --from=buildenv /usr/local/lib/3proxy/libdl.so.* /lib/
COPY --from=buildenv 3proxy/bin/3proxy /bin/
COPY --from=buildenv 3proxy/bin/*.ld.so /usr/local/3proxy/libexec/
RUN mkdir /usr/local/3proxy/logs &&\
 mkdir /usr/local/3proxy/conf &&\
 chown -R 65535:65535 /usr/local/3proxy &&\
 chmod -R 550  /usr/local/3proxy &&\
 chmod 750  /usr/local/3proxy/logs &&\
 chmod -R 555 /usr/local/3proxy/libexec &&\
 chown -R root /usr/local/3proxy/libexec &&\
 mkdir /etc/3proxy/ &&\
 echo chroot /usr/local/3proxy 65535 65535 >/etc/3proxy/3proxy.cfg &&\
 echo include /conf/3proxy.cfg >>/etc/3proxy/3proxy.cfg &&\
 chmod 440  /etc/3proxy/3proxy.cfg
CMD ["/bin/3proxy", "/etc/3proxy/3proxy.cfg"]
