%global _hardened_build 1
%global contrib_dir %{_builddir}/%{name}-%{version}/contrib/rpm/
%define build_timestamp %(date +"%Y%m%d%H%M")
%define use_systemd (0%{?fedora} && 0%{?fedora} >= 18) || (0%{?rhel} && 0%{?rhel} >= 7) || (0%{?suse_version} == 1315)

Name:           3proxy
Version:        0.8.7
Release:        git%{build_timestamp}%{?dist}
Summary:        Tiny but very powerful proxy
Summary(ru):    Маленький, но крайне мощный прокси-сервер

License:        BSD or ASL 2.0 or GPLv2+ or LGPLv2+
Group:          System Environment/Daemons
Url:            https://github.com/z3APA3A/3proxy

Source0:        https://github.com/z3APA3A/%{name}/archive/%{name}-%{version}.tar.gz

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  openssl-devel

%if %{use_systemd}
BuildRequires:    systemd
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd
%else
Requires(post):   systemd-sysv, systemd-units
Requires:         initscripts
%endif

%description
%{name} -- light proxy server.
Universal proxy server with HTTP, HTTPS, SOCKS v4, SOCKS v4a, SOCKS v5, FTP,
POP3, UDP and TCP portmapping, access control, bandwith control, traffic
limitation and accounting based on username, client IP, target IP, day time,
day of week, etc.

%description -l ru
%{name} -- маленький прокси сервер.
Это универсальное решение поддерживающее HTTP, HTTPS, SOCKS v4, SOCKS v4a,
SOCKS v5, FTP, POP3, UDP и TCP проброс портов (portmapping), списки доступа
управление скоростью доступа, ограничением трафика и статистикоу, базирующейся
на имени пользователя, слиентском IP адресе, IP цели, времени дня, дня недели
и т.д.

%prep
%setup -n %{name}-%{version}
patch -p0  -s -b <  %{contrib_dir}/3proxy-0.6.1-config-path.patch
# To use "fedora" CFLAGS (exported)
sed -i -e "s/CFLAGS =/CFLAGS +=/" Makefile.Linux

%build
%{__make} -f Makefile.Linux

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}%{_sysconfdir}
mkdir -p %{buildroot}%{_mandir}/man{3,8}
mkdir -p %{buildroot}%{_localstatedir}/log/%{name}
install -m755 -D src/%{name} %{buildroot}%{_bindir}/%{name}
install -m755 -D src/dighosts %{buildroot}%{_bindir}/dighosts
install -m755 -D src/ftppr %{buildroot}%{_bindir}/ftppr
install -m755 -D src/mycrypt %{buildroot}%{_bindir}/mycrypt
install -m755 -D src/pop3p %{buildroot}%{_bindir}/pop3p
install -m755 -D src/%{name} %{buildroot}%{_bindir}/%{name}
install -m755 -D src/proxy %{buildroot}%{_bindir}/htproxy
install -m755 -D src/socks %{buildroot}%{_bindir}/socks
install -m755 -D src/tcppm %{buildroot}%{_bindir}/tcppm
install -m755 -D src/udppm %{buildroot}%{_bindir}/udppm
install -pD -m644 %{contrib_dir}/%{name}.cfg     %{buildroot}/%{_sysconfdir}/%{name}.cfg

%if %{use_systemd}
install -pD -m755 %{contrib_dir}/%{name}.service %{buildroot}/%{_unitdir}/%{name}.service
%else
install -pD -m755 %{contrib_dir}/%{name}.init    %{buildroot}/%{_initrddir}/%{name}
%endif

for man in man/*.{3,8} ; do
    install "$man" "%{buildroot}%{_mandir}/man${man:(-1)}/"
done

%clean
rm -rf %{buildroot}

%post
%if %{use_systemd}
%systemd_post %{name}.service
%endif

%preun
%if %{use_systemd}
%systemd_preun %{name}.service
%endif

%postun
%if %{use_systemd}
%systemd_postun_with_restart %{name}.service
%endif

%files
%defattr(-,root,root,-)
%{_bindir}/*
%config(noreplace) %{_sysconfdir}/%{name}.cfg
%{_localstatedir}/log/%{name}
%doc README authors copying Release.notes
%{_mandir}/man8/*.8.gz
%{_mandir}/man3/*.3.gz

%if %{use_systemd}
%{_unitdir}/%{name}.service
%else
%{_initrddir}/%{name}
%endif

%changelog
* Sun Oct 23 2016 Anatolii Vorona <vorona.tolik@gmail.com> - 0.8.7-git
- upstream update - 0.8.7
- removed unneeded NetworkManager dispatcher
- fixes: added support Centos 6 (with init), Centos 7 (with systemd)

* Wed Feb 03 2016 Fedora Release Engineering <releng@fedoraproject.org> - 0.8.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Sat Jan 23 2016 Pavel Alexeev <Pahan@Hubbitus.info> - 0.8.2-1
- Major upstream update - 0.8.2. Bz#1300097.
- Tarballs now on github.

* Fri Jan 01 2016 Pavel Alexeev <Pahan@Hubbitus.info> - 0.7.1.3-1
- New upstream release 0.7.1.3 - bz#1263482.

* Tue Jun 16 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.7.1.2-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Thu Mar 05 2015 Adam Jackson <ajax@redhat.com> 0.7.1.2-2
- Drop sysvinit subpackage on F23+

* Mon Feb 23 2015 Pavel Alexeev <Pahan@Hubbitus.info> - 0.7.7.2-1
- New upstream version 0.7.7.2

* Mon Aug 18 2014 Pavel Alexeev <Pahan@Hubbitus.info> - 0.7.7.1-1
- Update to 0.7.7.1 - bz#1114274.

* Fri Aug 15 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.7-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Fri Jun 06 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.7-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Tue Apr 8 2014 Pavel Alexeev <Pahan@Hubbitus.info> - 0.7-1
- Update to 0.7 version bz#1085256.
- Add BR openssl-devel.

* Tue Jan 7 2014 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6.1-18
- Step to systemd macroses (#850383)

* Fri Aug 02 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.6.1-17
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Fri Apr 26 2013 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6.1-16
- Harden build - bz#955141

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.6.1-15
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Wed Jul 18 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.6.1-14
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Thu Jan 12 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.6.1-13
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Thu Jun 23 2011 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6.1-12
- Make service systemd compliant (BZ#657412).

* Mon Feb 07 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.6.1-11
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Thu Nov 4 2010 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6.1-10
- Add man3/3proxy.cfg.3 man (BZ#648204).
- Gone explicit man gzip - leave it for rpm.

* Sun May 30 2010 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6.1-9
- Correct path to config file in man (BUG#596087) add Patch0: 3proxy-0.6.1-config-path.patch

* Mon Mar 15 2010 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6.1-8
- Update to version 0.6.1
- In NM event processing replace service restart to condrestart - BZ#572662

* Wed Nov 25 2009 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6-7
- Again new init-script for Fix BZ#533144 :).

* Wed Nov 25 2009 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6-6
- Forgot commit new init-script for Fix BZ#533144.

* Sun Nov 8 2009 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6-5
- Fix BZ#533144:
- Add reload section to service file, fix stop.
- Add %%{_sysconfdir}/NetworkManager/dispatcher.d/40-%%{name} (Thanks to Pankaj Pandey)
- Include man-files.
- Add Requires: initscripts as owner directory %%{_sysconfdir}/NetworkManager/dispatcher.d/

* Thu Aug 20 2009 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6-3
- Fedora Review started - thank you Peter Lemenkov.
- Change rights (0755->0644) of config.
- Disable service by default.
- Add BR dos2unix.

* Mon Aug 17 2009 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6-2
- /usr/bin/proxy renamed to htproxy to avoid name bump with libproxy-bin.
- Add Source2: 3proxy.cfg from Alt Linux (slightly modified) - http://sisyphus.ru/ru/srpm/Sisyphus/3proxy/sources/1 (thanks to Afanasov Dmitry).
- Add log-dir %%{_localstatedir}/log/%%{name}

* Mon Aug 17 2009 Pavel Alexeev <Pahan@Hubbitus.info> - 0.6-1
- Ressurect old spec. New version 0.6.
- Rename spec to classic %%{name}.spec.
- Remove Hu part from release and add %%{?dist}.
- Change summary, description, URL. Add Russian localisation of sumamry and description.
- Strip some old comments.
- Add to %%doc Readme Changelog authors copying news.
- Turn macros usage from %%name to %%{name} for consistence.
- Change group from System/Servers to standard System Environment/Daemons.
- Add %%defattr(-,root,root,-) in %%files section.
- Add cleanup in %%install section.
- Add %%clean section with cleanup buildroot.
- License changed from just GPL to "BSD or ASL 2.0 or GPLv2+ or LGPLv2+" (according to Makefile.Linux)
- Add %%config(noreplace) mark to all configs.
- Add file %%{_initdir}/%%{name}
- Old %%{_initdir} macros replaced by %%{_initrddir}
- Hack makefile to use system CFLAGS.
- Add %%post/%%postun sections.

* Fri Jan 25 2008 Pavel Alexeev <Pahan [ at ] Hubbitus [ DOT ] info> - 0.5.3k
- Import from ftp://ftp.nluug.nl/pub/os/Linux/distr/altlinux/4.0/Server/4.0.1/files/SRPMS/3proxy-0.5.3h-alt1.src.rpm
    Combine with ftp://ftp.pbone.net/mirror/ftp.sourceforge.net/pub/sourceforge/t/th/three-proxy/3proxy-0.5.3g-1.src.rpm
- Steep to version 0.5.3k
- Comment out packager
- Reformat header of spec with tabs
- Add desc from second src.rpm of import
- Correct source0
- Add -c key fo %%setup macro
- Add BuildRoot definition (this is not ALT)
- Change
    Release:    alt1
    to
    Release:    0.Hu.0

* Fri Apr 13 2007 Lunar Child <luch@altlinux.ru> 0.5.3h-alt1
- new version

* Wed Mar 21 2007 Lunar Child <luch@altlinux.ru> 0.5.3g-alt2
- Added init script.
- Added new trivial config file.

* Tue Mar 20 2007 Lunar Child <luch@altlinux.ru> 0.5.3g-alt1
- First build for ALT Linux Sisyphus
