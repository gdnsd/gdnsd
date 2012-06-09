Summary: Authoritative DNS Server
Name: gdnsd
Version: 1.7.0
Release: 1%{?dist}
License: GPLv3+
Group: System Environment/Daemons
URL: https://github.com/blblack/gdnsd
Source0: https://github.com/downloads/blblack/gdnsd/gdnsd-%{version}.tar.xz
Requires(pre): /usr/sbin/useradd
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/service, /sbin/chkconfig
Requires(postun): /sbin/service
BuildRequires: libcap-devel
BuildRequires: perl(Test::More)
BuildRequires: perl(Net::DNS)
BuildRequires: perl(LWP)
BuildRequires: perl(Socket6)
BuildRequires: perl(IO::Socket::INET6)
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
gdnsd is an Authoritative-only DNS server. The initial g stands for
Geographic, as gdnsd offers a plugin system for geographic (or
other sorts of) balancing, redirection, and service-state-conscious
failover. If you don't care about that feature, it's still quite
good at being a very fast, lean, and resilient authoritative-only
server for static DNS data.

%package devel
Summary: Header files and libraries needed for gdnsd plugin development
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Header files and libraries needed for gdnsd plugin development.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}

%check
make check

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
make install-gdnsd-rootdir DESTDIR=%{buildroot}
install -D -p -m 0755 pkg/rpm/gdnsd.init %{buildroot}%{_initddir}/gdnsd

%clean
rm -rf %{buildroot}

%pre
if [ $1 -eq 1 ]; then
    /usr/sbin/useradd -c "gdnsd user" -s /sbin/nologin -r -d %{_var}/gdnsd gdnsd &>/dev/null || :
fi

%post
if [ $1 -eq 1 ]; then
    /sbin/chkconfig --add gdnsd
fi

%preun
if [ $1 -eq 0 ]; then
    /sbin/service gdnsd stop &>/dev/null || :
    /sbin/chkconfig --del gdnsd
fi

%postun
if [ $1 -ge 1 ]; then
    /sbin/service gdnsd condrestart &>/dev/null || :
fi

%files
%defattr(-,root,root,-)
%{_initddir}/gdnsd
%dir %{_libdir}/gdnsd/
%{_libdir}/gdnsd/*.so
%exclude %{_libdir}/gdnsd/*.la
%{_bindir}/gdnsd_geoip_test
%{_sbindir}/gdnsd
%doc %{_mandir}/man1/*
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*
%doc %{_defaultdocdir}/gdnsd/*
/srv/gdnsd

%files devel
%defattr(-,root,root,-)
%{_includedir}/gdnsd-*.h
%doc %{_mandir}/man3/*

%changelog
* Sun May  6 2012 Brandon Black <blblack@gmail.com> 1.7.0-1
- Updated for dev branch fs layouts, no release yet.

* Fri May  4 2012 Brandon Black <blblack@gmail.com> 1.6.7-1
- Forked from Matthias' work on Fedora RPMs.  My primary
  target here is Amazon Linux RPMs, but it will probably
  work for other Redhat-ish distros
- Updated to 1.6.7

* Tue Mar  6 2012 Matthias Saou <matthias@saou.eu> 1.6.3-1
- Update to 1.6.3.

* Thu May 19 2011 Matthias Saou <matthias@saou.eu> 1.5.2-1
- Update to 1.5.2.
- Add new libpcap-devel BR for the late_bind_secs feature.

* Thu Apr 14 2011 Matthias Saou <matthias@saou.eu> 1.4.4-1
- Update to 1.4.4.

* Sun Jan 30 2011 Matthias Saou <matthias@saou.eu> 1.4.1-1
- Update to 1.4.1.

* Mon Jan 10 2011 Matthias Saou <matthias@saou.eu> 1.3.6-1
- Initial RPM release.

