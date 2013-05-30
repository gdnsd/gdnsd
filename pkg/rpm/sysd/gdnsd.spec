Summary: Authoritative DNS Server
Name: gdnsd
Version: 1.8.3
Release: 1%{?dist}
License: GPLv3+
Group: System Environment/Daemons
URL: https://github.com/blblack/gdnsd
Source0: http://downloads.gdnsd.net/gdnsd-%{version}.tar.xz
Requires(pre): /usr/sbin/useradd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires: userspace-rcu
Requires: libev
Requires: libcap
%{?systemd_requires}
BuildRequires: systemd
BuildRequires: userspace-rcu-devel
BuildRequires: libev-devel
BuildRequires: libcap-devel
BuildRequires: perl(Test::More)
BuildRequires: perl(HTTP::Daemon)
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
Summary: Header files and docs needed for gdnsd plugin development
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Header files and docs needed for gdnsd plugin development.

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
install -D -p -m 0644 pkg/rpm/sysd/gdnsd.service %{buildroot}%{_unitdir}/gdnsd.service
mkdir -p %{buildroot}%{_var}/run/gdnsd
mkdir -p %{buildroot}%{_sysconfdir}/gdnsd
mkdir -p %{buildroot}%{_sysconfdir}/gdnsd/zones
echo '# gdnsd main config file, see gdnsd.config(5) for details' >%{buildroot}%{_sysconfdir}/gdnsd/config

%clean
rm -rf %{buildroot}

%pre
if [ $1 -eq 1 ]; then
    /usr/sbin/useradd -c "gdnsd user" -s /sbin/nologin -r -d %{_var}/run/gdnsd gdnsd &>/dev/null || :
fi

%post
%systemd_post gdnsd.service

%preun
%systemd_preun gdnsd.service

%postun
%systemd_postun gdnsd.service

%files
%defattr(-,root,root,-)
%{_unitdir}/gdnsd.service
%dir %{_libdir}/gdnsd/
%{_libdir}/gdnsd/*.so
%exclude %{_libdir}/gdnsd/*.la
%{_bindir}/gdnsd_geoip_test
%{_sbindir}/gdnsd
%{_libexecdir}/gdnsd/gdnsd_extmon_helper
%{_var}/run/gdnsd/
%{_sysconfdir}/gdnsd/
%{_sysconfdir}/gdnsd/zones/
%config %{_sysconfdir}/gdnsd/config
%doc %{_mandir}/man1/*
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*
%doc %{_defaultdocdir}/gdnsd/*

%files devel
%defattr(-,root,root,-)
%{_includedir}/gdnsd/*.h
%doc %{_mandir}/man3/*
