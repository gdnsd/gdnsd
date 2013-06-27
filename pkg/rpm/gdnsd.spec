Summary: Authoritative DNS Server
Name: gdnsd
Version: 1.8.3
Release: 1%{?dist}
License: GPLv3+
Group: System Environment/Daemons
URL: https://github.com/blblack/gdnsd
Source0: http://downloads.gdnsd.net/gdnsd-%{version}.tar.xz
Requires(pre): /usr/sbin/useradd
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/service, /sbin/chkconfig
Requires(postun): /sbin/service
Requires: userspace-rcu
Requires: libev
Requires: libcap
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
install -D -p -m 0755 pkg/rpm/gdnsd.init %{buildroot}%{_initddir}/gdnsd
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
%{_libdir}/gdnsd/
%exclude %{_libdir}/gdnsd/*.la
%{_bindir}/gdnsd_geoip_test
%{_sbindir}/gdnsd
%{_libexecdir}/gdnsd/
%dir %{_var}/run/gdnsd/
%dir %{_sysconfdir}/gdnsd/
%dir %{_sysconfdir}/gdnsd/zones/
%config(noreplace) %{_sysconfdir}/gdnsd/config
%{_mandir}/man1/*
%{_mandir}/man5/*
%{_mandir}/man8/*
%{_defaultdocdir}/gdnsd/

%files devel
%defattr(-,root,root,-)
%{_includedir}/gdnsd/
%{_mandir}/man3/*

