Name: libpib
Version: 0.0.3
Release: 1%{?dist}
Summary: Pseudo InfiniBand HCA Userspace Driver
Provides: libibverbs-driver.%{_arch}
Group: System Environment/Libraries
License: GPLv2 or BSD
Url: http://www.nminoru.jp/
Source: %{name}-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Provides: libpib-devel = %{version}-%{release}
Requires: libibverbs > 1.1.4
BuildRequires: libibverbs-devel > 1.1.4
# BuildArch: x86_64 
ExcludeArch: s390 s390x

%description
InfiniBand HCAs for use with the libibverbs library.

%prep
%setup -q

%build
make

%install
rm -rf $RPM_BUILD_ROOT
install -D -m 644 libpib-rdmav2.so ${RPM_BUILD_ROOT}%{_libdir}/libpib-rdmav2.so
install -D -m 644 pib.driver ${RPM_BUILD_ROOT}%{_sysconfdir}/libibverbs.d/pib.driver
# install -D -m 644 %{SOURCE1} ${RPM_BUILD_ROOT}%{_sysconfdir}/modprobe.d/libpib.conf
# install -D -m 644 %{SOURCE2} ${RPM_BUILD_ROOT}%{_sysconfdir}/rdma/pib.conf
# install -D -m 644 %{SOURCE3} ${RPM_BUILD_ROOT}%{_sysconfdir}/rdma/setup-mlx4.awk
# remove unpackaged files from the buildroot
rm -f $RPM_BUILD_ROOT%{_libdir}/libpib.so

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/libpib-rdmav2.so
%{_sysconfdir}/libibverbs.d/pib.driver
%doc AUTHORS COPYING README

%changelog
* Tue Oct 30 2013 NAKAMURA Minoru <nminoru@nminoru.jp> - 0.0.2
- Initial spec file
