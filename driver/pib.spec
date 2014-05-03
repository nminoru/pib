Name: pib
Version: 0.4.1
Release: 1%{?dist}
Summary: Pseudo InfiniBand (pib) HCA Kernel Driver
Group: System/Kernel
License: GPLv2 or BSD
Url: http://www.nminoru.jp/
Source0: %{name}-%{version}.tar.gz
Source1: %{name}.files
Source2: %{name}.conf
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires: %kernel_module_package_buildreqs
BuildArch: x86_64 

%kernel_module_package -f %{SOURCE1} default

%description
Pseudo InfiniBand (pib) HCA Kernel Driver

%prep

%setup
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
for flavor in %flavors_to_build; do
    rm -rf obj/$flavor
    cp -r source obj/$flavor
    make -C %{kernel_source $flavor} M=$PWD/obj/$flavor
done    

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/%{name}
for flavor in %flavors_to_build; do
    make -C %{kernel_source $flavor} modules_install M=$PWD/obj/$flavor
done    

install -m 644 -D %{SOURCE2} $RPM_BUILD_ROOT/etc/depmod.d/%{name}.conf

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Sat May 03 2014 Minoru NAKAMURA <nminoru@nminoru.jp> - 0.4.1
- Initial spec file

