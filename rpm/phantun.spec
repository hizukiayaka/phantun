Name:         	phantun 
Version:        0.6.1
Release:        1%{?dist}
Summary:        A lightweight and fast UDP to TCP obfuscator

License:        Apache-2.0
URL:            https://github.com/dndx/phantun/tree/main
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  selinux-policy-devel

%description
Your project with client and server components.

%package client
Summary:        Client component of phantun
Requires: (%{name}-selinux if selinux-policy-%{selinuxtype})

%description client
Phantun Client is like a machine with private IP address
(192.168.200.2/fcc8::2) behind a router. In order for it to reach
the Internet, you will need to SNAT the private IP address
before it's traffic leaves the NIC.

%package server
Summary:        Server component of phantun
Requires: (%{name}-selinux if selinux-policy-%{selinuxtype})

%description server
Phantun Server is like a server with private IP address
(192.168.201.2/fcc9::2) behind a router. In order to access it from
the Internet, you need to DNAT it's listening port on the router
and change the destination IP address to where the server
is listening for incoming connections.

%package selinux
Summary:        SELinux module for phantun
%{?selinux_requires}
%global modulename phantun
%global selinuxtype targeted

%description selinux
This package provides the SELinux policy module to ensure phantun
runs properly under an environment with SELinux enabled.

%global debug_package %{nil}

%prep
%setup -q

%build
cargo build --release
make -C selinux

%install
# Install binaries
install -D -m 0755 target/release/client %{buildroot}/usr/libexec/phantun/phantun-client
install -D -m 0755 target/release/server %{buildroot}/usr/libexec/phantun/phantun-server

mkdir -p %{buildroot}/usr/bin
# Create wrapper scripts
echo '#!/bin/bash
PID_FILE=$1
shift 1
mkdir -p /var/run/phantun
/usr/libexec/phantun/phantun-client "$@" &
echo $! > /var/run/phantun/${PID_FILE}' > %{buildroot}/usr/bin/phantun-client

echo '#!/bin/bash
PID_FILE=$1
shift 1
mkdir -p /var/run/phantun
/usr/libexec/phantun/phantun-server "$@" &
echo $! > /var/run/phantun/${PID_FILE}' > %{buildroot}/usr/bin/phantun-server

# Make wrapper scripts executable
chmod +x %{buildroot}/usr/bin/phantun-client
chmod +x %{buildroot}/usr/bin/phantun-server

# SELinux
install -d %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}
install -m 0644 selinux/%{modulename}.pp.bz2 %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

%files client
/usr/libexec/phantun/phantun-client
/usr/bin/phantun-client

%files server
/usr/libexec/phantun/phantun-server
/usr/bin/phantun-server

%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2

%changelog
* Thu Oct 14 2023 Randy Li <ayaka@soulik.info> - 0.6.1-1
- Initial package
