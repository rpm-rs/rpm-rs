Name:           rpm-with-patch
Version:        1.0
License:        LGPL
Release:        0
Summary:        "A package built from a tarball with a patch"

BuildArch:  noarch
Source0:    basic-2.3.4.tar.gz
Patch0:     update.patch

%description
A package built from a tarball with a patch - doubles as an even more minimal "basic" RPM.

%prep
%setup -q -n basic-2.3.4

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/bin/
mkdir -p %{buildroot}/usr/bin/
mkdir -p %{buildroot}/etc/%{name}/
mkdir -p %{buildroot}/usr/lib/%{name}/
mkdir -p %{buildroot}/usr/share/%{name}/
mkdir -p %{buildroot}/usr/share/doc/%{name}/
mkdir -p %{buildroot}/var/log/%{name}/
cp example_config.toml %{buildroot}/etc/%{name}/example_config.toml
cp example_data.xml %{buildroot}/usr/share/%{name}/example_data.xml
cp multiplication_tables.py %{buildroot}/usr/bin/%{name}
cp -R module/ %{buildroot}/usr/lib/%{name}/

%clean
rm -rf %{buildroot}

%files
/usr/bin/%{name}
/usr/lib/%{name}/
/usr/share/%{name}/*
%config /etc/%{name}/*

%changelog

