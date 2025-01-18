Name:           rpm-basic
Epoch:          1
Version:        2.3.4
Release:        5.el9
License:        MPL-2.0
Summary:        A package for exercising basic features of RPM

Group:          Development/Tools
Url:            http://www.savewalterwhite.com/
Packager:       Walter White
Vendor:         Los Pollos Hermanos
Vcs:            https://github.com/rpm-rs/rpm

Source0:         basic-2.3.4.tar.gz

BuildArch:	    noarch
BuildRequires:  file-devel

Requires: morality <= 2
Requires: methylamine >= 1.0.0-1
Requires(pre): /usr/sbin/ego
Requires(post): regret

Provides: shock = 33
Provides: aaronpaul
Provides: /usr/bin/ls
Provides: breaking(bad)

Obsoletes: tucosalamanca < 444
Obsoletes: gusfring < 32.1-0

Conflicts: hank > 35

Recommends: huel > 9:11.0-0
Recommends: SaulGoodman(CriminalLawyer)

Supplements: comedy = 0:11.1-4

Suggests: chilipowder

Enhances: purity > 9000

%description
This package attempts to exercise basic features of RPM packages.

%prep
%setup -q -n basic-2.3.4

%build
echo "No more half measures, Walter." > README
echo OK

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin/
mkdir -p %{buildroot}/etc/%{name}/
mkdir -p %{buildroot}/usr/lib/%{name}/
mkdir -p %{buildroot}/usr/share/%{name}/
mkdir -p %{buildroot}/usr/share/doc/%{name}/
mkdir -p %{buildroot}/var/log/%{name}/
mkdir -p %{buildroot}/var/tmp/%{name}/
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
%dir /var/tmp/%{name}/
%ghost /var/log/%{name}/basic.log
%config /etc/%{name}/*
%doc README

%changelog
* Mon Jun 14 2021 Walter White <ww@savewalterwhite.com> - 3.3.3-3
- I'm not in the meth business. I'm in the empire business.

* Sun Apr 25 2021 Gustavo Fring <gus@lospolloshermanos.com> - 2.2.2-2
- Never Make The Same Mistake Twice.

* Wed Mar 31 2021 Mike Ehrmantraut <mike@lospolloshermanos.com> - 1.1.1-1
- Just because you shot Jesse James, don't make you Jesse James.
