Name:           rpm-special-files
Version:        1.0
Release:        1
Summary:        Test RPM special file metadata
License:        MIT
BuildArch:      noarch

%description
Test RPM handling of special file metadata.

%install
mkdir -p %{buildroot}/run
mkfifo %{buildroot}/run/rpm-special-files.fifo

%files
%attr(0600,root,root) %dev(c,1,3) /dev/rpm-special-files-null
%attr(0640,root,root) %dev(b,7,0) /dev/rpm-special-files-loop
%attr(0620,root,root) /run/rpm-special-files.fifo

%changelog
* Sun Apr 09 2023 RPM Test <rpm-test@example.com> - 1.0-1
- Build special file fixture
