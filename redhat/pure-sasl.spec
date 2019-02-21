%define modname pure-sasl
%define version 0.6.1
%define unmangled_version 0.6.1
%define release 1
%{!?python: %define python python26}

Summary: Pure Python client SASL implementation
Name: %{python}-%{modname}
Version: %{version}
Release: %{release}
Source0: %{modname}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: Tyler Hobbs <tylerlhobbs@gmail.com>
Url: http://github.com/thobbs/pure-sasl

%description
This package provides a reasonably high-level SASL client written
in pure Python.  New mechanisms may be integrated easily, but by default,
support for PLAIN, ANONYMOUS, CRAM-MD5, and GSSAPI are
provided.

%prep
%setup -n %{modname}-%{unmangled_version}

%build
%{python} setup.py build

%install
%{python} setup.py install -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
%doc README.rst LICENSE
