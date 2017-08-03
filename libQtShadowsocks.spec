Name:		libQtShadowsocks
Version:	1.11.0
Release:	2%{?dist}
Summary:	A lightweight and ultra-fast shadowsocks library

License:	LGPLv3+
URL:		https://github.com/shadowsocks/%{name}
Source0:	%{url}/archive/v%{version}.tar.gz

BuildRequires:	botan-devel
%if 0%{?rhel}
BuildRequires:	cmake3
%else
BuildRequires:	cmake
%endif
BuildRequires:	qt5-qtbase-devel
Requires:	botan
Requires:	qt5-qtbase

AutoReq:	no

%package devel
Summary:	libQtShadowsocks header files
Requires:	libQtShadowsocks

%package -n shadowsocks-libQtShadowsocks
Summary:	A CLI shadowsocks server and client
Requires:	libQtShadowsocks

%description
A lightweight and ultra-fast shadowsocks library written in C++/Qt.

%description devel
Development files (headers) of libQtShadowsocks.

%description -n shadowsocks-libQtShadowsocks
A shadowsocks CLI client using libQtShadowsocks.


%prep
%setup -q


%build
%if 0%{?rhel}
%cmake3 .
%else
%cmake .
%endif
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}


%files
%doc
%{_libdir}/libQtShadowsocks.so*

%files devel
%{_libdir}/pkgconfig/QtShadowsocks.pc
%{_includedir}/*

%files -n shadowsocks-libQtShadowsocks
%{_bindir}/*


%changelog

