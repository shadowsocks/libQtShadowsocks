Name:		libQtShadowsocks
Version:	1.10.0
Release:	1%{?dist}
Summary:	A lightweight and ultra-fast shadowsocks library

License:	LGPLv3+
URL:		https://github.com/shadowsocks/%{name}
Source0:	%{url}/archive/v%{version}.tar.gz

BuildRequires:	qt5-qtbase-devel
BuildRequires:	qt5-qttools
BuildRequires:	botan-devel
Requires:	qt5-qtbase
Requires:	botan

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
%ifarch x86_64 amd64 ppc64le aarch64
%{qmake_qt5} DEFINES+="LIB64"
%else
%{qmake_qt5}
%endif
make %{?_smp_mflags}


%install
make install INSTALL_ROOT=%{buildroot}


%files
%doc
%{_libdir}/libQtShadowsocks.so*

%files devel
%{_libdir}/pkgconfig/QtShadowsocks.pc
%{_includedir}/*

%files -n shadowsocks-libQtShadowsocks
%{_bindir}/*


%changelog

