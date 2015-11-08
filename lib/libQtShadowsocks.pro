# This file is part of project libQtShadowsocks
# Copyright (C) 2014-2015 Symeon Huang <hzwhuang@gmail.com>
# Licensed Under LGPLv3

QT       += core network

QT       -= gui

CONFIG   += c++11

TARGET    = QtShadowsocks

TEMPLATE  = lib

isEmpty(INSTALL_PREFIX) {
    unix: INSTALL_PREFIX = /usr
    else: INSTALL_PREFIX = $$top_srcdir
}

isEmpty(BOTAN_VER) {
    BOTAN_VER = 1.10
}

VERSION   = 1.8.0
DEFINES  += QSS_VERSION=\\\"$$VERSION\\\"

win32: {
    DEFINES    += "FD_SETSIZE=1024"#increase the maximum pending tcp sockets. this value is 64 on Windows by default
    DEFINES    += QSS_STATIC
}

contains(DEFINES, QSS_STATIC) {
    CONFIG  += staticlib
}
else {
    DEFINES += QSS_LIBRARY
}

include(QtShadowsocks.pri)

unix: {
    CONFIG     += create_pc create_prl no_install_prl link_pkgconfig

    contains(DEFINES, LIB64): target.path = $$INSTALL_PREFIX/lib64
    else: target.path = $$INSTALL_PREFIX/lib
    header_files.files = $$HEADERS
    header_files.path  = $$INSTALL_PREFIX/include/qtshadowsocks
    INSTALLS   += target header_files

    QMAKE_PKGCONFIG_NAME = QtShadowsocks
    QMAKE_PKGCONFIG_DESCRIPTION = A lightweight and ultra-fast shadowsocks library written in C++/Qt
    QMAKE_PKGCONFIG_PREFIX  = $$INSTALL_PREFIX
    QMAKE_PKGCONFIG_LIBDIR  = $$target.path
    QMAKE_PKGCONFIG_INCDIR  = $$header_files.path
    QMAKE_PKGCONFIG_VERSION = $$VERSION
    QMAKE_PKGCONFIG_DESTDIR = pkgconfig

    PKGCONFIG  += botan-$$BOTAN_VER
}
