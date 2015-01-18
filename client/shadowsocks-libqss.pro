# This file is part of project libQtShadowsocks
# Copyright (C) 2014-2015 Symeon Huang <hzwhuang@gmail.com>
# Licensed Under LGPLv3

QT       += core network concurrent

QT       -= gui

TARGET    = shadowsocks-libqss

CONFIG   += console c++11

TEMPLATE  = app

HEADERS  += client.h

SOURCES  += client.cpp \
            main.cpp

isEmpty(INSTALL_PREFIX) {
    unix: INSTALL_PREFIX = /usr
    else: INSTALL_PREFIX = $$top_srcdir
}

isEmpty(BOTAN_VER) {
    BOTAN_VER = 1.10
}

unix: {
    CONFIG    += link_pkgconfig
    PKGCONFIG += QtShadowsocks botan-$$BOTAN_VER

    target.path = $$INSTALL_PREFIX/bin
    INSTALLS   += target
}

win32: {
    DEFINES     += "FD_SETSIZE=1024"#increase the maximum pending tcp sockets. this value is 64 on Windows by default
    DEFINES     += QSS_STATIC
    INCLUDEPATH += $$top_srcdir/../lib
    LIBS        += -L$$top_srcdir/../lib \
                   -lQtShadowsocks \
                   -lbotan-$$BOTAN_VER
}

