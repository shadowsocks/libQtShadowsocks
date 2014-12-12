# This file is part of project libQtShadowsocks
# Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
# Licensed Under GPLv3

QT       += core network concurrent

QT       -= gui

TARGET    = shadowsocks-libqss

CONFIG   += console

TEMPLATE  = app

HEADERS  += client.h

SOURCES  += client.cpp \
            main.cpp

isEmpty(INSTALL_PREFIX) {
    unix: INSTALL_PREFIX = /usr
    else: INSTALL_PREFIX = $$top_srcdir
}

unix: {
    CONFIG    += link_pkgconfig
    PKGCONFIG += QtShadowsocks botan-1.10

    target.path = $$INSTALL_PREFIX/bin
    INSTALLS   += target
}

win32: {
    DEFINES     += "FD_SETSIZE=1024"#increase the maximum pending tcp sockets. this value is 64 on Windows by default
    DEFINES     += QSS_STATIC
    INCLUDEPATH += $$top_srcdir/../include
    LIBS        += -L$$top_srcdir/../lib \
                   -lQtShadowsocks \
                   -lbotan-1.10
}

