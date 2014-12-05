# This file is part of project libQtShadowsocks
# Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
# Licensed Under GPLv3

QT       += core network concurrent

QT       -= gui

TARGET    = sslocal-libqss
CONFIG   += console

TEMPLATE  = app

INCLUDEPATH += $$top_srcdir/../src

HEADERS     += client.h

SOURCES     += client.cpp \
               main.cpp


unix: {
    CONFIG    += link_pkgconfig
    PKGCONFIG += botan-1.10
    LIBS      += -L/home/symeon/Projects/build/libqtshadowsocks-Desktop-Debug
}

win32: {
    #DEFINES += QCA_STATIC
    DEFINES     += "FD_SETSIZE=1024"#increase the maximum pending tcp sockets. this value is 64 on Windows by default
}

LIBS += -lQtShadowsocks -lbotan-1.10
