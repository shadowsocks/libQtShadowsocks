# This file is part of project libQtShadowsocks
# Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
# Licensed Under GPLv3

QT       += core network concurrent

QT       -= gui

TARGET    = ss-libqt
CONFIG   += console

TEMPLATE  = app

INCLUDEPATH += $$top_srcdir/../src

HEADERS     += client.h

SOURCES     += client.cpp \
               main.cpp


unix: {
    CONFIG    += link_pkgconfig
    PKGCONFIG += qca2
    LIBS      += -L/home/symeon/Projects/build/libqtshadowsocks-Desktop-Debug
}

win32: {
    INCLUDEPATH += $$top_srcdir/../qca/include
    DEFINES += QCA_STATIC
    win32-msvc2013: {
        LIBS += -L$$top_srcdir/../lib/msvc2013 \
                -L$$top_srcdir/../qca/lib/msvc2013 \
                -lqca-ossl
        QTPLUGIN += qca-ossl
    }
    else: {
        error ("Only support MSVC2013 compiler on Windows platform.")
    }
}

LIBS += -lqca -lQtShadowsocks
