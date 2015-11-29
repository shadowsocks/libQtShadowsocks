# This file is part of project libQtShadowsocks
# Copyright (C) 2015 Symeon Huang <hzwhuang@gmail.com>
# Licensed Under LGPLv3

QT       += testlib network

QT       -= gui

CONFIG   += c++11

TARGET    = qss_test
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

HEADERS += \
    address.t.h

SOURCES += \
    main.cpp \
    address.t.cpp
DEFINES += SRCDIR=\\\"$$PWD/\\\"

isEmpty(BOTAN_VER) {
    BOTAN_VER = 1.10
}

unix: {
    CONFIG      += link_pkgconfig
    PKGCONFIG   += botan-$$BOTAN_VER
}

INCLUDEPATH     += $$top_srcdir/../lib
LIBS            += -L$$top_srcdir/../lib \
                   -L../lib \
                   -lQtShadowsocks \
                   -lbotan-$$BOTAN_VER
