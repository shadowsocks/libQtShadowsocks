# This file is part of project libQtShadowsocks
# Copyright (C) 2015-2016 Symeon Huang <hzwhuang@gmail.com>
# Licensed Under LGPLv3

QT       += testlib network

QT       -= gui

CONFIG   += c++11

TARGET    = qss_test
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

HEADERS += \
    address.t.h \
    chacha.t.h \
    cipher.t.h

SOURCES += \
    main.cpp \
    address.t.cpp \
    chacha.t.cpp \
    cipher.t.cpp
DEFINES += SRCDIR=\\\"$$PWD/\\\"

isEmpty(BOTAN_VER) {
    BOTAN_VER = 1.10
}

macx: {
    QT_CONFIG  -= no-pkg-config
    DEFINES    += "FD_SETSIZE=1024"
}
unix: {
    CONFIG      += link_pkgconfig
    PKGCONFIG   += botan-$$BOTAN_VER
}
win32: {
    DEFINES     += QSS_STATIC
    CONFIG(release, release|debug): LIBS += -L../lib/release
    else:            LIBS += -L../lib/debug
}
INCLUDEPATH     += $$top_srcdir/../lib
LIBS            += -L$$top_srcdir/../lib \
                   -L../lib \
                   -lQtShadowsocks \
                   -lbotan-$$BOTAN_VER
