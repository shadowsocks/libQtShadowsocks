# This file is part of project libQtShadowsocks
# Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
# Licensed Under GPLv3

SOURCES  += \
    src/encryptor.cpp \
    src/connection.cpp \
    src/basecontroller.cpp \
    src/localcontroller.cpp \
    src/udprelay.cpp \
    src/common.cpp

HEADERS  += \
    src/profile.h \
    src/encryptor.h \
    src/connection.h \
    src/basecontroller.h \
    src/localcontroller.h \
    src/udprelay.h \
    src/common.h

unix: {
    target.path = /usr/lib
    INSTALLS   += target

    CONFIG     += link_pkgconfig
    PKGCONFIG  += qca2

    VERSION     = 0.1
}

win32: {
    INCLUDEPATH += $$top_srcdir/qca/include
    DEFINES += QCA_STATIC
    win32-msvc2013: {
        LIBS += -L$$top_srcdir/qca/lib/msvc2013
        DESTDIR = $$top_srcdir/lib/msvc2013
    }
    else: {
        error ("Only support MSVC2013 compiler on Windows platform.")
    }
}

LIBS     += -lqca
