# This file is part of project libQtShadowsocks
# Copyright (C) 2014-2016 Symeon Huang <hzwhuang@gmail.com>
# Licensed Under LGPLv3

QT       += core network

QT       -= gui

TARGET    = shadowsocks-libqss

CONFIG   += console c++11

TEMPLATE  = app

HEADERS  += client.h \
            utils.h

SOURCES  += client.cpp \
            main.cpp \
            utils.cpp

OTHER_FILES += README.md \
               config.json

isEmpty(INSTALL_PREFIX) {
    unix: INSTALL_PREFIX = /usr
    else: INSTALL_PREFIX = $$top_srcdir
}

isEmpty(BOTAN_VER) {
    BOTAN_VER = 1.10
}

# You should use these lines in your project.
#
#unix: {
#    CONFIG    += link_pkgconfig
#    PKGCONFIG += QtShadowsocks botan-$$BOTAN_VER
#
#    target.path = $$INSTALL_PREFIX/bin
#    INSTALLS   += target
#}
#
#win32: {
#    DEFINES     += "FD_SETSIZE=1024"#increase the maximum pending tcp sockets. this value is 64 on Windows by default
#    DEFINES     += QSS_STATIC
#    INCLUDEPATH += $$top_srcdir/../lib
#    LIBS        += -L$$top_srcdir/../lib \
#                   -lQtShadowsocks \
#                   -lbotan-$$BOTAN_VER
#}

# Because of this is a sub-project, we use compiled objects from lib directly
unix: {
    CONFIG      += link_pkgconfig
    PKGCONFIG   += botan-$$BOTAN_VER

    target.path  = $$INSTALL_PREFIX/bin
    INSTALLS    += target
}
win32: {
    DEFINES     += "FD_SETSIZE=1024"
    DEFINES     += QSS_STATIC
    CONFIG(release, release|debug): LIBS += -L../lib/release
    else:            LIBS += -L../lib/debug
}
INCLUDEPATH     += $$top_srcdir/../lib
LIBS            += -L$$top_srcdir/../lib \
                   -L../lib \
                   -lQtShadowsocks \
                   -lbotan-$$BOTAN_VER
