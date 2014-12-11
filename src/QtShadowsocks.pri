# This file is part of project libQtShadowsocks
# Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
# Licensed Under GPLv3

SOURCES  += \
    src/address.cpp \
    src/cipher.cpp \
    src/common.cpp \
    src/connection.cpp \
    src/controller.cpp \
    src/encryptor.cpp \
    src/udprelay.cpp

HEADERS  += \
    src/address.h \
    src/cipher.h \
    src/common.h \
    src/connection.h \
    src/controller.h \
    src/encryptor.h \
    src/export.h \
    src/profile.h \
    src/QtShadowsocks \
    src/udprelay.h

OTHER_FILES += \
    README.md

isEmpty(INSTALL_PREFIX) {
    unix: INSTALL_PREFIX = /usr
    else: INSTALL_PREFIX = $$top_srcdir
}

unix: {
    VERSION     = 1.0

    CONFIG     += create_pc create_prl no_install_prl link_pkgconfig

    target.path = $$INSTALL_PREFIX/lib
    INSTALLS   += target

    header_files.files = $$HEADERS
    header_files.path  = $$INSTALL_PREFIX/include/qtshadowsocks
    INSTALLS   += header_files

    QMAKE_PKGCONFIG_NAME = QtShadowsocks
    QMAKE_PKGCONFIG_DESCRIPTION = A Shadowsocks library written in C++/Qt5
    QMAKE_PKGCONFIG_PREFIX = $$INSTALL_PREFIX
    QMAKE_PKGCONFIG_LIBDIR = $$target.path
    QMAKE_PKGCONFIG_INCDIR = $$header_files.path
    QMAKE_PKGCONFIG_VERSION = $$VERSION
    QMAKE_PKGCONFIG_DESTDIR = pkgconfig

    PKGCONFIG  += botan-1.10
}

win32: {
    DEFINES     += "FD_SETSIZE=1024"#increase the maximum pending tcp sockets. this value is 64 on Windows by default
    DEFINES     += "_WIN32_WINNT=0x0600"#drop support for Windows XP
}
