# This file is part of project libQtShadowsocks
# Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
# Licensed Under GPLv3

SOURCES  += \
    src/cipher.cpp \
    src/common.cpp \
    src/connection.cpp \
    src/controller.cpp \
    src/encryptor.cpp \
    src/udprelay.cpp

HEADERS  += \
    src/cipher.h \
    src/common.h \
    src/connection.h \
    src/controller.h \
    src/encryptor.h \
    src/profile.h \
    src/udprelay.h

unix: {
    target.path = /usr/lib
    INSTALLS   += target

    CONFIG     += link_pkgconfig
    PKGCONFIG  += botan-1.10

    VERSION     = 0.2
}

win32: {
    DEFINES     += "FD_SETSIZE=1024"#increase the maximum pending tcp sockets. this value is 64 on Windows by default
    DEFINES     += "_WIN32_WINNT=0x0600"#drop support for Windows XP
}
