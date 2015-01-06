# This file is part of project libQtShadowsocks
# Copyright (C) 2014-2015 Symeon Huang <hzwhuang@gmail.com>
# Licensed Under LGPLv3

SOURCES  += \
    src/address.cpp \
    src/cipher.cpp \
    src/common.cpp \
    src/connection.cpp \
    src/controller.cpp \
    src/encryptor.cpp \
    src/udprelay.cpp \
    src/chacha.cpp

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
    src/udprelay.h \
    src/chacha.h

OTHER_FILES += \
    README.md
