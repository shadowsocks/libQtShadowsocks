QT       += core network concurrent

QT       -= gui

CONFIG   += c++11

TARGET    = QtShadowsocks

TEMPLATE  = lib

DEFINES  += QTSHADOWSOCKS_LIBRARY

SOURCES  += \
    src/encryptor.cpp \
    src/connection.cpp \
    src/basecontroller.cpp \
    src/localcontroller.cpp

HEADERS  += \
    src/profile.h \
    src/encryptor.h \
    src/qtshadowsocks_global.h \
    src/connection.h \
    src/basecontroller.h \
    src/localcontroller.h

LIBS     += -lqca

unix {
    target.path = /usr/lib
    INSTALLS   += target

    CONFIG     += link_pkgconfig
    PKGCONFIG  += qca2

    VERSION     = 0.1
}

