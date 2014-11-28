QT       += core network concurrent

QT       -= gui

CONFIG   += c++11

TARGET    = QtShadowsocks

TEMPLATE  = lib

DEFINES  += QTSHADOWSOCKS_LIBRARY

SOURCES  += \
    encryptor.cpp \
    connection.cpp \
    basecontroller.cpp \
    localcontroller.cpp

HEADERS  += \
    profile.h \
    encryptor.h \
    qtshadowsocks_global.h \
    connection.h \
    basecontroller.h \
    localcontroller.h

LIBS     += -lqca

unix {
    target.path = /usr/lib
    INSTALLS   += target

    CONFIG     += link_pkgconfig
    PKGCONFIG  += qca2

    VERSION     = 0.1
}
