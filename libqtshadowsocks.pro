QT       += core network concurrent

QT       -= gui

CONFIG += c++11

TARGET = qtshadowsocks

TEMPLATE = lib

DEFINES += QTSHADOWSOCKS_LIBRARY

SOURCES += \
    encryptor.cpp \
    connection.cpp \
    basecontroller.cpp \
    localcontroller.cpp

HEADERS += \
    sprofile.h \
    encryptor.h \
    qtshadowsocks_global.h \
    connection.h \
    basecontroller.h \
    localcontroller.h

unix {
    target.path = /usr/lib
    INSTALLS += target

    CONFIG    += link_pkgconfig
    PKGCONFIG += qca2
}

LIBS  += -lqca
