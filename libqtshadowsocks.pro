QT       += core network concurrent

QT       -= gui

CONFIG += c++11

TARGET = qtshadowsocks

TEMPLATE = lib

DEFINES += QTSHADOWSOCKS_LIBRARY

SOURCES += \
    local.cpp \
    encryptor.cpp \
    connection.cpp

HEADERS += \
    local.h \
    sprofile.h \
    encryptor.h \
    qtshadowsocks_global.h \
    connection.h

unix {
    target.path = /usr/lib
    INSTALLS += target

    CONFIG    += link_pkgconfig
    PKGCONFIG += qca2
}

LIBS  += -lqca
