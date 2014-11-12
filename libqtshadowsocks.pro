QT       += core network

QT       -= gui

TARGET = qtshadowsocks

TEMPLATE = lib

DEFINES += QTSHADOWSOCKS_LIBRARY

SOURCES += \
    local.cpp \
    encryptor.cpp

HEADERS += \
    local.h \
    sprofile.h \
    encryptor.h \
    qtshadowsocks_global.h

unix {
    target.path = /usr/lib
    INSTALLS += target
}
