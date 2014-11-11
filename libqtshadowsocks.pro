QT       += core network

QT       -= gui

TARGET = libqtshadowsocks
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    local.cpp \
    encryptor.cpp

HEADERS += \
    local.h \
    sprofile.h \
    encryptor.h
