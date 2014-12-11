# This file is part of project libQtShadowsocks
# Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
# Licensed Under GPLv3

QT       += core network concurrent

QT       -= gui

CONFIG   += c++11

TARGET    = QtShadowsocks

TEMPLATE  = lib

contains(DEFINES, QSS_STATIC) {
    CONFIG  += staticlib
}
else {
    DEFINES += QSS_LIBRARY
}

include(src/QtShadowsocks.pri)
