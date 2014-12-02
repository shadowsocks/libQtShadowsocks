QT       += core network concurrent

QT       -= gui

CONFIG   += staticlib c++11 crypto

TARGET    = QtShadowsocks

TEMPLATE  = lib

include(src/QtShadowsocks.pri)
