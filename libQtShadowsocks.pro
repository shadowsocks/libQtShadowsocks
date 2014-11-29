QT       += core network concurrent

QT       -= gui

CONFIG   += staticlib c++11

TARGET    = QtShadowsocks

TEMPLATE  = lib

DEFINES  += QTSHADOWSOCKS_LIBRARY

include(src/QtShadowsocks.pri)
