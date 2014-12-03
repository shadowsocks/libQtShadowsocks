# This file is part of project libQtShadowsocks
# Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
# Licensed Under GPLv3

QT       += core network concurrent

QT       -= gui

CONFIG   += staticlib c++11 crypto

TARGET    = QtShadowsocks

TEMPLATE  = lib

include(src/QtShadowsocks.pri)
