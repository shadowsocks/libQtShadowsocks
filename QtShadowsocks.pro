# This file is part of project libQtShadowsocks
# Copyright (C) 2014-2015 Symeon Huang <hzwhuang@gmail.com>
# Licensed Under LGPLv3

TEMPLATE = subdirs

CONFIG  += ordered

SUBDIRS  = lib/libQtShadowsocks.pro \
           client/shadowsocks-libqss.pro

OTHER_FILES += README.md
