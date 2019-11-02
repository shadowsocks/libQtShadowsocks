libQtShadowsocks
================

**This project is no longer being maintained**

[![Build Status](https://travis-ci.org/shadowsocks/libQtShadowsocks.svg?branch=master)](https://travis-ci.org/shadowsocks/libQtShadowsocks) <a href="https://copr.fedorainfracloud.org/coprs/librehat/shadowsocks/package/libQtShadowsocks/"><img src="https://copr.fedorainfracloud.org/coprs/librehat/shadowsocks/package/libQtShadowsocks/status_image/last_build.png" /></a>

Introduction
------------

`libQtShadowsocks` is a lightweight [shadowsocks][ss] library.

Written in C++ using Qt 5 framework and Botan library, it aims to provide a developer-friendly [shadowsocks][ss] library for Qt applications such as [shadowsocks-qt5](https://github.com/shadowsocks/shadowsocks-qt5/).

The sub-project `shadowsocks-libqss` utilises this library. You may wish to check the code to see how to integrate `libQtShadowsocks` into your project. `shadowsocks-libqss` can also be used as a standalone program in both local-side and server-side.

Check [installation wiki page](https://github.com/shadowsocks/libQtShadowsocks/wiki/Installation) to see how to install this library and/or `shadowsocks-libqss`.

[ss]: http://shadowsocks.org

License
-------

![](http://www.gnu.org/graphics/lgplv3-147x51.png)

Copyright (C) 2014-2017 Symeon Huang

This library is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this library. If not, see <http://www.gnu.org/licenses/>.
