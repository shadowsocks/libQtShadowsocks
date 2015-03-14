libQtShadowsocks
================

Introduction
------------

`libQtShadowsocks` is a lightweight library for `shadowsocks`.

It is written in C++ using Qt5 frameworks. Therefore, the major purpose of this project is to provide a developer-friendly shadowsocks library, mainly for Qt applications, i.e. [shadowsocks-qt5] (https://github.com/librehat/shadowsocks-qt5/).

The `client` utilises this library. You can check the code to see how to use `libQtShadowsocks` in your project. `client` can also be used as both Shadowsocks local client and Shadowsocks server.

Check [installation wiki page](https://github.com/librehat/libQtShadowsocks/wiki/Installation) to see how to install this project/

Current Status
--------------

###Supported Platforms###

- Microsoft Windows (Vista or higher)
- Linux
- xBSD (untested)
- Mac OS X (untested)

###Supported Methods###

- Table
- AES-128-CFB
- AES-192-CFB
- AES-256-CFB
- BF-CFB
- CAST5-CFB
- ChaCha20
- DES-CFB
- IDEA-CFB
- RC2-CFB
- RC4
- RC4-MD5
- Salsa20
- SEED-CFB

RoadMap
-------

Below features will possibly be implemented in future versions.

- ~~Traffic statistics (v1.2)~~
- ~~Server ping (v1.2)~~
- ~~ChaCha cipher (use bundled ChaCha for botan < 1.11)~~
- ~~Multiple servers balance (v1.4)~~
- Multiple profiles balance (v1.6)
- TCP fast open on Linux platform (v1.8)

Please open an [issue](https://github.com/librehat/libQtShadowsocks/issues) to request a new feature.

License
-------

Copyright (C) 2014-2015 Symeon Huang

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
