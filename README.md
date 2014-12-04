libQtShadowsocks
================

Introduction
------------

`libQtShadowsocks` is a lightweight library for `shadowsocks`.

It is written in C++ using Qt5 frameworks. Therefore, the major purpose of this project is to provide a developer-friendly shadowsocks library, mainly for Qt applications, i.e. [shadowsocks-qt5] (https://github.com/librehat/shadowsocks-qt5/).

The `client` utilises this library. You can check the code to see how to use `libQtShadowsocks` in your project. `client` can also be used as a local Shadowsocks client.

TODO
----

- Support use as server (server-side shadowsocks) (v1.0)
- Stabilise ABI and code structure (v1.0)
- Get rid of QCA. Use `Botan` directly (v1.0).
- ~~Support RC4-MD5 method (v1.x)~~
- Statically linked Windows build (v1.x)

Dependency
----------

- Qt5 >= 5.2 (`qtbase5-dev`)
- QCA >= 2.1.0

Many distributions don't provide the latest [QCA 2.1.0] (http://delta.affinix.com/download/qca/2.0/qca-2.1.0.tar.gz) package. You may have to build it yourself. In order to support mainstream encryption methods, please install `libssl-dev` (OpenSSL development package) before compiling.

Current Status
--------------

###Supported Platforms###

- Windows
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
- DES-CFB
- RC4-MD5

Warning
-------

This project is under heavy development. Please wait for a `v1.0` release before use it in production environment.

License
-------

Copyright (C) 2014 Symeon Huang

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
