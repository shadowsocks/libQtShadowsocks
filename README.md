libQtShadowsocks
================

Introduction
------------

`libQtShadowsocks` is a lightweight library for `shadowsocks`.

It is written in C++ using Qt5 frameworks. Therefore, the major purpose of this project is to provide a developer-friendly shadowsocks library, mainly for Qt applications, i.e. [shadowsocks-qt5] (https://github.com/librehat/shadowsocks-qt5/).

The `client` utilises this library. You can check the code to see how to use `libQtShadowsocks` in your project. `client` can also be used as both Shadowsocks local client and Shadowsocks server.

Dependency
----------

- Qt5 >= 5.2 (`qtbase5-dev`)
- Botan = 1.10.x (`libbotan-1.10-dev`)

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
- DES-CFB
- IDEA-CFB
- RC2-CFB
- RC4
- RC4-MD5
- Salsa20
- SEED-CFB

RoadMap
-------

Below features will possibly be implemented in future versions. While even version number indicates a stable version. Odd number means development version correspondingly.

- Traffic statistics (v1.2)
- Server ping (v1.2)
- Multiple server IP address random choose (v1.4)
- ChaCha cipher (v1.4, also need to wait for `Botan-1.12` release)
- Multiple profile balance (v1.6)

Please open an [issue](https://github.com/librehat/libQtShadowsocks/issues) to apply for a new feature.

Build & Install
---------------

Use `qmake-qt5` instead of `qmake` if your distribution uses `qmake` from Qt4.

```
qmake INSTALL_PREFIX=/usr
make
make install
```

If your distribution (i.e. Fedora) requires library installed into `/usr/lib64` on 64-bit system instead of `/usr/lib`, you have to add an extra argument `DEFINES+="LIB64"` to `qmake` command.

By default, it'll use `/usr` as path prefix on unix platforms, while the prefix is this source code directory (current working directory) on Windows platform.

After installation of `libQtShadowsocks`, you can `cd` into `client` and do the same procedure to install `shadowsocks-libqss`.

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
