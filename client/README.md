Client
------

`shadowsocks-libqss` is a CLI client utilising `libQtShadowsocks`.

Note: This subproject is also a part of project `libQtShadowsocks`.

You can build this Qt project and use it to test functionality of `libQtShadowsocks`, or simply use it as your shadowsocks client on either (or both) local-side and server-side.

Usage
-----

```
Usage: shadowsocks-libqss [options]

Options:
  -h, --help                       Displays this help.
  -v, --version                    Displays version information.
  -c, --config-file <config.json>  specify config.json file.
  -d,                              debug-level log.
  -s, --server-mode                run as shadowsocks server.
  -t                               test encrypt/decrypt speed.
```

If `-t` is specified, `shadowsocks-libqss` will do a speed test and print out the time used for encryption (using the method specified by `config.json` file). If the `config.json` file doesn't exist, it'll test all encryption methods and print the results. _Note: `shadowsocks-libqss` will exit after the speed test._

By default, it runs as local client. You have to pass `-s` if you want it run in server mode.

There is a `config.json` example for reference.

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
