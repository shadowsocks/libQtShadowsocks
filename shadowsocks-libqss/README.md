Shadowsocks-libQSS
------

`shadowsocks-libqss` is a CLI client utilising `libQtShadowsocks`.

Note: This subproject is also a part of project `libQtShadowsocks`.

You can build this Qt project and use it to test functionality of `libQtShadowsocks`, or simply use it as your shadowsocks client on either (or both) local-side and server-side.

Usage
-----

```
Usage: ./shadowsocks-libqss [options]

Options:
  -h, --help           Displays this help.
  -v, --version        Displays version information.
  -c <config_file>     specify config.json file.
  -s <server_address>  host name or IP address of your remote server.
  -p <server_port>     port number of your remote server.
  -b <local_address>   local address to bind. ignored in server mode.
  -l <local_port>      port number of your local server. ignored in server
                       mode.
  -k <password>        password of your remote server.
  -m <method>          encryption method.
  -t <timeout>         socket timeout in seconds.
  -H, --http-proxy     run in HTTP(S) proxy mode. ignored in server mode.
  -S, --server-mode    run as shadowsocks server.
  -T, --speed-test     test encrypt/decrypt speed.
  -d, --debug          debug-level log.
  --autoban            automatically ban IPs that send malformed header. ignored in local mode.
```

If `-T` or `--speed-test` is specified, `shadowsocks-libqss` will do a speed test and print out the time used for specified encryption method. If no method is set, it'll test all encryption methods and print the results. _Note: `shadowsocks-libqss` will exit after the speed test._

By default, it runs as local client. You have to pass `-S` or `--server-mode` if you want it run in server mode.

If `config.json` is specified, most command-line options will be **ignored**. There is a `config.json` example for reference.

License
-------

Copyright (C) 2014-2015 Symeon Huang

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
