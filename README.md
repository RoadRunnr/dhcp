dhcp
====
[![Build Status][travis badge]][travis]
[![Erlang Versions][erlang version badge]][travis]

This is DHCP Server in Erlang for running on Linux.

The Linux dependency comes mostly from the use of a special ioctl to inject ARP information into the kernel. The alternative to that would be to use raw packet socket, but those are not supported in Erlang.

The bind-to-interface socket option is also Linux specific, but the server could work without it.

Requirements
------------

* Linux
* Erlang (>= R22.3, older probably works as well)

BUILDING
--------

Using rebar:

    # rebar3 compile

<!-- Badges -->
[travis]: https://travis-ci.com/RoadRunnr/dhcp
[travis badge]: https://img.shields.io/travis/RoadRunnr/com/dhcp/master.svg?style=flat-square
[erlang version badge]: https://img.shields.io/badge/erlang-R22.3%20to%23.0-blue.svg?style=flat-square
