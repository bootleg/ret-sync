#!/usr/bin/python3
#
# Copyright (C) 2016, Alexandre Gazet.
# Copyright (C) 2012-2014, Quarkslab.
#
# Copyright (C) 2017, Cedric Halbronn, NCC Group.
#
# This file is part of ret-sync.
#
# ret-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Random notes:
# There is no concept of disabling tunnel polling for commands (happy race...).

import os
import re
import sys
import time
import socket
import errno

VERBOSE = 0

HOST = "localhost"
PORT = 9100


# ext_python is adapted from ret-sync/ext_gdb/sync.py
# TODO: factorize with the GNU GDB plugin


def get_mod_by_addr(maps, addr):
    for mod in maps:
        if (addr > mod[0]) and (addr < mod[1]):
            return [mod[0], mod[3]]
    return None


class Tunnel():

    def __init__(self, host):
        print("[sync] Initializing tunnel to IDA using %s:%d..." % (host, PORT))
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, PORT))
        except socket.error as msg:
            self.sock.close()
            self.sock = None
            self.sync = False
            print("[sync] Tunnel initialization  error: %s" % msg)
            return None

        self.sync = True

    def is_up(self):
        return (self.sock is not None and self.sync is True)

    def poll(self):
        if not self.is_up():
            return None

        self.sock.setblocking(False)

        try:
            msg = self.sock.recv(4096).decode()
        except socket.error as e:
            err = e.args[0]
            if (err == errno.EAGAIN or err == errno.EWOULDBLOCK):
                return '\n'
            else:
                self.close()
                return None

        self.sock.setblocking(True)
        return msg

    def send(self, msg):
        if not self.sock:
            print("[sync] tunnel_send: tunnel is unavailable (did you forget to sync ?)")
            return

        try:
            self.sock.send(msg.encode())
        except socket.error as msg:
            print(msg)
            self.sync = False
            self.close()

            print("[sync] tunnel_send error: %s" % msg)

    def close(self):
        if self.is_up():
            self.send("[notice]{\"type\":\"dbg_quit\",\"msg\":\"dbg disconnected\"}\n")

        if self.sock:
            try:
                self.sock.close()
            except socket.error as msg:
                print("[sync] tunnel_close error: %s" % msg)

        self.sync = False
        self.sock = None


class Rln:

    def __init__(self, sync):
        self.sync = sync

    def invoke(self, raddr):
        self.sync.locate(raddr)

        if (raddr is None) or (self.sync.offset is None):
            return "-"

        self.sync.tunnel.send("[sync]{\"type\":\"rln\",\"raddr\":%d" % raddr)

        # Let time for the IDB client to reply if it exists
        # Need to give it more time than usual to avoid "Resource temporarily unavailable"
        time.sleep(0.5)

        # Poll tunnel
        msg = self.sync.tunnel.poll()
        if msg:
            return msg[:-1]  # strip newline
        else:
            return "-"


class Sync:
    def __init__(self, host, maps):
        if not maps:
            print("[sync] the memory mappings needs to be provided")
            return None

        self.maps = maps
        self.base = None
        self.offset = None
        self.tunnel = None
        self.poller = None
        self.host = host

    def locate(self, offset):
        if not offset:
            print("<unknown offset>")
            return

        self.offset = offset
        mod = get_mod_by_addr(self.maps, self.offset)
        if mod:
            if VERBOSE >= 2:
                print("[sync] mod found")
                print(mod)

            base, sym = mod

            if self.base != base:
                self.tunnel.send("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n" % sym)
                self.base = base

            self.tunnel.send("[sync]{\"type\":\"loc\",\"base\":%d,\"offset\":%d}\n" % (self.base, self.offset))
        else:
            self.base = None
            self.offset = None

    def invoke(self, offset):
        if self.tunnel and not self.tunnel.is_up():
            self.tunnel = None

        if not self.tunnel:
            self.tunnel = Tunnel(self.host)
            if not self.tunnel.is_up():
                print("[sync] sync failed")
                return

            id = "ext_python"
            self.tunnel.send("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - %s\",\"dialect\":\"gdb\"}\n" % id)
            print("[sync] sync is now enabled with host %s" % str(self.host))
        else:
            print('(update)')

        self.locate(offset)


if __name__ == "__main__":
    print("[sync] this module cannot be called directly and needs to be imported from an external script")
