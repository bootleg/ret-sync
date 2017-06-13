#
# Copyright (C) 2016, Alexandre Gazet.
#
# Copyright (C) 2012-2014, Quarkslab.
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

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import os.path as altpath
import sys
import socket
import select
import base64
import binascii
import re
import ConfigParser
import traceback

HOST = 'localhost'
PORT = 9100

try:
    import json
except:
    print "[-] failed to import json\n%s" % repr(sys.exc_info())
    sys.exit(0)


class Client():

    def __init__(self, s_client, s_srv, name):
        self.client_sock = s_client
        self.srv_sock = s_srv
        self.name = name
        self.enabled = False
        self.buffer = ''

    def close(self):
        self.enabled = False
        if self.client_sock:
            self.client_sock.close()
        if self.srv_sock:
            self.srv_sock.close()

    def feed(self, data):
        batch = []
        self.buffer = ''.join([self.buffer, data])
        if self.buffer.endswith("\n"):
            batch = [req for req in self.buffer.strip().split('\n') if req != '']
            self.buffer = ''

        return batch


class DispatcherSrv():

    def __init__(self):
        self.idb_clients = []
        self.dbg_client = None
        self.srv_socks = []
        self.opened_socks = []

        self.current_dbg = None
        self.current_dialect = 'unknown'
        self.current_idb = None
        self.current_module = None

        self.sync_mode_auto = True
        self.disconn_pat = re.compile('dbg disconnected')
        self.req_handlers = {
            'new_client': self.req_new_client,
            'new_dbg': self.req_new_dbg,
            'dbg_quit': self.req_dbg_quit,
            'idb_n': self.req_idb_n,
            'idb_list': self.req_idb_list,
            'module': self.req_module,
            'sync_mode': self.req_sync_mode,
            'cmd': self.req_cmd,
            'bc': self.req_bc,
            'kill': self.req_kill
        }

    def bind(self, host, port):
        self.dbg_srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.dbg_srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dbg_srv_sock.bind((host, port))
        self.srv_socks.append(self.dbg_srv_sock)

        if not (socket.gethostbyname(host) == '127.0.0.1'):
            self.localhost_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.localhost_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.localhost_sock.bind(('localhost', port))
            self.srv_socks.append(self.localhost_sock)

    def accept(self, s):
        new_socket, addr = s.accept()
        self.opened_socks.append(new_socket)

    def listen(self):
        for s in self.srv_socks:
            s.listen(5)

    def close(self, s):
        s.close()
        self.opened_socks.remove(s)

    def loop(self):
        self.listen()
        self.announcement("dispatcher listening")

        while True:
            rlist, wlist, xlist = select.select(self.srv_socks + self.opened_socks, [], [])

            if not rlist:
                self.announcement("socket error: select")
                raise Exception("rabbit eating the cable")

            for s in rlist:
                if s in self.srv_socks:
                    self.accept(s)
                else:
                    self.handle(s)

    def handle(self, s):
        client = self.sock_to_client(s)
        for req in self.recvall(client):
            self.parse_exec(s, req)

    # find client object for its srv socket
    def sock_to_client(self, s):
        if self.current_dbg and (s == self.current_dbg.srv_sock):
            client = self.current_dbg
        else:
            clist = [client for client in self.idb_clients if (client.srv_sock == s)]
            if not clist:
                client = Client(None, s, None)
                self.idb_clients.append(client)
            else:
                client = clist[0]

        return client

    # buffered readline like function
    def recvall(self, client):
        try:
            data = client.srv_sock.recv(4096)
            if data == '':
                raise
        except:
            if client == self.current_dbg:
                self.broadcast("debugger closed the connection")
                self.dbg_quit()
            else:
                self.client_quit(client.srv_sock)
                self.broadcast("a client quit, nb client(s) left: %d" % len(self.idb_clients))

            return []

        return client.feed(data)

    # parse and execute requests from clients (idbs or dbg)
    def parse_exec(self, s, req):
        if not (req[0:8] == '[notice]'):
            # this is a normal [sync] request from debugger, forward it
            self.forward(req)
            # receive 'dbg disconnected', socket can be closed
            if re.search(self.disconn_pat, req):
                self.close(s)
            return

        req = self.normalize(req, 8)
        try:
            hash = json.loads(req)
        except:
            print "[-] dispatcher failed to parse json\n %s\n" % req
            return

        type = hash['type']
        if not type in self.req_handlers:
            print ("[*] dispatcher unknown request: %s" % type)
            return

        req_handler = self.req_handlers[type]
        req_handler(s, hash)

    def normalize(self, req, taglen):
        req = req[taglen:]
        req = req.replace("\\", "\\\\")
        req = req.replace("\n", "")
        return req

    def puts(self, msg, s):
        s.sendall(msg)

    # dispatcher announcements are forwarded to the idb
    def announcement(self, msg, s=None):
        if not s:
            if not self.current_idb:
                return
            s = self.current_idb.client_sock

        try:
            s.sendall("[notice]{\"type\":\"dispatcher\",\"subtype\":\"msg\",\"msg\":\"%s\"}\n" % msg)
        except:
            return

    # send message to all connected idb clients
    def broadcast(self, msg):
        for idbc in self.idb_clients:
            self.announcement(msg, idbc.client_sock)

    # send dbg message to currently active idb client
    def forward(self, msg, s=None):
        if not s:
            if not self.current_idb:
                return
            s = self.current_idb.client_sock

        if s:
            s.sendall(msg + "\n")

    # send dbg message to all idb clients
    def forward_all(self, msg, s=None):
        for idbc in self.idb_clients:
            self.forward(msg, idbc.client_sock)

    # disable current idb and enable new idb matched from current module name
    def switch_idb(self, new_idb):
        msg = "[sync]{\"type\":\"broker\",\"subtype\":\"%s\"}\n"
        if (not self.current_idb == new_idb) & (self.current_idb.enabled):
            self.current_idb.client_sock.sendall(msg % "disable_idb")
            self.current_idb.enabled = False

        if new_idb:
            new_idb.client_sock.sendall(msg % "enable_idb")
            self.current_idb = new_idb
            new_idb.enabled = True

    # a new idb client connects to the dispatcher via its broker
    def req_new_client(self, srv_sock, hash):
        port, name = hash['port'], hash['idb']
        try:
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.connect(('localhost', port))
            self.opened_socks.append(client_sock)
        except:
            self.opened_socks.remove(srv_sock)
            srv_sock.close()
            return

        # check if an idb client is already registered with the same name
        conflicting = [client for client in self.idb_clients if (client.name == name)]

        # promote to idb client
        new_client = self.sock_to_client(srv_sock)
        new_client.client_sock = client_sock
        new_client.name = name
        self.broadcast("add new client (listening on port %d), nb client(s): %d" % (port, len(self.idb_clients)))

        if conflicting:
            self.broadcast("conflicting name: %s !" % new_client.name)

        if not self.current_idb:
            self.current_idb = new_client

        # if new client match current module name, then enable it
        if self.current_module == name:
            self.switch_idb(new_client)

        # inform new client about debugger's dialect
        self.dbg_dialect(new_client)

    # clean state when a client is quiting
    def client_quit(self, s):
        self.opened_socks.remove(s)
        # remove exiting client from the list of active clients
        for idbc in [idbc for idbc in self.idb_clients if (idbc.srv_sock == s)]:
            self.idb_clients.remove(idbc)
            self.opened_socks.remove(idbc.client_sock)
            idbc.close()

            # no more clients, let's kill ourself
            if not self.idb_clients:
                for s in self.srv_socks:
                    s.close()
                sys.exit()

    # determine if debugger is Windows specific
    def is_windows_dbg(self, dialect):
        return (dialect in ['windbg', 'x64_dbg', 'ollydbg2'])

    # a new debugger client connects to the dispatcher
    def req_new_dbg(self, s, hash):
        msg = hash['msg']
        if self.current_dbg:
            self.dbg_quit()

        # promote to dbg client
        self.current_dbg = self.sock_to_client(s)
        self.current_dbg.client_sock = s
        self.idb_clients.remove(self.current_dbg)

        self.broadcast("new debugger client: %s" % msg)

        # store dbb's dialect
        if 'dialect' in hash:
            self.current_dialect = hash['dialect']

            # case when IDA is on a linux/bsd host and connected to remote windows
            # use ntpath instead of posixpath
            if sys.platform.startswith('linux') or sys.platform == 'darwin':
                if self.is_windows_dbg(self.current_dialect):
                    global altpath
                    import ntpath as altpath

        self.dbg_dialect()

    # inform client about debugger's dialect
    def dbg_dialect(self, client=None):
        msg = "[sync]{\"type\":\"dialect\",\"dialect\":\"%s\"}\n" % self.current_dialect
        if client:
            client.client_sock.sendall(msg)
        else:
            for idbc in self.idb_clients:
                idbc.client_sock.sendall(msg)

    # debugger client disconnect from the dispatcher
    def req_dbg_quit(self, s, hash):
        msg = hash['msg']
        self.broadcast("debugger quit: %s" % msg)
        self.dbg_quit()

    # clean state when debugger is quiting
    def dbg_quit(self):
        self.opened_socks.remove(self.current_dbg.srv_sock)
        self.current_dbg.close()
        self.current_dbg = None
        self.current_module = None
        self.switch_idb(None)
        self.current_dialect = 'unknown'

    # handle kill notice from a client, exit properly if no more client
    def req_kill(self, s, hash):
        self.client_quit(s)
        self.broadcast("received a kill notice from client, %d client(s) left" % len(self.idb_clients))

    # send list of currently connected idb clients
    def req_idb_list(self, s, hash):
        clist = "> currently connected idb(s):\n"
        if not self.idb_clients:
            clist += "    no idb client yet\n"
        else:
            for i in range(len(self.idb_clients)):
                clist += ("    [%d] %s\n" % (i, self.idb_clients[i].name))

        s.sendall(clist)

    # manually set current active idb to idb n from idb list
    def req_idb_n(self, s, hash):
        idb = hash['idb']
        try:
            idbn = int(idb)
        except:
            s.sendall("> n should be a decimal value")
            return

        try:
            idbc = self.idb_clients[idbn]
        except:
            s.sendall("> %d is invalid (see idblist)" % idbn)
            return

        self.switch_idb(idbc)
        s.sendall("> current idb set to %d" % idbn)

    # dbg notice that its current module has changed
    def req_module(self, s, hash):
        modpath = hash['path']
        self.current_module = modname = altpath.basename(modpath)
        matching = [idbc for idbc in self.idb_clients if (idbc.name.lower() == modname.lower())]

        if not self.sync_mode_auto:
            self.broadcast("sync_mode_auto off")
            return

        if len(matching) == 1:
            # matched is set as active
            self.switch_idb(matching[0])
        else:
            if not len(matching):
                msg = "mod request has no match for %s"
            else:
                msg = "ambiguous mod request, too many matches for %s"

            self.broadcast(msg % modname)
            # no match current idb (if existing) is disabled
            if self.current_idb.enabled:
                self.switch_idb(None)

    # sync mode tells if idb switch is automatic or manual
    def req_sync_mode(self, s, hash):
        mode = hash['auto']
        self.broadcast("sync mode auto set to %s" % mode)
        self.sync_mode_auto = (mode == "on")

    # bc request should be forwarded to all idbs
    def req_bc(self, s, hash):
        msg = "[sync]%s" % json.dumps(hash)
        self.forward_all(msg)

    def req_cmd(self, s, hash):
        cmd = hash['cmd']
        self.current_dbg.client_sock.sendall("%s\n" % cmd)


def err_log(msg):
    fd = open("%s.err" % __file__, 'w')
    fd.write(msg)
    fd.close()

if __name__ == "__main__":

    server = DispatcherSrv()

    for loc in ['IDB_PATH', 'USERPROFILE', 'HOME']:
        if loc in os.environ:
            confpath = os.path.join(os.path.realpath(os.environ[loc]), '.sync')
            if os.path.exists(confpath):
                config = ConfigParser.SafeConfigParser({'host': HOST, 'port': PORT})
                config.read(confpath)
                HOST = config.get("INTERFACE", 'host')
                PORT = config.getint("INTERFACE", 'port')
                server.announcement("configuration file loaded")
                break

    try:
        server.bind(HOST, PORT)
    except Exception as e:
        err_log("dispatcher failed to bind on %s:%s\n-> %s" % (HOST, PORT, repr(e)))
        sys.exit()

    try:
        server.loop()
    except Exception as e:
        err_log("dispatcher failed\n-> %s" % repr(e))
        server.announcement("dispatcher stop")
