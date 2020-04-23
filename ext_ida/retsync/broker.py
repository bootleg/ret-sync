#
# Copyright (C) 2016-2020, Alexandre Gazet.
#
# Copyright (C) 2012-2015, Quarkslab.
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

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import re
import shlex
import argparse
import subprocess
import socket
import select
from contextlib import contextmanager

try:
    from ConfigParser import SafeConfigParser
except ImportError:
    from configparser import ConfigParser as SafeConfigParser

try:
    import json
except ImportError:
    print("[-] failed to import json\n%s" % repr(sys.exc_info()))
    sys.exit(0)

# python 2.7 compat
try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

import rsconfig
from rsconfig import rs_encode, rs_decode

# Networking
HOST = rsconfig.HOST
PORT = rsconfig.PORT

# Logging
rs_log = rsconfig.init_logging(__file__)


# default value is current script's path
DISPATCHER_PATH = os.path.join(os.path.realpath(os.path.dirname(__file__)), 'dispatcher.py')
if not os.path.exists(DISPATCHER_PATH):
    print("[-] dispatcher path is not properly set, current value: <%s>" % DISPATCHER_PATH)
    sys.exit(0)


class Client():

    def __init__(self, s):
        self.sock = s
        self.buffer = ''

    def feed(self, data):
        batch = []
        self.buffer = ''.join([self.buffer, data])
        if self.buffer.endswith("\n"):
            batch = [req.strip() for req in self.buffer.split('\n') if req != '']
            self.buffer = ''

        return batch


class BrokerSrv():

    def puts(self, msg):
        print(msg)
        sys.stdout.flush()

    def announcement(self, msg):
        self.puts("[sync]{\"type\":\"broker\",\"subtype\":\"msg\",\"msg\":\"%s\"}\n" % msg)

    def notice_idb(self, msg):
        self.puts("[sync]{\"type\":\"broker\",\"subtype\":\"notice\",\"port\":\"%d\"}\n" % msg)

    def notice_dispatcher(self, type, args=None):
        if args:
            notice = "[notice]{\"type\":\"%s\",%s}\n" % (type, args)
        else:
            notice = "[notice]{\"type\":\"%s\"}\n" % (type)

        self.notify_socket.sendall(rs_encode(notice))

    def bind(self):
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_sock.bind(('localhost', 0))
        self.srv_port = self.srv_sock.getsockname()[1]

    def run_dispatcher(self):
        cmdline = "\"%s\" -u \"%s\"" % (PYTHON_PATH, DISPATCHER_PATH)
        tokenizer = shlex.shlex(cmdline)
        tokenizer.whitespace_split = True
        args = [arg.replace('\"', '') for arg in list(tokenizer)]
        try:
            proc = subprocess.Popen(args, shell=False,
                                    stdout=DEVNULL,
                                    stderr=DEVNULL)
            pid = proc.pid
        except (OSError, ValueError):
            pid = None
            self.err_log('failed to run dispatcher')

        time.sleep(0.2)
        return pid

    def notify(self):
        for attempt in range(rsconfig.RUN_DISPATCHER_MAX_ATTEMPT):
            try:
                self.notify_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.notify_socket.settimeout(2)
                self.notify_socket.connect(('127.0.0.1', PORT))
                break
            except socket.error:
                self.notify_socket.close()
                if (attempt != 0):
                    self.announcement("failed to connect to dispatcher (attempt %d)" % (attempt))
                if (attempt == (rsconfig.RUN_DISPATCHER_MAX_ATTEMPT - 1)):
                    self.announcement('failed to connect to dispatcher, too much attempts, exiting...')
                    sys.exit()

            self.announcement('dispatcher not found, trying to run it')
            pid = self.run_dispatcher()
            if pid:
                self.announcement("dispatcher now runs with pid: %d" % (pid))

        time.sleep(0.1)
        self.notice_dispatcher('new_client', "\"port\":%d,\"idb\":\"%s\"" % (self.srv_port, self.name))
        self.announcement('connected to dispatcher')
        self.notice_idb(self.srv_port)

    def accept(self):
        new_socket, addr = self.srv_sock.accept()
        self.clients_list.append(Client(new_socket))
        self.opened_sockets.append(new_socket)

    def close(self, s):
        client = [client for client in self.clients_list if (client.sock == s)]
        if len(client) == 1:
            self.clients_list.remove(client[0])
        s.close()
        self.opened_sockets.remove(s)

    def recvall(self, client):
        try:
            data = rs_decode(client.sock.recv(4096))
            if data == '':
                raise Exception('rabbit eating the cable')
        except socket.error:
            self.err_log('dispatcher connection error, quitting')

        return client.feed(data)

    def req_dispatcher(self, s, hash):
        subtype = hash['subtype']
        if subtype == 'msg':
            msg = hash['msg']
            self.announcement("dispatcher msg: %s" % msg)
        elif subtype == 'beacon':
            # dispatcher sends a beacon at startup
            self.beaconed = True

    def req_cmd(self, s, hash):
        cmd = hash['cmd']
        self.notice_dispatcher('cmd', "\"cmd\":\"%s\"" % cmd)

    def req_kill(self, s, hash):
        self.notice_dispatcher('kill')
        self.announcement('received kill notice')
        for s in ([self.srv_sock] + self.opened_sockets):
            s.close()
        sys.exit()

    # idb is checking if broker has received beacon from dispatcher
    def req_beacon(self, s, hash):
        if not self.beaconed:
            self.announcement('beacon not received (possible dispatcher error)')
            self.req_kill(s, hash)

    def parse_exec(self, s, req):
        if not (req[0:8] == '[notice]'):
            self.puts(req)
            return

        req = self.normalize(req, 8)

        try:
            hash = json.loads(req)
        except ValueError:
            self.announcement("[-] broker failed to parse json\n %s" % repr(req))
            return

        type = hash['type']
        if type not in self.req_handlers:
            self.announcement("[x] broker unknown request: %s\njson: %s" % (type, repr(req)))
            return

        req_handler = self.req_handlers[type]
        req_handler(s, hash)

    def normalize(self, req, taglen):
        req = req[taglen:]
        req = req.replace("\\", "\\\\")
        req = req.replace("\n", "")
        return req

    def handle(self, s):
        client = [client for client in self.clients_list if (client.sock == s)]
        if len(client) == 1:
            batch = self.recvall(client[0])
        else:
            self.announcement('socket error')
            raise Exception('rabbit eating the cable')

        for req in batch:
            if req != '':
                self.parse_exec(s, req)

    def loop(self):
        self.srv_sock.listen(5)
        while True:
            rlist, wlist, xlist = select.select([self.srv_sock] + self.opened_sockets, [], [])

            if not rlist:
                self.announcement('socket error: select')
                raise Exception('rabbit eating the cable')

            for s in rlist:
                if s is self.srv_sock:
                    self.accept()
                else:
                    self.handle(s)

    # use logging facility to record the exception and exit
    def err_log(self, msg):
        rs_log.exception(msg, exc_info=True)
        try:
            # inform idb and dispatcher
            self.announcement(msg)
            self.notice_dispatcher('kill')
        except Exception as e:
            pass
        finally:
            sys.exit()

    def __init__(self):
        self.name = None
        self.beaconed = False
        self.opened_sockets = []
        self.clients_list = []
        self.pat = re.compile('dbg disconnected')
        self.req_handlers = {
            'dispatcher': self.req_dispatcher,
            'cmd': self.req_cmd,
            'kill': self.req_kill,
            'beacon': self.req_beacon
        }


@contextmanager
def error_reporting(stage, info=None):
    try:
        yield
    except Exception as e:
        server.err_log(' error - '.join(filter(None, (stage, info))))


if __name__ == "__main__":

    server = BrokerSrv()

    with error_reporting('server.env', 'PYTHON_PATH not found'):
        PYTHON_PATH = os.environ['PYTHON_PATH']

    parser = argparse.ArgumentParser()
    parser.add_argument('--idb', nargs=1, action='store')

    with error_reporting('server.arg', 'missing idb argument'):
        args = parser.parse_args()
        server.name = args.idb[0]

    with error_reporting('server.config'):
        for loc in ('IDB_PATH', 'USERPROFILE', 'HOME'):
            if loc in os.environ:
                confpath = os.path.join(os.path.realpath(os.environ[loc]), '.sync')
                if os.path.exists(confpath):
                    config = SafeConfigParser({'port': PORT, 'host': HOST})
                    config.read(confpath)
                    if config.has_section('INTERFACE'):
                        PORT = config.getint('INTERFACE', 'port')
                        HOST = config.get('INTERFACE', 'host')
                    break

    with error_reporting('server.bind'):
        server.bind()

    with error_reporting('server.notify'):
        server.notify()

    with error_reporting('server.loop'):
        server.loop()
