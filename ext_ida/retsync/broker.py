#
# Copyright (C) 2016-2021, Alexandre Gazet.
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
import json
from contextlib import contextmanager

# python 2.7 compat
try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

import rsconfig
from rsconfig import rs_encode, rs_decode, load_configuration


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
        self.stdout.write(rs_encode(msg + '\n'))
        self.stdout.flush()

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
        script_path = os.path.join(os.path.realpath(os.path.dirname(__file__)), 'dispatcher.py')
        if not os.path.exists(script_path):
            msg = "dispatcher not found, should be in: %s" % script_path
            self.err_log(msg)

        cmdline = "\"%s\" -u \"%s\"" % (PYTHON_PATH, script_path)
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

    def notify(self, port):
        self.dispatcher_port = port
        for attempt in range(rsconfig.RUN_DISPATCHER_MAX_ATTEMPT):
            try:
                self.notify_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.notify_socket.settimeout(2)
                self.notify_socket.connect(('127.0.0.1', port))
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
            self.announcement("beacon not received (this may be dispatcher error, "
                              "tip: please check that the port %d is available )" % self.dispatcher_port)
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
        self.stdout = getattr(sys.stdout, 'buffer', sys.stdout)
        self.dispatcher_port = None
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

    rs_log = rsconfig.init_logging(__file__)
    server = BrokerSrv()

    with error_reporting('server.env', 'PYTHON_PATH not found'):
        PYTHON_PATH = os.environ['PYTHON_PATH']

    parser = argparse.ArgumentParser()
    parser.add_argument('--idb', nargs=1, action='store')

    with error_reporting('server.arg', 'missing idb argument'):
        args = parser.parse_args()
        server.name = args.idb[0]

    with error_reporting('server.config'):
        rs_cfg = load_configuration()

    with error_reporting('server.bind'):
        server.bind()

    with error_reporting('server.notify'):
        server.notify(rs_cfg.port)

    with error_reporting('server.loop'):
        server.loop()
