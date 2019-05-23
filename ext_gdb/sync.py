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
import re
import sys
import time
import socket
import errno
import base64
import tempfile
import threading
import json
import gdb
try:
    import configparser
except ImportError:
    import ConfigParser as configparser


VERBOSE = 0

HOST = "localhost"
PORT = 9100

TIMER_PERIOD = 0.2


# function gdb_execute courtesy of StalkR
# Wrapper when gdb.execute(cmd, to_string=True) does not work
def gdb_execute(cmd):
    f = tempfile.NamedTemporaryFile()
    gdb.execute("set logging file %s" % f.name)
    gdb.execute("set logging redirect on")
    gdb.execute("set logging overwrite")
    gdb.execute("set logging on")

    try:
        gdb.execute(cmd)
    except Exception as e:
        gdb.execute("set logging off")
        f.close()
        raise e

    gdb.execute("set logging off")
    s = open(f.name, "r").read()
    f.close()
    return s


def get_pid(ctx=None):
    if (ctx is not None) and ("pid" in ctx.keys()):
        return ctx["pid"]

    inferiors = gdb.inferiors()
    for inf in gdb.inferiors():
        if inf.is_valid():
            return inf.pid

    raise Exception("get_pid(): failed to find program's pid")


def coalesce_space(maps, next_start, next_name):
    if len(maps) == 0:
        return False

    start, end, size, name = maps[-1]

    # contiguous spaces
    if (end == next_start) and (name == next_name):
        return True

    return False


def get_maps(verbose=True, ctx=None):
    "Return list of maps (start, end, permissions, file name) via /proc"

    if (ctx is not None) and ("mappings" in ctx.keys()):
        return ctx["mappings"]

    pid = get_pid(ctx=ctx)
    if pid is False:
        if verbose:
            print("Program not started")
        return []
    maps = []

    mapping = gdb_execute('info proc mappings')
    try:
        for line in mapping.splitlines():
            e = [x for x in line.strip().split() if x != '']
            if (not e) or (len(e) < 5):
                continue
            else:
                if not e[0].startswith('0x'):
                    continue

                name = (' ').join(e[4:])
                e = e[:4] + [name]
                start, end, size, offset, name = e

                new_entry = [int(start, 16), int(end, 16), int(size, 16), name]

                if coalesce_space(maps, new_entry[0], name):
                    maps[-1][1] = new_entry[1]
                    maps[-1][2] += new_entry[2]
                else:
                    maps.append(new_entry)

    except Exception as e:
        print(e)
        print("[sync] failed to parse info proc mappings")

    return maps


def get_mod_by_addr(maps, addr):
    for mod in maps:
        if (addr > mod[0]) and (addr < mod[1]):
            return [mod[0], mod[3]]
    return None


def get_mod_by_name(maps, name):
    for mod in maps:
        if os.path.basename(mod[3]) == os.path.basename(name):
            return [mod[0], mod[3]]
    return None


def get_pc():
    try:
        pc_str = str(gdb.parse_and_eval("$pc"))
    except Exception as e:
        # debugger may not be running: 'No registers':
        return None

    return int((pc_str.split(" ")[0]), 16)


class Tunnel():

    def __init__(self, host, port):
        print("[sync] Initializing tunnel to IDA using %s:%d..." % (host, port))
        self.sock = None

        try:
            self.sock = socket.create_connection((host, port), 4)
        except socket.error as msg:
            if self.sock:
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


# run commands
# from https://sourceware.org/gdb/onlinedocs/gdb/Basic-Python.html#Basic-Python
# GDB is not thread-safe. If your Python program uses multiple threads,
# you must be careful to only call GDB-specific functions in the GDB thread.
# post_event ensures this.
class Runner():

    def __init__(self, batch):
        self.batch = batch

    def __call__(self):
        for cmd in self.batch:
            if (cmd == ''):
                continue
            gdb.execute(cmd, True, False)


# periodically poll socket in a dedicated thread
class Poller(threading.Thread):

    def __init__(self, sync):
        threading.Thread.__init__(self)
        self.evt_enabled = threading.Event()
        self.evt_enabled.clear()
        self.evt_stop = threading.Event()
        self.evt_stop.clear()
        self.sync = sync

    def run(self):
        while True:
            if self.evt_stop.is_set():
                break

            self.evt_enabled.wait()

            if not self.sync.tunnel:
                break

            if self.sync.tunnel.is_up():
                self.poll()

            time.sleep(TIMER_PERIOD)

    def poll(self):
        msg = self.sync.tunnel.poll()
        if msg:
            batch = [cmd.strip() for cmd in msg.split('\n') if cmd]
            if batch:
                gdb.post_event(Runner(batch))
        else:
            gdb.post_event(Runner(['syncoff']))
            self.stop()

    def enable(self):
        self.evt_enabled.set()

    def disable(self):
        self.evt_enabled.clear()

    def stop(self):
        self.evt_stop.set()


class Sync(gdb.Command):

    def __init__(self, host, port, ctx=None):
        gdb.Command.__init__(self, "sync", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.ctx = ctx
        self.pid = None
        self.maps = None
        self.base = None
        self.offset = None
        self.tunnel = None
        self.poller = None
        self.host = host
        self.port = port
        gdb.events.exited.connect(self.exit_handler)
        gdb.events.cont.connect(self.cont_handler)
        gdb.events.stop.connect(self.stop_handler)
        gdb.events.new_objfile.connect(self.newobj_handler)

        print("[sync] commands added")

    def identity(self):
        f = tempfile.NamedTemporaryFile()
        gdb.execute("shell uname -svm > %s" % f.name)
        id = open(f.name, 'r').read()
        f.close()
        return id.strip()

    def mod_info(self, addr):
        if not self.maps:
            self.maps = get_maps(ctx=self.ctx)
            if not self.maps:
                print("[sync] failed to get maps")
                return None

        return get_mod_by_addr(self.maps, addr)

    def locate(self):
        offset = get_pc()
        if not offset:
            print("<not running>")
            return

        if not self.pid:
            self.pid = get_pid(ctx=self.ctx)
            if self.pid is None:
                print("[sync] failed to get pid")
                return
            else:
                print("[sync] pid: %s" % self.pid)

        self.offset = offset

        mod = self.mod_info(self.offset)
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
            print("[sync] unknown module at current PC: 0x%x" % self.offset)
            print("[sync] NOTE: will resume sync when at a known module address")
            self.base = None
            self.offset = None

    def create_poll_timer(self):
        if not self.poller:
            self.poller = Poller(self)
            self.poller.start()

    def release_poll_timer(self):
        if self.poller:
            self.poller.stop()
            self.poller = None

    def newobj_handler(self, event):
        # force a new capture
        self.maps = None

    def cont_handler(self, event):
        if self.tunnel:
            if self.poller is not None:
                self.poller.disable()
        return ''

    def stop_handler(self, event):
        if self.tunnel:
            self.locate()
            if self.poller is not None:
                self.poller.enable()
        return ''

    def exit_handler(self, event):
        self.reset_state()
        print("[sync] exit, sync finished")

    def reset_state(self):
        try:
            self.release_poll_timer()

            if self.tunnel:
                self.tunnel.close()
                self.tunnel = None

            self.pid = None
            self.maps = None
            self.base = None
            self.offset = None
        except Exception as e:
            print(e)

    def invoke(self, arg, from_tty):
        if self.tunnel and not self.tunnel.is_up():
            self.tunnel = None

        if not self.tunnel:
            if arg == "":
                arg = self.host

            self.tunnel = Tunnel(arg, self.port)
            if not self.tunnel.is_up():
                print("[sync] sync failed")
                return

            id = self.identity()
            self.tunnel.send("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - %s\",\"dialect\":\"gdb\"}\n" % id)
            print("[sync] sync is now enabled with host %s" % str(arg))
            self.create_poll_timer()
        else:
            print('(update)')

        self.locate()
        if self.poller is not None:
            self.poller.enable()


class Syncoff(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "syncoff", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        self.sync.reset_state()
        print("[sync] sync is now disabled")


class Cmt(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "cmt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        if arg == "":
            print("[sync] usage: cmt [-a 0xBADF00D] <cmt to add>")
            return

        self.sync.tunnel.send("[sync]{\"type\":\"cmt\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" %
                              (arg, self.sync.base, self.sync.offset))


class Fcmt(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "fcmt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        self.sync.tunnel.send("[sync]{\"type\":\"fcmt\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" %
                              (arg, self.sync.base, self.sync.offset))


class Rcmt(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "rcmt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        self.sync.tunnel.send("[sync]{\"type\":\"rcmt\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" %
                              (arg, self.sync.base, self.sync.offset))


class Translate(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "translate", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        base, address, module = [a.strip() for a in arg.split(" ")]
        maps = get_maps(ctx=self.sync.ctx)
        if not maps:
            print("[sync] failed to get maps")
            return None

        mod = get_mod_by_name(maps, module)
        if not mod:
            print("[sync] failed to locate module %s" % module)
            return None

        mod_base, mod_sym = mod
        rebased = int(address, 16) - int(base, 16) + mod_base
        print("[sync] module %s based at 0x%x, rebased address: 0x%x\n" % (mod_sym, mod_base, rebased))


class Bc(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "bc", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        if arg == "":
            arg = "oneshot"

        if not (arg in ["on", "off", "oneshot"]):
            print("[sync] usage: bc <|on|off>")
            return

        self.sync.tunnel.send("[notice]{\"type\":\"bc\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" %
                              (arg, self.sync.base, self.sync.offset))


class Cmd(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "cmd", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        if arg == "":
            print("[sync] usage: cmd <command to execute and dump>")
        cmd_output = gdb_execute(arg).encode('ascii')
        b64_output = base64.b64encode(cmd_output).decode()
        self.sync.tunnel.send("[sync] {\"type\":\"cmd\",\"msg\":\"%s\", \"base\":%d,\"offset\":%d}\n" % (b64_output, self.sync.base, self.sync.offset))
        print("[sync] command output:\n%s" % cmd_output.strip())


class Rln(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "rln", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        raddr = int(arg, 16)

        # First disable tunnel polling for commands (happy race...)
        self.sync.release_poll_timer()

        # XXX - we don't support a rebase yet
        self.sync.tunnel.send("[sync]{\"type\":\"rln\",\"raddr\":%d,\"rbase\":%d,\"base\":%d,\"offset\":%d}\n" %
                              (raddr, 0x0, self.sync.base, self.sync.offset))

        # Let time for the IDB client to reply if it exists
        time.sleep(0.150)

        # Poll tunnel
        msg = self.sync.tunnel.poll()
        print("[sync] resolved symbol: %s" % msg)

        # Re-enable tunnel polling
        self.sync.create_poll_timer()


symtable = {}
class Bbt(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "bbt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        bt = gdb.execute("bt", to_string=True)
        bt = bt.split("\n")
        bt = [l.split() for l in bt]
        bt = bt[:-1]  # remove [] at the end

        for l in bt:
            try:
                raddr = int(l[1], 16)
            except ValueError:
                continue
            symbol = l[3]
            if symbol == '??':

                # Do not update each request. XXX - have an updatedb command for that?
                # if raddr in symtable.keys():
                #    continue

                # First disable tunnel polling for commands (happy race...)
                self.sync.release_poll_timer()

                # XXX - we don't support a rebase yet
                self.sync.tunnel.send("[sync]{\"type\":\"rln\",\"raddr\":%d,\"rbase\":%d,\"base\":%d,\"offset\":%d}\n" %
                                      (raddr, 0x0, self.sync.base, self.sync.offset))

                # Let time for the IDB client to reply if it exists
                time.sleep(0.150)

                # Poll tunnel
                msg = self.sync.tunnel.poll()

                symtable[raddr] = msg[:-1]  # remove \n at the end

        # Re-enable tunnel polling
        self.sync.create_poll_timer()

        # XXX - beautiful printed indented backtrace
        for l in bt:
            try:
                raddr = int(l[1], 16)
            except ValueError:
                continue
            try:
                symbol = symtable[raddr]
            except KeyError:
                continue
            if "+" in symbol:
                symbol = symbol.split("+")[0]
            l[3] = symbol

        bt = "\n".join([" ".join(l) for l in bt])
        print(bt)


class Bx(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "bx", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        fmt, sym = [a.strip() for a in arg.split(" ")]
        try:
            addr = int(sym, 16)
        except:
            pass
        else:
            gdb.execute("x %s %s" % fmt, sym)
            return

        # XXX - split symbol+offset in case "+" is found in sym
        offset = 0
        if "+" in sym:
            offset = int(sym.split("+")[1], 16)
            sym = sym.split("+")[0]

        # First disable tunnel polling for commands (happy race...)
        self.sync.release_poll_timer()

        # XXX - we don't support a rebase yet
        self.sync.tunnel.send("[sync]{\"type\":\"rrln\",\"sym\":\"%s\",\"rbase\":%d,\"base\":%d,\"offset\":%d}\n" %
                              (sym, 0x0, self.sync.base, self.sync.offset))

        # Let time for the IDB client to reply if it exists
        time.sleep(0.150)

        # Poll tunnel
        msg = self.sync.tunnel.poll()
        raddr = int(msg.rstrip())

        # Re-enable tunnel polling
        self.sync.create_poll_timer()

        gdb.execute("x %s 0x%x" % (fmt, raddr+offset))


class Cc(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "cc", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        # First disable tunnel polling for commands (happy race...)
        self.sync.release_poll_timer()

        self.sync.tunnel.send("[sync]{\"type\":\"cursor\"}\n")

        # Let time for the IDB client to reply if it exists
        time.sleep(0.150)

        # Poll tunnel
        msg = self.sync.tunnel.poll()
        ida_cursor = int(msg, 10)
        print("[sync] current cursor: 0x%x" % ida_cursor)

        # Re-enable tunnel polling
        self.sync.create_poll_timer()

        time.sleep(0.150)  # necessary to avoid garbage in res from gdb.execute()?

        # Set a breakpoint to cursor address in IDA
        res = gdb.execute("b *0x%x" % ida_cursor, to_string=True)
        if not res.startswith("Breakpoint "):
            print("[sync] failed to set a breakpoint to 0x%x" % ida_cursor)
            return
        bp_id = int(res.split()[1])

        # Continue to cursor
        res = gdb.execute("continue", to_string=True)

        # Finally, delete breakpoint that we hit
        # XXX - we should actually log if the breakpoint we set earlier is the one we hit
        #       otherwise we remove the breakpoint anyway :/
        regexp_list = re.findall("Thread \d hit Breakpoint \d+, (0x[0-9a-f]+) in", res)
        if not regexp_list:
            regexp_list = re.findall("Breakpoint \d+, (0x[0-9a-f]+) in", res)
        if regexp_list:
            reached_addr = int(regexp_list[0], 16)
            if reached_addr == ida_cursor:
                print("[sync] reached successfully")
                res = gdb.execute("d %d" % bp_id)
            else:
                print("[sync] reached other breakpoint before cc reached 0x%x" % ida_cursor)
        else:
            print("[sync] failed to remove breakpoint because gdb did not give us any info :/")


class Patch(gdb.Command):

    def __init__(self, sync):
        gdb.Command.__init__(self, "patch", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync = sync

    def invoke(self, arg, from_tty):
        if not self.sync.base:
            print("[sync] process not synced, command is dropped")
            return

        if arg == "":
            print("[sync] usage: patch <address> <count qwords/dwords> <len_unit>")
            return

        addr, count, length = [a.strip() for a in arg.split(" ")]
        addr = int(addr, 16)
        count = int(count)
        length = int(length)
        if length != 4 and length != 8:
            print("[sync] Only words and qword supported")
            return

        for i in range(count):
            if length == 8:
                res = gdb.execute("x /gx 0x%x" % (addr+8*i), to_string=True)
            elif length == 4:
                res = gdb.execute("x /wx 0x%x" % (addr+4*i), to_string=True)
            res = res.rstrip()  # remove EOL
            value = int(res.split("\t")[1], 16)
            self.sync.tunnel.send("[sync]{\"type\":\"patch\",\"addr\":%d,\"value\":%d, \"len\": %d}\n" %
                                  (addr+length*i, value, length))


class Help(gdb.Command):

    def __init__(self):
        gdb.Command.__init__(self, "synchelp", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        print(
"""[sync] extension commands help:
 > sync [<host>]                 = synchronize with <host> or the default value
 > syncoff                       = stop synchronization
 > cmt [-a address] <string>     = add comment at current eip (or [addr]) in IDA
 > rcmt [-a address] <string>    = reset comments at current eip (or [addr]) in IDA
 > fcmt [-a address] <string>    = add a function comment for 'f = get_func(eip)' (or [addr]) in IDA
 > cmd <string>                  = execute command <string> and add its output as comment at current eip in IDA
 > bc <on|off|>                  = enable/disable path coloring in IDA
                                   color a single instruction at current eip if called without argument
 > rln <address>                 = ask IDA Pro to convert an address into a symbol
 > bbt <symbol>                  = beautiful backtrace by executing "bt" and retrieving symbols from IDA Pro
                                   for each element of the backtrace
 > patch <addr> <count> <size>   = patch in IDA count elements of size (in [4, 8]) at address, reflecting live
                                   context
 > bx /i <symbol>                = similar to "x /i <address>" but supports a symbol resolved from IDA Pro
 > cc                            = continue to current cursor in IDA Pro (set a breakpoints, continue and remove it)
 > translate <base> <addr> <mod> = rebase an address with respect to local module's base\n\n""")


if __name__ == "__main__":
    ctx = None

    locations = [os.path.join(os.path.expanduser(os.path.dirname(__file__)), ".sync"),
                 os.path.join(os.environ['HOME'], ".sync")]

    for confpath in locations:
        if os.path.exists(confpath):
            config = configparser.SafeConfigParser({'host': HOST, 'port': PORT, 'context': ''})
            config.read(confpath)
            print("[sync] configuration file loaded from: %s" % confpath)

            if config.has_section("INTERFACE"):
                HOST = config.get("INTERFACE", 'host')
                PORT = config.getint("INTERFACE", 'port')
                print("       interface: %s:%s" % (HOST, PORT))

            if config.has_section("INIT"):
                ctx = config.get("INIT", 'context')
                if ctx != '':
                    # eval() for fun
                    ctx = eval(ctx)
                    print("[sync] initialization context:\n%s\n" % json.dumps(context, indent=4))
                else:
                    ctx = None

            break

    sync = Sync(HOST, PORT, ctx)
    Syncoff(sync)
    Cmt(sync)
    Rcmt(sync)
    Fcmt(sync)
    Bc(sync)
    Translate(sync)
    Cmd(sync)
    Rln(sync)
    Bbt(sync)
    Bx(sync)
    Cc(sync)
    Patch(sync)
    Help()
