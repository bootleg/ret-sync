#
# Copyright (C) 2016-2021, Alexandre Gazet.
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
import logging
import json
import gdb
import traceback
from collections import namedtuple
from string import Template

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import SafeConfigParser as ConfigParser


# default values
HOST = "localhost"
PORT = 9100
USE_TMP_LOGGING_FILE = True
TIMER_PERIOD = 0.1
PYTHON_MAJOR = sys.version_info[0]

# location searched by the debugger for a configuration file
CONFIG_LOCATIONS = [
    os.path.abspath(os.path.dirname(__file__)),
    os.environ['HOME']]

# encoding settings (for data going in/out the plugin)
RS_ENCODING = 'utf-8'

# log settings
LOG_LEVEL = logging.INFO
LOG_PREFIX = 'sync'
LOG_COLOR_ON = "\033[1m\033[34m"
LOG_COLOR_OFF = "\033[0m"
CMD_COLOR_ON = "\033[1m\033[91m"
CMD_COLOR_OFF = "\033[0m"


def rs_encode(buffer_str):
    return buffer_str.encode(RS_ENCODING)


def rs_decode(buffer_bytes):
    return buffer_bytes.decode(RS_ENCODING)


def rs_log(s, lvl=logging.INFO):
    if lvl >= LOG_LEVEL:
        print("%s[%s]%s %s" % (LOG_COLOR_ON, LOG_PREFIX, LOG_COLOR_OFF, s))


class DbgHelp():

    # function show_last_exception courtesy of saidelike
    # exception handler to ease commands debug
    @staticmethod
    def show_last_exception(cmd):
        horizontal_line = "-"
        right_arrow = "->"
        down_arrow = "\\->"

        print("")
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print(" Exception raised in {} command".format(cmd).center(80, horizontal_line))
        print("{}: {}".format(exc_type.__name__, exc_value))
        print(" Detailed stacktrace ".center(80, horizontal_line))
        for fs in traceback.extract_tb(exc_traceback)[::-1]:
            if PYTHON_MAJOR == 2:
                filename, lineno, method, code = fs
            else:
                filename, lineno, method, code = fs.filename, fs.lineno, fs.name, fs.line

            print("""{} File "{}", line {:d}, in {}()""".format(down_arrow, filename,
                                                                lineno, method))
            print("   {}    {}\n".format(right_arrow, code))

    # function gdb_execute courtesy of StalkR
    # Wrapper when gdb.execute(cmd, to_string=True) does not work
    @staticmethod
    def gdb_execute(cmd, use_tmp_logging_file=True):
        if not use_tmp_logging_file:
            return gdb.execute(cmd, to_string=True)
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

    @staticmethod
    def get_pid(ctx=None):
        if (ctx is not None) and ("pid" in ctx.keys()):
            return ctx["pid"]

        for inf in gdb.inferiors():
            # if Inferior.threads() is an empty tuple
            # the program being debugged is not being run.
            if inf.is_valid() and inf.threads():
                return inf.pid

        print("get_pid(): failed to find program's pid")
        return None

    @staticmethod
    def coalesce_space(maps, next_start, next_name):
        if len(maps) == 0:
            return False

        start, end, size, name = maps[-1]

        # contiguous spaces
        if (end == next_start) and (name == next_name):
            return True

        return False

    @staticmethod
    def get_maps(cfg):
        "Return list of maps (start, end, permissions, file name) via /proc"

        if (cfg.ctx is not None) and ("mappings" in cfg.ctx.keys()):
            return cfg.ctx["mappings"]

        pid = DbgHelp.get_pid(ctx=cfg.ctx)
        if pid is None:
            return []

        maps = []
        mapping = DbgHelp.gdb_execute('info proc mappings', cfg.use_tmp_logging_file)

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

                    if DbgHelp.coalesce_space(maps, new_entry[0], name):
                        maps[-1][1] = new_entry[1]
                        maps[-1][2] += new_entry[2]
                    else:
                        maps.append(new_entry)

        except Exception as e:
            print(e)
            rs_log("failed to parse info proc mappings")

        return maps

    @staticmethod
    def get_mod_by_addr(maps, addr):
        for mod in maps:
            if (addr > mod[0]) and (addr < mod[1]):
                return [mod[0], mod[3]]
        return None

    @staticmethod
    def get_mod_by_name(maps, name):
        for mod in maps:
            if os.path.basename(mod[3]) == os.path.basename(name):
                return [mod[0], mod[3]]
        return None

    @staticmethod
    def get_pc():
        try:
            pc_str = str(gdb.parse_and_eval("$pc"))
        except Exception as e:
            # debugger may not be running: 'No registers':
            return None

        return int((pc_str.split(" ")[0]), 16)


class Tunnel():

    def __init__(self, host, port):
        rs_log("initializing tunnel to IDA using %s:%d..." % (host, port))
        self.sock = None

        try:
            self.sock = socket.create_connection((host, port), 4)
        except socket.error as msg:
            if self.sock:
                self.sock.close()
                self.sock = None
            self.sync = False
            rs_log("tunnel initialization error: %s" % msg)
            return None

        self.sync = True

    def is_up(self):
        return (self.sock is not None and self.sync is True)

    def poll(self):
        if not self.is_up():
            return None

        self.sock.setblocking(False)

        try:
            msg = rs_decode(self.sock.recv(4096))
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
            rs_log("tunnel_send: tunnel is unavailable (did you forget to sync ?)")
            return

        try:
            self.sock.send(rs_encode(msg))
        except socket.error as msg:
            print(msg)
            self.sync = False
            self.close()

            rs_log("tunnel_send error: %s" % msg)

    def close(self):
        if self.is_up():
            self.send("[notice]{\"type\":\"dbg_quit\",\"msg\":\"dbg disconnected\"}\n")

        if self.sock:
            try:
                self.sock.close()
            except socket.error as msg:
                rs_log("tunnel_close error: %s" % msg)

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

            if not self.evt_enabled.is_set():
                while True:
                    if self.evt_enabled.wait(2*TIMER_PERIOD):
                        break
                    if not self.interpreter_alive():
                        return

            if not self.interpreter_alive():
                return
            if not self.sync.tunnel:
                return

            if self.sync.tunnel.is_up():
                self.poll()

            time.sleep(TIMER_PERIOD)

    # "the main thread is the thread from which the Python interpreter was started"
    def interpreter_alive(self):
        return threading.main_thread().is_alive()

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


# wrap gdb.Command invoke in try/catch
class WrappedCommand(gdb.Command):

    def __init__(self, sync, offline=False):
        self.sync = sync
        self.offline = offline

    def invoke(self, arg, from_tty):
        if not self.offline:
            if not self.sync.base:
                rs_log("process not synced or not running, command is dropped")
                return

        try:
            self._invoke(arg, from_tty)
        except Exception as e:
            DbgHelp.show_last_exception(self.__class__.__name__)


class Sync(gdb.Command):

    def __init__(self, cfg, commands=[]):
        rs_log("init")
        gdb.Command.__init__(self, "sync", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.cfg = cfg
        self.auto = True
        self.pid = None
        self.maps = None
        self.base = None
        self.offset = None
        self.tunnel = None
        self.poller = None

        gdb.events.exited.connect(self.exit_handler)
        gdb.events.cont.connect(self.cont_handler)
        gdb.events.stop.connect(self.stop_handler)
        gdb.events.new_objfile.connect(self.newobj_handler)

        for cmd in commands:
            cmd(self)

        rs_log("%d commands added" % len(commands))

    def identity(self):
        with tempfile.NamedTemporaryFile() as fd:
            gdb.execute("shell uname -svm > %s" % fd.name)
            id = open(fd.name, 'r').read()
        return id.strip()

    def ensure_maps_loaded(self):
        if not self.maps:
            self.maps = DbgHelp.get_maps(self.cfg)
            if not self.maps:
                rs_log("failed to get proc mappings")
                return None

    def mod_info(self, addr):
        self.ensure_maps_loaded()
        return DbgHelp.get_mod_by_addr(self.maps, addr)

    def locate(self):
        offset = DbgHelp.get_pc()
        if not offset:
            rs_log("<not running>")
            return

        if not self.pid:
            self.pid = DbgHelp.get_pid(ctx=self.cfg.ctx)
            if self.pid is None:
                return

            rs_log("pid: %s" % self.pid)

        self.offset = offset

        if self.auto:
            mod = self.mod_info(self.offset)
            if mod:
                base, sym = mod

                if (self.base != base):
                    modules = []
                    self.ensure_maps_loaded()

                    for mod in self.maps:
                        modules.append("{\"base\":%d,\"path\":\"%s\"}" % (mod[0], mod[3]))

                    self.tunnel.send("[notice]{\"type\":\"module\",\"path\":\"%s\",\"modules\":[%s]}\n" % (sym, ','.join(modules)))
                    self.base = base

                self.tunnel.send("[sync]{\"type\":\"loc\",\"base\":%d,\"offset\":%d}\n" % (self.base, self.offset))
            else:
                rs_log("unknown module at current PC: 0x%x" % self.offset)
                rs_log("NOTE: will resume sync when at a known module address")
                self.base = None
                self.offset = None

    def create_poll_timer(self):
        if not self.poller:
            self.poller = Poller(self)
            self.poller.start()

    def suspend_poll_timer(self):
        if self.poller:
            self.poller.disable()

    def rearm_poll_timer(self):
        if self.poller:
            self.poller.enable()

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
        rs_log("exit, sync finished")

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
                arg = self.cfg.host

            self.tunnel = Tunnel(arg, self.cfg.port)
            if not self.tunnel.is_up():
                rs_log("sync failed")
                return

            id = self.identity()
            self.tunnel.send("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - %s\",\"dialect\":\"gdb\"}\n" % id)
            rs_log("sync is now enabled with host %s" % str(arg))
            self.create_poll_timer()
        else:
            print('(update)')

        if self.poller:
            self.poller.enable()


class Syncoff(WrappedCommand):

    def __init__(self, sync):
        super(Syncoff, self).__init__(sync, True)
        gdb.Command.__init__(self, "syncoff", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        self.sync.reset_state()
        rs_log("sync is now disabled")


class Syncmodauto(WrappedCommand):

    def __init__(self, sync):
        super(Syncmodauto, self).__init__(sync, True)
        gdb.Command.__init__(self, "syncmodauto", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        if arg == 'on':
            self.sync.auto = True
        elif arg == 'off':
            self.sync.auto = False
        else:
            rs_log("usage: syncmodauto <on|off>")
            return

        self.sync.tunnel.send("[notice]{\"type\":\"sync_mode\",\"auto\":\"%s\"}\n" % arg)
        rs_log("auto sync is now %s" % arg)


class Idblist(WrappedCommand):

    def __init__(self, sync):
        super(Idblist, self).__init__(sync)
        gdb.Command.__init__(self, "idblist", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        # First suspend tunnel polling for commands (happy race...)
        self.sync.suspend_poll_timer()
        self.sync.tunnel.send("[notice]{\"type\":\"idb_list\"}\n")

        # Let time for the dispatcher to reply if it exists
        time.sleep(0.150)

        # Poll tunnel
        msg = self.sync.tunnel.poll()
        if not msg:
            rs_log('idblist failed')
        else:
            rs_log(msg.strip())

        # Re-enable tunnel polling
        self.sync.rearm_poll_timer()


class Idbn(WrappedCommand):

    def __init__(self, sync):
        super(Idbn, self).__init__(sync)
        gdb.Command.__init__(self, "idbn", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        if (not arg) or (arg and not arg.isdigit()):
            rs_log("usage: idbn <idb num>")
            return

        # First suspend tunnel polling for commands (happy race...)
        self.sync.suspend_poll_timer()
        self.sync.tunnel.send("[notice]{\"type\":\"idb_n\",\"idb\":\"%s\"}\n" % arg)

        # Let time for the dispatcher to reply if it exists
        time.sleep(0.150)

        err = self.poll_switch()
        if err:
            rs_log(err)
            self.sync.tunnel.send("[notice]{\"type\":\"dbg_err\"}\n")

        # Re-enable tunnel polling
        rs_log('Re-enable tunnel polling')
        self.sync.rearm_poll_timer()

    # parse input from dispatcher/program manager
    # get module information
    def poll_switch(self):
        msg = self.sync.tunnel.poll()
        if not msg:
            return 'idbn failed'

        if '> idb_n error:' in msg:
            return msg.strip()

        rs_log(msg)
        modname = msg.split('"')[1]
        maps = DbgHelp.get_maps(self.sync.cfg)

        if not maps:
            return 'failed to get program mappings'

        mod_info = DbgHelp.get_mod_by_name(maps, modname)

        if not mod_info:
            return ("failed to locate module \"%s\"" % modname)

        mod_base, mod_sym = mod_info
        self.sync.tunnel.send("[sync]{\"type\":\"rbase\",\"rbase\":%d}\n" % mod_base)
        return None


class Idb(WrappedCommand):

    def __init__(self, sync):
        super(Idb, self).__init__(sync)
        gdb.Command.__init__(self, "idb", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        if not arg:
            rs_log("usage: idb <module name>")
            return

        maps = DbgHelp.get_maps(self.sync.cfg)
        if not maps:
            rs_log("failed to get program mappings")
            return

        mod_name = arg.strip()
        mod_info = DbgHelp.get_mod_by_name(maps, mod_name)
        if not mod_info:
            rs_log("failed to locate module %s" % mod_name)
            return

        mod_base, mod_sym = mod_info
        rs_log("> mod: %s" % mod_sym)
        rs_log("> base address: %#x" % mod_base)

        self.sync.tunnel.send("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n" % mod_sym)
        self.sync.tunnel.send("[sync]{\"type\":\"rbase\",\"rbase\":%d}\n" % mod_base)


class Modlist(WrappedCommand):

    def __init__(self, sync):
        super(Modlist, self).__init__(sync)
        gdb.Command.__init__(self, "modlist", gdb.COMMAND_RUNNING, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        print(DbgHelp.gdb_execute('info proc mappings', self.sync.cfg.use_tmp_logging_file))


class Cmt(WrappedCommand):

    def __init__(self, sync):
        super(Cmt, self).__init__(sync)
        gdb.Command.__init__(self, "cmt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        if arg == "":
            rs_log("usage: cmt [-a 0xBADF00D] <cmt to add>")
            return

        self.sync.tunnel.send("[sync]{\"type\":\"cmt\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" %
                              (arg, self.sync.base, self.sync.offset))


class Fcmt(WrappedCommand):

    def __init__(self, sync):
        super(Fcmt, self).__init__(sync)
        gdb.Command.__init__(self, "fcmt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        self.sync.tunnel.send("[sync]{\"type\":\"fcmt\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" %
                              (arg, self.sync.base, self.sync.offset))


class Rcmt(WrappedCommand):

    def __init__(self, sync):
        super(Rcmt, self).__init__(sync)
        gdb.Command.__init__(self, "rcmt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        self.sync.tunnel.send("[sync]{\"type\":\"rcmt\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" %
                              (arg, self.sync.base, self.sync.offset))


class Translate(WrappedCommand):

    def __init__(self, sync):
        super(Translate, self).__init__(sync, True)
        gdb.Command.__init__(self, "translate", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        base, address, module = [a.strip() for a in arg.split(" ")]
        maps = DbgHelp.get_maps(self.sync.cfg)
        if not maps:
            rs_log("failed to get program mappings")
            return None

        mod = DbgHelp.get_mod_by_name(maps, module)
        if not mod:
            rs_log("failed to locate module %s" % module)
            return None

        mod_base, mod_sym = mod
        rebased = int(address, 16) - int(base, 16) + mod_base
        rs_log("module %s based at 0x%x, rebased address: 0x%x\n" % (mod_sym, mod_base, rebased))


class Bc(WrappedCommand):

    def __init__(self, sync):
        super(Bc, self).__init__(sync)
        gdb.Command.__init__(self, "bc", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        if arg == "":
            arg = "oneshot"

        if not (arg in ["on", "off", "oneshot"]):
            rs_log("usage: bc <|on|off>")
            return

        self.sync.tunnel.send("[notice]{\"type\":\"bc\",\"msg\":\"%s\",\"base\":%d,\"offset\":%d}\n" %
                              (arg, self.sync.base, self.sync.offset))


class Cmd(WrappedCommand):

    def __init__(self, sync):
        super(Cmd, self).__init__(sync)
        gdb.Command.__init__(self, "cmd", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        if arg == "":
            rs_log("usage: cmd <command to execute and dump>")
            return

        cmd_output = rs_encode(DbgHelp.gdb_execute(arg, self.sync.cfg.use_tmp_logging_file))
        b64_output = rs_decode(base64.b64encode(cmd_output))
        self.sync.tunnel.send("[sync] {\"type\":\"cmd\",\"msg\":\"%s\", \"base\":%d,\"offset\":%d}\n" % (b64_output, self.sync.base, self.sync.offset))
        rs_log("command output:\n%s" % cmd_output.strip())


class Rln(WrappedCommand):

    def __init__(self, sync):
        super(Rln, self).__init__(sync)
        gdb.Command.__init__(self, "rln", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        try:
            value = gdb.parse_and_eval(arg)
            if (str(value)) == 'void':
                raise ValueError
            raddr = int(str(value), 16)
        except ValueError as e:
            rs_log("rln: failed to evaluate expression \"%s\"" % arg)
            rs_log("     hint: be careful of register name case ($RIP ->$rip, cf. info registers)")
            return

        # First suspend tunnel polling for commands (happy race...)
        self.sync.suspend_poll_timer()
        self.sync.tunnel.send("[sync]{\"type\":\"rln\",\"raddr\":%d}\n" % raddr)

        # Let time for the IDB client to reply if it exists
        time.sleep(0.150)

        # Poll tunnel
        msg = self.sync.tunnel.poll()
        rs_log("resolved symbol: %s" % msg)

        # Re-enable tunnel polling
        self.sync.rearm_poll_timer()


class Bbt(WrappedCommand):

    def __init__(self, sync):
        super(Bbt, self).__init__(sync)
        gdb.Command.__init__(self, "bbt", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)
        self.sync.symtable = {}

    def _invoke(self, arg, from_tty):
        bt = gdb.execute("bt", to_string=True)
        bt = bt.split("\n")
        bt = [l.split() for l in bt]
        bt = bt[:-1]  # remove [] at the end

        # First suspend tunnel polling for commands (happy race...)
        self.sync.suspend_poll_timer()

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

                self.sync.tunnel.send("[sync]{\"type\":\"rln\",\"raddr\":%d}\n" % raddr)

                # Let time for the IDB client to reply if it exists
                time.sleep(0.150)

                # Poll tunnel
                msg = self.sync.tunnel.poll()

                self.sync.symtable[raddr] = msg.strip()  # remove \n at the end

        # Re-enable tunnel polling
        self.sync.rearm_poll_timer()

        # XXX - beautiful printed indented backtrace
        for l in bt:
            try:
                raddr = int(l[1], 16)
            except ValueError:
                continue
            try:
                symbol = self.sync.symtable[raddr]
            except KeyError:
                continue
            if "+" in symbol:
                symbol = symbol.split("+")[0]
            l[3] = symbol

        bt = "\n".join([" ".join(l) for l in bt])
        print(bt)


class Bx(WrappedCommand):

    def __init__(self, sync):
        super(Bx, self).__init__(sync)
        gdb.Command.__init__(self, "bx", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        fmt, sym = [a.strip() for a in arg.split(" ")]
        try:
            addr = int(sym, 16)
        except Exception as e:
            pass
        else:
            gdb.execute("x %s %s" % (fmt, sym))
            return

        # XXX - split symbol+offset in case "+" is found in sym
        offset = 0
        if "+" in sym:
            offset = int(sym.split("+")[1], 16)
            sym = sym.split("+")[0]

        # First suspend tunnel polling for commands (happy race...)
        self.sync.suspend_poll_timer()
        self.sync.tunnel.send("[sync]{\"type\":\"rrln\",\"sym\":\"%s\"}\n" % sym)

        # Let time for the IDB client to reply if it exists
        time.sleep(0.150)

        # Poll tunnel
        msg = self.sync.tunnel.poll()
        msg = msg.rstrip()
        if msg.startswith('0x'):
            raddr = int(msg, 16)
        else:
            raddr = int(msg)

        # Re-enable tunnel polling
        self.sync.rearm_poll_timer()

        gdb.execute("x %s 0x%x" % (fmt, raddr+offset))


class Cc(WrappedCommand):

    def __init__(self, sync):
        super(Cc, self).__init__(sync)
        gdb.Command.__init__(self, "cc", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        # First suspend tunnel polling for commands (happy race...)
        self.sync.suspend_poll_timer()
        self.sync.tunnel.send("[sync]{\"type\":\"cursor\"}\n")

        # Let time for the IDB client to reply if it exists
        time.sleep(0.150)

        # Poll tunnel
        msg = self.sync.tunnel.poll()
        ida_cursor = int(msg, 16)
        rs_log("current cursor: 0x%x" % ida_cursor)

        # Re-enable tunnel polling
        self.sync.rearm_poll_timer()

        time.sleep(0.150)  # necessary to avoid garbage in res from gdb.execute()?

        # Set a breakpoint to cursor address in IDA
        res = gdb.execute("b *0x%x" % ida_cursor, to_string=True)
        if not res.startswith("Breakpoint "):
            rs_log("failed to set a breakpoint to 0x%x" % ida_cursor)
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
                rs_log("reached successfully")
                res = gdb.execute("d %d" % bp_id)
            else:
                rs_log("reached other breakpoint before cc reached 0x%x" % ida_cursor)
        else:
            rs_log("failed to remove breakpoint because gdb did not give us any info :/")


class Patch(WrappedCommand):

    def __init__(self, sync):
        super(Patch, self).__init__(sync)
        gdb.Command.__init__(self, "patch", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        if arg == "":
            rs_log("usage: patch <address> <count qwords/dwords> <len_unit>")
            return

        addr, count, length = [a.strip() for a in arg.split(" ")]
        addr = int(addr, 16)
        count = int(count)
        length = int(length)
        if length != 4 and length != 8:
            rs_log("Only words and qword supported")
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


class Help(WrappedCommand):

    def __init__(self, sync):
        super(Help, self).__init__(sync, True)
        gdb.Command.__init__(self, "synchelp", gdb.COMMAND_OBSCURE, gdb.COMPLETE_NONE)

    def _invoke(self, arg, from_tty):
        rs_log(Template("""extension commands help:
  >$y sync$n [<host>]                 = synchronize with <host> or the default value
  >$y syncoff$n                       = stop synchronization
  >$y idblist$n                       = display list of all IDB clients connected to the dispatcher
  >$y idb$n <module name>             = set given module as the active idb (see !modlist)"
  >$y idbn$n <n>                      = set active idb to the n_th client. n should be a valid decimal value
  >$y modlist$n                       = wrapper around info proc mappings
  >$y syncmodauto$n <on|off>          = enable/disable idb auto switch based on module name
  >$y cmt$n [-a address] <string>     = add comment at current eip (or [addr]) in IDA
  >$y rcmt$n [-a address] <string>    = reset comments at current eip (or [addr]) in IDA
  >$y fcmt$n [-a address] <string>    = add a function comment for 'f = get_func(eip)' (or [addr]) in IDA
  >$y cmd$n <string>                  = execute command <string> and add its output as comment at current eip in IDA
  >$y bc$n <on|off|>                  = enable/disable path coloring in IDA
                                    color a single instruction at current eip if called without argument
  >$y rln$n <address>                 = ask IDA Pro to convert an address into a symbol
  >$y bbt$n <symbol>                  = beautiful backtrace by executing "bt" and retrieving symbols from IDA Pro
                                    for each element of the backtrace
  >$y patch$n <addr> <count> <size>   = patch in IDA count elements of size (in [4, 8]) at address, reflecting live
                                   context
  >$y pbx$n /i <symbol>               = similar to "x /i <address>" but supports a symbol resolved from IDA Pro
  >$y pcc$n                           = continue to current cursor in IDA Pro (set a breakpoints, continue and remove it)
  >$y translate$n <base> <addr> <mod> = rebase an address with respect to local module's base\n"""
              ).substitute(y=CMD_COLOR_ON, n=CMD_COLOR_OFF))


def load_configuration():
    user_conf = namedtuple('user_conf', 'host port ctx use_tmp_logging_file')
    host, port, ctx, use_tmp_logging_file = HOST, PORT, None, USE_TMP_LOGGING_FILE

    for confpath in [os.path.join(p, '.sync') for p in CONFIG_LOCATIONS]:
        if os.path.exists(confpath):
            config = ConfigParser({'host': HOST, 'port': PORT, 'context': '', 'use_tmp_logging_file': USE_TMP_LOGGING_FILE})
            config.read(confpath)
            rs_log("configuration file loaded from: %s" % confpath)

            if config.has_section('GENERAL'):
                use_tmp_logging_file = config.getboolean('GENERAL', 'use_tmp_logging_file')
                print("       general: use_tmp_logging_file is %s" % use_tmp_logging_file)

            if config.has_section('INTERFACE'):
                host = config.get('INTERFACE', 'host')
                port = config.getint('INTERFACE', 'port')
                print("       interface: %s:%s" % (host, port))

            if config.has_section('INIT'):
                ctx_entry = config.get('INIT', 'context')
                if ctx_entry != '':
                    try:
                        # eval() for fun
                        ctx = eval(ctx_entry)
                        rs_log("initialization context:\n%s\n" % json.dumps(ctx, indent=4))
                    except Exception as e:
                        rs_log('failed to parse [INIT] section from .sync configuration file')
                        DbgHelp.show_last_exception('eval')

            break

    return user_conf(host, port, ctx, use_tmp_logging_file)


if __name__ == "__main__":
    try:
        id(SYNC_PLUGIN)
        rs_log('plugin already loaded')
    except NameError as e:
        rs_cfg = load_configuration()
        rs_commands = [Syncoff, Syncmodauto, Idblist, Idbn, Idb, Modlist, Cmt,
                       Rcmt, Fcmt, Bc, Translate, Cmd, Rln, Bbt, Bx, Cc, Patch, Help]

        SYNC_PLUGIN = Sync(rs_cfg, rs_commands)
