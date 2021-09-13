"""
Copyright (c) 2020-2021, Alexandre Gazet

Copyright (c) 2014, Cedric TESSIER

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

    * Neither the name of Cedric TESSIER nor the names of other
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import socket
import errno
import time
import sys
import threading
import json
import base64
import os
import logging

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import SafeConfigParser as ConfigParser


HOST = "localhost"
PORT = 9100
TIMER_PERIOD = 0.1

if __name__ == "__main__":
    print("Run only as script from lldb... Not as standalone program")
    sys.exit(1)

try:
    import lldb
except ImportError:
    pass


CMD_NOTICE = 1
CMD_SYNC = 2

CMD_CLS = {CMD_NOTICE: "notice", CMD_SYNC: "sync"}


# encoding settings (for data going in/out the plugin)
RS_ENCODING = 'utf-8'

# log settings
LOG_LEVEL = logging.INFO
LOG_PREFIX = 'sync'
LOG_COLOR_ON = "\033[1m\033[34m"
LOG_COLOR_OFF = "\033[0m"


def rs_encode(buffer_str):
    return buffer_str.encode(RS_ENCODING)


def rs_decode(buffer_bytes):
    return buffer_bytes.decode(RS_ENCODING)


def rs_log(s, lvl=logging.INFO):
    if lvl >= LOG_LEVEL:
        print("%s[%s]%s %s" % (LOG_COLOR_ON, LOG_PREFIX, LOG_COLOR_OFF, s))


# periodically poll socket in a dedicated thread
class Poller(threading.Thread):

    def __init__(self, sc):
        threading.Thread.__init__(self)
        self.evt_enabled = threading.Event()
        self.evt_enabled.clear()
        self.evt_stop = threading.Event()
        self.evt_stop.clear()
        self.sc = sc

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
            if not self.sc._tunnel:
                return

            if self.sc._tunnel.is_up():
                self.poll()

            time.sleep(TIMER_PERIOD)

    # "the main thread is the thread from which the Python interpreter was started"
    def interpreter_alive(self):
        return threading.main_thread().is_alive()

    def poll(self):
        msg = self.sc._tunnel.poll()
        if msg:
            batch = [cmd.strip() for cmd in msg.split('\n') if cmd]
            if batch:
                for cmd in batch:
                    self.sc.exec(cmd)
        else:
            self.sc.exec('syncoff')
            self.stop()

    def enable(self):
        self.evt_enabled.set()

    def disable(self):
        self.evt_enabled.clear()

    def stop(self):
        self.evt_stop.set()


# TODO: factorize with GNU GDB plugin
class Tunnel():

    def __init__(self, host):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, PORT))
        except socket.error as msg:
            self.sock.close()
            self.sock = None
            self.sync = False
            rs_log("Tunnel initialization  error: %s" % msg)
            return None

        self.sync = True

    def is_up(self):
        return (self.sock is not None and self.sync is True)

    def send(self, msg):
        if not self.sock:
            rs_log("tunnel_send: tunnel is unavailable (did you forget to sync ?)")
            return

        try:
            self.sock.send(rs_encode(msg))
        except socket.error as msg:
            self.sync = False
            self.close()

            rs_log("tunnel_send error: %s" % msg)

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


class EventHandlerThread(threading.Thread):
    def __init__(self, sync):
        self.sync = sync
        self.process = sync.process
        self.listener = lldb.SBListener('ret_sync listener')
        self.broadcaster = self.process.GetBroadcaster()
        self.broadcaster.AddListener(self.listener, lldb.SBProcess.eBroadcastBitStateChanged)
        self.event = lldb.SBEvent()
        super(EventHandlerThread, self).__init__()

    def run(self):
        while self.sync._tunnel and self.process.is_alive:
            if self.listener.PeekAtNextEventForBroadcasterWithType(self.broadcaster,
                    lldb.SBProcess.eBroadcastBitStateChanged, self.event):
                self.sync._handleNewState(self.process)
                self.listener.Clear()
            time.sleep(0.1)
        # Broadcast last process state
        self.sync._handleNewState(self.process)
        rs_log("event handler stopped")


class Sync(object):

    def __init__(self):
        self._tunnel = None
        self.poller = None
        self._pcache = {}
        self._dbg = lldb.debugger
        self._platform = self._dbg.GetSelectedPlatform()

    def reset(self):
        if self._tunnel:
            self._tunnel.close()
        self._tunnel = None
        self._pcache = {}

    def _getIdentity(self):
        return self._platform.GetOSDescription()

    identity = property(_getIdentity)

    def _getProcess(self):
        target = self._dbg.GetSelectedTarget()
        return target.GetProcess()

    def procinfo(self, process=None):
        if not process:
            process = self.process
        uid = process.GetUniqueID()
        return self._pcache.get(uid, None)

    process = property(_getProcess)

    def _locate(self, process):
        pinfo = self.procinfo(process)
        if not pinfo:
            return

        target = self._dbg.GetSelectedTarget()
        ptr_size = target.GetAddressByteSize()
        last_addr = (-1) % (2**(ptr_size*8))
        thread = process.GetSelectedThread()
        frame = thread.GetSelectedFrame()
        offset = frame.pc

        mod = frame.GetModule()

        # Find first mapped section of the module
        base = 0
        for i in range(4):
            sect = mod.GetSectionAtIndex(i)
            addr = sect.addr.GetLoadAddress(target)
            if addr != last_addr:
                base = addr
                break

        pinfo["offset"] = offset
        # Notice if we changed current module
        if base != pinfo["base"]:
            pinfo["base"] = base
            modname = mod.GetFileSpec().fullpath
            self.cmd(CMD_NOTICE, "module", path=modname)

        self.cmd(CMD_SYNC, "loc", base=base, offset=offset)

    def _handleStop(self, process):
        if not self._tunnel:
            return
        self._locate(process)
        self.rearm_poll_timer()

    def _handleExit(self, process):
        self.release_poll_timer()
        self.reset()
        rs_log("exit, sync finished")

    def _handleNewState(self, process):
        state = process.GetState()
        if state == lldb.eStateStopped:
            self._handleStop(process)
        elif state == lldb.eStateRunning or state == lldb.eStateStepping:
            self.suspend_poll_timer()
        elif state == lldb.eStateExited:
            self._handleExit(process)

    def _connect(self, host):
        if self._tunnel:
            return True
        if not host:
            host = HOST
        rs_log("connecting to %s" % host)
        self._tunnel = Tunnel(host)
        if not self._tunnel.is_up():
            rs_log("sync failed")
            self.reset()
            return False
        self.cmd(CMD_NOTICE, "new_dbg", msg="dbg connect - %s" % self.identity, dialect="lldb")
        rs_log("sync is now enabled with host %s" % host)
        self.create_poll_timer()
        return True

    def initialize(self, host):
        if not self._connect(host):
            return
        # Sync cannot do more if a process is not alive
        if not self.process.is_alive:
            return
        uid = self.process.GetUniqueID()
        if uid not in self._pcache:
            # Init per process cache
            self._pcache[uid] = {}
            pinfo = self._pcache[uid]
            pinfo["base"] = 0
            pinfo["offset"] = 0
            # Init per process event handler
            thread = EventHandlerThread(self)
            pinfo["thread"] = thread
            thread.start()
            rs_log("event handler started")

        self._locate(self.process)
        self.rearm_poll_timer()

    def running(self):
        return self.process.is_alive

    def cmd(self, clas, typ, **kwargs):
        if not self._tunnel:
            return
        cmd = "[%s]" % CMD_CLS.get(clas, None)
        if not cmd:
            rs_log("Invalid command class")
            return
        args = {"type": typ}
        args.update(kwargs)
        cmd += json.dumps(args) + "\n"
        self._tunnel.send(cmd)

    def exec(self, command):
        ci = self._dbg.GetCommandInterpreter()
        res = lldb.SBCommandReturnObject()

        ci.HandleCommand(command, res)
        if not res.Succeeded():
            rs_log("failed to execute command \"%s\"" % command)
            return None

        return res.GetOutput()

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


def getSync(session):
    sync = session.get("_sync", None)
    if not sync:
        rs_log("Internal error: _sync not found")
        sys.exit(1)
    return sync


def setSync(session, sync):
    session["_sync"] = sync


# TODO: factorize with GNU GDB plugin
def loadConfig():
    global HOST
    global PORT

    locations = [os.path.join(os.path.realpath(os.path.dirname(__file__)), ".sync"),
                 os.path.join(os.environ['HOME'], ".sync")]

    for confpath in locations:
        if os.path.exists(confpath):
            config = ConfigParser({'host': HOST, 'port': PORT})
            config.read(confpath)
            HOST = config.get("INTERFACE", 'host')
            PORT = config.getint("INTERFACE", 'port')
            rs_log("configuration file loaded %s:%s" % (HOST, PORT))
            break


def __lldb_init_module(debugger, session):
    loadConfig()
    sync = Sync()
    setSync(session, sync)

# ---


@lldb.command("sync", "Enable sync with IDA")
def sync(debugger, command, result, session):
    sc = getSync(session)
    args = command.split()
    host = args[0] if args else None

    sc.initialize(host)


@lldb.command("syncoff", "Disable sync with IDA")
def syncoff(debugger, command, result, session):
    sc = getSync(session)
    sc.reset()
    rs_log("sync is now disabled")


@lldb.command("bc", "Enable / disable path coloring in IDA")
def bc(debugger, command, result, session):
    sc = getSync(session)
    if not sc.running():
        rs_log("process is not running, command is dropped")
        return

    args = command.split()
    arg = args[0] if args else None

    if not arg:
        arg = "oneshot"

    if not (arg in ["on", "off", "oneshot"]):
        rs_log("usage: bc <|on|off>")
        return
    pinfo = sc.procinfo()
    if not pinfo:
        return
    sc.cmd(CMD_NOTICE, "bc", msg=arg, base=pinfo["base"], offset=pinfo["offset"])


def addcmt(typ, debugger, command, result, session):
    sc = getSync(session)
    if not sc.running():
        rs_log("process is not running, command is dropped")
        return

    if not command and typ != "rcmt":
        rs_log("usage: %s <cmt to add>" % typ)
        return

    pinfo = sc.procinfo()
    if not pinfo:
        return
    sc.cmd(CMD_SYNC, typ, msg=command, base=pinfo["base"], offset=pinfo["offset"])


@lldb.command("cmt", "Add comment in IDA")
def cmt(debugger, command, result, session):
    return addcmt("cmt", debugger, command, result, session)


@lldb.command("fcmt", "Add function comment in IDA")
def fcmt(debugger, command, result, session):
    return addcmt("fcmt", debugger, command, result, session)


@lldb.command("rcmt", "Reset comment in IDA")
def rcmt(debugger, command, result, session):
    return addcmt("rcmt", debugger, command, result, session)


@lldb.command("cmd", "Execute command and add its output as comment")
def cmd(debugger, command, result, session):
    sc = getSync(session)
    if not sc.running():
        rs_log("process is not running, command is dropped")
        return

    if not command:
        rs_log("need a command to execute")
        return

    res = sc.exec(command)
    if res:
        encoded = base64.b64encode(res)
        pinfo = sc.procinfo()
        if not pinfo:
            return

        sc.cmd(CMD_SYNC, "cmd", msg=encoded, base=pinfo["base"], offset=pinfo["offset"])


@lldb.command("synchelp", "Print sync plugin help")
def synchelp(debugger, command, result, session):
    rs_log(
"""extension commands help:
 > sync <host>                   = synchronize with <host> or the default value
 > syncoff                       = stop synchronization
 > cmt <string>                  = add comment at current eip in IDA
 > rcmt <string>                 = reset comments at current eip in IDA
 > fcmt <string>                 = add a function comment for 'f = get_func(eip)' in IDA
 > cmd <string>                  = execute command <string> and add its output as comment at current eip in IDA
 > bc <on|off|>                  = enable/disable path coloring in IDA
                                   color a single instruction at current eip if called without argument\n""")
