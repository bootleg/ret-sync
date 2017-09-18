#
# Copyright (C) 2016-2017, Alexandre Gazet.
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
#

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import traceback
import struct
import binascii
import base64
import ctypes
import socket
import ConfigParser

try:
    import argparse
except:
    print "[-] please make sure python's argparse module is available\n%s" % repr(sys.exc_info())
    sys.exit(0)

import idaapi
import idautils
from idaapi import PluginForm


# Enable/disable logging JSON received in the IDA output window
DEBUG_JSON = False

if sys.platform == 'win32':
    PYTHON_BIN = 'python.exe'
    PYTHON_PATH = os.path.normpath("C:\\Python27")

elif sys.platform.startswith('linux') or sys.platform == 'darwin':
    PYTHON_BIN = 'python'
    PYTHON_PATH = os.path.normpath("/usr/bin")

else:
    print "[-] please fix PYTHON_PATH & PYTHON_BIN values, %s platform currently unknown" % sys.platform
    sys.exit(0)

if not os.path.exists(os.path.join(PYTHON_PATH, PYTHON_BIN)):
    print "[-] please fix PYTHON_PATH value"
    sys.exit(0)


site_packages = os.path.join(PYTHON_PATH, "lib", "site-packages")
if site_packages not in sys.path:
    sys.path.insert(0, site_packages)

try:
    from PyQt5 import QtCore, QtWidgets
    from PyQt5.QtCore import QProcess, QProcessEnvironment
except:
    print "[-] failed to import Qt libs from PyQt5\n%s" % repr(sys.exc_info())
    sys.exit(0)

try:
    import json
except:
    print "[-] failed to import json\n%s" % repr(sys.exc_info())
    sys.exit(0)

# default value is current script's path
BROKER_PATH = os.path.join(os.path.normpath(os.path.dirname(__file__)), "broker.py")
if not os.path.exists(BROKER_PATH):
    print "[-] broker path is not properly set, current value: <%s>" % BROKER_PATH
    sys.exit(0)

IDB_PATH = os.path.dirname(os.path.realpath(idc.GetIdbPath()))

CONNECT_BROKER_MAX_ATTEMPT = 4

COL_GREEN = 0x33ff00
COL_DEEP_PURPLE = 0xff44dd
COL_YLW = 0x23ffff
COL_BLUE_NAVY = 0x000080
COL_GRAY = 0x808080

COL_CURLINE = COL_YLW
#COL_CURLINE = COL_BLUE_NAVY # renders better with some themes
COL_CBTRACE = COL_GREEN

NETNODE_STORE = "$ SYNC_STORE"
NETNODE_INDEX = 0xFFC0DEFF

DBG_DIALECTS = {
    'windbg': {'prefix': '!', 'si': 't', 'so': 'p', 'go': 'g', 'bp': 'bp ', 'hbp': 'ba e 1 ', 'bp1': 'bp /1 ', 'hbp1': 'ba e 1 /1 '},
    'gdb': {'prefix': '', 'si': 'si', 'so': 'ni', 'go': 'continue', 'bp': 'b *', 'hbp': 'hb *',  'bp1': 'tb *', 'hbp1': 'thb *'},
    'ollydbg2': {'prefix': '', 'si': 'si', 'so': 'so', 'go': 'go', 'bp': 'bp ', 'hbp': 'xxx ', 'bp1': 'xxx ', 'hbp1': 'xxx '},
    'x64_dbg': {'prefix': '', 'si': 'sti', 'so': 'sto', 'go': 'go', 'bp': 'bp ', 'hbp': 'bph ', 'bp1': 'xxx ', 'hbp1': 'xxx '},
}

# --------------------------------------------------------------------------


class RequestHandler(object):

    # color callback
    def cb_color(self, ea):
        idaapi.set_item_color(ea, COL_CBTRACE)

    # instruction step callback
    def cb_curline(self, ea):
        if self.prev_loc:
            prev_ea, prev_color = self.prev_loc
            cur_color = idaapi.get_item_color(prev_ea)
            # race condition: block/instruction's color may have been modified
            # after it was saved
            if (cur_color != prev_color) and (cur_color != COL_CURLINE):
                prev_color = cur_color
            idaapi.set_item_color(prev_ea, prev_color)

        self.prev_loc = [ea, idaapi.get_item_color(ea)]
        idaapi.set_item_color(ea, COL_CURLINE)

    def cb_restore_last_line(self):
        if self.prev_loc:
            ea, col = self.prev_loc
            idaapi.set_item_color(ea, col)

    # support -a / --address switch
    def addr_switch(self, offset, msg):
        if (not msg) or (msg == ''):
            return [offset, msg]

        try:
            args = self.parser.parse_args(msg.split())
        except:
            print "[*] failed to parse command"
            return [None, msg]

        # no address switch supplied
        if not args.address:
            return [offset, msg]

        try:
            addr = int(''.join(args.address), 16)
        except:
            print "[*] failed to parse address, should be hex"
            return [None, msg]

        # make sure the address points to a valid instruction/data
        head = idaapi.get_item_head(addr)
        if head != addr:
            print "[*] ambiguous address, did you mean 0x%x ?" % head
            return [None, msg]

        return [addr, ' '.join(args.msg)]

    # check if address is within a valid segment
    def is_safe(self, offset):
        return not (idc.SegStart(offset) == idaapi.BADADDR)

    # rebase address with respect to local image base
    def rebase(self, base, offset):
        if base:
            # check for non-compliant debugger client
            if base > offset:
                print "[sync] unsafe addr"
                return None

            if not (self.base == base):
                offset = (offset - base) + self.base

            # update base address of remote module
            if self.base_remote != base:
                self.base_remote = base

        if not self.is_safe(offset):
            print "[sync] unsafe addr"
            return None

        return offset

    # rebase address with respect to remote image base
    def rebase_remote(self, offset):
        if not (self.base == self.base_remote):
            offset = (offset - self.base) + self.base_remote

        return offset

    # demangle names
    def demangle(self, name):
        mask = idc.GetLongPrm(INF_SHORT_DN)
        demangled = idc.Demangle(name, mask)
        if demangled is None:
            return name
        else:
            return demangled

    # prevent flooding debug engine with too much commands
    # sync plugin does NOT wait for any sort of ack
    # example: "^ Debuggee already running error in 'g'"
    def notice_anti_flood(self):
        time.sleep(0.1)

    # append comment and handle cmt's size limitation (near 1024)
    def append_cmt(self, ea, cmt, rptble=False):
        if len(cmt) > 1024:
            print "[*] warning, comment needs to be splitted (from 0x%x)" % ea
            nh = idaapi.next_head(ea, idaapi.BADADDR)
            if nh == idaapi.BADADDR:
                print "[*] failed to find next instruction candidate"
                return

            self.append_cmt(nh, cmt[1024:], rptble)
            cmt = cmt[:1024]

        idaapi.append_cmt(ea, cmt, rptble)

    # location request, update disassembly IDA view
    def req_loc(self, hash):
        offset, base = hash['offset'], hash.get('base')
        ea = self.rebase(base, offset)
        if not ea:
            return

        if(self.color):
            self.cb_color(ea)

        idaapi.jumpto(ea)
        self.cb_curline(ea)
        self.gm.center()

    # log command output request at addr
    def req_cmd(self, hash):
        msg_b64, offset, base = hash['msg'], hash['offset'], hash['base']
        msg = base64.b64decode(msg_b64)
        ea = self.rebase(base, offset)
        if not ea:
            return

        print ("[*] cmd output added at 0x%x" % ea)
        self.append_cmt(ea, str(msg))

    # reset comment at addr
    def req_rcmt(self, hash):
        msg, offset, base = hash['msg'], hash['offset'], hash['base']
        offset, msg = self.addr_switch(offset, msg)
        if not offset:
            return

        ea = self.rebase(base, offset)
        if not ea:
            return

        idaapi.set_cmt(ea, str(''), False)
        print ("[*] reset comment at 0x%x" % ea)

    # add comment request at addr
    def req_cmt(self, hash):
        msg, offset, base = hash['msg'], hash['offset'], hash['base']
        offset, msg = self.addr_switch(offset, msg)
        if not offset:
            return

        ea = self.rebase(base, offset)
        if not ea:
            return

        self.append_cmt(ea, str(msg))
        print ("[*] comment added at 0x%x" % ea)

    # add a function comment at addr
    def req_fcmt(self, hash):
        msg, offset, base = hash['msg'], hash['offset'], hash['base']
        offset, msg = self.addr_switch(offset, msg)
        if not offset:
            return

        ea = self.rebase(base, offset)
        if not ea:
            return

        func = idaapi.get_func(ea)
        if not func:
            print ("[*] could not find func for 0x%x" % ea)
            return

        idaapi.set_func_cmt(func, str(msg), False)
        print ("[*] function comment added at 0x%x" % ea)

    # add an address comment request at addr
    def req_raddr(self, hash):
        raddr, rbase, offset, base = hash['raddr'], hash['rbase'], hash['offset'], hash['base']
        ea = self.rebase(base, offset)
        if not ea:
            return

        if self.base_remote != rbase:
            print("[*] could not rebase this address, not in module")
            return

        addr = self.rebase(rbase, raddr)
        if not addr:
            return

        self.append_cmt(ea, "0x%x (rebased from 0x%x)" % (addr, raddr))
        print ("[*] comment added at 0x%x" % ea)

    # return current cursor in IDA Pro
    def req_cursor(self, hash):
        print("[*] request IDA Pro cursor position")
        addr = idc.ScreenEA()
        self.notice_broker("cmd", "\"cmd\":\"%s\"" % addr)
        return

    # patch memory at specified address using info from debugger
    def req_patch(self, hash):
        addr, value, length = hash['addr'], hash['value'], hash['len']
        if length != 4 and length != 8:
            print("[x] unsupported length: %d" % length)
            return
        if length == 4:
            prev_value = Dword(addr)
            if MakeDword(addr) != 1:
                print("[x] MakeDword failed")
            if PatchDword(addr, value) != 1:
                print("[x] PatchDword failed")
            if not idc.OpOff(addr, 0, 0):
                print("[x] OpOff failed")
        elif length == 8:
            prev_value = Qword(addr)
            if MakeQword(addr) != 1:
                print("[x] MakeQword failed")
            if PatchQword(addr, value) != 1:
                print("[x] PatchQword failed")
            if not idc.OpOff(addr, 0, 0):
                print("[x] OpOff failed")

        print ("[*] patched 0x%x = 0x%x (previous was 0x%x)" % (addr, value, prev_value))

    # return idb's symbol for a given address
    def req_rln(self, hash):
        raddr, rbase, offset, base = hash['raddr'], hash['rbase'], hash['offset'], hash['base']

        print("[*] 0x%x -  0x%x - 0x%x - 0x%x" % (raddr, rbase, offset, base))

        addr = self.rebase(rbase, raddr)
        if not addr:
            print("[*] could not rebase this address (0x%x)" % raddr)
            return

        sym = idaapi.get_func_name(addr)
        if sym:
            sym = self.demangle(sym)
            func = idaapi.get_func(addr)
            if not func:
                print ("[*] could not find func for 0x%x" % addr)
                return

            lck = idaapi.lock_func(func)

            limits = idaapi.area_t()
            if idaapi.get_func_limits(func, limits):
                if limits.startEA != addr:
                    if (addr > limits.startEA):
                        sym = "%s%s0x%x" % (sym, "+", addr - limits.startEA)
                    else:
                        sym = "%s%s0x%x" % (sym, "-", limits.startEA - addr)
            lck = None
        else:
            sym = idc.Name(addr)
            if sym:
                sym = self.demangle(sym)

        if sym:
            self.notice_broker("cmd", "\"cmd\":\"%s\"" % sym)
            print ("[*] resolved symbol: %s" % sym)
        else:
            print ("[*] could not resolve symbol for address 0x%x" % addr)

    # return address for a given idb's symbol
    def req_rrln(self, hash):
        sym, rbase, offset, base = hash['sym'], hash['rbase'], hash['offset'], hash['base']

        print("[*] %s -  0x%x - 0x%x - 0x%x" % (sym, rbase, offset, base))

        addr = idc.LocByName(sym)
        if addr:
            self.notice_broker("cmd", "\"cmd\":\"%s\"" % addr)
            print ("[*] resolved address: %s" % addr)
        else:
            print ("[*] could not resolve address for symbol %s" % sym)

    # add label request at addr
    def req_lbl(self, hash):
        msg, offset, base = hash['msg'], hash['offset'], hash['base']
        offset, msg = self.addr_switch(offset, msg)
        if not offset:
            return

        ea = self.rebase(base, offset)
        if not ea:
            return

        flags = False
        if str(msg).startswith('@@'):
            flags = idaapi.SN_LOCAL

        idaapi.set_name(ea, str(msg), flags)
        print ("[*] label added at 0x%x" % ea)

    # color request at addr
    def req_bc(self, hash):
        global COL_CBTRACE
        msg, offset, base = hash['msg'], hash['offset'], hash['base']

        if self.is_active:
            ea = self.rebase(base, offset)
            if not ea:
                return
        else:
            ea = self.base

        if (msg == 'oneshot'):
            print ("[*] color oneshot added at 0x%x" % ea)
            # mark address as being colored
            self.prev_loc = [ea, COL_CBTRACE]
        elif (msg == 'on'):
            print ("[*] color start from 0x%x" % ea)
            self.color = True
            self.prev_loc = [ea, COL_CBTRACE]
        elif (msg == 'off'):
            print ("[*] color end at 0x%x" % ea)
            self.color = False
        elif (msg == 'set'):
            new_col = hash['rgb']
            if new_col > 0xffffff:
                print ("[*] restoring color")
                new_col = COL_GREEN

            COL_CBTRACE = new_col
            print ("[*] set color to 0x%x" % COL_CBTRACE)
        else:
            print ("[*] invalid color request (%s)" % msg)

    # reload .bpcmds from idb
    def req_bps_get(self, hash):
        print ("[-] reload .bpcmds")
        node = idaapi.netnode(NETNODE_INDEX)
        if not node:
            print ("[-] failed to open netnode store")
            self.notice_broker("cmd", "\"cmd\":\"no blob\"")
            return

        node.create(NETNODE_STORE)
        blob = node.getblob(0, str(chr(1)))

        if not blob:
            print ("  -> no blob")
            self.notice_broker("cmd", "\"cmd\":\"    -> reloading .bpcmds: no blob\"")
            return

        self.notice_broker("cmd", "\"cmd\":\"%s\"" % blob)
        return

    # save .bpcmds to idb
    def req_bps_set(self, hash):
        blob = hash['msg']
        print ("[-] save .bpcmds")
        node = idaapi.netnode(NETNODE_INDEX)
        if not node:
            print ("[-] failed to open netnode store")
            self.notice_broker("cmd", "\"cmd\":\"    -> failed to save .bpcmds")
            return

        new = node.create(NETNODE_STORE)
        if new == 0:
            print ("    -> creating new netnode store")

        out = node.setblob(str(blob), 0, str(chr(1)))
        self.notice_broker("cmd", "\"cmd\":\"    -> .bpcmds saved\"")
        return

    # compare loaded module md5 with idb's input file md5
    def req_modcheck(self, hash):
        md5, pdb = hash.get('md5'), hash.get('pdb')
        remote = None

        if md5:
            print ("[*] modcheck idb (md5)")
            local = idc.GetInputMD5()
            remote = (''.join(str(md5).encode("ascii").split())).upper()
        elif pdb:
            print ("[*] modcheck idb (pdb guid)")
            msg = base64.b64decode(pdb)
            local = DbgDirHlpr.read_rsds_codeview()
            remote = DbgDirHlpr.parse_itoldyouso_output(msg)

        print ("    -> remote: <%s>" % remote)
        print ("    -> local : <%s>" % local)

        if remote == "0":
            res = "[!] warning, no Debug Directory"
        elif local == remote:
            res = "[+] module successfully matched"
        else:
            res = "[!] warning, modules mismatch"

        print res
        self.notice_broker("cmd", "\"cmd\":\"%s\"" % res)
        return

    # specify debugger dialect used to send commands
    def req_set_dbg_dialect(self, hash):
        global SyncForm
        dialect = hash['dialect']
        if dialect in DBG_DIALECTS:
            self.dbg_dialect = DBG_DIALECTS[dialect]
            print "[sync] set debugger dialect to %s, enabling hotkeys" % dialect
            SyncForm.init_hotkeys()
        else:
            SyncForm.uninit_hotkeys()

    # request from broker
    def req_broker(self, hash):
        subtype = hash['subtype']

        if (subtype == 'msg'):
            # simple message announcement
            print ("[*] << broker << %s" % hash['msg'])

        elif(subtype == 'notice'):
            # notice from broker
            self.broker_port = int(hash['port'])
            print ("[*] << broker << listening on port %d" % self.broker_port)

            for attempt in range(CONNECT_BROKER_MAX_ATTEMPT):
                try:
                    host = socket.gethostbyname('localhost')
                    self.broker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.broker_sock.connect((host, self.broker_port))
                    break
                except:
                    print "[sync] failed to connect to broker"
                    print sys.exc_info()
                    if self.broker_sock:
                        self.broker_sock.close()
                    self.broker_sock = None
                    time.sleep(0.1)
                    if (attempt == (CONNECT_BROKER_MAX_ATTEMPT - 1)):
                        self.announcement("[sync] failed to connect to broker (attempt %d)" % attempt)
                        sys.exit()

        # enable/disable idb, if disable it drops most sync requests
        elif(subtype == 'enable_idb'):
            self.is_active = True
            print "[sync] idb is enabled"

        elif(subtype == 'disable_idb'):
            self.is_active = False
            self.cb_restore_last_line()
            print "[sync] idb is disabled"

    # parse and execute request
    # Note that sometimes we don't receive the whole request from the broker.py
    # so parsing fails. One way for fixing this would be to fix broker.py to get
    # everything until "\n" before proxying it but the way we do here is to read
    # everything until "}" is received (end of json)
    def parse_exec(self, req):
        if self.prev_req:
            if self.prev_req != "":
                if DEBUG_JSON:
                    print "[+] JSON merge with request: \"%s\"" % req

            req = self.prev_req + req
            self.prev_req = ""
        if req == '':
            return
        if DEBUG_JSON:
            print("parse_exec -> " + str(req))

        if not (req[0:6] == '[sync]'):
            print "\[<] bad hdr %s" % repr(req)
            print '[-] Request dropped due to bad header'
            return

        req_ = self.normalize(req, 6)
        try:
            hash = json.loads(req_)
        except:
            if DEBUG_JSON:
                print "[-] Sync failed to parse json\n '%s'. Caching for next req..." % req_
                print "------------------------------------"
            self.prev_req = req
            return

        type = hash['type']
        if type not in self.req_handlers:
            print ("[*] unknown request: %s" % type)
            return

        req_handler = self.req_handlers[type]

        # few requests are handled even though idb is not enable
        if type in ['broker', 'dialect', 'bc']:
            req_handler(hash)
        else:
            if self.is_active:
                req_handler(hash)
            else:
                print "[-] Drop the request because idb is not enabled"
                return

        idaapi.refresh_idaview_anyway()

    def normalize(self, req, taglen):
        req = req[taglen:]
        req = req.replace("\\", "\\\\")
        req = req.replace("\n", "")
        return req

    # send a kill notice to the broker (then forwarded to the dispatcher)
    def kill_notice(self):
        self.notice_broker("kill")

    # send a bp command (F2) to the debugger (via the broker and dispatcher)
    def bp_notice(self, oneshot=False):
        if not self.is_active:
            print "[sync] idb isn't enabled, bp can't be set"
            return

        ea = idaapi.get_screen_ea()
        offset = self.rebase_remote(ea)
        cmd = "%s0x%x" % (self.dbg_dialect['bp1' if oneshot else 'bp'], offset)

        self.notice_broker("cmd", "\"cmd\":\"%s\"" % cmd)
        print "[sync] >> set %s" % cmd

    # send a hardware bp command (Ctrl-F2) to the debugger (via the broker and dispatcher)
    def hbp_notice(self, oneshot=False):
        if not self.is_active:
            print "[sync] idb isn't enabled, hbp can't be set"
            return

        ea = idaapi.get_screen_ea()
        offset = self.rebase_remote(ea)
        cmd = "%s0x%x" % (self.dbg_dialect['hbp1' if oneshot else 'hbp'], offset)

        self.notice_broker("cmd", "\"cmd\":\"%s\"" % cmd)
        print "[sync] >> set %s" % cmd

    # send a oneshot bp command (F3) to the debugger (via the broker and dispatcher)
    def bp_oneshot_notice(self):
        self.bp_notice(True)

    # send a oneshot hardware bp command (Ctrl-F3) to the debugger (via the broker and dispatcher)
    def hbp_oneshot_notice(self):
        self.hbp_notice(True)

    # export IDB's breakpoint (Ctrl-F1) to the debugger (via the broker and dispatcher)
    def export_bp_notice(self):
        if not self.dbg_dialect:
            print "[sync] idb isn't synced yet, can't export bp"
            return

        mod = self.name.split('.')[0].strip()
        nbp = idc.GetBptQty()

        for i in range(nbp):
            ea = idc.GetBptEA(i)
            attrs = [idc.BPTATTR_TYPE, idc.BPTATTR_COND, idc.BPTATTR_FLAGS]
            btype, cond, flags = [idc.GetBptAttr(ea, x) for x in attrs]

            if cond:
                print "bp %d: conditional bp not supported" % i
            else:
                if ((btype in [idc.BPT_EXEC, idc.BPT_SOFT]) and
                   ((flags & idc.BPT_ENABLED) != 0)):

                    offset = ea - self.base
                    bp = self.dbg_dialect['hbp' if (btype == idc.BPT_EXEC) else 'bp']
                    cmd = "%s%s+0x%x" % (bp, mod, offset)
                    self.notice_broker("cmd", "\"cmd\":\"%s\"" % cmd)
                    print "bp %d: %s" % (i, cmd)

        print "[sync] export done"

    # send a translate command (Alt-F2) to the debugger (via the broker and dispatcher)
    def translate_notice(self):
        if not self.dbg_dialect:
            print "[sync] idb isn't synced yet, can't translate"
            return

        ea = idaapi.get_screen_ea()
        mod = self.name.split('.')[0].strip()
        cmd = self.dbg_dialect['prefix'] + "translate 0x%x 0x%x %s" % (self.base, ea, mod)

        self.notice_broker("cmd", "\"cmd\":\"%s\"" % cmd)
        print "[sync] translate address 0x%x" % ea

    # send a go command (F5) to the debugger (via the broker and dispatcher)
    def go_notice(self):
        if not self.is_active:
            print "[sync] idb isn't enabled, can't go"
            return

        self.notice_broker("cmd", "\"cmd\":\"%s\"" % self.dbg_dialect['go'])
        self.notice_anti_flood()

    # send a single trace command (F11) to the debugger (via the broker and dispatcher)
    def si_notice(self):
        if not self.is_active:
            print "[sync] idb isn't enabled, can't trace"
            return

        self.notice_broker("cmd", "\"cmd\":\"%s\"" % self.dbg_dialect['si'])
        self.notice_anti_flood()

    # send a single step command (F10) to the debugger (via the broker and dispatcher)
    def so_notice(self):
        if not self.is_active:
            print "[sync] idb isn't enabled, can't single step"
            return

        self.notice_broker("cmd", "\"cmd\":\"%s\"" % self.dbg_dialect['so'])
        self.notice_anti_flood()

    # send a notice message to the broker process
    def notice_broker(self, type, args=None):
        if not self.broker_sock:
            return

        if args:
            notice = "[notice]{\"type\":\"%s\",%s}\n" % (type, args)
        else:
            notice = "[notice]{\"type\":\"%s\"}\n" % (type)

        try:
            self.broker_sock.sendall(notice)
        except:
            None

    def stop(self):
        if self.broker_sock:
            self.broker_sock.close()
            self.broker_sock = None

        self.cb_restore_last_line()
        idaapi.refresh_idaview_anyway()
        self.is_active = False
        print "[sync] idb is disabled"

    def __init__(self, parser):
        self.color = False
        self.prev_loc = None
        self.prev_node = None
        self.name = idaapi.get_root_filename()
        print "[sync] name %s" % self.name
        self.base = idaapi.get_imagebase()
        print "[sync] module base 0x%x" % self.base
        self.base_remote = None
        self.gm = GraphManager()
        self.parser = parser
        self.broker_sock = None
        self.is_active = False
        self.dbg_dialect = None
        self.req_handlers = {
            'broker': self.req_broker,
            'loc': self.req_loc,
            'cmd': self.req_cmd,
            'cmt': self.req_cmt,
            'rcmt': self.req_rcmt,
            'fcmt': self.req_fcmt,
            'raddr': self.req_raddr,
            'cursor': self.req_cursor,
            'patch': self.req_patch,
            'rln': self.req_rln,
            'rrln': self.req_rrln,
            'lbl': self.req_lbl,
            'bc': self.req_bc,
            'bps_get': self.req_bps_get,
            'bps_set': self.req_bps_set,
            'modcheck': self.req_modcheck,
            'dialect': self.req_set_dbg_dialect
        }
        self.prev_req = ""  # used as a cache if json is not completely received


# --------------------------------------------------------------------------


class Broker(QtCore.QProcess):

    def cb_on_error(self, error):
        errors = ["Failed to start", "Crashed", "Timedout",
                  "Read error", "Write Error", "Unknown Error"]
        print "[-] broker error: ", errors[error]

    def cb_broker_on_state_change(self, new_state):
        states = ["Not running", "Starting", "Running"]
        print "[*] broker new state: ", states[new_state]
        if states[new_state] == "Not running":
            print "[*] Check dispatcher.py.err if you think this is an error"

    def cb_broker_on_out(self):
        # readAllStandardOutput() returns QByteArray
        buffer = self.readAllStandardOutput().data().encode("ascii")
        batch = buffer.split('\n')
        for req in batch:
            self.worker.parse_exec(req)

    def __init__(self, parser):
        QtCore.QProcess.__init__(self)

        self.error.connect(self.cb_on_error)
        self.readyReadStandardOutput.connect(self.cb_broker_on_out)
        self.stateChanged.connect(self.cb_broker_on_state_change)

        # Create a request handler
        self.worker = RequestHandler(parser)

# --------------------------------------------------------------------------


class DbgDirHlpr(object):

    @staticmethod
    def read_rsds_codeview():
        guid = None
        penode = idaapi.netnode()
        penode.create(peutils_t.PE_NODE)
        fpos = penode.altval(peutils_t.PE_ALT_DBG_FPOS)

        if (fpos == 0):
            print "[*] No debug directory"
            return guid

        input_file = idc.GetInputFilePath()
        if not os.path.exists(input_file):
            print "[*] input file not available"
        else:
            with open(input_file, 'r') as fd:
                fd.seek(fpos)
                raw = fd.read(0x1C)

                """
                typedef struct _IMAGE_DEBUG_DIRECTORY {
                  DWORD Characteristics;
                  DWORD TimeDateStamp;
                  WORD  MajorVersion;
                  WORD  MinorVersion;
                  DWORD Type;
                  DWORD SizeOfData;
                  DWORD AddressOfRawData;
                  DWORD PointerToRawData;
                } IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;
                """
                dbgdir = struct.unpack('LLHHLLLL', raw)
                #  2, IMAGE_DEBUG_TYPE_CODEVIEW
                if not (dbgdir[4] == 2):
                    print "[*] not CODEVIEW data"
                else:
                    fd.seek(dbgdir[7])
                    if not (fd.read(4) == "RSDS"):
                        print "[*] unsupported CODEVIEW information format (%s)" % sig
                    else:
                        d1, d2, d3 = struct.unpack('LHH', fd.read(0x8))
                        d4 = struct.unpack('>H', fd.read(0x2))[0]
                        d5 = binascii.hexlify(fd.read(0x6)).upper()
                        guid = "%08X-%04X-%04X-%04X-%s" % (d1, d2, d3, d4, d5)

        return guid

    @staticmethod
    def parse_itoldyouso_output(res):
        for line in res.splitlines(True):
            line = line.strip()
            if line.startswith('pdb sig: '):
                return (line.split(':')[-1]).strip()
        return None


# --------------------------------------------------------------------------


class GraphManager():

    def __init__(self):
        self.prev_node = None
        self.graph_viewer = ida_kernwin.get_current_viewer()

    def center(self):
        curnode = ida_graph.viewer_get_curnode(self.graph_viewer)

        if not (self.prev_node == curnode):
            ida_graph.viewer_center_on(self.graph_viewer, curnode)
            self.prev_node = curnode

        return curnode


# --------------------------------------------------------------------------


class SyncForm_t(PluginForm):

    def cb_broker_started(self):
        print "[*] broker started"
        self.btn.setText("Restart")

    def cb_broker_finished(self):
        print "[*] broker finished"
        if self.broker:
            self.broker.worker.stop()
            self.cb.stateChanged.disconnect(self.cb_change_state)
            self.cb.toggle()
            self.cb.stateChanged.connect(self.cb_change_state)

        self.btn.setText("Start")

    # send a kill notice to the broker
    # wait at most 2sec for him to gently kill itself
    def smooth_kill(self):
        self.uninit_hotkeys()
        if self.broker:
            broker = self.broker
            self.broker = None
            broker.worker.cb_restore_last_line()
            broker.worker.kill_notice()
            broker.waitForFinished(1500)

    def init_broker(self):
        print "[*] init_broker"
        modname = self.input.text().encode('ascii', 'replace')
        cmdline = u"\"%s\" -u \"%s\" --idb \"%s\"" % (
                  os.path.join(PYTHON_PATH, PYTHON_BIN),
                  BROKER_PATH, modname)
        print "[*] init broker,", cmdline

        self.broker = Broker(self.parser)
        env = QProcessEnvironment.systemEnvironment()
        env.insert("IDB_PATH", IDB_PATH)
        env.insert("PYTHON_PATH", os.path.realpath(PYTHON_PATH))
        env.insert("PYTHON_BIN", PYTHON_BIN)

        try:
            self.broker.started.connect(self.cb_broker_started)
            self.broker.finished.connect(self.cb_broker_finished)
            self.broker.setProcessEnvironment(env)
            self.broker.start(cmdline)
        except Exception as e:
            print "[-] failed to start broker: %s\n%s" % (str(e), traceback.format_exc())
            return

        self.init_hotkeys()
        self.broker.worker.name = modname

    def init_hotkeys(self):
        if not self.hotkeys_ctx:
            self.init_single_hotkey("F2", self.broker.worker.bp_notice)
            self.init_single_hotkey("F3", self.broker.worker.bp_oneshot_notice)
            self.init_single_hotkey("Ctrl-F2", self.broker.worker.hbp_notice)
            self.init_single_hotkey("Ctrl-F3", self.broker.worker.hbp_oneshot_notice)
            self.init_single_hotkey("Ctrl-F1", self.broker.worker.export_bp_notice)
            self.init_single_hotkey("Alt-F2", self.broker.worker.translate_notice)
            self.init_single_hotkey("F5", self.broker.worker.go_notice)
            self.init_single_hotkey("F10", self.broker.worker.so_notice)
            self.init_single_hotkey("F11", self.broker.worker.si_notice)

    def init_single_hotkey(self, key, fnCb):
        ctx = idaapi.add_hotkey(key, fnCb)
        if ctx is None:
            print("[sync] failed to register hotkey %s", key)
            del ctx
        else:
            self.hotkeys_ctx.append(ctx)

    def uninit_hotkeys(self):
        if not self.hotkeys_ctx:
            return

        for ctx in self.hotkeys_ctx:
            if idaapi.del_hotkey(ctx):
                del ctx

        self.hotkeys_ctx = []

    def cb_btn_restart(self):
        print "[sync] restarting broker."
        if self.cb.checkState() == QtCore.Qt.Checked:
            self.cb.toggle()
            time.sleep(0.1)
        self.cb.toggle()

    def cb_change_state(self, state):
        if state == QtCore.Qt.Checked:
            print "[*] sync enabled"
            # Restart broker
            self.hotkeys_ctx = []
            self.init_broker()
        else:
            if self.broker:
                self.smooth_kill()
            print "[*] sync disabled\n"

    def OnCreate(self, form):
        print "[sync] form create"

        # Get parent widget
        parent = self.FormToPyQtWidget(form)

        # Create checkbox
        self.cb = QtWidgets.QCheckBox("Synchronization enable")
        self.cb.move(20, 20)
        self.cb.stateChanged.connect(self.cb_change_state)

        # Create label
        label = QtWidgets.QLabel('Overwrite idb name:')

        name = idaapi.get_root_filename()
        print "[sync] default idb name: %s" % name
        # Check in conf for name overwrite
        confpath = os.path.join(os.path.realpath(IDB_PATH), '.sync')
        if os.path.exists(confpath):
            print "[sync] found config file: %s" % confpath
            config = ConfigParser.SafeConfigParser()
            config.read(confpath)
            if config.has_option(name, 'name'):
                name = config.get(name, 'name')
                print "[sync] overwrite idb name with %s" % name

        # Create input field
        self.input = QtWidgets.QLineEdit(parent)
        self.input.setText(name)
        self.input.setMaxLength = 256
        self.input.setFixedWidth(300)

        # Create restart button
        self.btn = QtWidgets.QPushButton('restart', parent)
        self.btn.setToolTip('Restart broker.')
        self.btn.clicked.connect(self.cb_btn_restart)

        # Create layout
        layout = QtWidgets.QGridLayout()
        layout.addWidget(self.cb)
        layout.addWidget(label)
        layout.addWidget(self.input)
        layout.addWidget(self.btn, 2, 2)
        layout.setColumnStretch(3, 1)
        layout.setRowStretch(3, 1)
        parent.setLayout(layout)

        # workaround: crash when instanciated in Broker.__init__
        # weird interaction with Qtxxx libraries ?
        #  File "C:\Python27\Lib\argparse.py", line 1584, in __init__
        #    self._positionals = add_group(_('positional arguments'))
        #  File "C:\Python27\Lib\gettext.py", line 566, in gettext
        #    return dgettext(_current_domain, message)
        #  TypeError: 'NoneType' object is not callable
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-a", "--address", nargs=1, action='store')
        self.parser.add_argument('msg', nargs=argparse.REMAINDER)

        # Synchronization is enabled by default
        self.cb.toggle()

    def OnClose(self, form):
        print "[sync] form close"
        self.smooth_kill()
        global SyncForm
        del SyncForm

    def Show(self):
        return PluginForm.Show(self, "ret-sync", options=PluginForm.FORM_PERSIST)


# --------------------------------------------------------------------------

def main():
    if not idaapi.get_root_filename():
        print "[sync] please load a file/idb before"
        return

    global SyncForm

    try:
        SyncForm
    except:
        SyncForm = SyncForm_t()

    SyncForm.Show()

main()
