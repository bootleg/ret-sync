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
#

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import time
import traceback
import struct
import binascii
import base64
import socket
import json
import uuid
import argparse

from retsync.syncrays import Syncrays
import retsync.rsconfig as rsconfig
from retsync.rsconfig import rs_encode, rs_decode, rs_log, rs_debug, load_configuration

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import QProcess, QProcessEnvironment

import idc
import idaapi
import idautils
import ida_bytes
import ida_graph
import ida_range
import ida_funcs
import ida_name
import ida_hexrays
import ida_kernwin
import ida_idaapi
import ida_dbg
import ida_nalt

from idaapi import PluginForm


# get PYTHON_PATH settings, based on platform
PYTHON_PATH = rsconfig.get_python_interpreter()
os.environ['PYTHON_PATH'] = PYTHON_PATH

# default value is current script's path
BROKER_PATH = os.path.join(os.path.normpath(os.path.dirname(__file__)), rsconfig.PLUGIN_DIR, 'broker.py')
if not os.path.exists(BROKER_PATH):
    rs_log("[-] broker path is not properly set, current value: <%s>" % BROKER_PATH)
    raise RuntimeError

os.environ['IDB_PATH'] = os.path.dirname(os.path.realpath(idaapi.get_path(idaapi.PATH_TYPE_IDB)))

COL_CBTRACE = rsconfig.COL_CBTRACE


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
            if (cur_color != prev_color) and (cur_color != rsconfig.COL_CURLINE):
                prev_color = cur_color
            idaapi.set_item_color(prev_ea, prev_color)

        self.prev_loc = [ea, idaapi.get_item_color(ea)]
        idaapi.set_item_color(ea, rsconfig.COL_CURLINE)

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
        except argparse.ArgumentError:
            rs_log('failed to parse command')
            return [None, msg]

        # no address switch supplied
        if not args.address:
            return [offset, msg]

        try:
            addr = int(''.join(args.address), 16)
        except (TypeError, ValueError):
            rs_log('failed to parse address, should be hex')
            return [None, msg]

        # make sure the address points to a valid instruction/data
        head = idaapi.get_item_head(addr)
        if head != addr:
            rs_log("ambiguous address, did you mean 0x%x ?" % head)
            return [None, msg]

        return [addr, ' '.join(args.msg)]

    # check if address is within a valid segment
    def is_safe(self, offset):
        return not (idc.get_segm_start(offset) == ida_idaapi.BADADDR)

    # rebase (and update) address with respect to local image base
    def rebase(self, base, offset):
        if base is not None:
            # check for non-compliant debugger client
            if base > offset:
                rs_log('unsafe addr: 0x%x > 0x%x' % (base, offset))
                return None

            # update base address of remote module
            if self.base_remote != base:
                self.base_remote = base

            offset = self.rebase_local(offset)

        if not self.is_safe(offset):
            rs_log('unsafe addr: 0x%x not in valid segment' % (offset))
            return None

        return offset

    # rebase address with respect to local image base
    def rebase_local(self, offset):
        if not (self.base == self.base_remote):
            offset = (offset - self.base_remote) + self.base

        return offset

    # rebase address with respect to remote image base
    def rebase_remote(self, offset):
        if not (self.base == self.base_remote):
            offset = (offset - self.base) + self.base_remote

        return offset

    # demangle names
    def demangle(self, name):
        mask = idc.get_inf_attr(idc.INF_SHORT_DEMNAMES)
        demangled = idc.demangle_name(name, mask)
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
            rs_log("warning, comment needs to be splitted (from 0x%x)" % ea)
            nh = idaapi.next_head(ea, ida_idaapi.BADADDR)
            if nh == ida_idaapi.BADADDR:
                rs_log('[x] failed to find next instruction candidate')
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

        if self.color:
            self.cb_color(ea)

        idaapi.jumpto(ea)
        self.cb_curline(ea)
        self.gm.center()

        if self.hexsync.enabled:
            self.hexsync.cb_loc(ea)

    # set remote base on purpose
    def req_rbase(self, hash):
        rbase = hash['rbase']
        self.base_remote = rbase

    # log command output request at addr
    def req_cmd(self, hash):
        msg_b64, offset, base = hash['msg'], hash['offset'], hash['base']
        msg = rs_decode(base64.b64decode(msg_b64))
        ea = self.rebase(base, offset)
        if not ea:
            return

        rs_log("cmd output added at 0x%x" % ea)
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
        rs_log("reset comment at 0x%x" % ea)

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
        rs_log("comment added at 0x%x" % ea)

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
            rs_log("could not find func for 0x%x" % ea)
            return

        idaapi.set_func_cmt(func, str(msg), False)
        rs_log("function comment added at 0x%x" % ea)

    # add an address comment request at addr
    def req_raddr(self, hash):
        raddr, rbase, offset, base = hash['raddr'], hash['rbase'], hash['offset'], hash['base']
        ea = self.rebase(base, offset)
        if not ea:
            return

        if self.base_remote != rbase:
            rs_log('could not rebase this address, 0x%x != 0x0, not in module')
            return

        addr = self.rebase(rbase, raddr)
        if not addr:
            return

        self.append_cmt(ea, "0x%x (rebased from 0x%x)" % (addr, raddr))
        rs_log("comment added at 0x%x" % ea)

    # return current cursor in IDA Pro
    def req_cursor(self, hash):
        rs_log('request IDA Pro cursor position')
        addr = self.rebase_remote(idc.get_screen_ea())
        self.notice_broker('cmd', "\"cmd\":\"0x%x\"" % addr)
        return

    # patch memory at specified address using info from debugger
    def req_patch(self, hash):
        addr, value, length = hash['addr'], hash['value'], hash['len']

        if length == 4:
            prev_value = idc.get_wide_dword(addr)
            if not ida_bytes.create_data(ea, FF_DWORD, 4, ida_idaapi.BADADDR):
                rs_log('[x] ida_bytes.create_data FF_DWORD failed')
            if not ida_bytes.patch_dword(addr, value):
                rs_log('[x] patch_dword failed')
            if not idc.op_plain_offset(addr, 0, 0):
                rs_log('[x] op_plain_offset failed')

        elif length == 8:
            prev_value = idc.get_qword(addr)
            if not ida_bytes.create_data(addr, FF_QWORD, 8, ida_idaapi.BADADDR):
                rs_log('[x] ida_bytes.create_data FF_QWORD failed')
            if not ida_bytes.patch_qword(addr, value):
                rs_log('[x] patch_qword failed')
            if not idc.op_plain_offset(addr, 0, 0):
                rs_log('[x] op_plain_offset failed')

        else:
            rs_log("[x] unsupported length: %d" % length)
            return

        rs_log("patched 0x%x = 0x%x (previous was 0x%x)" % (addr, value, prev_value))

    # return idb's symbol for a given address
    def req_rln(self, hash):
        raddr = hash['raddr']

        rs_debug("rln: 0x%x" % raddr)

        addr = self.rebase_local(raddr)
        if not addr:
            rs_log("could not rebase this address (0x%x)" % raddr)
            return

        sym = idaapi.get_func_name(addr)
        if sym:
            sym = self.demangle(sym)
            func = idaapi.get_func(addr)
            if not func:
                rs_log("could not find func for 0x%x" % addr)
                return

            lck = idaapi.lock_func(func)
            limits = ida_range.range_t()
            rs = ida_range.rangeset_t()

            if ida_funcs.get_func_ranges(rs, func) != ida_idaapi.BADADDR:
                limits.start_ea = rs.begin().start_ea
                limits.end_ea = rs.begin().end_ea

                if limits.start_ea != addr:
                    if (addr > limits.start_ea):
                        sym = "%s%s0x%x" % (sym, "+", addr - limits.start_ea)
                    else:
                        sym = "%s%s0x%x" % (sym, "-", limits.start_ea - addr)
            lck = None
        else:
            sym = idc.get_name(addr, ida_name.GN_VISIBLE)
            if sym:
                sym = self.demangle(sym)

        if sym:
            self.notice_broker('cmd', "\"cmd\":\"%s\"" % sym)
            rs_debug("resolved symbol: %s" % sym)
        else:
            rs_log("could not resolve symbol for address 0x%x" % addr)

    # return address for a given idb's symbol
    def req_rrln(self, hash):
        sym = hash['sym']
        rs_log("rrln> symbol \"%s\"" % sym)

        addr = idc.get_name_ea_simple(str(sym))
        if addr:
            raddr = self.rebase_remote(addr)
            self.notice_broker("cmd", "\"cmd\":\"%s\"" % raddr)
            rs_log("rrln> remote: 0x%x, local: 0x%x)" % (raddr, addr))
        else:
            rs_log("rrln> symbol not found \"%s\"" % sym)

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
        rs_log("label added at 0x%x" % ea)

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
            rs_log("color oneshot added at 0x%x" % ea)
            # mark address as being colored
            self.prev_loc = [ea, COL_CBTRACE]
        elif (msg == 'on'):
            rs_log("color start from 0x%x" % ea)
            self.color = True
            self.prev_loc = [ea, COL_CBTRACE]
        elif (msg == 'off'):
            rs_log("color end at 0x%x" % ea)
            self.color = False
        elif (msg == 'set'):
            new_col = hash['rgb']
            if new_col > 0xffffff:
                rs_log('restoring color')
                new_col = rsconfig.COL_GREEN

            COL_CBTRACE = new_col
            rs_log("set color to 0x%x" % COL_CBTRACE)
        else:
            rs_log("invalid color request (%s)" % msg)

    # reload .bpcmds from idb
    def req_bps_get(self, hash):
        rs_log('[-] reload .bpcmds')
        node = idaapi.netnode(rsconfig.NETNODE_INDEX)
        if not node:
            rs_log('[-] failed to open netnode store')
            self.notice_broker("cmd", "\"cmd\":\"no blob\"")
            return

        node.create(rsconfig.NETNODE_STORE)
        blob = rs_decode(node.getblob(0, str(chr(1))))

        if not blob:
            rs_log('  -> no blob')
            self.notice_broker('cmd', "\"cmd\":\"    -> reloading .bpcmds: no blob\"")
            return

        self.notice_broker('cmd', "\"cmd\":\"%s\"" % blob)
        return

    # save .bpcmds to idb
    def req_bps_set(self, hash):
        blob = hash['msg']
        rs_log('[-] save .bpcmds')
        node = idaapi.netnode(rsconfig.NETNODE_INDEX)
        if not node:
            rs_log('[-] failed to open netnode store')
            self.notice_broker('cmd', "\"cmd\":\"    -> failed to save .bpcmds")
            return

        new = node.create(rsconfig.NETNODE_STORE)
        if new == 0:
            rs_log('    -> creating new netnode store')

        out = node.setblob(rs_encode(blob), 0, chr(1))
        self.notice_broker("cmd", "\"cmd\":\"    -> .bpcmds saved\"")
        return

    # compare loaded module md5 with idb's input file md5
    def req_modcheck(self, hash):
        md5, pdb = hash.get('md5'), hash.get('pdb')
        remote = None

        if md5:
            rs_log("modcheck idb (md5)")
            local = rs_decode(binascii.hexlify(idaapi.retrieve_input_file_md5())).upper()
            remote = (''.join(md5.split())).upper()
        elif pdb:
            rs_log("modcheck idb (pdb guid)")
            msg = rs_decode(base64.b64decode(pdb))
            local = DbgDirHlpr.read_rsds_guid()
            remote = DbgDirHlpr.parse_itoldyouso_output(msg)

        rs_log("    -> remote: <%s>" % remote)
        rs_log("    -> local : <%s>" % local)

        if remote == '0':
            output = '[!] warning, no Debug Directory'
        elif local == remote:
            output = '[+] module successfully matched'
        else:
            output = '[!] warning, modules mismatch'

        rs_log(output)
        self.notice_broker("cmd", "\"cmd\":\"%s\"" % output)
        return

    # specify debugger dialect used to send commands
    def req_set_dbg_dialect(self, hash):
        global SyncForm
        dialect = hash['dialect']
        if dialect in rsconfig.DBG_DIALECTS:
            self.dbg_dialect = rsconfig.DBG_DIALECTS[dialect]
            rs_log("set debugger dialect to %s, enabling hotkeys" % dialect)
            SyncForm.init_hotkeys()
        else:
            SyncForm.uninit_hotkeys()

    # request from broker
    def req_broker(self, hash):
        subtype = hash['subtype']

        if (subtype == 'msg'):
            # simple message announcement
            rs_log("<< broker << %s" % hash['msg'])

        elif(subtype == 'notice'):
            # notice from broker
            self.broker_port = int(hash['port'])
            rs_debug("<< broker << binding on port %d" % self.broker_port)

            for attempt in range(rsconfig.CONNECT_BROKER_MAX_ATTEMPT):
                try:
                    host = socket.gethostbyname('localhost')
                    self.broker_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.broker_sock.settimeout(2)
                    self.broker_sock.connect((host, self.broker_port))
                    break
                except socket.error:
                    rs_log('failed to connect to broker')
                    rs_log(sys.exc_info())
                    if self.broker_sock:
                        self.broker_sock.close()
                    self.broker_sock = None
                    time.sleep(0.1)
                    if (attempt == (rsconfig.CONNECT_BROKER_MAX_ATTEMPT - 1)):
                        self.announcement("[sync] failed to connect to broker (attempt %d)" % attempt)
                        raise RuntimeError

            # request broker to validate its beacon
            time.sleep(0.4)
            self.beacon_notice()

        # enable/disable idb, if disable it drops most sync requests
        elif(subtype == 'enable_idb'):
            self.is_active = True
            rs_log('idb is enabled')

        elif(subtype == 'disable_idb'):
            self.is_active = False
            self.base_remote = None
            self.cb_restore_last_line()
            rs_log('idb is disabled')

    # parse and execute request
    # Note that sometimes we don't receive the whole request from the broker.py
    # so parsing fails. One way for fixing this would be to fix broker.py to get
    # everything until "\n" before proxying it but the way we do here is to read
    # everything until "}" is received (end of json)
    def parse_exec(self, req):
        if self.prev_req:
            if self.prev_req != "":
                if rsconfig.DEBUG_JSON:
                    rs_log("JSON merge with request: \"%s\"" % req)

            req = self.prev_req + req
            self.prev_req = ""
        if req == '':
            return
        if rsconfig.DEBUG_JSON:
            rs_log("parse_exec -> " + str(req))

        if not (req.startswith('[sync]')):
            rs_log("[<] bad hdr %s" % repr(req))
            rs_log('[-] Request dropped due to bad header')
            return

        req_ = self.normalize(req, 6)

        try:
            hash = json.loads(req_)
        except ValueError:
            if rsconfig.DEBUG_JSON:
                rs_log("[x] Sync failed to parse json\n '%s'. Caching for next req..." % req_)
                rs_log("------------------------------------")
            self.prev_req = req
            return

        rtype = hash['type']
        if rtype not in self.req_handlers:
            rs_log("unknown request: %s" % rtype)
            return

        req_handler = self.req_handlers[rtype]

        # few requests are handled even though idb is not enable
        if rtype in ['broker', 'dialect', 'bc']:
            req_handler(hash)
        else:
            if self.is_active:
                req_handler(hash)
            else:
                rs_debug("[-] Drop the %s request because idb is not enabled" % rtype)
                return

        idaapi.refresh_idaview_anyway()

    def normalize(self, req, taglen):
        req = req[taglen:]
        req = req.replace("\\", "\\\\")
        req = req.replace("\n", "")
        return req.strip()

    # send a kill notice to the broker (then forwarded to the dispatcher)
    def kill_notice(self):
        self.notice_broker("kill")

    # send a beacon notice to the broker
    def beacon_notice(self):
        self.notice_broker('beacon')

    # send a bp command (F2) to the debugger (via the broker and dispatcher)
    def bp_notice(self, oneshot=False):
        if not self.is_active:
            rs_log("idb isn't enabled, bp can't be set")
            return

        ea = idaapi.get_screen_ea()
        offset = self.rebase_remote(ea)
        cmd = "%s0x%x" % (self.dbg_dialect['bp1' if oneshot else 'bp'], offset)

        if (oneshot and 'oneshot_post' in self.dbg_dialect):
            cmd += self.dbg_dialect['oneshot_post']

        self.notice_broker("cmd", "\"cmd\":\"%s\"" % cmd)
        rs_log(">> set %s" % cmd)

    # send a hardware bp command (Ctrl-F2) to the debugger (via the broker and dispatcher)
    def hbp_notice(self, oneshot=False):
        if not self.is_active:
            rs_log("idb isn't enabled, hbp can't be set")
            return

        ea = idaapi.get_screen_ea()
        offset = self.rebase_remote(ea)
        cmd = "%s0x%x" % (self.dbg_dialect['hbp1' if oneshot else 'hbp'], offset)

        self.notice_broker("cmd", "\"cmd\":\"%s\"" % cmd)
        rs_log(">> set %s" % cmd)

    # send a oneshot bp command (F3) to the debugger (via the broker and dispatcher)
    def bp_oneshot_notice(self):
        self.bp_notice(True)

    # send a oneshot hardware bp command (Ctrl-F3) to the debugger (via the broker and dispatcher)
    def hbp_oneshot_notice(self):
        self.hbp_notice(True)

    # export IDB's breakpoint (Ctrl-F1) to the debugger (via the broker and dispatcher)
    def export_bp_notice(self):
        if not self.dbg_dialect:
            rs_log("idb isn't synced yet, can't export bp")
            return

        is_windbg = (self.dbg_dialect == 'windbg')

        # Windbg supports relative address, ie. mod+0xCAFE
        # for non relative address the remote base address is needed
        if (not is_windbg) and (not self.base_remote):
            rs_log("idb isn't enabled, can't export bp")
            return

        mod = self.name.split('.')[0].strip()
        nbp = ida_dbg.get_bpt_qty()

        for i in range(nbp):
            ea = idc.get_bpt_ea(i)
            attrs = [idc.BPTATTR_TYPE, idc.BPTATTR_COND, idc.BPTATTR_FLAGS]
            btype, cond, flags = [idc.get_bpt_attr(ea, x) for x in attrs]

            if cond:
                rs_log("bp %d: conditional bp not supported" % i)
            else:
                if ((btype in [idc.BPT_EXEC, idc.BPT_SOFT]) and
                   ((flags & idc.BPT_ENABLED) != 0)):

                    bp = self.dbg_dialect['hbp' if (btype == idc.BPT_EXEC) else 'bp']

                    if is_windbg:
                        offset = ea - self.base
                        cmd = "%s%s+0x%x" % (bp, mod, offset)
                    else:
                        offset = self.rebase_remote(ea)
                        cmd = "%s0x%x" % (bp, offset)

                    self.notice_broker("cmd", "\"cmd\":\"%s\"" % cmd)
                    rs_log("bp %d: %s" % (i, cmd))

        rs_log('export done')

    # send a translate command (Alt-F2) to the debugger (via the broker and dispatcher)
    def translate_notice(self):
        if not self.dbg_dialect:
            rs_log("idb isn't synced yet, can't translate")
            return

        ea = idaapi.get_screen_ea()
        mod = self.name.split('.')[0].strip()
        cmd = self.dbg_dialect['prefix'] + "translate 0x%x 0x%x %s" % (self.base, ea, mod)
        self.notice_broker("cmd", "\"cmd\":\"%s\"" % cmd)
        rs_debug("translate address 0x%x" % ea)

    # send a command to the debugger (via the broker and dispatcher)
    def cmd_notice(self, cmd, descr):
        if cmd in self.dbg_dialect:
            self.notice_broker("cmd", "\"cmd\":\"%s\"" % self.dbg_dialect[cmd])
            self.notice_anti_flood()
        else:
            rs_log("the \"%s\" command is not available for the current debugger" % cmd)

    # send a go command (Alt-F5) to the debugger (via the broker and dispatcher)
    def go_notice(self):
        self.cmd_notice('go', descr='go')

    # send a go command (Ctrl-Alt-F5) to the debugger (via the broker and dispatcher)
    def run_notice(self):
        self.cmd_notice('run', descr='run')

    # send a single trace command (F11) to the debugger (via the broker and dispatcher)
    def si_notice(self):
        self.cmd_notice('si', descr='trace')

    # send a single step command (F10) to the debugger (via the broker and dispatcher)
    def so_notice(self):
        self.cmd_notice('so', descr='step')

    # send a notice message to the broker process
    def notice_broker(self, type, args=None):
        if not self.broker_sock:
            return

        if args:
            notice = "[notice]{\"type\":\"%s\",%s}\n" % (type, args)
        else:
            notice = "[notice]{\"type\":\"%s\"}\n" % (type)

        try:
            self.broker_sock.sendall(rs_encode(notice))
        except socket.error:
            None

    def stop(self):
        if self.broker_sock:
            self.broker_sock.close()
            self.broker_sock = None

        self.cb_restore_last_line()
        idaapi.refresh_idaview_anyway()
        self.is_active = False
        rs_log("idb is disabled")

    def __init__(self, parser):
        self.color = False
        self.prev_loc = None
        self.prev_node = None
        self.name = idaapi.get_root_filename()
        self.base = idaapi.get_imagebase()
        rs_log("module base 0x%x" % self.base)
        self.base_remote = None
        self.gm = GraphManager()
        self.hexsync = Syncrays()
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
            'rbase': self.req_rbase,
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

    QP_STATES = ('Not running', 'Starting', 'Running')
    QP_ERRORS = ('Failed to start', 'Crashed', 'Timedout',
                 'Read error', 'Write Error', 'Unknown Error')

    def cb_on_error(self, error):
        rs_log("[-] broker error: %s" % Broker.QP_ERRORS[error])

    def cb_broker_on_state_change(self, new_state):
        rs_debug("broker new state: %s" % Broker.QP_STATES[new_state])
        if Broker.QP_STATES[new_state] == 'Not running':
            if rsconfig.LOG_TO_FILE_ENABLE:
                rs_log('    check tmp file retsync.<broker|dispatcher>.err if you think this is an error')

    def cb_broker_on_out(self):
        # readAllStandardOutput() returns QByteArray
        data = rs_decode(self.readAllStandardOutput().data())
        batch = data.split('\n')
        for req in batch:
            self.worker.parse_exec(req.strip())

    def __init__(self, parser):
        QtCore.QProcess.__init__(self)

        self.error.connect(self.cb_on_error)
        self.readyReadStandardOutput.connect(self.cb_broker_on_out)
        self.stateChanged.connect(self.cb_broker_on_state_change)

        # create a request handler
        self.worker = RequestHandler(parser)

# --------------------------------------------------------------------------


class DbgDirHlpr(object):

    @staticmethod
    def read_rsds_guid():
        guid = None
        penode = idaapi.netnode()
        penode.create(idautils.peutils_t.PE_NODE)
        rsds = penode.getblob(0, "s")

        if rsds and rsds.startswith(b'RSDS'):
            guid = ("%s" % uuid.UUID(bytes_le=rsds[4:20])).upper()

        return guid

    @staticmethod
    def read_rsds_pdb():
        penode = idaapi.netnode()
        PE_SUPSTR_PDBNM = idautils.peutils_t.PE_ALT_DBG_FPOS - 8
        penode.create(idautils.peutils_t.PE_NODE)
        pdbname = penode.supstr(PE_SUPSTR_PDBNM, 'S')
        return pdbname

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


class CheckBoxActionHandler(idaapi.action_handler_t):
    def __init__(self, cb):
        idaapi.action_handler_t.__init__(self)
        self.cb = cb

    def activate(self, ctx):
        self.cb.toggle()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# --------------------------------------------------------------------------


class CmdHook(ida_kernwin.UI_Hooks):

    def __init__(self):
        idaapi.UI_Hooks.__init__(self)
        self.hooked = {}
        self.bugfixed = False

        # 74sp1 BUGFIX: IDAPython: ida_kernwin.UI_Hooks.preprocess_action()
        # wouldn't allow inhibiting the action
        pattern = re.compile('preprocess_action\(self, name\) -> int')
        if pattern.search(ida_kernwin.UI_Hooks.preprocess_action.__doc__):
            self.bugfixed = True

    def minver74sp1(self):
        # idaapi.IDA_SDK_VERSION >= 740:
        return self.bugfixed

    def add_hook(self, action_name, callback):
        self.hooked[action_name] = callback

    def del_hook(self, action_name):
        del self.hooked[action_name]

    def preprocess_action(self, action_name):
        if action_name not in self.hooked:
            return 0

        self.hooked[action_name]()
        return 1


# --------------------------------------------------------------------------


class SyncForm_t(PluginForm):

    hotkeys_ctx = []
    cmd_hooks = CmdHook()

    def cb_broker_started(self):
        rs_log("broker started")
        self.btn.setText("Restart")

    def cb_broker_finished(self):
        rs_log("broker finished")
        self.uninit_hotkeys()
        if self.broker:
            self.broker.worker.stop()
            self.cb_sync.stateChanged.disconnect(self.cb_change_state)
            self.cb_sync.toggle()
            self.cb_sync.stateChanged.connect(self.cb_change_state)

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
        rs_debug("init_broker")
        modname = self.input.text()
        if modname == "":
            modname = self.handle_name_aliasing()
            self.input.setText(modname)

        cmdline = "\"%s\" -u \"%s\" --idb \"%s\"" % (
                  PYTHON_PATH,
                  BROKER_PATH,
                  modname)
        rs_log("cmdline: %s" % cmdline)

        try:
            self.broker = Broker(self.parser)
            self.broker.started.connect(self.cb_broker_started)
            self.broker.finished.connect(self.cb_broker_finished)
            self.broker.start(cmdline)
        except Exception as e:
            rs_log("[-] failed to start broker: %s\n%s" % (str(e), traceback.format_exc()))
            return

        self.broker.worker.name = modname

    def init_hotkeys(self):
        hotkeys_info = (
            ('F2', self.broker.worker.bp_notice, 'BreakpointToggle'),
            ('F3', self.broker.worker.bp_oneshot_notice),
            ('F10', self.broker.worker.so_notice),
            ('F11', self.broker.worker.si_notice, 'FullScreen'),
            ('Ctrl-F1', self.broker.worker.export_bp_notice, 'ExternalHelp'),
            ('Ctrl-F2', self.broker.worker.hbp_notice),
            ('Ctrl-F3', self.broker.worker.hbp_oneshot_notice),
            ('Alt-F2', self.broker.worker.translate_notice, 'ManualInstruction'),
            ('Alt-F5', self.broker.worker.go_notice),
            ('Ctrl-Alt-F5', self.broker.worker.run_notice),
        )

        if not self.hotkeys_ctx:
            for hk_info in hotkeys_info:
                self.init_single_hotkey(*hk_info)

        # enable ida_kernwin.UI_Hooks
        if self.cmd_hooks.minver74sp1():
            self.cmd_hooks.hook()

    def init_single_hotkey(self, key, fnCb, conflict=None):
        if conflict:
            if self.cmd_hooks.minver74sp1():
                # 'hook' existing action shortcut when possible
                self.cmd_hooks.add_hook(conflict, fnCb)
                return
            else:
                # 'mute' existing action shortcut
                ida_kernwin.update_action_shortcut(conflict, None)

        ctx = idaapi.add_hotkey(key, fnCb)
        if ctx is None:
            rs_log("failed to register hotkey %s" % key)
            del ctx
        else:
            self.hotkeys_ctx.append((ctx, key, conflict))

    def uninit_hotkeys(self):
        # disable ida_kernwin.UI_Hooks
        if self.cmd_hooks.minver74sp1():
            self.cmd_hooks.unhook()

        if not self.hotkeys_ctx:
            return

        # delete registered context and restore original action
        for ctx, key, conflict in self.hotkeys_ctx:
            if idaapi.del_hotkey(ctx):
                del ctx
            else:
                rs_log("failed to delete hotkey %s" % key)

            if conflict and not self.cmd_hooks.minver74sp1():
                ida_kernwin.update_action_shortcut(conflict, key)

        self.hotkeys_ctx = []

    def cb_btn_restart(self):
        rs_log('restarting broker')
        if self.cb_sync.checkState() == QtCore.Qt.Checked:
            self.cb_sync.toggle()
            time.sleep(0.1)
        self.cb_sync.toggle()

    def cb_change_state(self, state):
        if state == QtCore.Qt.Checked:
            rs_log("sync enabled")
            # Restart broker
            self.hotkeys_ctx = []
            self.init_broker()
        else:
            if self.broker:
                self.smooth_kill()
            rs_log("sync disabled\n")

    def cb_hexrays_sync_state(self, state):
        if self.broker:
            if state == QtCore.Qt.Checked:
                rs_log("hexrays sync enabled\n")
                self.broker.worker.hexsync.enable()
            else:
                rs_log("hexrays sync disabled\n")
                self.broker.worker.hexsync.disable()

    def cb_hexrays_toggle(self):
        self.cb_hexrays.toggle()

    # issue a warning if pdb name is different from
    # the name used to register the idb to the dispatcher
    def pdb_name_warning(self, name):
        pdbpath = DbgDirHlpr.read_rsds_pdb()
        if not pdbpath:
            return

        normpath = os.path.normpath(pdbpath.replace("\\", "\\\\"))
        pdb_root, pdb_ext = os.path.splitext(os.path.basename(normpath))
        mod_root, mod_ext = os.path.splitext(name)

        if pdb_root.strip() != mod_root.strip():
            rs_log("hint: pdb name ('%s') differs from registered module name ('%s')" % (pdb_root+mod_ext, name))

    # discover the name used to expose the idb, default is from get_root_filename
    # alias can be defined in '.sync' configuration file
    def handle_name_aliasing(self):
        name = idaapi.get_root_filename()
        rs_log("default idb name: %s" % name)

        try:
            conf = load_configuration(name)
            if conf.path:
                rs_log("found config file: %s" % repr(conf))
            if conf.alias:
                name = conf.alias
                rs_log("overwrite idb name with %s" % name)
        except Exception as e:
            rs_log('failed to load configuration file')

        self.pdb_name_warning(name)
        return name

    def OnCreate(self, form):
        rs_debug("form create")

        # get parent widget
        parent = self.FormToPyQtWidget(form)

        # create global sync checkbox
        self.cb_sync = QtWidgets.QCheckBox('Synchronization enable')
        self.cb_sync.move(20, 20)
        self.cb_sync.stateChanged.connect(self.cb_change_state)

        # create hexrays sync checkbox
        self.cb_hexrays = QtWidgets.QCheckBox('Hex-Rays Synchronization enable')
        self.cb_hexrays.move(20, 20)
        self.cb_hexrays.stateChanged.connect(self.cb_hexrays_sync_state)

        # create label
        label = QtWidgets.QLabel('Overwrite idb name:')
        name = self.handle_name_aliasing()

        # create input field
        self.input = QtWidgets.QLineEdit(parent)
        self.input.setText(name)
        self.input.setMaxLength = 256
        self.input.setFixedWidth(300)

        # create restart button
        self.btn = QtWidgets.QPushButton('restart', parent)
        self.btn.setToolTip('Restart broker.')
        self.btn.clicked.connect(self.cb_btn_restart)

        # create layout
        layout = QtWidgets.QGridLayout()
        layout.addWidget(self.cb_sync)
        layout.addWidget(self.cb_hexrays)
        layout.addWidget(label)
        layout.addWidget(self.input)
        layout.addWidget(self.btn, 2, 2)
        layout.setColumnStretch(4, 1)
        layout.setRowStretch(4, 1)
        parent.setLayout(layout)

        self.parser = argparse.ArgumentParser()
        self.parser.add_argument('-a', '--address', nargs=1, action='store')
        self.parser.add_argument('msg', nargs=argparse.REMAINDER)

        # synchronization is enabled by default
        self.cb_sync.toggle()

        # register action for hexrays sync
        action_hex_sync_desc = idaapi.action_desc_t(
            'hexrays_sync_toogle:action',
            'Toggle Hex-Rays syncing',
            CheckBoxActionHandler(self.cb_hexrays),
            'Ctrl+H',
            'Toggle Hex-Rays syncing',
            198)

        idaapi.register_action(action_hex_sync_desc)
        idaapi.attach_action_to_toolbar(
            "DebugToolBar",
            'hexrays_sync_toogle:action')

        # register action for global sync
        action_g_sync_desc = idaapi.action_desc_t(
            'g_sync_toogle:action',
            'Toggle syncing',
            CheckBoxActionHandler(self.cb_sync),
            'Ctrl+Shift+S',
            'Toggle syncing',
            203)

        idaapi.register_action(action_g_sync_desc)
        idaapi.attach_action_to_toolbar(
            "DebugToolBar",
            'g_sync_toogle:action')

    def OnClose(self, form):
        rs_debug("form close")
        self.smooth_kill()

        idaapi.unregister_action('hexrays_sync_toogle:action')
        idaapi.detach_action_from_toolbar(
            "DebugToolBar",
            'hexrays_sync_toogle:action')

        idaapi.unregister_action('g_sync_toogle:action')
        idaapi.detach_action_from_toolbar(
            "DebugToolBar",
            'g_sync_toogle:action')

        global SyncForm
        del SyncForm
        SyncForm = None

    def Show(self):
        return PluginForm.Show(self, "ret-sync", options=PluginForm.WOPN_PERSIST)


# --------------------------------------------------------------------------


class RetSyncPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = 'Reverse-Engineering Tools synchronization, ret-sync .'
    help = 'Synchronize a debugging session with IDA.'
    wanted_name = 'ret-sync'
    wanted_hotkey = 'Alt-Shift-S'
    global SyncForm
    SyncForm = None

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        if not idaapi.get_root_filename():
            rs_log('please load a file/idb before')
            return

        global SyncForm
        if not SyncForm:
            SyncForm = SyncForm_t()
            SyncForm.Show()
            rs_log("plugin loaded")


def PLUGIN_ENTRY():
    return RetSyncPlugin()


if __name__ == "__main__":
    rs_log("ret-sync is an IDA Pro plugin, please see README for installation notes")
