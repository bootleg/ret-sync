#
# Copyright (C) 2018-2020, Alexandre Gazet.
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
import sys
import traceback

import idaapi
import ida_hexrays

from . import rsconfig


class HexEventCb(object):

    def __init__(self, syncrays):
        self.syncrays = syncrays
        return

    def event_cb(self, event, *args):
        try:
            # if pseudocode has been refreshed
            if event == idaapi.hxe_func_printed:
                cfunc = args[0]

                if self.syncrays.last_func == cfunc.entry_ea:
                    # force a refresh
                    self.syncrays.last_func = None
        except Exception:
            traceback.print_exc()

        return 0


class Syncrays(object):

    def __init__(self):
        self.enabled = False
        self.prev_ea = None
        self.discarded_ea = None
        self.last_func = None
        self.vdui_t = None
        self.cfunc = None
        self.eamap = None
        self.safe_mode = False
        self.event_cb = HexEventCb(self).event_cb

        if not idaapi.init_hexrays_plugin():
            print("[sync] hexrays not available")
        else:
            version = idaapi.get_hexrays_version()
            print("[sync] hexrays #{} found".format(version))
            major, minor, revision, build_date = [int(x) for x in version.split('.')]

            if (major < 7) or (major >= 7 and minor < 2):
                print("[sync] hexrays version >= 7.2 is needed")
                self.safe_mode = True

    def enable(self):
        idaapi.install_hexrays_callback(self.event_cb)
        self.enabled = True

    def disable(self):
        idaapi.remove_hexrays_callback(self.event_cb)
        self.enabled = False

    # return True if target lines are found
    def color_ins_vec(self, ea, col):
        update = False

        if ea and (ea in self.eamap):
            for ins in self.eamap[ea]:
                px, py = self.cfunc.find_item_coords(ins)
                self.lines[py].bgcolor = col
                update = True

        return update

    def cb_loc(self, ea):
        update = False

        # find_item_coords is only available for versions >= 7.2
        if self.safe_mode:
            return

        func = idaapi.get_func(ea)
        if not func:
            return

        if self.last_func != func.start_ea:
            self.vdui_t = ida_hexrays.open_pseudocode(ea, 0)
            if not self.vdui_t:
                return
            self.cfunc = self.vdui_t.cfunc
            if not self.cfunc:
                # may happen in case of decompilation error
                return
            self.eamap = self.cfunc.get_eamap()
            self.prev_ea = None
            self.last_func = func.start_ea

        self.lines = self.cfunc.get_pseudocode()
        self.color_ins_vec(self.discarded_ea, rsconfig.COL_BLANK_HEX)
        self.color_ins_vec(self.prev_ea, rsconfig.COL_PREVLINE_HEX)
        update = self.color_ins_vec(ea, rsconfig.COL_CURLINE_HEX)

        if update:
            self.discarded_ea = self.prev_ea
            self.prev_ea = ea
