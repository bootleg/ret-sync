#!/usr/bin/env python3

"""
Copyright (C) 2020, Alexandre Gazet.

This file is part of ret-sync plugin for Binary Ninja.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from collections import namedtuple

import binaryninjaui
if 'qt_major_version' in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QKeySequence
else:
    from PySide2.QtCore import Qt
    from PySide2.QtGui import QKeySequence

from binaryninjaui import UIAction, UIActionHandler

from .sync import SyncPlugin
from .retsync.rsconfig import rs_log


def add_commands(plugin):
    DbgAction = namedtuple('DbgAction', 'name, key_seq, handler')
    plugin_actions = (
        DbgAction("SyncEnable", QKeySequence(Qt.ALT + Qt.Key_S), UIAction(plugin.cmd_sync)),
        DbgAction("SyncDisable", QKeySequence(Qt.ALT + Qt.SHIFT + Qt.Key_S), UIAction(plugin.cmd_syncoff)),
        DbgAction("SyncGo", QKeySequence(Qt.ALT + Qt.Key_F5), UIAction(plugin.cmd_go)),
        DbgAction("SyncStepOver", QKeySequence(Qt.Key_F10), UIAction(plugin.cmd_so)),
        DbgAction("SyncStepInto", QKeySequence(Qt.Key_F11), UIAction(plugin.cmd_si)),
        DbgAction("SyncTranslate", QKeySequence(Qt.ALT + Qt.Key_F2), UIAction(plugin.cmd_translate)),
        DbgAction("SyncBp", QKeySequence(Qt.Key_F2), UIAction(plugin.cmd_bp)),
        DbgAction("SyncHwBp", QKeySequence(Qt.CTRL + Qt.Key_F2), UIAction(plugin.cmd_hwbp)),
        DbgAction("SyncBpOneShot", QKeySequence(Qt.ALT + Qt.Key_F3), UIAction(plugin.cmd_bp1)),
        DbgAction("SyncHwBpOneShot", QKeySequence(Qt.CTRL + Qt.Key_F3), UIAction(plugin.cmd_hwbp1))
        )

    for action in plugin_actions:
        UIAction.registerAction(action.name, action.key_seq)
        UIActionHandler.globalActions().bindAction(action.name, action.handler)

    rs_log('commands added')


retsync_plugin = SyncPlugin()
retsync_plugin.init_widget()
add_commands(retsync_plugin)
