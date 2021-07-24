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
import binaryninjaui
if 'qt_major_version' in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
    from PySide6 import QtCore
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget
    from PySide6.QtGui import QKeySequence
else:
    from PySide2 import QtCore
    from PySide2.QtCore import Qt
    from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget
    from PySide2.QtGui import QKeySequence

from binaryninjaui import UIAction, UIActionHandler
from binaryninjaui import DockHandler, DockContextHandler


from .rsconfig import rs_log


class SyncStatus(object):
    IDLE = "idle"
    ENABLED = "listening"
    RUNNING = "connected"


# based on hellodockwidget.py
# from https://github.com/Vector35/binaryninja-api/
class SyncDockWidget(QWidget, DockContextHandler):
    def __init__(self, parent, name, data):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel('Status: '))
        self.status = QLabel('idle')
        status_layout.addWidget(self.status)
        status_layout.setAlignment(QtCore.Qt.AlignCenter)

        client_dbg_layout = QHBoxLayout()
        client_dbg_layout.addWidget(QLabel('Client debugger: '))
        self.client_dbg = QLabel('n/a')
        client_dbg_layout.addWidget(self.client_dbg)
        client_dbg_layout.setAlignment(QtCore.Qt.AlignCenter)

        client_pgm_layout = QHBoxLayout()
        client_pgm_layout.addWidget(QLabel('Client program: '))
        self.client_pgm = QLabel('n/a')
        client_pgm_layout.addWidget(self.client_pgm)
        client_pgm_layout.setAlignment(QtCore.Qt.AlignCenter)

        layout = QVBoxLayout()
        layout.addStretch()
        layout.addLayout(status_layout)
        layout.addLayout(client_dbg_layout)
        layout.addLayout(client_pgm_layout)
        layout.addStretch()
        self.setLayout(layout)

    def shouldBeVisible(self, view_frame):
        if view_frame is None:
            return False
        else:
            return True

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    def set_status(self, status):
        if status == SyncStatus.RUNNING:
            self.status.setStyleSheet('color: green')
        elif status == SyncStatus.ENABLED:
            self.status.setStyleSheet('color: blue')
        else:
            self.status.setStyleSheet('')

        self.status.setText(status)

    def set_connected(self, dialect):
        self.set_status(SyncStatus.RUNNING)
        self.client_dbg.setText(dialect)

    def set_program(self, pgm):
        self.client_pgm.setText(pgm)

    def reset_client(self):
        self.set_status(SyncStatus.ENABLED)
        self.client_pgm.setText('n/a')
        self.client_dbg.setText('n/a')

    def reset_status(self):
        self.set_status(SyncStatus.IDLE)
        self.client_pgm.setText('n/a')
        self.client_dbg.setText('n/a')

    @staticmethod
    def create_widget(name, parent, data=None):
        return SyncDockWidget(parent, name, data)
