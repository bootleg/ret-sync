#
# Copyright (C) 2019, Alexandre Gazet.
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

import os
import sys
import tempfile
import logging
from logging.handlers import RotatingFileHandler

try:
    import distutils.spawn
    spawn_module = True
except ImportError:
    spawn_module = False


# global plugin settings
PLUGIN_DIR = 'retsync'

# cold storage in IDA database
NETNODE_STORE = "$ SYNC_STORE"
NETNODE_INDEX = 0xFFC0DEFF

# networking settings
HOST = 'localhost'
PORT = 9100
CONNECT_BROKER_MAX_ATTEMPT = 4
RUN_DISPATCHER_MAX_ATTEMPT = 4

# color definitions
COL_BLANK = 0xffffffff
COL_GREEN = 0x33ff00
COL_DEEP_PURPLE = 0xff44dd
COL_YLW = 0x23ffff
COL_YLW_LIGHT = 0xccffff
COL_BLUE_NAVY = 0x000080
COL_GRAY = 0x808080

# general purpose current instruction syncing color
COL_CURLINE = COL_YLW

# trace color, used by !bc feature
COL_CBTRACE = COL_GREEN

# syncrays colors, gradient of yellow
COL_BLANK_HEX = COL_BLANK
COL_CURLINE_HEX = COL_YLW
COL_PREVLINE_HEX = COL_YLW_LIGHT

# dialects to translate debugger commands (breakpoint, step into/over, etc.)
DBG_DIALECTS = {
    'windbg': {
        'prefix': '!',
        'si': 't',
        'so': 'p',
        'go': 'g',
        'bp': 'bp ',
        'hbp': 'ba e 1 ',
        'bp1': 'bp /1 ',
        'hbp1': 'ba e 1 /1 '},
    'gdb': {
        'prefix': '',
        'si': 'si',
        'so': 'ni',
        'go': 'continue',
        'bp': 'b *',
        'hbp': 'hb *',
        'bp1': 'tb *',
        'hbp1': 'thb *'},
    'ollydbg2': {
        'prefix': '',
        'si': 'si',
        'so': 'so',
        'go': 'go',
        'bp': 'bp ',
        'hbp': 'xxx ',
        'bp1': 'xxx ',
        'hbp1': 'xxx '},
    'x64_dbg': {
        'prefix': '',
        'si': 'sti',
        'so': 'sto',
        'go': 'go',
        'bp': 'bp ',
        'hbp': 'bph ',
        'bp1': 'xxx ',
        'hbp1': 'xxx '},
}


# debugging settings
# enable/disable logging JSON received in the IDA output window
DEBUG_JSON = False

# global log level (console output)
LOG_LEVEL = logging.INFO

# log prefix to identify plugin
LOG_PREFIX = 'sync'

# enable/disable broker and dipatcher exception logging to file
LOG_TO_FILE_ENABLE = False

# logging feature for broker and dispatcher (disabled by default)
LOG_FMT_STRING = '%(asctime)-12s [%(levelname)s] %(message)s'


def init_logging(src):
    logging.basicConfig(level=logging.DEBUG)
    name = os.path.basename(src)
    logger = logging.getLogger('retsync.plugin.' + name)

    if LOG_TO_FILE_ENABLE:
        rot_handler = logging.handlers.RotatingFileHandler(
            os.path.join(tempfile.gettempdir(), "retsync.%s.err" % name),
            mode='a',
            maxBytes=8192,
            backupCount=1)

        formatter = logging.Formatter(LOG_FMT_STRING)
        rot_handler.setFormatter(formatter)
        rot_handler.setLevel(logging.DEBUG)
        logger.addHandler(rot_handler)

    return logger


# console output wrapper
def rs_log(s, lvl=logging.INFO):
    if lvl >= LOG_LEVEL:
        print("[%s] %s" % (LOG_PREFIX, s))


def rs_debug(s):
    rs_log(s, logging.DEBUG)


# encoding settings (for data going in/out the plugin)
RS_ENCODING = 'utf-8'


def rs_encode(buffer_str):
    return buffer_str.encode(RS_ENCODING)


def rs_decode(buffer_bytes):
    return buffer_bytes.decode(RS_ENCODING)


# default paths Windows platforms
PY_WIN_DEFAULTS = (
    "C:\\Program Files\\Python37",
    "C:\\Program Files\\Python37-32",
    "C:\\Python27",
    "C:\\Python27-x64",
    )

# default paths Windows platforms
PY_WIN_LOCAL_DEFAULTS = (
    "%LOCALAPPDATA%\\Programs\\Python\\Python37",
    "%LOCALAPPDATA%\\Programs\\Python\\Python38",
    )

# default paths Linux/Mac OS X platforms
PY_LINUX_DEFAULTS = (
    "/usr/bin",
    )


# retsync plugin needs a Python interpreter to run broker and dispatcher
def get_python_interpreter():
    # when available, use spawn module to search through PATH
    if spawn_module:
        interpreter = distutils.spawn.find_executable('python')
        if interpreter:
            # discard Universal Windows Platform (UWP) directory
            parts = os.path.split(interpreter)
            if (len(parts) > 1 and parts[-2].endswith('WindowsApps')):
                rs_log("Warning, python.exe was detected but is installed as a Windows App (UWP).\n"
                       "       Dir: \"%s\"\n"
                       "       This plugin requires a Windows desktop program in order to work properly.\n"
                       "       Searching for other installations.\n" % interpreter)
            else:
                return interpreter

    # otherwise, look in various known default paths
    if sys.platform == 'win32':
        PYTHON_BIN = 'python.exe'
        PYTHON_PATHS = PY_WIN_DEFAULTS

        # add paths from %LOCALAPPDATA%
        localpaths = tuple([os.path.expandvars(pp) for pp in PY_WIN_LOCAL_DEFAULTS])
        PYTHON_PATHS = PYTHON_PATHS + localpaths

    elif sys.platform.startswith('linux') or sys.platform == 'darwin':
        PYTHON_BIN = 'python'
        PYTHON_PATHS = PY_LINUX_DEFAULTS

    else:
        rs_log("plugin initialization failed: unknown platform \"%s\"\n"
               "       please fix PYTHON_PATH/PYTHON_BIN in %s/rsconfig.py\n"
               % (sys.platform, PLUGIN_DIR))

        raise RuntimeError

    for pp in PYTHON_PATHS:
        interpreter = os.path.realpath(os.path.normpath(os.path.join(pp, PYTHON_BIN)))
        if os.path.exists(interpreter):
            return interpreter

    rs_log("plugin initialization failed: Python interpreter not found\n"
           "       please fix PYTHON_PATH/PYTHON_BIN in %s/rsconfig.py\n" % PLUGIN_DIR)

    raise RuntimeError
