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

import os
import sys
import tempfile
import logging
from logging.handlers import RotatingFileHandler
from collections import namedtuple

from binaryninja.highlight import HighlightColor
from binaryninja.enums import HighlightStandardColor

try:
    from ConfigParser import SafeConfigParser
except ImportError:
    from configparser import ConfigParser as SafeConfigParser


# networking settings
HOST = 'localhost'
PORT = 9100

CB_TRACE_COLOR = HighlightColor(HighlightStandardColor.GreenHighlightColor, alpha=192)

# encoding settings (for data going in/out the plugin)
RS_ENCODING = 'utf-8'

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
    'lldb': {
        'prefix': '',
        'si': 'si',
        'so': 'ni',
        'go': 'continue',
        'run': 'run',
        'bp': 'b *',
        'hbp': 'xxx',
        'bp1': 'tb *',
        'hbp1': 'xxx'},
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
        'prefix': '!',
        'si': 'sti',
        'so': 'sto',
        'go': 'go',
        'bp': 'bp ',
        'hbp': 'bph ',
        'bp1': 'bp ',
        'hbp1': 'bph ',
        'oneshot_post': ',ss'},
}


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


def rs_encode(buffer_str):
    return buffer_str.encode(RS_ENCODING)


def rs_decode(buffer_bytes):
    return buffer_bytes.decode(RS_ENCODING)


def rs_log(s, lvl=logging.INFO):
    if lvl >= LOG_LEVEL:
        print("[%s] %s" % (LOG_PREFIX, s))


def load_configuration(pgm_path, name=None):
    user_conf = namedtuple('user_conf', 'host port alias path')
    host, port, alias, path = HOST, PORT, None, None

    for loc in (pgm_path, 'USERPROFILE', 'HOME'):
        if loc in os.environ:
            confpath = os.path.join(os.path.realpath(os.environ[loc]), '.sync')

            if os.path.exists(confpath):
                config = SafeConfigParser({'host': HOST, 'port': PORT})
                config.read(confpath)

                if config.has_section('INTERFACE'):
                    host = config.get('INTERFACE', 'host')
                    port = config.getint('INTERFACE', 'port')

                if name and config.has_option('ALIASES', name):
                    alias_ = config.get('ALIASES', name)
                    if alias_ != "":
                        alias = alias_

                path = confpath
                break

    return user_conf(host, port, alias, path)
