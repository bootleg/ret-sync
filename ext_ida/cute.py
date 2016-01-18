'''
Cute - a crossQt compatibility module for IDAPython.

Feel free to copy this code into your own projects.

Latest version can be found at https://github.com/tmr232/Cute



The MIT License (MIT)

Copyright (c) 2015 Tamir Bahar

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
'''
import os
import sys

import idaapi

# This nasty piece of code is here to force the loading of IDA's PySide.
# Without it, Python attempts to load PySide from the site-packages directory,
# and failing, as it does not play nicely with IDA.
old_path = sys.path[:]
try:
    ida_python_path = os.path.dirname(idaapi.__file__)
    sys.path.insert(0, ida_python_path)
    if idaapi.IDA_SDK_VERSION >= 690:
        from PyQt5 import QtGui, QtCore, QtWidgets
        import sip

        use_qt5 = True
    else:
        from PySide import QtGui, QtCore
        from PySide import QtGui as QtWidgets

        use_qt5 = False
finally:
    sys.path = old_path


def connect(sender, signal, callback):
    '''Connect a signal.
    Use this function only in cases where code should work with both Qt5 and Qt4, as it is an ugly hack.
    Args:
        sender: The Qt object emitting the signal
        signal: A string, containing the signal signature (as in Qt4 and PySide)
        callback: The function to be called upon receiving the signal
    '''
    if use_qt5:
        return getattr(sender, signal.split('(', 1)[0]).connect(callback)
    else:
        return sender.connect(QtCore.SIGNAL(signal), callback)

def disconnect(sender, signal, callback):
    '''Disconnect a signal.
    Use this function only in cases where code should work with both Qt5 and Qt4, as it is an ugly hack.
    Args:
        sender: The Qt object emitting the signal
        signal: A string, containing the signal signature (as in Qt4 and PySide)
        callback: The function to be called upon receiving the signal
    '''
    if use_qt5:
        return getattr(sender, signal.split('(', 1)[0]).disconnect(callback)
    else:
        return sender.disconnect(QtCore.SIGNAL(signal), callback)


def form_to_widget(tform):
    '''Get the tform's widget.
    IDA has two different form-to-widget functions, one for PyQt and one for PySide.
    This function uses the relevant one based on the version of IDA you are using.
    Args:
        tform: The IDA TForm to get the widget from.
    '''
    class Ctx(object):
        QtGui = QtGui
        if use_qt5:
            QtWidgets = QtWidgets
            sip = sip

    if use_qt5:
        return idaapi.PluginForm.FormToPyQtWidget(tform, ctx=Ctx())
    else:
        return idaapi.PluginForm.FormToPySideWidget(tform, ctx=Ctx())
