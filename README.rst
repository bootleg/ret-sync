
ret-sync
========

**ret-sync** stands for Reverse-Engineering Tools SYNChronization. It is a set
of plugins that help to synchronize a debugging session
(WinDbg/GDB/LLDB/OllyDbg/OllyDbg2/x64dbg) with IDA/Ghidra disassemblers. The
underlying idea is simple: take the best from both worlds (static and dynamic
analysis).

Debuggers and dynamic analysis provide us with:

* local view, with live dynamic context (registers, memory, *etc.*)
* built-in specialized features/API (ex: WinDbg's ``!peb``, ``!drvobj``, ``!address``, *etc.*)


Disassemblers and static analysis provide us with:

* macro view over modules
* code analysis, signatures, types, *etc.*
* fancy graph view
* decompilation
* persistent storage of knowledge within IDBs/GPRs


Key features:

* Pass data (comment, command output) from debugger to disassembler
* Multiple IDBs can be synced at the same time allowing to easily trace through multiple modules
* No need to deal with ASLR, addresses are rebased on-the-fly
* Disassembler and debugger can be on different hosts


**ret-sync** is a fork of `qb-sync <https://github.com/quarkslab/qb-sync>`_ that I developed and maintained during my stay at `Quarkslab <http://www.quarkslab.com>`_.


Below we detail most of the commands for IDA/Windbg but most concepts apply to all debuggers so
please read the WinDbg section first even if you want to work with other debuggers.


Content
-------

- ``ext_ida`` : IDA plugin
- ``ext_windbg/sync``: WinDbg extension source files, once built: ``sync.dll``
- ``ext_gdb/sync.py``: GDB plugin
- ``ext_lldb/sync.py``: LLDB plugin
- ``ext_olly1``: OllyDbg 1.10 plugin
- ``ext_olly2``: OllyDbg v2 plugin
- ``ext_x64dbg``: x64dbg plugin
- ``ext_ghidra``: Ghidra plugin



Prerequisites
-------------

IDA 7.x branch is required. For older versions (6.9x) please see archived
release ``ida6.9x``.

A development environment (preferably Visual Studio 2017) is required
to build the WinDbg extension (see "**Build it**" section).

Python is required by various scripts. ``argparse`` is
included in Python standard libraries for release >= 2.7.
Python 2 and Python 3 are supported.



Binary release
--------------

Pre-built binaries for WinDbg/OllyDbg/OllyDbg2/x64dbg debuggers are proposed
through an ``Azure DevOps`` pipeline: |Build Status| . Simply select the last
build and check the ``Artifacts`` button.

.. |Build Status| image:: https://dev.azure.com/bootlegdev/ret-sync-release/_apis/build/status/ret-sync-release-CI?branchName=master
   :target: https://dev.azure.com/bootlegdev/ret-sync-release/_build/latest?definitionId=8?branchName=master



Configuration file
------------------

Extensions/plugins check for a configuration file named ``.sync`` in the user's
home directory. (The IDA plugin also looks for the configuration file in the
IDB's directory first to allow per-IDB settings). Please note, this file is not
created by default.

Values declared in this file override default values. This file must be a valid
``.ini`` file. It can be used to customize some settings, especially network
related settings through the ``[INTERFACE]`` section.

To illustrate its use with a scenario, let's suppose one wants to synchronize
IDA with a debugger running inside a virtual machine (or simply another host),
common remote kernel debugging scenario.

Simply create a ``.sync`` file on the IDA side **and** on the debugger side (in
the user's home directory for example) with the following content:

::

    [INTERFACE]
    host=192.168.128.1
    port=9234


It tells **ret-sync** ``IDA`` plugin to listen on the interface
``192.168.128.1`` with port ``9234``, and to the debugger plugin to connect to
this host/port.



IDA global shortcuts
--------------------

**ret-sync** defines these global shortcuts in IDA:

* ``Alt-Shift-S``  - Run ret-sync plugin
* ``Ctrl-Shift-S``  - Toggle global syncing
* ``Ctrl-H``  - Toggle Hex-Rays syncing

Two buttons are also available in the Debug toolbar to toggle global and
Hex-Rays syncing.



Getting started
---------------

Quick-start to set up IDA/Windbg syncing.


Build it
++++++++

For Windbg, either use pre-built binaries or use the Visual Studio 2017
solution provided in ``ext_windbg``, (see
https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes if
needed).


Install it
++++++++++

For Windbg, copy the built extension (``sync.dll``) into the plugin directory (be
careful of ``x86``/``x64`` versions), for example:

* ``C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext``


For IDA, copy ``Syncplugin.py`` and ``retsync`` folder from ``ext_ida`` to IDA
plugins directory, for example:

* ``C:\Program Files\IDA Pro 7.4\plugins``
* ``%APPDATA%\Hex-Rays\IDA Pro\plugins``
* ``~/.idapro/plugins``


Use it
++++++

0. If necessary, create ``.sync`` configuration files.

1. Open IDB

2. Run the plugin in IDA (``Alt-Shift-S``) or ``Edit`` -> ``Plugins`` -> ``ret-sync``::

    [sync] form create
    [sync] default idb name: target.bin
    [*] sync enabled
    [*] init_broker
    [*] cmdline: "C:\Python27\python.exe" -u "C:\Program Files\IDA Pro 7.3\plugins\retsync\broker.py" --idb "target.bin"
    [sync] name target.bin
    [sync] module base 0x0
    [sync] hexrays #7.3.0.190610 found
    [*] broker new state: Starting
    [*] broker new state: Running
    [*] broker started
    [*] << broker << dispatcher not found, trying to run it
    [*] << broker << dispatcher now runs with pid: 14568
    [*] << broker << connected to dispatcher
    [*] << broker << listening on port 63898
    [*] << broker << dispatcher msg: add new client (listening on port 63898), nb client(s): 1


3. Launch WinDbg on target

4. Load extension (``.load`` command)::

    0:000> .load sync
    [sync.dll] DebugExtensionInitialize, ExtensionApis loaded


5. Sync WinDbg::

      0:000> !sync
      [sync] No argument found, using default host (127.0.0.1:9100)
      [sync] sync success, sock 0x5a8
      [sync] probing sync
      [sync] sync is now enabled with host 127.0.0.1

   In IDA's Output window::

      [*] << broker << dispatcher msg: add new client (listening on port 63898), nb client(s): 1
      [*] << broker << dispatcher msg: new debugger client: dbg connect - HostMachine\HostUser
      [sync] set debugger dialect to windbg, enabling hotkeys


   If Windbg's current module matches IDA file name::

      [sync] idb is enabled with the idb client matching the module name.


6. IDA plugin's GUI

   The ``Overwrite idb name`` input field is meant to change the default IDB name. It is
   the name that is used by the plugin to register with the dispatcher.
   IDB automatic switch is based on module name matching. In case of conflicting names
   (like a ``foo.exe`` and ``foo.dll``), this can be used to ease matching.
   Please note, if you modify the input field while the sync is active, you have to re-register
   with the dispatcher; this can be done simply by using the "``Restart``" button.

   Please note that it is possible to alias by default using the ``.sync`` config file::

       [<ida_root_filename>]
       name=<alias name>

   The section name is the IDB's root file name and has only one option: ``name``.


7. Use WinDbg and enjoy IDA's activity



Extra commands
++++++++++++++

* **!syncoff**

  Stop synchronization


* **!synchelp**

  Display the list of available commands with short explanation.


* **!cmt [-a address] <string>**

  Add comment at current eip in IDA::

    [WinDbg]
    0:000:x86> pr
    eax=00000032 ebx=00000032 ecx=00000032 edx=0028eebc esi=00000032 edi=00000064
    eip=00430db1 esp=0028ed94 ebp=00000000 iopl=0         nv up ei pl nz na po nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
    image00000000_00400000+0x30db1:
    00430db1 57    push    edi

    0:000:x86> dd esp 8
    0028ed94  00000000 00433845 0028eebc 00000032
    0028eda4  0028f88c 00000064 002b049e 00000110

    0:000:x86> !cmt 0028ed94  00000000 00433845 0028eebc 00000032
    [sync.dll]  !cmt called

    [IDA]
    .text:00430DB1    push    edi             ; 0028ed94  00000000 00433845 0028eebc 00000032


* **!rcmt [-a address]**

  Reset comment at current ip in IDA::

    [WinDbg]
    0:000:x86> !rcmt
    [sync] !rcmt called

    [IDA]
    .text:00430DB1    push    edi


* **!fcmt [-a address] <string>**

  Add a function comment for function in which current ip is located::

    [WinDbg]
    0:000:x86> !fcmt decodes buffer with key
    [sync] !fcmt called

    [IDA]
    .text:004012E0 ; decodes buffer with key
    .text:004012E0                 public decrypt_func
    .text:004012E0 decrypt_func    proc near
    .text:004012E0                 push    ebp

  Note: calling this command without argument reset the function's comment.

* **!raddr <expression>**

  Add a comment with rebased address evaluated from expression

* **!rln <expression>**

  Get symbol from the IDB for the given address

* **!lbl [-a address] <string>**

  Add a label name at current ip in IDA::

    [WinDbg]
    0:000:x86> !lbl meaningful_label
    [sync] !lbl called

    [IDA]
    .text:000000000040271E meaningful_label:
    .text:000000000040271E    mov     rdx, rsp

* **!cmd <string>**

  Execute a command in WinDbg and add its output as comment at current eip in IDA::

    [WinDbg]
    0:000:x86> pr
    eax=00000032 ebx=00000032 ecx=00000032 edx=0028eebc esi=00000032 edi=00000064
    eip=00430db1 esp=0028ed94 ebp=00000000 iopl=0         nv up ei pl nz na po nc
    cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
    image00000000_00400000+0x30db1:
    00430db1 57     push    edi
    [sync.dll]  !cmd r edi

    [IDA]
    .text:00430DB1    push    edi             ; edi=00000064


* **!bc <||on|off|set 0xBBGGRR>**

  Enable/disable path coloring in IDA. This is NOT a code tracing tool,
  there are efficient tools for that. Each manually stepped instruction is
  colored in the graph. Color a single instruction at current eip if called
  without argument.
  "set" argument is used to set path color with a new hex rgb code (reset color
  if called with a value > 0xFFFFFF).


* **!idblist**

  Get list of all IDB clients connected to the dispatcher::

    [WinDbg]
    0:000> !idblist
    > currently connected idb(s):
        [0] target.exe

* **!syncmodauto <on|off>**

  Enable/disable IDB auto switch based on module name::

    [WinDbg]
    0:000> !syncmodauto off

    [IDA]
    [*] << broker << dispatcher msg: sync mode auto set to off


* **!idbn <n>**

  Set active IDB to the nth client. n should be a valid decimal value.
  This is a semi-automatic mode (personal tribute to the tremendous jj)::

    [WinDbg]
    0:000:> !idbn 0
    > current idb set to 0

  In this example, current active IDB client would have been set to::

	[0] target.exe.


* **!jmpto <expression>**

  Expression given as argument is evaluated in the context of the current debugger's status.
  IDA's view is then synced with the resulting address if a matching module is registered.
  Can be seen as a manual syncing, relocation is automatically performed, on the fly.
  Especially useful for randomly relocated binary.


* **!jmpraw <expression>**

  Expression given as argument is evaluated in the context of the current debugger's status.
  If an IDB is enabled then IDA's view is synced with the resulting address. Address is not rebased
  and there is no IDB switching.
  Especially useful for dynamically allocated/generated code.

* **!modmap <base> <size> <name>**

  A synthetic ("faked") module (defined using its base address and size) is added to the debugger internal list.
  From msdn: "If all the modules are reloaded - for example, by calling Reload with the Module parameter set to an empty string - all synthetic modules will be discarded."
  It can be used to more easily debug dynamically allocated/generated code.

* **!modunmap <base>**

  Remove a previously mapped synthetic module at base address.

* **!modcheck <||md5>**

  Use to check if current module really matches IDB's file (ex: module has been updated)
  When called without an argument, pdb's GUID from Debug Directory is used. It can alternatively use md5,
  but only with a local debuggee (not in remote kernel debugging).

* **!bpcmds <||save|load|>**

  **bpcmds** wrapper, save and reload **.bpcmds** (breakpoints commands list) output to current IDB.
  Display (but not execute) saved data if called with no argument.
  Persistent storage is achieved using IDA's netnode feature.

* **!ks**

  This command is a DML enhanced output of **kv** command. Code Addresses are clickable (**!jmpto**) as well as data addresses (**dc**).

* **!translate <base> <addr> <mod>**

  Meant to be used from IDA (``Alt-F2`` shortcut), rebase an address with respect to its module's name and offset.


Address optional argument
+++++++++++++++++++++++++

**!cmt**, **!rcmt** and **!fcmt** commands support an optional address option: ``-a`` or ``--address``.
Address should be passed as an hexadecimal value. Command parsing is based on python's
``argparse`` module. To stop line parsing use ``--``.::

    [WinDbg]
    0:000:x86> !cmt -a 0x430DB2 comment

The address has to be a valid instruction's address.



IDA bindings over WinDbg commands:
++++++++++++++++++++++++++++++++++

``Syncplugin.py`` also registers WinDbg command wrapper hotkeys.

* ``F2`` - Set breakpoint at cursor address
* ``F3`` - Set one-shot breakpoint at cursor address
* ``Ctrl-F2`` - Set hardware breakpoint at cursor address
* ``Ctrl-F3`` - Set one-shot hardware breakpoint at cursor address
* ``Alt-F2`` - Translate (rebase in debugger) current cursor address
* ``Alt-F5`` - Go
* ``F10`` - Single step
* ``F11`` - Single trace

These commands are only available when the current IDB is active. When
possible they have also been implemented for others debuggers.



Ghidra
------

Ghidra is a software reverse engineering (SRE) suite of tools developed by
NSA's Research Directorate, it can be used alternatively or in complement with
IDA.

``ext_ghidra`` is a server extension as ``ext_ida``. It uses the same ``.sync``
configuration files and implements the same protocol, thus all the debugger
extensions (WinDbg/GDB/LLDB/OllyDbg/OllyDbg2/x64dbg) are compatible.

1. Compile the extension or copy ``ZIP`` from ``ext_ghidra/dist`` to ``$GHIDRA_DIR/Extensions/Ghidra/``
2. From Ghidra projects manager: ``File`` -> ``Install Extensions...``
3. Use toolbar icons or shortcuts to enable (``Alt+s``)/disable (``Alt+Shift+s``)/restart (``Alt+r``)
   synchronization.

A status window is also available from ``CodeBrowser`` tool: ``Windows`` -> ``RetSyncPlugin``.

Bindings over debugger commands are also implemented. They are very similar to
the ones from IDA's extension.

* ``F2`` - Set breakpoint at cursor address
* ``Ctrl-F2`` - Set hardware breakpoint at cursor address
* ``Alt-F3`` - Set one-shot breakpoint at cursor address
* ``Ctrl-F3`` - Set one-shot hardware breakpoint at cursor address
* ``Alt-F2`` - Translate (rebase in debugger) current cursor address
* ``F5`` - Go
* ``F10`` - Single step
* ``F11`` - Single trace


GNU gdb (GDB)
-------------

GDB has also been heavily tested. We only describe a subset of the
capabilities. Refer to WinDbg commands for a more complete description of what
is supported.

Use it
++++++

0. Load extension (see auto-load-scripts)::

    gdb> source sync.py
    [sync] configuration file loaded 192.168.52.1:9100
    [sync] commands added


1. Sync with host::

    gdb> sync
    [sync] sync is now enabled with host 192.168.52.1
    <not running>

    gdb> r
    Starting program: /bin/ls
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/libthread_db.so.1".

2. Use commands, **without "!" prefix**::

    (gdb) cmd x/i $pc
    [sync] command output: => 0x8049ca3:    push   edi

    (gdb) synchelp
    [sync] extension commands help:
     > sync <host>
     > syncoff
     > cmt [-a address] <string>
     > rcmt [-a address] <string>
     > fcmt [-a address] <string>
     > cmd <string>
     > bc <on|off|>
     > rln <address>
     > bbt <symbol>
     > patch <addr> <count> <size>
     > bx /i <symbol>
     > cc
     > translate <base> <addr> <mod>

* **rln**

  Get symbol from the IDB for the given address

* **bbt**

  Beautiful backtrace. Similar to **bt** but requests symbols from IDA::

    (gdb) bt
    #0  0x0000000000a91a73 in ?? ()
    #1  0x0000000000a6d994 in ?? ()
    #2  0x0000000000a89125 in ?? ()
    #3  0x0000000000a8a574 in ?? ()
    #4  0x000000000044f83b in ?? ()
    #5  0x0000000000000000 in ?? ()
    (gdb) bbt
    #0 0x0000000000a91a73 in IKE_GetAssembledPkt ()
    #1 0x0000000000a6d994 in catcher ()
    #2 0x0000000000a89125 in IKEProcessMsg ()
    #3 0x0000000000a8a574 in IkeDaemon ()
    #4 0x000000000044f83b in sub_44F7D0 ()
    #5 0x0000000000000000 in  ()

* **patch**

  Patch bytes in IDA based on live context

* **bx**

  Beautiful display. Similar to **x** but using a symbol. The symbol will be resolved by IDA.

* **cc**

  Continue to cursor in IDA. This is an alternative to using ``F3`` to set a one-shot breakpoint and ``F5``
  to continue. This is useful if you prefer to do it from gdb::

    (gdb) b* 0xA91A73
    Breakpoint 1 at 0xa91a73
    (gdb) c
    Continuing.

    Breakpoint 1, 0x0000000000a91a73 in ?? ()
    (gdb) cc
    [sync] current cursor: 0xa91a7f
    [sync] reached successfully
    (gdb)


Override PID, memory mappings
+++++++++++++++++++++++++++++

In some scenarios, such as debugging embedded devices over serial or raw
firmware in QEMU, gdb is not aware of the PID and cannot access
``/proc/<pid>/maps``.

In these cases, it is possible to pass a custom context to the plugin through
the ``INIT`` section of the ``.sync`` configuration file. It allows overriding
some fields such as the PID and memory mappings.

``.sync`` content extract::

    [INIT]
    context = {
          "pid": 200,
          "mappings": [ [0x400000, 0x7A81158, 0x7681158, "asav941-200.qcow2|lina"] ]
      }


Each entry in the mappings is: ``mem_base``, ``mem_end``, ``mem_size``, ``mem_name``.



LLDB
----

LLDB support is experimental, however:

0. Load extension (can also be added in ``~/.lldbinit``)::

    lldb> command script import sync

1. Sync with host::

    lldb> process launch -s
    lldb> sync
    [sync] connecting to localhost
    [sync] sync is now enabled with host localhost
    [sync] event handler started

2. Use commands::

    lldb> synchelp
    [sync] extension commands help:
     > sync <host>                   = synchronize with <host> or the default value
     > syncoff                       = stop synchronization
     > cmt <string>                  = add comment at current eip in IDA
     > rcmt <string>                 = reset comments at current eip in IDA
     > fcmt <string>                 = add a function comment for 'f = get_func(eip)' in IDA
     > cmd <string>                  = execute command <string> and add its output as comment at current eip in IDA
     > bc <on|off|>                  = enable/disable path coloring in IDA
                                       color a single instruction at current eip if called without argument
    lldb> cmt mooo


OllyDbg 1.10
------------

OllyDbg 1.10 support is experimental, however:

0. Build the plugin using the VS solution
1. Copy the dll within OllyDbg's plugin directory
2. Use Plugins menu or shortcuts to enable (``Alt+s``)/disable (``Alt+u``)
   synchronization.


OllyDbg2
--------

OllyDbg2 support is experimental, however:

0. Build the plugin using the VS solution
1. Copy the dll within OllyDbg2's plugin directory
2. Use Plugins menu or shortcuts to enable (``Ctrl+s``)/disable (``Ctrl+u``)
   synchronization.

Due to the beta status of OllyDbg2 API, only the following features have been implemented:

- Graph sync [use ``F7``; ``F8`` for stepping]
- Comment   [use ``CTRL+;``]
- Label     [use ``CTRL+:``]


x64dbg
-------

Based on testplugin,  https://github.com/x64dbg/testplugin. x64dbg support is experimental, however:

0. Build the plugin using the VS solution

   May you need a different version of the plugin sdk,
   a copy can be found in each release of x64dbg.

   Paste the "``pluginsdk``" directory into "``ext_x64dbg\x64dbg_sync``"

1. Copy the dll (extension is ``.d32`` or ``.dp64``) within x64dbg's plugin directory.

2. Use commands to enable ("``!sync"``) or disable ("``!syncoff``") synchronization.

Extend
------

While mostly focus on dynamic analysis, it is of-course possible to use other tools, see:

- http://blog.tetrane.com/2015/02/reven-in-your-toolkit.html


TODO
-----

- Sure.


KNOWN BUGS/LIMITATIONS
-----------------------

- Tested with Python 2.7/3.7, IDA 7.4 (Windows, Linux and Mac OS X), Ghidra 9.1, GNU gdb (GDB) 7.4.1 (Debian), lldb 310.2.37.
- **THERE IS NO AUTHENTICATION/ENCRYPTION** whatsoever between the parties; you're on your own.
- Self modifying code is out of scope.

With GDB:

- it seems that stop event is not called when using 'return' command.
- multi-threading debugging have issues with signals.

With WinDbg:

- IDA's client plugin gets notified even though encountered breakpoint
  uses a command string that makes it continue ('``g``'). This can cause major slow-down
  if there are too much of these events. A limited fix has been implemented, the
  best solution is still to sync off temporarily.
- Possible race condition

With IDA:

- Graph window redrawing is quite slow for big graphs.
- **ret-sync** shortcuts conflicts in Linux environments.


LICENSE
-------

**ret-sync** is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/.


GREETZ
------

Hail to Bruce Dang, StalkR, @Ivanlef0u, Damien Aumaître, Sébastien Renaud and
Kévin Szkudlapski, @_m00dy_, @saidelike, Xavier Mehrenberger, ben64, Raphaël
Rigo for their kindness, help, feedbacks and thoughts. Ilfak Guilfanov and
Igor Skochinsky for their help with IDA's internals and outstanding support.
