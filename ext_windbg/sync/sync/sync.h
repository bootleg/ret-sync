/*
Copyright (C) 2016, Alexandre Gazet.

Copyright (C) 2012-2015, Quarkslab.

This file is part of ret-sync.

ret-sync is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _WINSOCKAPI_

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KDEXT_64BIT
#include <wdbgexts.h>
#include <dbgeng.h>

#ifdef __cplusplus
extern "C" {
#endif


#define INIT_API()                             \
    HRESULT Status;                            \
    if ((Status = ExtQuery(Client)) != S_OK) return Status;

#define EXT_RELEASE(Unk) \
    ((Unk) != NULL ? ((Unk)->Release(), (Unk) = NULL) : NULL)

#define EXIT_API     ExtRelease

// Extension information
#define EXT_MAJOR_VER    1
#define EXT_MINOR_VER    0

// Global variables initialized by query
extern PDEBUG_CLIENT4        g_ExtClient;
extern PDEBUG_CONTROL        g_ExtControl;
extern PDEBUG_SYMBOLS3       g_ExtSymbols;
extern PDEBUG_REGISTERS      g_ExtRegisters;

extern ULONG64 g_Offset, g_Base;

HRESULT
ExtQuery(PDEBUG_CLIENT4 Client);

void
ExtRelease(void);

HRESULT
NotifyOnTargetAccessible(PDEBUG_CONTROL Control);

#ifdef __cplusplus
}
#endif
