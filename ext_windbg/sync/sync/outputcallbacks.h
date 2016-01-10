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

/*
 Based on out.cpp from WinDDK's dumpstk sample
*/

#define MAX_CMD  8192
#define CB_OUTPUTCTRL DEBUG_OUTCTL_THIS_CLIENT
#define CB_FLAGS DEBUG_EXECUTE_ECHO | DEBUG_EXECUTE_NO_REPEAT

class StdioOutputCallbacks : public IDebugOutputCallbacks
{
public:
    // IUnknown.
    STDMETHOD(QueryInterface)(
        THIS_
        IN REFIID InterfaceId,
        OUT PVOID* Interface
        );
    STDMETHOD_(ULONG, AddRef)(
        THIS
        );
    STDMETHOD_(ULONG, Release)(
        THIS
        );

    // IDebugOutputCallbacks.
    STDMETHOD(Output)(
        THIS_
        IN ULONG Mask,
        IN PCSTR Text
        );
};


typedef struct _CMD_BUFFER
{
    HRESULT hRes;
    size_t  len;
    CHAR    buffer[MAX_CMD];
} CMD_BUFFER, *PCMD_BUFFER;

extern StdioOutputCallbacks g_OutputCb;
extern bool g_OutputCbLocal;
extern CMD_BUFFER g_CmdBuffer;
