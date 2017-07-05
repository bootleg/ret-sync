/*
Copyright (C) 2016, Alexandre Gazet.

Copyright (C) 2012-2014, Quarkslab.

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

extern BOOL g_Synchronized;

extern void dbgout(char *fmt, ...);

extern void dbgoutW(wchar_t* fmt, ...);

HRESULT TunnelIsUp();

HRESULT TunnelCreate(PCSTR Host, PCSTR Port);

HRESULT TunnelClose();

HRESULT TunnelPoll(int *lpNbBytesRecvd, LPSTR *lpBuffer);

HRESULT TunnelReceive(int *lpNbBytesRecvd, LPSTR *lpBuffer);

HRESULT TunnelSend(PCSTR Format, ...);

HRESULT ToBase64(const BYTE *pbBinary, DWORD cbBinary, LPSTR *pszString);

HRESULT FromBase64(LPSTR pszString, BYTE **ppbBinary);

HRESULT WsaErrMsg(int LastError);

HRESULT convert_tow(const char * mbstr,  PTCH *wcstr);
