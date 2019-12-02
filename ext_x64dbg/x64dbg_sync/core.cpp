/*
Copyright (C) 2016-2019, Alexandre Gazet.

Copyright (C) 2014-2015, Quarkslab.

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

#include "core.h"
#include "pluginsdk\TitanEngine\TitanEngine.h"
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <strsafe.h>
#include "tunnel.h"

#define VERBOSE 0

// Default host value is locahost
static CHAR *g_DefaultHost = "127.0.0.1";
static CHAR *g_DefaultPort = "9100";

// Command polling feature
static HANDLE g_hPollTimer;
static HANDLE g_hPollCompleteEvent;
static CRITICAL_SECTION g_CritSectPollRelease;

// Debuggee's state;
ULONG64 g_Offset = NULL;
ULONG64 g_Base = NULL;

// Synchronisation mode
static BOOL g_SyncAuto = true;

// Buffer used to solve symbol's name
static CHAR g_NameBuffer[MAX_MODULE_SIZE];


HRESULT
LoadConfigurationFile()
{
	DWORD count = 0;
	HRESULT hRes = S_OK;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	CHAR lpProfile[MAX_PATH] = { 0 };
	LPTSTR lpConfHost = NULL;
	LPTSTR lpConfPort = NULL;

	count = GetEnvironmentVariable("userprofile", lpProfile, MAX_PATH);
	if (count == 0 || count > MAX_PATH){
		return E_FAIL;
	}

	hRes = StringCbCat(lpProfile, MAX_PATH, CONF_FILE);
	if FAILED(hRes){
		return E_FAIL;
	}

	hFile = CreateFile(lpProfile, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE){
		_plugin_logprintf("[sync] Configuration file not present, using default values\n");
		return E_FAIL;
	}

	_plugin_logprintf("[sync] Loading configuration file: \"%s\"\n", lpProfile);
	CloseHandle(hFile);

	lpConfHost = (LPTSTR)malloc(MAX_PATH);
	lpConfPort = (LPTSTR)malloc(MAX_PATH);
	if (lpConfHost == NULL || lpConfPort == NULL){
		goto failed;
	}

	count = GetPrivateProfileString("INTERFACE", "host", "127.0.0.1", lpConfHost, MAX_PATH, lpProfile);
	if ((count > 0) && (count < (MAX_PATH - 2))){
		g_DefaultHost = lpConfHost;
		_plugin_logprintf("[sync]    -> set HOST to %s\n", g_DefaultHost);
	}

	count = GetPrivateProfileString("INTERFACE", "port", "9100", lpConfPort, MAX_PATH, lpProfile);
	if ((count > 0) && (count < (MAX_PATH - 2))) {
		g_DefaultPort = lpConfPort;
		_plugin_logprintf("[sync]    -> set PORT to %s\n", g_DefaultPort);
	}

	return hRes;

failed:
	if (lpConfHost != NULL){ free(lpConfHost); }
	if (lpConfPort != NULL){ free(lpConfPort); }

	return E_FAIL;
}


// Update state and send info to client: eip module's base address, offset, name
HRESULT
UpdateState()
{
	BOOL bRes = FALSE;
	HRESULT hRes = E_FAIL;
	DWORD dwRes = 0;
	ULONG64 PrevBase = g_Base;
	HANDLE hProcess = INVALID_HANDLE_VALUE;

	g_Offset = GetContextData(UE_CIP);

	g_Base = DbgFunctions()->ModBaseFromAddr((duint)g_Offset);
	if (!g_Base)
	{
		_plugin_logprintf("[sync] UpdateState(%p): could not get module base...\n", g_Offset);
		return hRes;
	}

#if VERBOSE >= 2
	_plugin_logprintf("[sync] UpdateState(%p): module base %p\n", g_Offset, g_Base);
#endif

	// Check if we are in a new module
	if ((g_Base != PrevBase) & g_SyncAuto)
	{
		hProcess = ((PROCESS_INFORMATION*)TitanGetProcessInformation())->hProcess;

		dwRes = GetModuleBaseNameA(hProcess, (HMODULE)g_Base, g_NameBuffer, MAX_MODULE_SIZE);
		if (dwRes==0)
		{
			_plugin_logprintf("[sync] UpdateState(%p): could not get module name...\n", g_Offset);
			return hRes;
		}

#if VERBOSE >= 2
		_plugin_logprintf("[sync] UpdateState(%p): module : \"%s\"\n", g_Offset, g_NameBuffer);
#endif

		hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", g_NameBuffer);
		if (FAILED(hRes)){

			return hRes;
		}
	}

	hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", g_Base, g_Offset);

	return hRes;
}


// Poll socket for incoming commands
HRESULT
PollCmd()
{
	BOOL bRes = FALSE;
	HRESULT hRes = S_OK;
	int NbBytesRecvd = 0;
	const int ch = 0xA;
	char *msg, *next, *orig = NULL;

	hRes = TunnelPoll(&NbBytesRecvd, &msg);

	if (SUCCEEDED(hRes) & (NbBytesRecvd > 0) & (msg != NULL))
	{
		next = orig = msg;

		while ((msg - orig) < NbBytesRecvd)
		{
			next = strchr(msg, ch);
			if (next != NULL)
				*next = 0;

			bRes = DbgCmdExec(msg);
			if (!bRes){
				dbgout("[sync] received command: %s (not yet implemented)\n", msg);
			}

			// No more command
			if (next == NULL)
				break;

			msg = next + 1;
		}

		free(orig);
	}

	return hRes;
}


void ReleasePollTimer()
{
	BOOL bRes = FALSE;
	DWORD dwErr = 0;

	EnterCriticalSection(&g_CritSectPollRelease);

#if VERBOSE >= 2
	_plugin_logputs("[sync] ReleasePollTimer called\n");
#endif

	if (!(g_hPollTimer == INVALID_HANDLE_VALUE))
	{
		ResetEvent(g_hPollCompleteEvent);
		bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
		if (!bRes)
		{
			// msdn: If the error code is ERROR_IO_PENDING, it is not necessary to
			// call this function again. For any other error, you should retry the call.
			dwErr = GetLastError();
			if (dwErr != ERROR_IO_PENDING){
				bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
				if (!bRes){
#if VERBOSE >= 2
					_plugin_logputs("[sync] ReleasePollTimer called\n");
#endif
				}

			}
		}

		g_hPollTimer = INVALID_HANDLE_VALUE;
	}

	LeaveCriticalSection(&g_CritSectPollRelease);
}


// Poll timer callback implementation: call PollCmd and set completion event
VOID
CALLBACK PollTimerCb(PVOID lpParameter, BOOL TimerOrWaitFired)
{
	HRESULT hRes;
	UNREFERENCED_PARAMETER(lpParameter);
	UNREFERENCED_PARAMETER(TimerOrWaitFired);

	hRes = PollCmd();

	// If an error occured in PollCmd() the timer callback is deleted.
	// (typically happens when client has closed the connection)
	if (FAILED(hRes)){
		ReleasePollTimer();
	}
}


// Setup poll timer callback
VOID
CreatePollTimer()
{
	BOOL bRes;

	bRes = CreateTimerQueueTimer(&g_hPollTimer, NULL, (WAITORTIMERCALLBACK)PollTimerCb,
		NULL, TIMER_PERIOD, TIMER_PERIOD, WT_EXECUTEINTIMERTHREAD);

	if (!(bRes)){
		_plugin_logputs("[sync] failed to CreatePollTimer\n");
	}
}


// sync command implementation
HRESULT sync(PSTR Args)
{
	HRESULT hRes = S_OK;

	// Reset global state
	g_Base = NULL;
	g_Offset = NULL;

	if (g_Synchronized)
	{
		_plugin_logputs("[sync] sync update\n");
		UpdateState();
		goto Exit;
	}

	if (FAILED(hRes = TunnelCreate(g_DefaultHost, g_DefaultPort)))
	{
		_plugin_logputs("[sync] sync failed\n");
		goto Exit;
	}

	_plugin_logputs("[sync] probing connection\n");

	hRes = TunnelSend("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - x64_dbg\",\"dialect\":\"x64_dbg\"}\n");
	if (FAILED(hRes))
	{
		_plugin_logputs("[sync] probe failed, is IDA/Ghidra plugin listening?\n");
		goto Exit;
	}

	_plugin_logprintf("[sync] sync is now enabled with host %s\n", g_DefaultHost);
	UpdateState();
	CreatePollTimer();

Exit:

	return hRes;
}


// syncoff command implementation
HRESULT syncoff()
{
	HRESULT hRes = S_OK;

	if (!g_Synchronized){
		return hRes;
	}

	ReleasePollTimer();
	hRes = TunnelClose();
	_plugin_logputs("[sync] sync is now disabled\n");

	return hRes;
}


extern "C" __declspec(dllexport) void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
	_plugin_logprintf("[sync] debugging of file %s started!\n", (const char*)info->szFileName);
}


extern "C" __declspec(dllexport) void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{

#if VERBOSE >= 2
	_plugin_logputs("[sync] debugging stopped!");
#endif
	syncoff();
}


extern "C" __declspec(dllexport) void CBPAUSEDEBUG(CBTYPE cbType, PLUG_CB_PAUSEDEBUG* info)
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] debugging paused!");
#endif

	if (SUCCEEDED(TunnelIsUp()))
	{
		UpdateState();
		CreatePollTimer();
	}

}


extern "C" __declspec(dllexport) void CBRESUMEDEBUG(CBTYPE cbType, PLUG_CB_RESUMEDEBUG* info)
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] debugging resumed!");
#endif

	ReleasePollTimer();
}


extern "C" __declspec(dllexport) void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
{
	if (info->DebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
	{
		//_plugin_logprintf("[sync] DebugEvent->EXCEPTION_DEBUG_EVENT->%.8X\n", info->DebugEvent->u.Exception.ExceptionRecord.ExceptionCode);
	}
}


extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	switch (info->hEntry)
	{
	case MENU_ENABLE_SYNC:
	{
		_plugin_logputs("[sync] enable sync");
		sync(NULL);
	}
	break;

	case MENU_DISABLE_SYNC:
	{
		_plugin_logputs("[sync] disable sync");
		syncoff();
	}
	break;

	break;
	}
}


static bool cbSyncCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] sync command!");
	sync(NULL);
	return true;
}


static bool cbSyncoffCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] syncoff command!");
	syncoff();
	return true;
}


void coreInit(PLUG_INITSTRUCT* initStruct)
{
	// register commands
#if VERBOSE >= 2
	_plugin_logprintf("[sync] pluginHandle: %d\n", pluginHandle);
#endif

	if (!_plugin_registercommand(pluginHandle, "!sync", cbSyncCommand, false))
		_plugin_logputs("[sync] error registering the \"!sync\" command!");

	if (!_plugin_registercommand(pluginHandle, "!syncoff", cbSyncoffCommand, true))
		_plugin_logputs("[sync] error registering the \"!syncoff\" command!");

	// initialize globals
	g_Synchronized = FALSE;

	g_hPollCompleteEvent = CreateEvent(NULL, true, false, NULL);
	if (g_hPollCompleteEvent == NULL)
	{
		_plugin_logputs("[sync] Command polling feature init failed\n");
		return;
	}

	InitializeCriticalSection(&g_CritSectPollRelease);

	if (SUCCEEDED(LoadConfigurationFile())){
		_plugin_logprintf("[sync] Configuration file loaded\n");
	}
}


void coreStop()
{
	// close tunnel and release objects
	ReleasePollTimer();
	TunnelClose();
	DeleteCriticalSection(&g_CritSectPollRelease);
	CloseHandle(g_hPollCompleteEvent);

	// unregister plugin's commands and menu entries
	_plugin_unregistercommand(pluginHandle, "!sync");
	_plugin_unregistercommand(pluginHandle, "!syncoff");
	_plugin_menuclear(hMenu);
}


void coreSetup()
{
	_plugin_menuaddentry(hMenu, MENU_ENABLE_SYNC, "&Enable sync");
	_plugin_menuaddentry(hMenu, MENU_DISABLE_SYNC, "&Disable sync");
}
