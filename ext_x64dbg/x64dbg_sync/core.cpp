/*
Copyright (C) 2016-2021, Alexandre Gazet.

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
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <strsafe.h>
#include "tunnel.h"


// Default host value is locahost
static const CHAR *g_DefaultHost = "127.0.0.1";
static const CHAR *g_DefaultPort = "9100";

// Command polling feature
static HANDLE g_hPollTimer = INVALID_HANDLE_VALUE;
static HANDLE g_hSyncTimer = INVALID_HANDLE_VALUE;
static HANDLE g_hPollCompleteEvent = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_CritSectPollRelease;

// Debuggee's state;
ULONG_PTR g_Offset = NULL;
ULONG_PTR g_Base = NULL;
REGDUMP regs;

// Synchronisation mode
static BOOL g_SyncAuto = true;

// Buffer used to solve symbol's name
static CHAR g_NameBuffer[MAX_MODULE_SIZE];

// Buffer used generate commands
static CHAR g_CommandBuffer[MAX_COMMAND_LINE_SIZE];


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
	if (count == 0 || count > MAX_PATH) {
		return E_FAIL;
	}

	hRes = StringCbCat(lpProfile, MAX_PATH, CONF_FILE);
	if FAILED(hRes) {
		return E_FAIL;
	}

	hFile = CreateFile(lpProfile, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		_plugin_logprintf("[sync] Configuration file not present, using default values\n");
		return E_FAIL;
	}

	_plugin_logprintf("[sync] Loading configuration file: \"%s\"\n", lpProfile);
	CloseHandle(hFile);

	lpConfHost = (LPTSTR)malloc(MAX_PATH);
	lpConfPort = (LPTSTR)malloc(MAX_PATH);
	if (lpConfHost == NULL || lpConfPort == NULL) {
		goto failed;
	}

	count = GetPrivateProfileString("INTERFACE", "host", "127.0.0.1", lpConfHost, MAX_PATH, lpProfile);
	if ((count > 0) && (count < (MAX_PATH - 2))) {
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
	if (lpConfHost != NULL) { free(lpConfHost); }
	if (lpConfPort != NULL) { free(lpConfPort); }

	return E_FAIL;
}


// mimic IDebugRegisters::GetInstructionOffset
// returns the location of the current thread's current instruction.
HRESULT 
GetInstructionOffset(ULONG_PTR *cip)
{
	bool bRes = FALSE;
	*cip = 0;

	bRes = DbgGetRegDumpEx(&regs, sizeof(regs));
	if (!bRes) {
		_plugin_logprintf("[sync] failed to DbgGetRegDumpEx\n");
		return E_FAIL;
	}

	*cip = regs.regcontext.cip;
	return S_OK;
}


// Update state and send info to client: eip module's base address, offset, name
HRESULT
UpdateState()
{
	HRESULT hRes = E_FAIL;
	DWORD dwRes = 0;
	ULONG_PTR PrevBase = g_Base;
	HANDLE hProcess = INVALID_HANDLE_VALUE;

	hRes = GetInstructionOffset(&g_Offset);
	if (FAILED(hRes))
		goto UPDATE_FAILURE;

	g_Base = DbgFunctions()->ModBaseFromAddr((duint)g_Offset);
	if (!g_Base)
	{
		_plugin_logprintf("[sync] UpdateState(%p): could not get module base...\n", g_Offset);
		goto UPDATE_FAILURE;
	}

#if VERBOSE >= 2
	_plugin_logprintf("[sync] UpdateState(%p): module base %p\n", g_Offset, g_Base);
#endif

	// Check if we are in a new module
	if ((g_Base != PrevBase) && g_SyncAuto)
	{
		hProcess = DbgGetProcessHandle();

		dwRes = GetModuleBaseNameA(hProcess, (HMODULE)g_Base, g_NameBuffer, MAX_MODULE_SIZE);
		if (dwRes == 0)
		{
			_plugin_logprintf("[sync] UpdateState(%p): could not get module name...\n", g_Offset);
			goto UPDATE_FAILURE;
		}

#if VERBOSE >= 2
		_plugin_logprintf("[sync] UpdateState(%p): module : \"%s\"\n", g_Offset, g_NameBuffer);
#endif

		hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", g_NameBuffer);
		if (FAILED(hRes)) {
			return hRes;
		}
	}

	hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", (ULONG64)g_Base, (ULONG64)g_Offset);

	return hRes;

UPDATE_FAILURE:
	// Inform the dispatcher that an error occured in the state update
	if (g_Base != NULL)
	{
		TunnelSend("[notice]{\"type\":\"dbg_err\"}\n");
		g_Base = NULL;
	}

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

	if (SUCCEEDED(hRes) && (NbBytesRecvd > 0) && (msg != NULL))
	{
		orig = msg;

		while ((msg - orig) < NbBytesRecvd)
		{
			next = strchr(msg, ch);
			if (next != NULL)
				*next = 0;

#if VERBOSE >= 2
			_plugin_logprintf("[sync] received command : %s\n", msg);
#endif

			bRes = DbgCmdExec(msg);
			if (!bRes) {
				_plugin_logprintf("[sync] received command: %s (not yet implemented)\n", msg);
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

			if (dwErr != ERROR_IO_PENDING) {
				bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
				if (!bRes) {
#if VERBOSE >= 2
					_plugin_logputs("[sync] ReleasePollTimer failed\n");
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
	HRESULT hRes = S_FALSE;
	UNREFERENCED_PARAMETER(lpParameter);
	UNREFERENCED_PARAMETER(TimerOrWaitFired);

	// If tunnel is down, prevent callback from running
	if (FAILED(TunnelIsUp())) {
#if VERBOSE >= 2
		_plugin_logputs("[sync] PollTimerCb: tunnel is down\n");
#endif
		goto INHIBIT_TIMER_CB;
	}

	hRes = PollCmd();

	// If an error occured in PollCmd() the timer callback is deleted.
	// (typically happens when client has closed the connection)
	if (FAILED(hRes)) {
#if VERBOSE >= 2
		_plugin_logputs("[sync] PollTimerCb: PollCmd failed\n");
#endif
		goto INHIBIT_TIMER_CB;
	}

	return;

INHIBIT_TIMER_CB:
	ReleasePollTimer();
}


// Setup poll timer callback
VOID
CreatePollTimer()
{
	BOOL bRes;

	bRes = CreateTimerQueueTimer(&g_hPollTimer, NULL, (WAITORTIMERCALLBACK)PollTimerCb,
		NULL, TIMER_PERIOD, TIMER_PERIOD, WT_EXECUTEINTIMERTHREAD);

	if (!(bRes)) {
		g_hPollTimer = INVALID_HANDLE_VALUE;
		_plugin_logputs("[sync] CreatePollTimer failed\n");
	}
}


// Sync connection timer callback, run after a 1s timeout
VOID
CALLBACK SyncTimerCb(PVOID lpParameter, BOOL TimerOrWaitFired)
{
	UNREFERENCED_PARAMETER(lpParameter);
	UNREFERENCED_PARAMETER(TimerOrWaitFired);

	_plugin_logputs("[sync] detecting possible connect timeout\n");
}


// Setup poll timer callback
VOID
CreateSyncTimer()
{
	BOOL bRes;

	bRes = CreateTimerQueueTimer(&g_hSyncTimer, NULL, (WAITORTIMERCALLBACK)SyncTimerCb,
		NULL, SYNC_TIMER_DELAY, 0, WT_EXECUTEONLYONCE);

	if (!(bRes)) {
		g_hSyncTimer = INVALID_HANDLE_VALUE;
		_plugin_logputs("[sync] CreateSyncTimer failed\n");
	}
}


void ReleaseSyncTimer()
{
	BOOL bRes = FALSE;
	DWORD dwErr = 0;

#if VERBOSE >= 2
	_plugin_logputs("[sync] ReleaseSyncTimer called\n");
#endif

	if (g_hSyncTimer != INVALID_HANDLE_VALUE)
	{
		bRes = DeleteTimerQueueTimer(NULL, g_hSyncTimer, NULL);
		if (!bRes)
		{
			// msdn: If the error code is ERROR_IO_PENDING, it is not necessary to
			// call this function again. For any other error, you should retry the call.
			dwErr = GetLastError();

			if (dwErr != ERROR_IO_PENDING) {
				bRes = DeleteTimerQueueTimer(NULL, g_hSyncTimer, NULL);
				if (!bRes) {
#if VERBOSE >= 2
					_plugin_logputs("[sync] ReleaseSyncTimer failed\n");
#endif
				}
			}
		}
	}

	g_hSyncTimer = INVALID_HANDLE_VALUE;
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

	_plugin_logprintf("[sync] attempting to connect to %s:%s\n", g_DefaultHost, g_DefaultPort);

	CreateSyncTimer();

	hRes = TunnelCreate(g_DefaultHost, g_DefaultPort);
	if (FAILED(hRes))
	{
		_plugin_logputs("[sync] sync failed\n");
		ReleaseSyncTimer();
		goto Exit;
	}

	ReleaseSyncTimer();

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

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced\n");
		return hRes;
	}

	ReleasePollTimer();
	hRes = TunnelClose();
	_plugin_logputs("[sync] sync is now disabled\n");

	return hRes;
}


HRESULT synchelp()
{
	HRESULT hRes = S_OK;

	_plugin_logputs("[sync] extension commands help:\n"
		" > !sync                          = synchronize with <host from conf> or the default value\n"
		" > !syncoff                       = stop synchronization\n"
		" > !syncmodauto <on | off>        = enable / disable idb auto switch based on module name\n"
		" > !synchelp                      = display this help\n"
		" > !cmt <string>                  = add comment at current eip in IDA\n"
		" > !rcmt <string>                 = reset comments at current eip in IDA\n"
		" > !idblist                       = display list of all IDB clients connected to the dispatcher\n"
		" > !idb <module name>             = set given module as the active idb (see !idblist)\n"
		" > !idbn <n>                      = set active idb to the n_th client. n should be a valid decimal value\n"
		" > !translate <base> <addr> <mod> = rebase an address with respect to local module's base\n"
		" > !insync                        = synchronize the selected instruction block in the disassembly window.\n\n");

	return hRes;
}


HRESULT syncmodauto(PSTR Args)
{
	HRESULT hRes = S_OK;
	char* param = NULL;
	char* context = NULL;

	// strip command and trailing whitespaces
	strtok_s(Args, " ", &param);
	strtok_s(param, " ", &context);

	if (param != NULL)
	{
		if (strcmp("on", param) == 0)
		{
			g_SyncAuto = true;
			goto LBL_NOTICE;
		}
		else if (strcmp("off", param) == 0)
		{
			g_SyncAuto = false;
			goto LBL_NOTICE;
		}
	}

	_plugin_logputs("[sync] !syncmodauto parameter should be in <on|off> \n");
	return E_FAIL;

LBL_NOTICE:
	hRes = TunnelSend("[notice]{\"type\":\"sync_mode\",\"auto\":\"%s\"}\n", param);
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] !syncmodauto failed to send notice\n");
		return E_FAIL;
	}

	return hRes;
}


// idblist command implementation
HRESULT idblist()
{
	HRESULT hRes = S_OK;
	int NbBytesRecvd = 0;
	LPSTR msg = NULL;

	ReleasePollTimer();

	hRes = TunnelSend("[notice]{\"type\":\"idb_list\"}\n");
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] !idblist failed\n");
		goto RESTORE_TIMER;
	}

	hRes = TunnelReceive(&NbBytesRecvd, &msg);
	if (SUCCEEDED(hRes) && (NbBytesRecvd > 0) && (msg != NULL)) {
		_plugin_logputs(msg);
		free(msg);
	}

RESTORE_TIMER:
	CreatePollTimer();
	return hRes;
}


// insync command implementation
HRESULT InsSync()
{
	HRESULT hRes = E_FAIL;
	DWORD dwRes = 0;
	ULONG_PTR PrevBase = g_Base;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	SELECTIONDATA sel;

	hRes = GuiSelectionGet(GUI_DISASSEMBLY, &sel);
	if (FAILED(hRes))
		goto INSYNC_FAILURE;

	g_Base = DbgFunctions()->ModBaseFromAddr(sel.start);
	if (!g_Base)
	{
		_plugin_logprintf("[insync] InsSync(%p): could not get module base...\n", sel.start);
		goto INSYNC_FAILURE;
	}

#if VERBOSE >= 2
	_plugin_logprintf("[insync] InsSync(%p): module base %p\n", sel.start, g_Base);
#endif

	// Check if we are in a new module
	if ((g_Base != PrevBase) && g_SyncAuto)
	{
		hProcess = DbgGetProcessHandle();

		dwRes = GetModuleBaseNameA(hProcess, (HMODULE)g_Base, g_NameBuffer, MAX_MODULE_SIZE);
		if (dwRes == 0)
		{
			_plugin_logprintf("[insync] InsSync(%p): could not get module name...\n", sel.start);
			goto INSYNC_FAILURE;
		}

#if VERBOSE >= 2
		_plugin_logprintf("[insync] InsSync(%p): module : \"%s\"\n", sel.start, g_NameBuffer);
#endif

		hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", g_NameBuffer);
		if (FAILED(hRes)) {
			return hRes;
		}
	}

	hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", (ULONG64)g_Base, (ULONG64)sel.start);

	return hRes;

INSYNC_FAILURE:
	// Inform the dispatcher that an error occured in the instruction sync
	if (g_Base != NULL)
	{
		TunnelSend("[notice]{\"type\":\"dbg_err\"}\n");
		g_Base = NULL;
	}

	return hRes;
}


HRESULT idbn(PSTR Args)
{
	HRESULT hRes = S_OK;
	int NbBytesRecvd = 0;
	char* msg = NULL;
	char* param = NULL;
	char* img_name = NULL;
	char* context = NULL;
	ULONG_PTR modbase = NULL;

	// strip command and trailing whitespaces
	strtok_s(Args, " ", &param);
	strtok_s(param, " ", &context);

	ReleasePollTimer();

	hRes = TunnelSend("[notice]{\"type\":\"idb_n\",\"idb\":\"%s\"}\n", param);
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] !idbn failed to send notice\n");
		return E_FAIL;
	}

	hRes = TunnelReceive(&NbBytesRecvd, &msg);
	if (FAILED(hRes))
		goto DBG_ERROR;

	// check if dispatcher answered with an error message
	// e.g. "> idb_n error: index %d is invalid (see idblist)"
	if (strstr(msg, "> idb_n error:") != NULL)
	{
		_plugin_logprintf("%s\n", msg);
		goto DBG_ERROR;
	}

	strtok_s(msg, "\"", &context);
	img_name = strtok_s(NULL, "\"", &context);
	if (img_name == NULL)
	{
		_plugin_logputs("[sync] idb_n notice: invalid answser - could not extract image name\n");
		goto DBG_ERROR;
	}

	_plugin_logprintf("idbn: %s\n", img_name);

	modbase = DbgFunctions()->ModBaseFromName(img_name);
	if (!modbase)
	{
		_plugin_logprintf("[sync] idbn: ModBaseFromName(%s) failed get module base...\n", img_name);
		return E_FAIL;
	}

	_plugin_logprintf("[sync] idbn: %s at %Ix\n", img_name, modbase);

	// Send this module its remote base address
	hRes = TunnelSend("[sync]{\"type\":\"rbase\",\"rbase\":%llu}\n", (UINT64)modbase);
	if (FAILED(hRes)) {
		goto DBG_ERROR;
	}

	goto TIMER_REARM_EXIT;

DBG_ERROR:
	// send dbg_err notice to disable the idb as its remote address base
	// was not properly resolved
	TunnelSend("[notice]{\"type\":\"dbg_err\"}\n");

TIMER_REARM_EXIT:
	CreatePollTimer();

	if (msg != NULL)
		free(msg);

	return hRes;
}


HRESULT idb(PSTR Args)
{
	HRESULT hRes = S_OK;
	char* context = NULL;
	char* param = NULL;
	ULONG_PTR modbase = NULL;

	// strip command and trailing whitespaces
	strtok_s(Args, " ", &param);
	strtok_s(param, " ", &context);

	hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", param);
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] TunnelSend failed for module notice\n");
		return hRes;
	}

	modbase = DbgFunctions()->ModBaseFromName(param);
	if (!modbase)
	{
		_plugin_logprintf("[sync] idb: ModBaseFromName(%s) failed to get module base...\n", param);
		goto DBG_ERROR;
	}

	_plugin_logprintf("[sync] idb: %s at %Ix\n", param, modbase);

	// Send this module its remote base address
	hRes = TunnelSend("[sync]{\"type\":\"rbase\",\"rbase\":%llu}\n", (UINT64)modbase);
	if (FAILED(hRes)) {
		_plugin_logputs("[sync] TunnelSend failed for rbase message\n");
		goto DBG_ERROR;
	}

	return hRes;

DBG_ERROR:
	// send dbg_err notice to disable the idb as its remote address base
	// was not properly resolved
	TunnelSend("[notice]{\"type\":\"dbg_err\"}\n");
	return hRes;
}


// add comment (cmt) command implementation
HRESULT cmt(PSTR Args)
{
	BOOL bRes = FALSE;
	HRESULT hRes = S_OK;
	int res = 0;
	ULONG_PTR cip = NULL;
	char* token = NULL;

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !cmt command unavailable\n");
		return E_FAIL;
	}

	if (!strtok_s(Args, " ", &token))
	{
		_plugin_logputs("[sync] failed to tokenize comment\n");
		return E_FAIL;
	}

	hRes = GetInstructionOffset(&cip);
	if (FAILED(hRes))
		return E_FAIL;

	res = _snprintf_s(g_CommandBuffer, _countof(g_CommandBuffer), _TRUNCATE, "commentset %Ix, \"%s\"", cip, token);
	if (res == _TRUNCATE) {
		_plugin_logprintf("[sync] truncation occured in commentset command generation\n", g_CommandBuffer);
	}
	else
	{
		bRes = DbgCmdExec(g_CommandBuffer);
		if (!bRes) {
			_plugin_logprintf("[sync] failed to execute \"%s\" command\n", g_CommandBuffer);
		}
	}
	ZeroMemory(g_CommandBuffer, _countof(g_CommandBuffer));

	hRes = TunnelSend("[sync]{\"type\":\"cmt\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", token, (ULONG64)g_Base, (ULONG64)g_Offset);
	if (FAILED(hRes))
	{
		_plugin_logputs("[sync] failed to send comment\n");
	}

	return hRes;
}


// reset comment (rcmt) command implementation
HRESULT rcmt()
{
	HRESULT hRes = S_OK;
	BOOL bRes = FALSE;
	int res = 0;
	ULONG_PTR cip = NULL;

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !cmt command unavailable\n");
		return E_FAIL;
	}

	hRes = GetInstructionOffset(&cip);
	if (FAILED(hRes))
		return E_FAIL;

	res = _snprintf_s(g_CommandBuffer, _countof(g_CommandBuffer), _TRUNCATE, "commentdel %Ix", cip);
	if (res == _TRUNCATE) {
		_plugin_logputs("[sync] truncation occured in commentdel command generation\n");
	}
	else
	{
		bRes = DbgCmdExec(g_CommandBuffer);
		if (!bRes) {
			_plugin_logprintf("[sync] failed to execute \"%s\" command\n", g_CommandBuffer);
		}
	}

	ZeroMemory(g_CommandBuffer, _countof(g_CommandBuffer));

	hRes = TunnelSend("[sync]{\"type\":\"rcmt\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", "", (ULONG64)g_Base, (ULONG64)g_Offset);
	if (FAILED(hRes))
	{
		_plugin_logputs("[sync] failed to reset comment\n");
	}

	return hRes;
}


// reset comment (rcmt) command implementation
HRESULT translate(PSTR Args)
{
	HRESULT hRes = S_OK;
	BOOL bRes = FALSE;
	int res = 0;
	char* context = NULL;
	char* rbase = NULL;
	char* ea = NULL;
	char* mod = NULL;
	ULONG_PTR modbase = NULL;

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !translate command unavailable\n");
		return E_FAIL;
	}

	strtok_s(Args, " ", &context);
	rbase = strtok_s(NULL, " ", &context);
	ea = strtok_s(NULL, " ", &context);
	mod = strtok_s(NULL, " ", &context);

	if ((rbase == NULL) || (ea == NULL) || (mod == NULL)) {
		_plugin_logputs("[sync] !translate <base> <ea> <mod>   (this command is meant to be used by a disassembler plugin)\n");
	}

	modbase = DbgFunctions()->ModBaseFromName(mod);
	if (!modbase)
	{
		_plugin_logprintf("[sync] translate: ModBaseFromName(%s) failed to get module base...\n", mod);
		return E_FAIL;
	}

	res = _snprintf_s(g_CommandBuffer, _countof(g_CommandBuffer), _TRUNCATE, "disasm %#Ix-%s+%s", modbase, rbase, ea);
	if (res == _TRUNCATE) {
		_plugin_logputs("[sync] truncation occured in disasm command generation\n");
	}
	else
	{
		bRes = DbgCmdExec(g_CommandBuffer);
		if (!bRes) {
			_plugin_logprintf("[sync] failed to execute \"%s\" command\n", g_CommandBuffer);
		}
	}
	ZeroMemory(g_CommandBuffer, _countof(g_CommandBuffer));

	return hRes;
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


static bool cbSyncmodautoCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] syncmodauto command!");
#endif

	if (strlen(argv[0]) < _countof("!syncmodauto")) {
		_plugin_logputs("[sync] !syncmodauto missing parameter (<on|off>)\n");
		return false;
	}

	_plugin_logputs("[sync] syncmodauto command!");
	syncmodauto((PSTR)argv[0]);
	return true;
}


static bool cbSynchelpCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] synchelp command!");
	synchelp();
	return true;
}


static bool cbIdblistCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] idblist command!");

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !idblist command unavailable\n");
		return false;
	}

	idblist();
	return true;
}


static bool cbIdbnCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] idbn command!");

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !idbn command unavailable\n");
		return false;
	}

	if (strlen(argv[0]) < _countof("!idbn")) {
		_plugin_logputs("[sync] !idbn <idb num>\n");
		return false;
	}

	idbn((PSTR)argv[0]);
	return true;
}


static bool cbIdbCommand(int argc, char* argv[])
{
	_plugin_logputs("[sync] idb command!");

	if (!g_Synchronized) {
		_plugin_logputs("[sync] not synced, !idb command unavailable\n");
		return false;
	}

	if (strlen(argv[0]) < _countof("!idb")) {
		_plugin_logputs("[sync] !idb <module name>\n");
		return false;
	}

	idb((PSTR)argv[0]);
	return true;
}


static bool cbCmtCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] cmt command!");
#endif

	if (strlen(argv[0]) < _countof("!cmt")) {
		_plugin_logputs("[sync] !cmt <comment to add>\n");
		return false;
	}

	cmt((PSTR)argv[0]);
	return true;
}


static bool cbRcmtCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] rcmt command!");
#endif

	rcmt();
	return true;
}


static bool cbInsyncCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] insync command!");
#endif

	InsSync();
	return true;
}


static bool cbTranslateCommand(int argc, char* argv[])
{
#if VERBOSE >= 2
	_plugin_logputs("[sync] translate command!");
#endif

	if (strlen(argv[0]) < _countof("!translate")) {
		_plugin_logputs("[sync] !translate <base> <ea> <mod>   (this command is meant to be used by a disassembler plugin)\n");
		return false;
	}

	translate(argv[0]);
	return true;
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
		cbSyncCommand(0, NULL);
		break;

	case MENU_DISABLE_SYNC:
		cbSyncoffCommand(0, NULL);
		break;

	case MENU_IDB_LIST:
		cbIdblistCommand(0, NULL);
		break;

	case MENU_SYNC_HELP:
		cbSynchelpCommand(0, NULL);
		break;

	break;
	}
}


void coreInit(PLUG_INITSTRUCT* initStruct)
{
	// register commands
#if VERBOSE >= 2
	_plugin_logprintf("[sync] pluginHandle: %d\n", pluginHandle);
#endif

	if (!_plugin_registercommand(pluginHandle, "!sync", cbSyncCommand, true))
		_plugin_logputs("[sync] error registering the \"!sync\" command!");

	if (!_plugin_registercommand(pluginHandle, "!syncoff", cbSyncoffCommand, true))
		_plugin_logputs("[sync] error registering the \"!syncoff\" command!");

	if (!_plugin_registercommand(pluginHandle, "!syncmodauto", cbSyncmodautoCommand, true))
		_plugin_logputs("[sync] error registering the \"!syncmodauto\" command!");

	if (!_plugin_registercommand(pluginHandle, "!synchelp", cbSynchelpCommand, false))
		_plugin_logputs("[sync] error registering the \"!synchelp\" command!");

	if (!_plugin_registercommand(pluginHandle, "!idblist", cbIdblistCommand, true))
		_plugin_logputs("[sync] error registering the \"!idblist\" command!");

	if (!_plugin_registercommand(pluginHandle, "!idbn", cbIdbnCommand, true))
		_plugin_logputs("[sync] error registering the \"!idbn\" command!");

	if (!_plugin_registercommand(pluginHandle, "!idb", cbIdbCommand, true))
		_plugin_logputs("[sync] error registering the \"!idb\" command!");

	if (!_plugin_registercommand(pluginHandle, "!cmt", cbCmtCommand, true))
		_plugin_logputs("[sync] error registering the \"!cmt\" command!");

	if (!_plugin_registercommand(pluginHandle, "!rcmt", cbRcmtCommand, true))
		_plugin_logputs("[sync] error registering the \"!rcmt\" command!");

	if (!_plugin_registercommand(pluginHandle, "!translate", cbTranslateCommand, true))
		_plugin_logputs("[sync] error registering the \"!translate\" command!");

	if (!_plugin_registercommand(pluginHandle, "!insync", cbInsyncCommand, true))
		_plugin_logputs("[sync] error registering the \"!insync\" command");

	// initialize globals
	g_Synchronized = FALSE;

	g_hPollCompleteEvent = CreateEvent(NULL, true, false, NULL);
	if (g_hPollCompleteEvent == NULL)
	{
		_plugin_logputs("[sync] Command polling feature init failed\n");
		return;
	}

	InitializeCriticalSection(&g_CritSectPollRelease);

	if (SUCCEEDED(LoadConfigurationFile())) {
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
	_plugin_unregistercommand(pluginHandle, "!synchelp");
	_plugin_unregistercommand(pluginHandle, "!syncmodauto");
	_plugin_unregistercommand(pluginHandle, "!idblist");
	_plugin_unregistercommand(pluginHandle, "!idbn");
	_plugin_unregistercommand(pluginHandle, "!idb");
	_plugin_unregistercommand(pluginHandle, "!cmt");
	_plugin_unregistercommand(pluginHandle, "!rcmt");
	_plugin_unregistercommand(pluginHandle, "!translate");
	_plugin_unregistercommand(pluginHandle, "!insync");
	_plugin_menuclear(hMenu);
}


void coreSetup()
{
	_plugin_menuaddentry(hMenu, MENU_ENABLE_SYNC, "&Enable sync");
	_plugin_menuaddentry(hMenu, MENU_DISABLE_SYNC, "&Disable sync");
	_plugin_menuaddentry(hMenu, MENU_IDB_LIST, "&Retrieve idb list");
	_plugin_menuaddentry(hMenu, MENU_SYNC_HELP, "&Display sync commands help");
}
