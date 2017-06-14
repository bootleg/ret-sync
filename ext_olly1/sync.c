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

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winnt.h>
#include <strsafe.h>
#include <shlwapi.h>

#include "plugin.h"
#include "tunnel.h"

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "crypt32.lib")


#define VERBOSE 0
#define MAX_NAME 1024
#define MAX_CMD  1024
#define TIMER_PERIOD 100
#define CONF_FILE "\\.sync"


HINSTANCE        hinst;                // DLL instance
HWND             hwmain;               // Handle of main OllyDbg window


// Default host value is locahost
static CHAR *g_DefaultHost = "127.0.0.1";
static CHAR *g_DefaultPort = "9100";
BOOL g_ExtConfFile = 0;

// Buffer used to solve symbol's name
static char g_NameBuffer[MAX_NAME];
// Buffer used to receive breakpoint command
static char g_CommandBuffer[MAX_CMD];

// Debuggee's state
ulong g_Offset = 0;
ulong g_Base = 0;

// Synchronisation mode
static BOOL g_SyncAuto = TRUE;

// Command polling feature
static HANDLE g_hPollTimer = INVALID_HANDLE_VALUE;
static HANDLE g_hPollCompleteEvent = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_CritSectPollRelease;


HRESULT LoadConfigurationFile()
{
	DWORD count;
	HRESULT hRes = S_OK;
	HANDLE hFile;
	CHAR lpProfile[MAX_PATH] = { 0 };
	LPSTR lpConfHost, lpConfPort;

	count = GetEnvironmentVariableA("userprofile", lpProfile, MAX_PATH);
	if ((count == 0) | (count > MAX_PATH))
		return E_FAIL;

	hRes = StringCbCatA(lpProfile, MAX_PATH, CONF_FILE);
	if FAILED(hRes)
		return E_FAIL;

	hFile = CreateFileA(lpProfile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return E_FAIL;

	CloseHandle(hFile);
	lpConfHost = (LPSTR)malloc(MAX_PATH);
	lpConfPort = (LPSTR)malloc(MAX_PATH);

	count = GetPrivateProfileStringA("INTERFACE", "host", "127.0.0.1", lpConfHost, MAX_PATH, lpProfile);
	if ((count == 0) | (count == (MAX_PATH - 1)) | (count == (MAX_PATH - 2)))
		goto failed;

	count = GetPrivateProfileStringA("INTERFACE", "port", "9100", lpConfPort, MAX_PATH, lpProfile);
	if ((count == 0) | (count == (MAX_PATH - 1)) | (count == (MAX_PATH - 2)))
		goto failed;

	g_DefaultHost = lpConfHost;
	g_DefaultPort = lpConfPort;
	g_ExtConfFile = 1;

	return hRes;

failed:
	free(lpConfHost);
	free(lpConfPort);

	return E_FAIL;
}


// Poll socket for incoming commands
HRESULT PollCmd()
{
	HRESULT hRes = S_OK;
	int NbBytesRecvd;
	int ch = 0xA;
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

			dbgout("[sync] received command- %s (not implemented yet)\n", msg);

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
	dbgout("[sync] ReleasePollTimer called\n");
#endif

	if (!(g_hPollTimer == INVALID_HANDLE_VALUE))
	{
		ResetEvent(g_hPollCompleteEvent);
		bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
		if (bRes == 0)
		{
			// msdn: If the error code is ERROR_IO_PENDING, it is not necessary to
			// call this function again. For any other error, you should retry the call.
			dwErr = GetLastError();
			if (dwErr != ERROR_IO_PENDING)
			{
				bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);

				if (!bRes)
				{
#if VERBOSE >= 2
					dbgout("[sync] DeleteTimerQueueTimer failed\n");
#endif
				}
			}
		}

		g_hPollTimer = INVALID_HANDLE_VALUE;
	}

	LeaveCriticalSection(&g_CritSectPollRelease);
}


// Poll timer callback implementation: call PollCmd and set completion event
void CALLBACK PollTimerCb(PVOID lpParameter, BOOL TimerOrWaitFired)
{
	HRESULT hRes;
	UNREFERENCED_PARAMETER(lpParameter);
	UNREFERENCED_PARAMETER(TimerOrWaitFired);

	hRes = PollCmd();

	// If an error occured in PollCmd() the timer callback is deleted.
	// (typically happens when client has closed the connection)
	if (FAILED(hRes))
		ReleasePollTimer();
}


// Setup poll timer callback
void CreatePollTimer()
{
	BOOL bRes;

	bRes = CreateTimerQueueTimer(&g_hPollTimer, NULL, (WAITORTIMERCALLBACK)PollTimerCb,
		NULL, TIMER_PERIOD, TIMER_PERIOD, WT_EXECUTEINTIMERTHREAD);
	if (!(bRes))
		dbgout("[sync] failed to CreatePollTimer\n");
}


//Update state and send info to client: eip module's base address, offset, name
HRESULT UpdateState(t_reg *reg)
{
	HRESULT hRes = S_OK;
	t_module *pmod;
	ulong PrevBase;
	ulong tid;
	t_thread *pthread;

	PrevBase = g_Base;

	if (reg == NULL)
	{
		tid = Getcputhreadid();
		pthread = Findthread(tid);

		if (pthread != NULL)
			reg = &(pthread->reg);
		else
			return E_FAIL;
	}

	g_Offset = reg->ip;
	pmod = Findmodule(g_Offset);

#if VERBOSE >= 2
	dbgout("[*] eip %08x - pmod %08x\n", g_Offset, pmod);
#endif

	if (pmod == NULL)
		return E_FAIL;

	g_Base = pmod->base;
	if (g_Base != PrevBase)
	{
		strncpy_s(g_NameBuffer, MAX_NAME, pmod->path, _TRUNCATE);

		hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", g_NameBuffer);
		dbgout("[*] mod path %s\n", g_NameBuffer);

		if (FAILED(hRes))
			return hRes;
	}

	hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%lu,\"offset\":%lu}\n", g_Base, g_Offset);
	return hRes;
}


HRESULT sync(PSTR Args)
{
	HRESULT hRes = S_OK;
	PCSTR Host;
	PSTR pszId = NULL;

	// Reset global state
	g_Base = 0;
	g_Offset = 0;

#if VERBOSE >= 2
	dbgout("[sync] sync function called\n");
#endif

	if (g_Synchronized)
	{
		dbgout("[sync] sync update\n");
		UpdateState(NULL);
		goto exit;
	}

	if (!Args || !*Args) {
		dbgout("[sync] No argument found, using default host (%s:%s)\n", g_DefaultHost, g_DefaultPort);
		Host = g_DefaultHost;
	}
	else{
		Host = Args;
	}

	if (FAILED(hRes = TunnelCreate(Host, g_DefaultPort)))
	{
		dbgout("[sync] sync failed\n");
		goto exit;
	}

	dbgout("[sync] probing sync\n");

	hRes = TunnelSend("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - %s\"}\n", "Ollydbg1_sync");
	if (SUCCEEDED(hRes))
	{
		dbgout("[sync] sync is now enabled with host %s\n", Host);
		UpdateState(NULL);
		CreatePollTimer();
	}
	else
		dbgout("[sync] sync aborted\n");

exit:
	if (!(pszId == NULL))
		free(pszId);

	return hRes;
}


HRESULT syncoff(){
	HRESULT hRes = S_OK;

#if VERBOSE >= 2
	dbgout("[sync] !syncoff  command called\n");
#endif

	if (!g_Synchronized)
		return hRes;

	ReleasePollTimer();
	hRes = TunnelClose();
	dbgout("[sync] sync is now disabled\n");

	return hRes;
}


// Entry point into a plugin DLL. Many system calls require DLL instance
// which is passed to DllEntryPoint() as one of parameters. Remember it.
// Preferrable way is to place initializations into ODBG_Plugininit() and
// cleanup in ODBG_Plugindestroy().
BOOL WINAPI DllEntryPoint(HINSTANCE hi, DWORD reason, LPVOID reserved) {
	if (reason == DLL_PROCESS_ATTACH)
		hinst = hi;                          // Mark plugin instance
	return 1;                            // Report success
};

// ODBG_Plugindata(): fill in plugin name and return version of plugin interface.
extc int _export cdecl ODBG_Plugindata(char shortname[32])
{
	strncpy_s(shortname, 32, "ret-sync plugin", _TRUNCATE);
	return PLUGIN_VERSION;
};

// OllyDbg calls this obligatory function once during startup. Place all
// one-time initializations here. If all resources are successfully allocated,
// function must return 0. On error, it must free partially allocated resources
// and return -1, in this case plugin will be removed. Parameter ollydbgversion
// is the version of OllyDbg, use it to assure that it is compatible with your
// plugin; hw is the handle of main OllyDbg window, keep it if necessary.
// Parameter features is reserved for future extentions, do not use it.
extc int _export cdecl ODBG_Plugininit(int ollydbgversion, HWND hw, ulong *features)
{
	HRESULT hRes = E_FAIL;

	if (ollydbgversion < PLUGIN_VERSION)
		return -1;

	hwmain = hw;

	Addtolist(0, 0, "ret-sync plugin for OllyDbg v1.10");
	Addtolist(0, -1, "  Copyright (C) 2012-2014 Quarkslab / 2016 ret-sync");

	InitializeCriticalSection(&g_CritSectPollRelease);

	hRes = LoadConfigurationFile();
	if (SUCCEEDED(hRes))
		dbgout("[sync] Configuration file loaded\n       -> set HOST to %s:%s\n", g_DefaultHost, g_DefaultPort);

	return 0;
};


extc void _export cdecl ODBG_Pluginsaveudd(t_module *pmod, int ismainmodule)
{
	// nope
};


extc int _export cdecl ODBG_Pluginuddrecord(t_module *pmod, int ismainmodule, ulong tag, ulong size, void *data) {
	return 1;
};

// Function adds items either to main OllyDbg menu (origin=PM_MAIN) or to popup
// menu in one of standard OllyDbg windows. When plugin wants to add own menu
// items, it gathers menu pattern in data and returns 1, otherwise it must
// return 0. Except for static main menu, plugin must not add inactive items.
// Item indices must range in 0..63. Duplicated indices are explicitly allowed.
extc int _export cdecl ODBG_Pluginmenu(int origin, char data[4096], void *item)
{
	switch (origin) {
	case PM_MAIN: // Plugin menu in main window
		strncpy_s(data, 4096, "0 &Sync (alt-s)|1 &Syncoff (alt-u)|2 &About", _TRUNCATE);
		return 1;
	default:
		break; // Any other window
	};
	return 0; // Window not supported by plugin
};



// This optional function receives commands from plugin menu in window of type
// origin. Argument action is menu identifier from ODBG_Pluginmenu(). If user
// activates automatically created entry in main menu, action is 0.
extc void _export cdecl ODBG_Pluginaction(int origin, int action, void *item)
{
	if (origin == PM_MAIN) {
		switch (action) {

		case 0:
			// Menu item "Sync", enable sync.
			sync(NULL);
			break;

		case 1:
			// Menu item "Syncoff", disable sync.
			syncoff();
			break;

		case 2:
			// Menu item "About", displays plugin info.
			MessageBox(hwmain,
				"ret-sync plugin\n"
				"Copyright (C) 2012-2014 Quarkslab / 2016 ret-sync\n",
				"ret-sync plugin", MB_OK | MB_ICONINFORMATION);
			break;

		default:
			break;
		};
	}
};


// This function receives possible keyboard shortcuts from standard OllyDbg
// windows. If it recognizes shortcut, it must process it and return 1,
// otherwise it returns 0.
extc int _export cdecl ODBG_Pluginshortcut(
	int origin, int ctrl, int alt, int shift, int key, void *item) {
#if VERBOSE >= 2
	dbgout("[*] ODBG_Pluginshortcut - ctrl %x - alt %x - key %x\n", ctrl, alt, key);
#endif
	if (ctrl == 0 && alt != 0)
	{
		if (key == 'S')
		{
			sync(NULL);
			return 1;
		}
		else if (key == 'U')
		{
			syncoff();
			return 1;
		}

	};
	return 0;                            // Shortcut not recognized
};



// Function is called when user opens new or restarts current application.
// Plugin should reset internal variables and data structures to initial state.
extc void _export cdecl ODBG_Pluginreset(void)
{
#if VERBOSE >= 2
	dbgout("[*] ODBG_Pluginreset\n");
#endif
	syncoff();
};

// OllyDbg calls this optional function when user wants to terminate OllyDbg.
extc int _export cdecl ODBG_Pluginclose(void)
{
#if VERBOSE >= 2
	dbgout("[*] ODBG_Pluginclose\n");
#endif
	syncoff();
	return 0;
};


// OllyDbg calls this optional function once on exit. At this moment, all MDI
// windows created by plugin are already destroyed (and received WM_DESTROY
// messages). Function must free all internally allocated resources, like
// window classes, files, memory and so on.
extc void _export cdecl ODBG_Plugindestroy(void)
{
#if VERBOSE >= 2
	dbgout("[*] ODBG_Plugindestroy\n");
#endif

	ReleasePollTimer();
	DeleteCriticalSection(&g_CritSectPollRelease);
	TunnelClose();

	if (g_ExtConfFile)
	{
		free(g_DefaultHost);
		free(g_DefaultPort);
	}
};


int ODBG_Paused(int reason, t_reg *reg)
{
#if VERBOSE >= 2
	dbgout("[*] ODBG_Paused\n");
#endif

	switch (reason){
	case PP_EVENT:
	case PP_PAUSE:
		if (g_Synchronized)
		{
			UpdateState(reg);
			CreatePollTimer();
		}
		break;

	case PP_TERMINATED:
		syncoff();

	default:
		break;
	}
	return 0;
}

// If you define ODBG_Pluginmainloop, this function will be called each time
// from the main Windows loop in OllyDbg. If there is some debug event from
// the debugged application, debugevent points to it, otherwise it is NULL. Do
// not declare this function unnecessarily, as this may negatively influence
// the overall speed!
extc void _export cdecl ODBG_Pluginmainloop(DEBUG_EVENT *debugevent) {
	if (!(g_hPollTimer == INVALID_HANDLE_VALUE))
		ReleasePollTimer();
};
