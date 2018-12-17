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


#define PLUGINNAME     L"SyncPlugin"    // Unique plugin name
#define VERSION        L"1.0.0"      // Plugin version

HINSTANCE        hdllinst;             // Instance of plugin DLL

#define VERBOSE 0
#define MAX_NAME 1024
#define MAX_CMD  1024
#define TIMER_PERIOD 100
#define CONF_FILE "\\.sync"

// Default host value is locahost
static CHAR *g_DefaultHost = "127.0.0.1";
static CHAR *g_DefaultPort = "9100";
BOOL g_ExtConfFile = 0;

// Buffer used to solve symbol's name
static wchar_t g_NameBuffer[MAX_NAME];
// Buffer used to receive breakpoint command
static wchar_t g_CommandBuffer[MAX_CMD];

// Debuggee's state
ulong g_Offset = 0;
ulong g_Base   = 0;

// Synchronisation mode
static BOOL g_SyncAuto = TRUE;

// Command polling feature
static HANDLE g_hPollTimer;
static HANDLE g_hPollCompleteEvent;
static CRITICAL_SECTION g_CritSectPollRelease;


HRESULT
LoadConfigurationFile()
{
    DWORD count;
    HRESULT hRes = S_OK;
    HANDLE hFile;
    CHAR lpProfile[MAX_PATH] = {0};
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
    lpConfHost = (LPSTR) malloc(MAX_PATH);
    lpConfPort = (LPSTR) malloc(MAX_PATH);

    count = GetPrivateProfileStringA("INTERFACE", "host", "127.0.0.1", lpConfHost, MAX_PATH, lpProfile);
    if ((count == 0) | (count == (MAX_PATH-1)) | (count == (MAX_PATH-2)))
        goto failed;

    count = GetPrivateProfileStringA("INTERFACE", "port", "9100", lpConfPort, MAX_PATH, lpProfile);
    if ((count == 0) | (count == (MAX_PATH-1)) | (count == (MAX_PATH-2)))
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


// send a combination of WM_KEYDOWN, WM_KEYUP for a given virtual-key code
void MonkeyInput(WORD wVk)
{
    unsigned int scanCode, lParam;
    BOOL bRes;

    #if VERBOSE >= 2
    dbgout("[*] MonkeyInput 0x%x, hwnd 0x%x\n", wVk, hwollymain);
    #endif

    scanCode = MapVirtualKey((unsigned int)wVk, MAPVK_VK_TO_VSC);
    if (scanCode == 0) {
        dbgout("[sync] failed to MapVirtualKey (no translation)\n");
        goto Exit;
    }

    lParam = 0x00000001 | (scanCode << 16);

    bRes = PostMessage(hwollymain, WM_KEYDOWN, wVk, lParam);
    if (!bRes) {
        dbgout("[sync] failed to PostMessage (WM_KEYDOWN)\n");
        goto Exit;
    }

    bRes = PostMessage(hwollymain, WM_KEYUP, wVk, lParam);
    if (!bRes) {
        dbgout("[sync] failed to PostMessage (WM_KEYUP)\n");
    }

Exit:
    return;
}


HRESULT
SetBreakpoint(char *command, BOOL oneshot)
{
    HRESULT hRes=S_OK;
    int res;
    t_result result;
    wchar_t *address = NULL;
    unsigned long type;

    #if VERBOSE >= 2
    dbgout("[sync] SetBreakpoint: %s\n", command);
    #endif

    Suspendallthreads();

    hRes = convert_tow(command, &address);
    if(FAILED(hRes)){
        hRes = E_FAIL;
        goto Exit;
    }

    res = Expression(&result, address, NULL, 0, 0, 0, 0, 0, EMOD_CHKEXTRA);
    if (result.datatype == EXPR_INVALID)
    {
        dbgout("[sync] SetBreakpoint: failed to evaluate Expression (0x%x)\n", res);
        hRes = E_FAIL;
        goto Exit;
    }

    type = BP_BREAK | (oneshot ? BP_ONESHOT : BP_MANUAL);

    res = Setint3breakpoint(result.u, type, 0, 0, 0, BA_PERMANENT, L"", L"", L"");
    if (res != 0)
    {
        dbgout("[sync] failed to Setint3breakpoint\n");
        hRes = E_FAIL;
        goto Exit;
    }

    Flushmemorycache();

Exit:
    Resumeallthreads();

    if (address != NULL){
        free(address);
    }

    return hRes;
}


HRESULT
SetHardwareBreakpoint(char *command, BOOL oneshot)
{
    HRESULT hRes=S_OK;
    int res, index;
    t_result result;
    wchar_t *address = NULL;
    unsigned long type;

	UNREFERENCED_PARAMETER(oneshot);

    #if VERBOSE >= 2
    dbgout("[sync] SetHardwareBreakpoint: %s\n", command);
    #endif

    Suspendallthreads();

    hRes = convert_tow(command, &address);
    if(FAILED(hRes)){
        hRes = E_FAIL;
        goto Exit;
    }

    res = Expression(&result, address, NULL, 0, 0, 0, 0, 0, EMOD_CHKEXTRA);
    if (result.datatype == EXPR_INVALID)
    {
        dbgout("[sync] SetHardwareBreakpoint: failed to evaluate Expression (0x%x)\n", res);
        hRes = E_FAIL;
        goto Exit;
    }

    type = BP_BREAK | BP_EXEC | BP_MANUAL;

    index = Findfreehardbreakslot(type);
    if (index == -1)
    {
        dbgout("[sync] failed to Findfreehardbreakslot\n");
        hRes = E_FAIL;
        goto Exit;
    }

    #if VERBOSE >= 2
    dbgout("[sync] Findfreehardbreakslot 0x%x\n", index);
    #endif

    res = Sethardbreakpoint(index, 1, result.u, type, 0, 0, 0, BA_PERMANENT, L"", L"", L"");
    if (res != 0)
    {
        dbgout("[sync] failed to Sethardbreakpoint\n");
        hRes = E_FAIL;
        goto Exit;
    }

    Flushmemorycache();

Exit:
    Resumeallthreads();

    if (address != NULL){
        free(address);
    }

    return hRes;
}


// Poll socket for incoming commands
HRESULT
PollCmd()
{
    HRESULT hRes=S_OK;
    int NbBytesRecvd;
    int ch = 0xA;
    char *msg, *next, *orig = NULL;

    hRes=TunnelPoll(&NbBytesRecvd, &msg);

    if (SUCCEEDED(hRes) & (NbBytesRecvd>0) & (msg != NULL))
    {
        next = orig = msg;

        while((msg-orig) < NbBytesRecvd)
        {
            next = strchr(msg, ch);
            if( next != NULL)
                *next = 0;

            // bp1, hbp, hbp1 disabled for now, thread safety issue ?
            // possibly need for a gdb.post_event like feature

            if (strncmp(msg, "si", 2) == 0) {
                MonkeyInput(VK_F7);
            }
            else if (strncmp(msg, "so", 2) == 0) {
                MonkeyInput(VK_F8);
            }
            else if (strncmp(msg, "go", 2) == 0) {
                MonkeyInput(VK_F9);
            }
            else if (strncmp(msg, "bp", 2) == 0) {
                SetBreakpoint(msg+2, FALSE);
            }
            else {
                dbgout("[sync] received command: %s (not yet implemented)\n", msg);
            }

            // No more command
            if( next == NULL)
                break;

            msg = next+1;
        }

        free(orig);
    }

    return hRes;
}


void ReleasePollTimer()
{
    BOOL bRes;
    DWORD dwErr;

    EnterCriticalSection(&g_CritSectPollRelease);

    #if VERBOSE >= 2
    dbgout("[sync] ReleasePollTimer called\n");
    #endif

    if (!(g_hPollTimer==INVALID_HANDLE_VALUE))
    {
        ResetEvent(g_hPollCompleteEvent);
        bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
        if (bRes == 0)
        {
            // msdn: If the error code is ERROR_IO_PENDING, it is not necessary to
            // call this function again. For any other error, you should retry the call.
            dwErr = GetLastError();
            if (dwErr != ERROR_IO_PENDING)
                bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
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


HRESULT
convert_tow(const char * mbstr,  PTCH *wcstr)
{
    HRESULT hRes = S_OK;
    size_t returnValue;
    errno_t err;

    err = _mbstowcs_s_l(&returnValue, NULL, 0, mbstr, _TRUNCATE, CP_ACP);
    if (err != 0)
    {
        dbgout("[sync] _mbstowcs_s_l failed: %d\n", GetLastError());
        return E_FAIL;
    }

    *wcstr = (wchar_t *) malloc(returnValue+1);
    if (mbstr == NULL)
    {
        dbgout("[sync] convert failed to allocate buffer: %d\n", GetLastError());
        return E_FAIL;
    }

    err = _mbstowcs_s_l(&returnValue, *wcstr, returnValue, mbstr, _TRUNCATE, CP_ACP);
    if (err != 0)
    {
        dbgout("[sync] _mbstowcs_s_l failed: %d\n", GetLastError());
        if(!(*wcstr == NULL))
            free(*wcstr);

        return E_FAIL;
    }

    return hRes;
}


HRESULT convert(const wchar_t *wcstr, PSTR * mbstr)
{
    HRESULT hRes = S_OK;
    size_t returnValue;
    errno_t err;

    err = _wcstombs_s_l(&returnValue, NULL, 0, wcstr, _TRUNCATE, CP_ACP);
    if (err != 0)
    {
        dbgout("[sync] _wcstombs_s_l failed: %d\n", GetLastError());
        return E_FAIL;
    }

    *mbstr = (PSTR) malloc(returnValue+1);
    if (mbstr == NULL)
    {
        dbgout("[sync] convert failed to allocate buffer: %d\n", GetLastError());
        return E_FAIL;
    }

    err = _wcstombs_s_l(&returnValue, *mbstr, returnValue, wcstr, _TRUNCATE, CP_ACP);
    if (err != 0)
    {
        dbgout("[sync] _wcstombs_s_l failed: %d\n", GetLastError());
        if(!(*mbstr == NULL))
            free(*mbstr);

        return E_FAIL;
    }

    return hRes;
}


//Update state and send info to client: eip module's base address, offset, name
HRESULT UpdateState()
{
    HRESULT hRes = S_OK;
    PSTR modname = NULL;
    t_module *pmod;
    ulong PrevBase;

    PrevBase = g_Base;
    g_Offset = run.eip;
    pmod = Findmodule(g_Offset);

    #if VERBOSE >= 2
    dbgout("[*] eip %08x - pmod %08x\n", g_Offset, pmod);
    #endif

    if (pmod == NULL)
        return E_FAIL;

    g_Base = pmod->base;
    if (g_Base != PrevBase)
    {
        wcsncpy_s(g_NameBuffer, MAX_NAME, pmod->path, _TRUNCATE);

        hRes = convert(g_NameBuffer, &modname);
        if(FAILED(hRes))
            return hRes;

        hRes=TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", modname);
        dbgout("[*] mod path %s\n", modname);

        free(modname);

        if(FAILED(hRes))
            return hRes;
    }

    hRes=TunnelSend("[sync]{\"type\":\"loc\",\"base\":%lu,\"offset\":%lu}\n", g_Base, g_Offset);
    return hRes;
}


static void LogSyncState()
{
    if (g_Synchronized)
        Addtolist(0, DRAW_NORMAL, L"[sync] sync is enabled");
    else
        Addtolist(0, DRAW_NORMAL, L"[sync] sync is disabled");
};


HRESULT sync(PSTR Args)
{
    HRESULT hRes=S_OK;
    PCSTR Host;
    PSTR pszId=NULL;

    // Reset global state
    g_Base = 0;
    g_Offset = 0;

    #if VERBOSE >= 2
    dbgout("[sync] sync function called\n");
    #endif

    if(g_Synchronized)
    {
        dbgout("[sync] sync update\n");
        UpdateState();
        goto exit;
    }

    if (!Args || !*Args) {
        dbgout("[sync] No argument found, using default host (%s:%s)\n", g_DefaultHost, g_DefaultPort);
        Host=g_DefaultHost;
    }else{
        Host=Args;
    }

    if(FAILED(hRes=TunnelCreate(Host, g_DefaultPort)))
    {
        dbgout("[sync] sync failed\n");
        goto exit;
    }

    dbgout("[sync] probing sync\n");

    /* Used a fixed identity
    if(FAILED(hRes=Identity(&pszId)))
    {
        dbgout("[sync] get identity failed\n");
        goto exit;
    }
    */

    hRes=TunnelSend("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - %s\",\"dialect\":\"ollydbg2\"}\n", "Ollydbg2_sync");
    if(SUCCEEDED(hRes))
    {
        dbgout("[sync] sync is now enabled with host %s\n", Host);
        UpdateState();
        CreatePollTimer();
        LogSyncState();
    }
    else
        dbgout("[sync] sync aborted\n");



exit:
    if(!(pszId==NULL))
        free(pszId);

    return hRes;
}


HRESULT syncoff()
{
    HRESULT hRes=S_OK;

    #if VERBOSE >= 2
    dbgout("[sync] !syncoff  command called\n");
    #endif

    if(!g_Synchronized)
        return hRes;

    ReleasePollTimer();
    hRes=TunnelClose();

    #if VERBOSE >= 2
    dbgout("[sync] sync is now disabled\n");
    #endif

    LogSyncState();
    return hRes;
}


// Menu function of about menu, displays About dialog.
static int Mabout(t_table *pt, wchar_t *name, ulong index, int mode)
{
    int n;
    wchar_t s[TEXTLEN];

    UNREFERENCED_PARAMETER(pt);
    UNREFERENCED_PARAMETER(name);
    UNREFERENCED_PARAMETER(index);

    if (mode==MENU_VERIFY)
        return MENU_NORMAL;

    else if (mode==MENU_EXECUTE)
    {
        Resumeallthreads();
        n=StrcopyW(s,TEXTLEN,L"ret-sync plugin ");
        n+=StrcopyW(s+n,TEXTLEN-n,VERSION);
        n+=StrcopyW(s+n,TEXTLEN-n,L"\nCopyright (C) 2012-2014 Quarkslab\nCopyright (C) 2016 ret-sync\n");
        Suspendallthreads();

        MessageBox(hwollymain,s, L"Sync plugin", MB_OK|MB_ICONINFORMATION);
        return MENU_NOREDRAW;
    };
    return MENU_ABSENT;
};


// Menablesync: enable synchronization
static int Menablesync(t_table *pt, wchar_t *name, ulong index, int mode)
{
    UNREFERENCED_PARAMETER(pt);
    UNREFERENCED_PARAMETER(name);
    UNREFERENCED_PARAMETER(index);

    #if VERBOSE >= 2
    dbgout("[sync] Menablesync - mode %x\n", mode);
    #endif

    if (mode==MENU_VERIFY)
        return MENU_NORMAL;

    else if (mode==MENU_EXECUTE)
    {
        sync(NULL);
        return MENU_NOREDRAW;
    };
    return MENU_ABSENT;
};


// Menablesync: disable synchronization
static int Mdisablesync(t_table *pt, wchar_t *name, ulong index, int mode)
{
    UNREFERENCED_PARAMETER(pt);
    UNREFERENCED_PARAMETER(name);
    UNREFERENCED_PARAMETER(index);

    #if VERBOSE >= 2
    dbgout("[sync] Mdisablesync - mode %x\n", mode);
    #endif

    if (mode==MENU_VERIFY)
        return MENU_NORMAL;

    else if (mode==MENU_EXECUTE)
    {
        syncoff();
        return MENU_NOREDRAW;
    };
    return MENU_ABSENT;
};


//
// Add or edit Comment / Label at address.
//
static int MCommentAndLabel(t_table *pt, wchar_t *name, ulong index, int mode)
{
	HRESULT hRes;
	t_dump* dump;
	t_module* cur_mod;
	ulong saveType = DT_NONE;
	int retVal = MENU_ABSENT;
	int findNameResult;
	int copiedBytes = 0;
	int column = 0;
	int letter = 0;
	POINT point;
	PSTR args = NULL;
	PWSTR wargs = NULL;
	wchar_t buffer[TEXTLEN];
	wchar_t nameBuffer[TEXTLEN];

	UNREFERENCED_PARAMETER(name);

    switch(mode)
    {
        //check if menu applies
    case MENU_VERIFY:
        // ordinary menu item
        retVal = MENU_NORMAL;
        break;

        //execute menu item
    case MENU_EXECUTE:
        {


            nameBuffer[0] = L'\0';

            if(index == NM_COMMENT)
            {
                saveType = NM_COMMSAV;
                column = 3;
            }
            else if(index == NM_LABEL)
            {
                saveType = NM_LABELSAV;
                column = 0;
            }

            dump = (t_dump*)pt->customdata;

            #if VERBOSE >= 2
            dbgout("[*] customdata : %p\n", dump);
            #endif

            if(!dump)
            {
                dbgout("[-] Critical error: no t_dump structure !\n");
                break;
            }

            //suspend all threads in debuggee
            Suspendallthreads();

            #if VERBOSE >= 2
            // Note : if 'name' is NULL, then the comment is made by the plugin menu,
            //     otherwise, if the shortcut key is pressed, name equals the menu name ("Comment")
            if(name)
                dbgoutW(L"[*] Name : %s\n", name);

            dbgoutW(L"[*] Selection address : %#p\n", dump->sel0);
            #endif

            // get table selection coords
            if(Gettableselectionxy(&dump->table, column, &point) < 0)
            {
                point.x = -1;
                point.y = -1;
            }

            //check to see if the current instruction has already a comment or a label
            findNameResult = FindnameW(dump->sel0, index, NULL, 0);
            if(findNameResult == 0)
            {
                if(index == NM_COMMENT)
                    copiedBytes = StrcopyW(buffer, TEXTLEN, L"Add comment at ");
                else if(index == NM_LABEL)
                    copiedBytes = StrcopyW(buffer, TEXTLEN, L"Add label at ");
            }
            else
            {
                FindnameW(dump->sel0, index, nameBuffer, TEXTLEN);
                if(index == NM_COMMENT)
                    copiedBytes = StrcopyW(buffer, TEXTLEN, L"Edit comment at ");
                else if(index == NM_LABEL)
                    copiedBytes = StrcopyW(buffer, TEXTLEN, L"Edit label at ");
            }

            // decode chosen address and append decoded address (e.g FOO.DEADBEEF) to dialog box header string. ex: "Add comment at FOO.0DEADBEEF"
            Decodeaddress(dump->sel0, 0, DM_MODNAME | DM_WIDEFORM, (wchar_t*)((BYTE*)buffer + (sizeof(wchar_t) * copiedBytes)), TEXTLEN - copiedBytes, NULL);

            // not sure what the 'letter' param for GetString() is... (at least this is a single letter put into the dialog box)
            //TODO: need to fix that when doc is available
            if(nameBuffer[0] != L'\0')
                letter = nameBuffer[0];

            //popup dialog, get user string in "nameBuffer"
            if(Getstring(hwollymain, buffer, nameBuffer, TEXTLEN, saveType, letter, point.x, point.y, dump->table.font, DIA_UTF8) > 0)
            {
                // insert comment or label
                InsertnameW(dump->sel0, index, nameBuffer);

                //broadcast change to olly
                Broadcast(0x489, 1, 0);

                //send to IDA (iif synch is ON)
                if(g_Synchronized)
                {
                   // get module description according to current selection
                   cur_mod = Findmodule(dump->sel0);

                   if(!cur_mod)
                   {
                       dbgout("[-] Couldn't find any module for address: %#p\n", dump->sel0);
                       goto __resumethreads;
                   }

                   // unicode buffer for args
                   wargs = (wchar_t*) malloc(TEXTLEN * sizeof(wchar_t));

                   // build arguments passed into the tunnel. e.g. "-a 0xdeadbeef this is a superduper comment" / "-a 0xdeadbeef @@my_label"
                   wcsncpy_s(wargs, TEXTLEN, L"-a ", TEXTLEN);
                   _snwprintf_s(buffer , TEXTLEN, TEXTLEN, L"%#lx ", dump->sel0);
                   wcsncat_s(wargs, TEXTLEN, buffer, TEXTLEN);
                   wcsncat_s(wargs, TEXTLEN, nameBuffer, TEXTLEN);

                   hRes = convert(wargs, &args);
                   if(SUCCEEDED(hRes))
                   {
                       // send comment to IDA
					   if (index == NM_COMMENT)
					   {
						   TunnelSend("[sync]{\"type\":\"cmt\",\"msg\":\"%s\",\"base\":%lu,\"offset\":%lu}\n", args, cur_mod->base, dump->sel0);
					   }
					   else if (index == NM_LABEL)// send label to IDA
					   {
						   TunnelSend("[sync]{\"type\":\"lbl\",\"msg\":\"%s\",\"base\":%lu,\"offset\":%lu}\n", args, cur_mod->base, dump->sel0);
					   }
                   }

                   // whatever happened, free the buffers
                   if(wargs)
                       free(wargs); wargs = NULL;
                   if(args)
                       free(args); args = NULL;
                } //end  if(g_Synchronized)
            }//end Getstring()

            //resume all threads in debuggee
__resumethreads:
            Resumeallthreads();

            // force window to redraw
            retVal = MENU_REDRAW;
            break;
        }// end case MENU_EXECUTE
    }//end switch

    return retVal;
};


// Plugin menu that will appear in the main OllyDbg menu.
// Define two shortcuts:
//      "ctrl+s" to enable synchronization
//      "ctrl+u" to disable synchronization
static t_menu mainmenu[] = {
  { L"Enable sync (Ctrl+s)",
       L"Enable sync (Ctrl+s)",
       KK_DIRECT|KK_CTRL|0x53 , Menablesync, NULL, 0 },
  { L"Disable sync (Ctrl+u)",
       L"Disable sync (Ctrl+u)",
      KK_DIRECT|KK_CTRL|0x55, Mdisablesync, NULL, 0 },
  { L"|About",
       L"About Sync plugin",
       K_NONE, Mabout, NULL, 0 },
  { NULL, NULL, K_NONE, NULL, NULL, 0 }
};


// Plugin menu that will appear in "Disasm" Window
// Define two shortcuts:
//     "ctrl + ;" to enable comment synchro
//     "ctrl + :" to enable label synchro
static t_menu disasmmenu[] = {
  { L"[Sync] Comment",
    L"Synchronize comment",
    KK_DIRECT /* shortcut appears in menu */| KK_CHAR /* must be processed as char, otherwise ';' is not taken */| KK_CTRL | ';',
    MCommentAndLabel,
    NULL,
    NM_COMMENT
  },
  { L"[Sync] Label",
    L"Synchronize label",
    KK_DIRECT | KK_CHAR | KK_CTRL | ':',
    MCommentAndLabel,
    NULL,
    NM_LABEL
  },
  { NULL, NULL, K_NONE, NULL, NULL, 0 }
};

// Plugin menu that will appear in "Dump" Window
// Define one shortcut:
//     "ctrl + :" to enable label synchro
static t_menu dumpmenu[] = {
  { L"[Sync] Label",
    L"Synchronize label",
    KK_DIRECT | KK_CHAR | KK_CTRL | ':',
    MCommentAndLabel,
    NULL,
    NM_LABEL
  },
  { NULL, NULL, K_NONE, NULL, NULL, 0 }
};
// Adds items either to main OllyDbg menu (type=PWM_MAIN)
extc t_menu * __cdecl ODBG2_Pluginmenu(wchar_t *type) {
    if (wcscmp(type,PWM_MAIN)==0)
        return mainmenu;
    else if(wcscmp(type, PWM_DISASM) == 0)
       return disasmmenu;
    else if (wcscmp(type, PWM_DUMP) == 0)
        return dumpmenu;
    return NULL;                         // No menu
};


// Entry point of the plugin DLL.
BOOL WINAPI DllEntryPoint(HINSTANCE hi, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);

    if (reason==DLL_PROCESS_ATTACH)
        hdllinst=hi;
    return 1;
};

// ODBG2_Pluginquery:
// - check whether given OllyDbg version is correctly supported
// - fill plugin name and plugin version (as UNICODE strings) and
//   return version of expected plugin interface.
extc int __cdecl ODBG2_Pluginquery(int ollydbgversion, ulong *features,
    wchar_t pluginname[SHORTNAME], wchar_t pluginversion[SHORTNAME])
{
    UNREFERENCED_PARAMETER(features);

    #if VERBOSE >= 2
    dbgout("[*] ODBG2_Pluginquery\n");
    #endif
    if (ollydbgversion<201)
        return 0;

    wcscpy_s(pluginname, SHORTNAME, PLUGINNAME);
    wcscpy_s(pluginversion, SHORTNAME, VERSION);
    return PLUGIN_VERSION;
};

// ODBG2_Plugininit: one-time initializations and resources allocation
extc int __cdecl ODBG2_Plugininit(void)
{
    #if VERBOSE >= 2
    dbgout("[*] ODBG2_Plugininit\n");
    #endif

    g_Synchronized = 0;
    g_Base = 0;

    g_hPollCompleteEvent = CreateEvent(NULL, 1, 0, NULL);
    if (g_hPollCompleteEvent == NULL)
    {
        dbgout("[sync] Command polling feature init failed\n");
        return E_FAIL;
    }

    InitializeCriticalSection(&g_CritSectPollRelease);
    if(SUCCEEDED(LoadConfigurationFile()))
        dbgout("[sync] Configuration file loaded\n       -> set HOST to %s:%s\n", g_DefaultHost, g_DefaultPort);

    return 0;
};


// ODBG2_Pluginreset: called when user opens new or restarts current application.
// Plugin should reset internal variables and data structures to the initial
// state.
extc void __cdecl ODBG2_Pluginreset(void)
{
    #if VERBOSE >= 2
    dbgout("[*] ODBG2_Pluginclose\n");
    #endif

    g_Base = 0;
};


// ODBG2_Pluginclose: called when user wants to terminate OllyDbg.
extc int __cdecl ODBG2_Pluginclose(void)
{
    #if VERBOSE >= 2
    dbgout("[*] ODBG2_Pluginclose\n");
    #endif

    return 0;
};


// ODBG2_Plugindestroy: called once on exit.
extc void __cdecl ODBG2_Plugindestroy(void)
{
    #if VERBOSE >= 2
    dbgout("[*] ODBG2_Plugindestroy\n");
    #endif

    ReleasePollTimer();
    DeleteCriticalSection(&g_CritSectPollRelease);
    TunnelClose();

    if(g_ExtConfFile)
    {
        free(g_DefaultHost);
        free(g_DefaultPort);
    }
}


// ODBG2_Pluginnotify: notifies plugin on relatively infrequent events.
extc void __cdecl ODBG2_Pluginnotify(int code, void *data, ulong param1, ulong param2)
{
    UNREFERENCED_PARAMETER(param1);
    UNREFERENCED_PARAMETER(param2);
    UNREFERENCED_PARAMETER(data);

    #if VERBOSE >= 2
    dbgout("[*] ODBG2_Pluginnotify\n");
    #endif

    switch (code) {
    case PN_STATUS:
        #if VERBOSE >= 2
        dbgout("[*] PN_STATUS, status %x\n", run.status);
        #endif

        if (run.status == STAT_PAUSED)
        {
            if (SUCCEEDED(TunnelIsUp()))
            {
                UpdateState();
                CreatePollTimer();
            }
        }
        break;

    case PN_RUN:
        #if VERBOSE >= 2
        dbgout("[*] status PN_RUN\n");
        #endif

        ReleasePollTimer();
        break;

    case PN_NEWPROC:
        // uncomment to sync by default
        //sync(NULL);
        break;

    case PN_ENDPROC:
        syncoff();
        break;

    default:
        break;
    };
};

