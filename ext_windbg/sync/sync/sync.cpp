/*
Copyright (C) 2016-2020, Alexandre Gazet.

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

#include "sync.h"
#include "tunnel.h"
#include "outputcallbacks.h"

#include <wincrypt.h>
#include <strsafe.h>
#include <shlwapi.h>

#define VERBOSE 0
#define MAX_NAME 1024
#define BUFSIZE 1024
#define TIMER_PERIOD 100
#define CONF_FILE "\\.sync"

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "Shlwapi.lib")
#pragma comment (lib, "dbgeng.lib")


PDEBUG_CLIENT4              g_ExtClient;
PDEBUG_CONTROL              g_ExtControl;
PDEBUG_SYMBOLS3             g_ExtSymbols;
PDEBUG_REGISTERS            g_ExtRegisters;
WINDBG_EXTENSION_APIS   ExtensionApis;

// Default host value is locahost
static CHAR *g_DefaultHost = "127.0.0.1";
static CHAR *g_DefaultPort = "9100";
BOOL g_ExtConfFile = false;

// Buffer used to solve symbol's name
static CHAR g_NameBuffer[MAX_NAME];

// Buffer used to receive breakpoint command
CMD_BUFFER g_CmdBuffer;


// Debuggee's state;
ULONG64 g_Offset = NULL;
ULONG64 g_Base = NULL;

// Synchronisation mode
static BOOL g_SyncAuto = true;

// Command polling feature
static HANDLE g_hPollTimer;
static HANDLE g_hPollCompleteEvent;
static CRITICAL_SECTION g_CritSectPollRelease;

// Queries for all debugger interfaces.
extern "C" HRESULT
ExtQuery(PDEBUG_CLIENT4 Client)
{
    HRESULT hRes = S_OK;

    if (g_ExtClient != NULL){
        return S_OK;
    }

    if (FAILED(hRes = Client->QueryInterface(__uuidof(IDebugControl), (void **)&g_ExtControl))){
        goto Fail;
    }

#if VERBOSE >= 2
    dprintf("[sync] IDebugControl loaded\n");
#endif

    if (FAILED(hRes = Client->QueryInterface(__uuidof(IDebugSymbols3), (void **)&g_ExtSymbols))){
        goto Fail;
    }

#if VERBOSE >= 2
    dprintf("[sync] IDebugSymbols3 loaded\n");
#endif

    if (FAILED(hRes = Client->QueryInterface(__uuidof(IDebugRegisters), (void **)&g_ExtRegisters))){
        goto Fail;
    }

#if VERBOSE >= 2
    dprintf("[sync] IDebugRegisters loaded\n");
#endif

    g_ExtClient = Client;
    return S_OK;

Fail:
    ExtRelease();
    return hRes;
}


// Cleans up all debugger interfaces.
void
ExtRelease(void)
{
    dprintf("[sync] COM interfaces released\n");
    g_ExtClient = NULL;
    EXT_RELEASE(g_ExtControl);
    EXT_RELEASE(g_ExtSymbols);
    EXT_RELEASE(g_ExtRegisters);
}


HRESULT
LoadConfigurationFile()
{
    DWORD count = 0;
    HRESULT hRes = S_OK;
    HANDLE hFile;
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
        return E_FAIL;
    }

    CloseHandle(hFile);

    lpConfHost = (LPTSTR)malloc(MAX_PATH);
    lpConfPort = (LPTSTR)malloc(MAX_PATH);
    if (lpConfHost == NULL || lpConfPort == NULL){
		goto Fail;
    }

    count = GetPrivateProfileString("INTERFACE", "host", "127.0.0.1", lpConfHost, MAX_PATH, lpProfile);
    if ((count == 0) || (count >= (MAX_PATH - 2))){
		goto Fail;
    }

    count = GetPrivateProfileString("INTERFACE", "port", "9100", lpConfPort, MAX_PATH, lpProfile);
    if ((count == 0) || (count >= (MAX_PATH - 2))){
		goto Fail;
    }

    g_DefaultHost = lpConfHost;
    g_DefaultPort = lpConfPort;
    g_ExtConfFile = true;

    return hRes;

Fail:
    if (lpConfHost != NULL){ free(lpConfHost); }
    if (lpConfPort != NULL){ free(lpConfPort); }

    return E_FAIL;
}


// Update state and send info to client: eip module's base address, offset, name
HRESULT
UpdateState()
{
    HRESULT hRes;
    ULONG64 PrevBase = g_Base;
    ULONG NameSize = 0;

    /*
    msdn: GetInstructionOffset method returns the location of
    the current thread's current instruction.
    */
    hRes = g_ExtRegisters->GetInstructionOffset(&g_Offset);
    if (FAILED(hRes)){
        dprintf("[sync] failed to GetInstructionOffset\n");
        goto UPDATE_FAILURE;
    }

    /*
    msdn: GetModuleByOffset method searches through the target's modules for one
    whose memory allocation includes the specified location.
    */
    hRes = g_ExtSymbols->GetModuleByOffset(g_Offset, 0, NULL, &g_Base);
    if (FAILED(hRes)){
        dprintf("[sync] failed to GetModuleByOffset for offset: 0x%I64x\n", g_Offset);
        goto UPDATE_FAILURE;
    }

    // Check if we are in a new module
    if ((g_Base != PrevBase) & g_SyncAuto)
    {
        /*
        Update module name stored in g_NameBuffer
        msdn: GetModuleNameString  method returns the name of the specified module.
        */
        hRes = g_ExtSymbols->GetModuleNameString(DEBUG_MODNAME_LOADED_IMAGE, DEBUG_ANY_ID, g_Base, g_NameBuffer, MAX_NAME, &NameSize);
        if (SUCCEEDED(hRes)){
            if ((NameSize > 0) & (((char)*g_NameBuffer) != 0))
            {
#if VERBOSE >= 2
                dprintf("[sync] DEBUG_MODNAME_LOADED_IMAGE: \"%s\"\n", g_NameBuffer);
#endif

                hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", g_NameBuffer);
                if (FAILED(hRes)){
                    return hRes;
                }
            }
        }
    }

    hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", g_Base, g_Offset);
    return hRes;

UPDATE_FAILURE:
    // Inform the dispatcher that an error occured in the state update
    if (g_Base != NULL)
    {
        TunnelSend("[notice]{\"type\":\"dbg_err\"}\n");
        g_ExtControl->ControlledOutput(
            DEBUG_OUTCTL_AMBIENT_DML,
            DEBUG_OUTPUT_NORMAL,
            "<?dml?>       hint: <exec cmd=\".reload\">.reload</exec> command may help\n");

        g_Base = NULL;
    }

    return hRes;
}


HRESULT
Identity(PSTR *Buffer)
{
    HRESULT hRes;
    ULONG IdentitySize = 0;

    hRes = g_ExtClient->GetIdentity(NULL, NULL, &IdentitySize);
    if (FAILED(hRes))
    {
        dprintf("[sync] GetIdentity failed\n");
        return hRes;
    }

    *Buffer = (PSTR)malloc(IdentitySize + 1);
    if (Buffer == NULL)
    {
        dprintf("[sync] Identity failed to allocate buffer: %d\n", GetLastError());
        return E_FAIL;
    }

    hRes = g_ExtClient->GetIdentity(*Buffer, IdentitySize, &IdentitySize);
    if (FAILED(hRes))
    {
        dprintf("[sync] GetIdentity failed\n");
        return hRes;
    }

    return hRes;
}


BOOL
IsLocalDebuggee()
{
    HRESULT hRes = S_OK;
    BOOL bLocal = FALSE;
    ULONG Class;
    ULONG Qualifier;

    hRes = g_ExtControl->GetDebuggeeType(&Class, &Qualifier);
    if (FAILED(hRes)){
        return bLocal;
    }

    if ((Class == DEBUG_CLASS_USER_WINDOWS) & (Qualifier == DEBUG_USER_WINDOWS_PROCESS)){
        bLocal = TRUE;
    }

    else if ((Class == DEBUG_CLASS_KERNEL) & (Qualifier == DEBUG_KERNEL_LOCAL)){
        bLocal = TRUE;
    }

    return bLocal;
}


// Poll socket for incoming commands
HRESULT
PollCmd()
{
    HRESULT hRes = S_OK;
    int NbBytesRecvd = 0;
    int ch = 0xA;
    char *msg, *next, *orig = NULL;

    hRes = TunnelPoll(&NbBytesRecvd, &msg);
    if (SUCCEEDED(hRes) && (NbBytesRecvd > 0) && (msg != NULL))
    {
        orig = msg;

        while ((msg - orig) < NbBytesRecvd)
        {
            next = strchr(msg, ch);
            if (next != NULL){
                *next = 0;
            }

            hRes = g_ExtControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, msg, DEBUG_EXECUTE_ECHO);
            if (FAILED(hRes))
                dprintf("[sync] failed to execute received command\n", msg);

            // No more command
            if (next == NULL){
                break;
            }

            msg = next + 1;
        }

        free(orig);
    }

    return hRes;
}


VOID
ReleasePollTimer()
{
    BOOL bRes;
    DWORD dwErr;

    EnterCriticalSection(&g_CritSectPollRelease);

#if VERBOSE >= 2
    dprintf("[sync] ReleasePollTimer called\n");
#endif

    if (!(g_hPollTimer == INVALID_HANDLE_VALUE))
    {
        ResetEvent(g_hPollCompleteEvent);
        bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
        if (bRes == NULL)
        {
            // msdn: If the error code is ERROR_IO_PENDING, it is not necessary to
            // call this function again. For any other error, you should retry the call.
            dwErr = GetLastError();
            if (dwErr != ERROR_IO_PENDING){
                bRes = DeleteTimerQueueTimer(NULL, g_hPollTimer, g_hPollCompleteEvent);
                if (!(bRes)){
                    dprintf("[sync] failed to DeleteTimerQueueTimer\n");
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
        dprintf("[sync] failed to CreatePollTimer\n");
    }
}


// Under certain conditions, breakpoint event should be dismissed
// msdn: bp 0x1000 "r rax; g"
// Problem: matching conditionnal commands:
//       bp Address ".if (Condition) {OptionalCommands} .else {gc}"
HRESULT
EventFilterCb(BOOL *pbIgnoreEvent)
{
    HRESULT hRes = S_OK;
    ULONG Type, ProcessId, ThreadId, BreakpointId, ExtraInformationUsed, CommandSize;
    PDEBUG_BREAKPOINT Breakpoint;
    CHAR *LastCommand;

    // msdn: Returns information about the last event that occurred in a target.
    hRes = g_ExtControl->GetLastEventInformation(&Type, &ProcessId, &ThreadId, &BreakpointId, sizeof(ULONG),
        &ExtraInformationUsed, NULL, NULL, NULL);

    if (FAILED(hRes)){
        goto Exit;
    }

    // ignore some specific debug events
    if ((Type == DEBUG_EVENT_CHANGE_SYMBOL_STATE) || (Type == DEBUG_EVENT_UNLOAD_MODULE) || (Type == DEBUG_EVENT_LOAD_MODULE))
    {
        *pbIgnoreEvent = true;
        goto Exit;
    }

    if ((Type != DEBUG_EVENT_BREAKPOINT) || (ExtraInformationUsed != 4)){
        goto Exit;
    }

    hRes = g_ExtControl->GetBreakpointById(BreakpointId, &Breakpoint);
    if (FAILED(hRes)){
        goto Exit;
    }

    // msdn: Returns the command string that is executed when a breakpoint is triggered.
    hRes = Breakpoint->GetCommand(g_CmdBuffer.buffer, MAX_CMD, &CommandSize);
    if (SUCCEEDED(hRes))
    {
        if (CommandSize > 1)
        {
            bool bTrackingColon = false;
            bool bTrackingG = false;

            for (ULONG i = CommandSize - 1; i < CommandSize; i--) {
                if (bTrackingColon) {
                    if (g_CmdBuffer.buffer[i] == 'g') {
                        bTrackingColon = false;
                        bTrackingG = true;
                    }
                }
                else if (bTrackingG) {
                    if (g_CmdBuffer.buffer[i] == ' ' || g_CmdBuffer.buffer[i] == ';') {
                        *pbIgnoreEvent = true;
                    }

                    break;
                }
                else {

                    if (g_CmdBuffer.buffer[i] == ';') {
                        bTrackingColon = true;
                    }
                    else if (g_CmdBuffer.buffer[i] == 'g') {
                        bTrackingG = true;
                    }
                }
            }
        }
    }

Exit:
    return hRes;
}


// plugin initialization
extern "C"
HRESULT
CALLBACK
DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    HRESULT hRes = S_OK;
    IDebugClient *DebugClient;
    PDEBUG_CONTROL DebugControl;

    *Version = DEBUG_EXTENSION_VERSION(EXT_MAJOR_VER, EXT_MINOR_VER);
    *Flags = 0;

    if (FAILED(hRes = DebugCreate(__uuidof(IDebugClient), (void **)&DebugClient))){
        return hRes;
    }

    if (SUCCEEDED(hRes = DebugClient->QueryInterface(__uuidof(IDebugControl), (void **)&DebugControl)))
    {
        // Get the windbg-style extension APIS
        ExtensionApis.nSize = sizeof(ExtensionApis);
        hRes = DebugControl->GetWindbgExtensionApis64(&ExtensionApis);
        DebugControl->Release();
        dprintf("[sync] DebugExtensionInitialize, ExtensionApis loaded\n");
    }

    DebugClient->Release();
    g_ExtClient = NULL;
    g_Synchronized = FALSE;
    g_hPollTimer = INVALID_HANDLE_VALUE;

    g_hPollCompleteEvent = CreateEvent(NULL, true, false, NULL);
    if (g_hPollCompleteEvent == NULL)
    {
        dprintf("[sync] Command polling feature init failed\n");
        return E_FAIL;
    }

    InitializeCriticalSection(&g_CritSectPollRelease);

    if (SUCCEEDED(LoadConfigurationFile())){
        dprintf("[sync] Configuration file loaded\n       -> set HOST to %s:%s\n", g_DefaultHost, g_DefaultPort);
    }

    return hRes;
}


// notification callback
extern "C"
void
CALLBACK
DebugExtensionNotify(ULONG Notify, ULONG64 Argument)
{
    UNREFERENCED_PARAMETER(Argument);
    HRESULT hRes = S_OK;
    BOOL bIgnoreEvent = false;

    switch (Notify){
    case DEBUG_NOTIFY_SESSION_ACTIVE:
#if VERBOSE >= 2
        dprintf("[sync] DebugExtensionNotify: A debugging session is active. The session may not necessarily be suspended.\n");
#endif
        break;

    case DEBUG_NOTIFY_SESSION_INACTIVE:
#if VERBOSE >= 2
        dprintf("[sync] DebugExtensionNotify: No debugging session is active.\n");
#endif
        break;

    case DEBUG_NOTIFY_SESSION_ACCESSIBLE:
#if VERBOSE >= 2
        dprintf("[sync] DebugExtensionNotify: The debugging session has suspended and is now accessible.\n");
#endif
        if (SUCCEEDED(TunnelIsUp()))
        {
            hRes = EventFilterCb(&bIgnoreEvent);
            if (SUCCEEDED(hRes) && bIgnoreEvent){
                break;
            }

            UpdateState();
            CreatePollTimer();
        }
        break;

    case DEBUG_NOTIFY_SESSION_INACCESSIBLE:
#if VERBOSE >= 2
        dprintf("[sync] DebugExtensionNotify: The debugging session has started running and is now inaccessible.\n");
#endif
        ReleasePollTimer();
        break;

    default:
#if VERBOSE >= 2
        dprintf("[sync] DebugExtensionNotify: Unknown Notify reason (%x).\n", Notify);
#endif
        break;
    }

    return;
}


extern "C"
void
CALLBACK
DebugExtensionUninitialize(void)
{
    dprintf("[sync] DebugExtensionUninitialize\n");

    ReleasePollTimer();
    DeleteCriticalSection(&g_CritSectPollRelease);
    TunnelClose();

    if (g_ExtConfFile)
    {
        free(g_DefaultHost);
        free(g_DefaultPort);
    }

    EXIT_API();
    return;
}


HRESULT
CALLBACK
sync(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    PCSTR Host;
    PSTR pszId = NULL;
    INIT_API();

    // Reset global state
    g_Base = NULL;
    g_Offset = NULL;

#if VERBOSE >= 2
    dprintf("[sync] sync function called\n");
#endif

    if (g_Synchronized)
    {
        dprintf("[sync] sync update\n");
        UpdateState();
        goto Exit;
    }

    if (!Args || !*Args) {
        dprintf("[sync] No argument found, using default host (%s:%s)\n", g_DefaultHost, g_DefaultPort);
        Host = g_DefaultHost;
    }
    else{
        Host = Args;
    }

    if (FAILED(hRes = TunnelCreate(Host, g_DefaultPort)))
    {
        dprintf("[sync] sync failed\n");
        goto Exit;
    }

    dprintf("[sync] probing sync\n");

    if (FAILED(hRes = Identity(&pszId)))
    {
        dprintf("[sync] get identity failed\n");
        goto Exit;
    }

    hRes = TunnelSend("[notice]{\"type\":\"new_dbg\",\"msg\":\"dbg connect - %s\",\"dialect\":\"windbg\"}\n", pszId);
    if (FAILED(hRes))
    {
        dprintf("[sync] sync aborted\n");
        goto Exit;
    }

    dprintf("[sync] sync is now enabled with host %s\n", Host);
    UpdateState();
    CreatePollTimer();

Exit:
    if (!(pszId == NULL)){
        free(pszId);
    }

    return hRes;
}


HRESULT
CALLBACK
syncoff(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    UNREFERENCED_PARAMETER(Args);
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !syncoff  command called\n");
#endif

    if (!g_Synchronized){
        return hRes;
    }

    ReleasePollTimer();
    hRes = TunnelClose();
    dprintf("[sync] sync is now disabled\n");

    return hRes;
}


HRESULT
CALLBACK
syncmodauto(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    char * msg;
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !syncmodauto called\n");
#endif

    if (!Args || !*Args){
        goto syncmod_arg_fail;
    }

    if (strcmp("on", Args) == 0)
    {
        msg = (char *)Args;
        g_SyncAuto = true;
    }
    else if (strcmp("off", Args) == 0)
    {
        msg = (char *)Args;
        g_SyncAuto = false;
    }
    else{
        goto syncmod_arg_fail;
    }

    hRes = TunnelSend("[notice]{\"type\":\"sync_mode\",\"auto\":\"%s\"}\n", msg);
    return hRes;

syncmod_arg_fail:
    dprintf("[sync] usage !syncmodauto <on|off>\n");
    return E_FAIL;
}


// execute a command and dump its output
HRESULT
CALLBACK
curmod(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes;
    ULONG64 Offset = 0;
    ULONG64 Base = 0;
    ULONG NameSize = 0;
    CHAR NameBuffer[MAX_NAME] = {0};

    /*
    msdn: GetInstructionOffset method returns the location of
    the current thread's current instruction.
    */
    hRes = g_ExtRegisters->GetInstructionOffset(&Offset);
    if (FAILED(hRes)) {
        dprintf("[sync] failed to GetInstructionOffset\n");
        return hRes;
    }

    dprintf("[sync] instruction offset: %p\n", Offset);

    /*
    msdn: GetModuleByOffset method searches through the target's modules for one
    whose memory allocation includes the specified location.
    */
    hRes = g_ExtSymbols->GetModuleByOffset(Offset, 0, NULL, &Base);
    if (FAILED(hRes)) {
        dprintf("[sync] failed to GetModuleByOffset for offset: 0x%I64x\n", Base);
        return hRes;
    }

    dprintf("       module base: %p\n", Base);

    /*
    Update module name stored in g_NameBuffer
    msdn: GetModuleNameString  method returns the name of the specified module.
    */
    hRes = g_ExtSymbols->GetModuleNameString(DEBUG_MODNAME_LOADED_IMAGE, DEBUG_ANY_ID, Base, NameBuffer, MAX_NAME, &NameSize);
    if (SUCCEEDED(hRes)) {
        if ((NameSize > 0) & (((char)*NameBuffer) != 0))
        {
            dprintf("       module name: %s\n", NameBuffer);
        }
    }

    return hRes;
}


// execute a command and dump its output
HRESULT
CALLBACK
cmd(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    ULONG Flags;
    PDEBUG_OUTPUT_CALLBACKS Callbacks;
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !cmd command called\n");
#endif

    if (!Args || !*Args) {
        dprintf("[sync] !cmd <command to execute and dump>\n");
        return E_FAIL;
    }

    if (FAILED(hRes = g_ExtClient->GetOutputCallbacks(&Callbacks)))
    {
        dprintf("[sync] GetOutputCallbacks failed\n");
        goto Exit;
    }

    if (FAILED(hRes = g_ExtClient->SetOutputCallbacks(&g_OutputCb)))
    {
        dprintf("[sync] SetOutputCallbacks failed\n");
        goto Exit;
    }

    // msdn: Execute method executes the specified debugger commands.
    Flags = DEBUG_EXECUTE_ECHO;

    if (g_OutputCbLocal){
        Flags = DEBUG_EXECUTE_NOT_LOGGED;
    }

    hRes = g_ExtControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, Args, Flags);

    g_ExtClient->FlushCallbacks();
    g_ExtClient->SetOutputCallbacks(Callbacks);

#if VERBOSE >= 2
    dprintf("[sync] OutputCallbacks removed\n");
#endif

Exit:
    return hRes;
}


// execute a command, output is redirected to a local buffer
HRESULT
LocalCmd(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    g_CmdBuffer.len = 0;
    ZeroMemory(g_CmdBuffer.buffer, MAX_CMD);

    g_OutputCbLocal = true;
    hRes = cmd(Client, Args);
    g_OutputCbLocal = false;

    return hRes;
}


// execute a list of command ('\n' split)
HRESULT
ExecCmdList(PCSTR cmd)
{
    HRESULT hRes = S_OK;
    ULONG Status;
    char *ptr, *end;

    ptr = (char *)cmd;
    end = ptr + strlen(cmd);

    while (cmd < end)
    {
        ptr = (char *)strchr(cmd, 0x0a);
        if (ptr != NULL){
            *ptr = 0;
        }
        else{
            break;
        }

        // msdn: Executes the specified debugger commands.
        hRes = g_ExtControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, cmd, DEBUG_EXECUTE_ECHO | DEBUG_EXECUTE_NO_REPEAT);
        if (FAILED(hRes)) {
            break;
        }

        // msdn: Describes the nature of the current target.
        hRes = g_ExtControl->GetExecutionStatus(&Status);
        if (FAILED(hRes)){
            break;
        }

        // Drop commands if the target is not paused
        if (!(Status == DEBUG_STATUS_BREAK)){
            break;
        }

        cmd = ptr + 1;
    }

    return hRes;
}


HRESULT
CALLBACK
cmt(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !cmt called\n");
#endif

    if (!Args || !*Args) {
        dprintf("[sync] !cmt <comment to add>\n");
        return E_FAIL;
    }

    hRes = TunnelSend("[sync]{\"type\":\"cmt\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", Args, g_Base, g_Offset);

    return hRes;
}


HRESULT
CALLBACK
rcmt(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !rcmt called\n");
#endif

    if (!Args || !*Args) {
        Args = "";
    }

    hRes = TunnelSend("[sync]{\"type\":\"rcmt\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", Args, g_Base, g_Offset);

    return hRes;
}


HRESULT
CALLBACK
fcmt(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !fcmt called\n");
#endif

    if (!Args || !*Args) {
        Args = "";
    }

    hRes = TunnelSend("[sync]{\"type\":\"fcmt\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", Args, g_Base, g_Offset);

    return hRes;
}


HRESULT
CALLBACK
lbl(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !lbl called\n");
#endif

    if (!Args || !*Args) {
        dprintf("[sync] !lbl <comment to add>\n");
        return E_FAIL;
    }

    hRes = TunnelSend("[sync]{\"type\":\"lbl\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", Args, g_Base, g_Offset);

    return hRes;
}


HRESULT
CALLBACK
bc(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    ULONG DwRGB = 0;
    ULONG RemainderIndex;
    DEBUG_VALUE DebugValue = {};
    char * msg;
    char * rgb_msg[64] = { 0 };
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !bc called\n");
#endif

    if (!Args || !*Args)
    {
        msg = "oneshot";
    }
    else if (strcmp("on", Args) == 0)
    {
        msg = (char *)Args;
    }
    else if (strcmp("off", Args) == 0)
    {
        msg = (char *)Args;
    }

    else if (strncmp("set ", Args, 4) == 0)
    {
        *((char *)Args + 3) = 0;
        hRes = g_ExtControl->Evaluate((char *)(Args + 4), DEBUG_VALUE_INT32, &DebugValue, &RemainderIndex);
        if (FAILED(hRes))
        {
            dprintf("[sync] failed to evaluate RGB code\n");
            return E_FAIL;
        }

        DwRGB = (ULONG)DebugValue.I32;
        _snprintf_s((char *)rgb_msg, 64, _TRUNCATE, "%s\", \"rgb\":%lu, \"reserved\":\"", Args, DwRGB);
        msg = (char *)rgb_msg;
    }
    else
    {
        dprintf("[sync] usage !bc <|||on|off|set 0xBBGGRR> >\n");
        return E_FAIL;
    }

    hRes = TunnelSend("[notice]{\"type\":\"bc\",\"msg\":\"%s\",\"base\":%llu,\"offset\":%llu}\n", msg, g_Base, g_Offset);
    return hRes;
}


char* trim_entry(char* line)
{
    char* backward = NULL;

    // trim newline
    strtok_s(line, "\n", &backward);

    // trim leading whitespace
    while (isspace(*line))
        line++;

    strtok_s(line, "(", &backward);
    backward = line + strlen(line);

    // trim trailing whitespace
    while (isspace(backward[-1]))
        backward--;

    *backward = '\0';
    return line;
}


HRESULT
CALLBACK
idblist(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    int NbBytesRecvd = 0;
    int i = 0;
    char* msg = NULL;
    char* ctx = NULL;
    char* mod = NULL;
    UNREFERENCED_PARAMETER(Args);
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !idblist called\n");
#endif

    ReleasePollTimer();

    hRes = TunnelSend("[notice]{\"type\":\"idb_list\"}\n");
    if (FAILED(hRes)){
        dprintf("[sync] !idblist failed\n");
        goto TIMER_REARM_EXIT;
    }

    hRes = TunnelReceive(&NbBytesRecvd, &msg);
    if (SUCCEEDED(hRes) && (NbBytesRecvd > 0) && (msg != NULL))
    {
        strtok_s(msg, "\n", &ctx);

        while (strtok_s(NULL, "]", &ctx) != NULL)
        {
            mod = strtok_s(NULL, "\n", &ctx);
            if (mod == NULL)
                break;

            hRes = g_ExtControl->ControlledOutput(
                DEBUG_OUTCTL_AMBIENT_DML,
                DEBUG_OUTPUT_NORMAL,
                "<?dml?>    [%d] <exec cmd=\"!idbn %d\">%s</exec>\n",
                i, i, trim_entry(mod));

            i++;
        }

        free(msg);
    }

TIMER_REARM_EXIT:
    CreatePollTimer();
    return hRes;
}


HRESULT
GetModuleByImageName(CHAR* ImageName, PULONG64 pModuleBase, PCHAR* pModuleName)
{
    HRESULT hRes = S_OK;
    errno_t err = 0;
    ULONG Loaded, Unloaded;
    ULONG ImageNameSize = 0;
    ULONG ModuleNameSize = 0;
    ULONG LoadedImageNameSize = 0;
    ULONG64 Base = 0;
    CHAR ImageNameBuffer[MAX_NAME] = {0};
    CHAR ModuleNameBuffer[MAX_NAME] = {0};
    CHAR LoadedImageNameBuffer[MAX_NAME] = {0};
    unsigned int i = 0;

    if (pModuleBase != NULL)
        *pModuleBase = NULL;
    if (pModuleName != NULL)
        *pModuleName = NULL;

    hRes = g_ExtSymbols->GetNumberModules(&Loaded, &Unloaded);
    if (FAILED(hRes)) {
        dprintf("[sync] GetNumberModules failed\n");
        return hRes;
    }

    for (i = 0; i < Loaded; i++)
    {
        hRes = g_ExtSymbols->GetModuleByIndex(i, &Base);
        if (FAILED(hRes)) {
            dprintf("[sync] GetModuleByIndex failed\n");
            return hRes;
        }

        /*
        msdn: GetModuleNames method returns the names of the specified module.
        */
        hRes = g_ExtSymbols->GetModuleNames(
            DEBUG_ANY_ID,
            Base,
            ImageNameBuffer, MAX_NAME, &ImageNameSize,
            ModuleNameBuffer, MAX_NAME, &ModuleNameSize,
            LoadedImageNameBuffer, MAX_NAME, &LoadedImageNameSize
        );

        if (hRes != S_OK) {
            dprintf("[sync] GetModuleNames failed (0x%x)\n", hRes);
            return E_FAIL;
        }

        if (strcmp(ImageName, PathFindFileName(ImageNameBuffer)) == 0)
        {
            if (pModuleBase != NULL)
            {
                hRes = g_ExtSymbols->GetModuleByIndex(i, pModuleBase);
                if (FAILED(hRes)) {
                    dprintf("[sync] GetModuleByIndex failed\n");
                    return hRes;
                }
            }

            if (pModuleName != NULL)
            {
                *pModuleName = (PCHAR)malloc(ModuleNameSize);
                err = strncpy_s(*pModuleName, ModuleNameSize, ModuleNameBuffer, _TRUNCATE);
                if (err == STRUNCATE) {
                    free(*pModuleName);
                    return E_FAIL;
                }

            }

            return hRes;
        }
    }

    return E_FAIL;
}

HRESULT
CALLBACK
idbn(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    ULONG64 Base = 0;
    int NbBytesRecvd = 0;
    char* msg = NULL;
    char* img_name = NULL;
    char* mod_name = NULL;
    char* context = NULL;
    INIT_API();

    if (!Args || !*Args) {
        dprintf("[sync] !idbn <idb num>\n");
        return E_FAIL;
    }

    // strip trailing whitespaces
    strtok_s((char*)Args, " ", &context);

    ReleasePollTimer();

    hRes = TunnelSend("[notice]{\"type\":\"idb_n\",\"idb\":\"%s\"}\n", Args);
    if (FAILED(hRes)){
        dprintf("[sync] !idbn failed to send notice\n");
        return E_FAIL;
    }

    hRes = TunnelReceive(&NbBytesRecvd, &msg);
    if (FAILED(hRes))
        goto DBG_ERROR;

    // check if dispatcher answered with an error message
    // e.g. "> idb_n error: index %d is invalid (see idblist)"
    if (strstr(msg, "> idb_n error:") != NULL)
    {
        dprintf("%s\n", msg);
        goto DBG_ERROR;
    }

    strtok_s(msg, "\"", &context);
    img_name = strtok_s(NULL, "\"", &context);
    if (img_name == NULL)
    {
        dprintf("[sync] idb_n: invalid answser - could not extract image name\n");
        goto DBG_ERROR;
    }

    hRes = GetModuleByImageName(img_name, &Base, &mod_name);
    if (FAILED(hRes)) {
        dprintf("[sync] idb_n: GetModuleByImageName failed for image \"%s\"\n", img_name);
        dprintf("       module may not be loaded, idb switch canceled\n");
        goto DBG_ERROR;
    }

    hRes = g_ExtControl->ControlledOutput(
         DEBUG_OUTCTL_AMBIENT_DML,
         DEBUG_OUTPUT_NORMAL,
         "<?dml?>> active idb is now \"<exec cmd=\"lmvm %s\">%s</exec>\" (%s)\n", mod_name, img_name, Args);

    if (mod_name != NULL)
        free(mod_name);

    if (FAILED(hRes)) {
        dprintf("[sync] ControlledOutput failed\n");
        goto DBG_ERROR;
    }

    // Send this module its remote base address
    hRes = TunnelSend("[sync]{\"type\":\"rbase\",\"rbase\":%llu}\n", Base);
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


HRESULT
CALLBACK
idb(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    ULONG64 Base = 0;
    ULONG ImageNameSize = 0;
    ULONG LoadedImageNameSize = 0;
    CHAR ImageNameBuffer[MAX_NAME] = { 0 };
    CHAR LoadedImageNameBuffer[MAX_NAME] = { 0 };
    CHAR *ModuleName = NULL;
    CHAR *Context = NULL;
    INIT_API();

    if (!Args || !*Args) {
        dprintf("[sync] !idb <module name>\n");
        return E_FAIL;
    }

    // strip trailing whitespaces
    strtok_s((char *)Args, " ", &Context);

    g_ExtControl->ControlledOutput(
        DEBUG_OUTCTL_AMBIENT_DML,
        DEBUG_OUTPUT_NORMAL,
        "<?dml?>> mod: \"<exec cmd=\"lmvm %s\">%s</exec>\"\n", Args, Args);

    /*
    msdn:  GetModuleByModuleName2 method searches through the process's modules for one with the specified name.
    */
    hRes = g_ExtSymbols->GetModuleByModuleName2(Args, 0, DEBUG_GETMOD_NO_UNLOADED_MODULES, NULL, &Base);
    if (FAILED(hRes)) {
        dprintf("[sync] GetModuleByModuleName2 failed for module: \"%s\"\n", Args);
        dprintf("       module may not be loaded, idb switch canceled\n");
        return hRes;
    }

    dprintf("> base address: %#Ix\n", Base);

    /*
    msdn: GetModuleNames method returns the names of the specified module.
    */
    hRes = g_ExtSymbols->GetModuleNames(
        DEBUG_ANY_ID,
        Base,
        ImageNameBuffer, MAX_NAME, &ImageNameSize,
        NULL, 0, NULL,
        LoadedImageNameBuffer, MAX_NAME, &LoadedImageNameSize);
    if (FAILED(hRes)) {
        dprintf("[sync] GetModuleNames failed for module at 0x%x\n", Base);
        return hRes;
    }

    // Ask dispatcher to enable the resolved module
    ModuleName = (LoadedImageNameSize > 1) ? LoadedImageNameBuffer : ImageNameBuffer;
    hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", ModuleName);
    if (FAILED(hRes)) {
        dprintf("[sync] TunnelSend failed for module notice\n");
        return hRes;
    }

    // Send this module its remote base address
    hRes = TunnelSend("[sync]{\"type\":\"rbase\",\"rbase\":%llu}\n", Base);
    if (FAILED(hRes)) {
        dprintf("[sync] TunnelSend failed for rbase message\n");
        return hRes;
    }

    return hRes;
}


HRESULT
CALLBACK
modlist(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    char* cmd = NULL;
    char* token_start = NULL;
    char* token_end = NULL;
    char* token_mod = NULL;
    char* token_nextline = NULL;
    char* token_index = NULL;
    UNREFERENCED_PARAMETER(Args);
    INIT_API();

    hRes = LocalCmd(Client, "!for_each_module .echo @#ModuleIndex @#Base @#End @#ModuleName @#ImageName @#LoadedImageName");
    if (FAILED(hRes) || FAILED(g_CmdBuffer.hRes) || (g_CmdBuffer.len == 0))
    {
        dprintf("[sync] failed to evaluate for_each_module one-liner, %x, %x\n", hRes, g_CmdBuffer.hRes);
        goto EXIT;
    }

    cmd = (char*)(g_CmdBuffer.buffer);

    // parse lines
    while (cmd != NULL)
    {
        token_index = strtok_s(NULL, " ", &cmd);
        if (token_index == NULL)
            break;

        token_start = strtok_s(NULL, " ", &cmd);
        token_end = strtok_s(NULL, " ", &cmd);
        token_mod = strtok_s(NULL, " ", &cmd);
        token_nextline = strtok_s(NULL, "\n", &cmd);

        hRes = g_ExtControl->ControlledOutput(
            DEBUG_OUTCTL_AMBIENT_DML,
            DEBUG_OUTPUT_NORMAL,
            "<?dml?>%s : %s %s <exec cmd=\"!idb %s\">%-24s</exec>  %s\n",
            token_index, token_start, token_end, token_mod, token_mod, token_nextline);
    }

EXIT:
    g_CmdBuffer.len = 0;
    ZeroMemory(g_CmdBuffer.buffer, MAX_CMD);
    return hRes;
}


HRESULT
CALLBACK
jmpto(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes;
    ULONG64 Base, Offset = 0;
    ULONG NameSize = 0;
    ULONG RemainderIndex;
    DEBUG_VALUE DebugValue = {};
    INIT_API();

    if (!Args || !*Args)
    {
        dprintf("[sync] !jumpto <expression>\n");
        return E_FAIL;
    }

    /*
    msdn: Evaluate method evaluates an expression, returning the result.
    */
    hRes = g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT64, &DebugValue, &RemainderIndex);
    if (FAILED(hRes))
    {
        dprintf("[sync] jumpto: failed to evaluate expression\n");
        return E_FAIL;
    }

    Offset = (ULONG64)DebugValue.I64;

    /*
    msdn: GetModuleByOffset method searches through the target's modules for one
    whose memory allocation includes the specified location.
    */
    hRes = g_ExtSymbols->GetModuleByOffset(Offset, 0, NULL, &Base);
    if (FAILED(hRes))
    {
        dprintf("[sync] jumpto: failed to get module base for address 0x%x\n", Offset);
        return E_FAIL;
    }

    /*
    Update module name stored in g_NameBuffer
    msdn: GetModuleNameString  method returns the name of the specified module.
    */
    hRes = g_ExtSymbols->GetModuleNameString(DEBUG_MODNAME_LOADED_IMAGE, DEBUG_ANY_ID, Base, g_NameBuffer, MAX_NAME, &NameSize);
    if (FAILED(hRes)){
        dprintf("[sync] jumpto: failed to get module name for target address\n");
        return E_FAIL;
    }

    if ((NameSize == 0) | (((char)*g_NameBuffer) == 0)){
        dprintf("[sync] jumpto: null module name for target address\n");
        return E_FAIL;
    }

    // Check if we are in a new module
    if (g_Base != Base)
    {
        // Update base address of current active module
        g_Base = Base;

        hRes = TunnelSend("[notice]{\"type\":\"module\",\"path\":\"%s\"}\n", g_NameBuffer);
        if (FAILED(hRes)){
            return hRes;
        }
    }

    hRes = TunnelSend("[sync]{\"type\":\"loc\",\"base\":%llu,\"offset\":%llu}\n", Base, Offset);

    return hRes;
}


HRESULT
CALLBACK
raddr(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes;
    ULONG64 Base, Offset = 0;
    ULONG RemainderIndex = 0;
    DEBUG_VALUE DebugValue = {};
    INIT_API();

    if (!Args || !*Args)
    {
        dprintf("[sync] !rebaseaddr <expression>\n");
        return E_FAIL;
    }

    /*
    msdn: Evaluate method evaluates an expression, returning the result.
    */
    hRes = g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT64, &DebugValue, &RemainderIndex);
    if (FAILED(hRes))
    {
        dprintf("[sync] rebaseaddr: failed to evaluate expression\n");
        return E_FAIL;
    }

    Offset = (ULONG64)DebugValue.I64;

    /*
    msdn: GetModuleByOffset method searches through the target's modules for one
    whose memory allocation includes the specified location.
    */
    hRes = g_ExtSymbols->GetModuleByOffset(Offset, 0, NULL, &Base);
    if (FAILED(hRes))
    {
        dprintf("[sync] rebaseaddr: failed to get module base for address 0x%x\n", Offset);
        return E_FAIL;
    }

    hRes = TunnelSend("[sync]{\"type\":\"raddr\",\"raddr\":%llu,\"rbase\":%llu,\"base\":%llu,\"offset\":%llu}\n",
        Offset, Base, g_Base, g_Offset);

    return hRes;
}


HRESULT
CALLBACK
rln(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes;
    ULONG64 Offset = 0;
    ULONG64 Displacement = 0;
    ULONG   NameSize = 0;
    ULONG RemainderIndex;
    DEBUG_VALUE DebugValue = {};
    char *msg = NULL;
    char* sym = NULL;
    char NameBuffer[MAX_NAME] = {0};
    int NbBytesRecvd = 0;
    INIT_API();

    if (!Args || !*Args)
    {
        dprintf("[sync] !rln <expression>\n");
        return E_FAIL;
    }

    /*
    msdn: Evaluate method evaluates an expression, returning the result.
    */
    hRes = g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT64, &DebugValue, &RemainderIndex);
    if (FAILED(hRes))
    {
        dprintf("[sync] rln: failed to evaluate expression\n");
        return E_FAIL;
    }

    Offset = (ULONG64)DebugValue.I64;

    // First disable tunnel polling for commands (happy race...)
    ReleasePollTimer();

    hRes = TunnelSend("[sync]{\"type\":\"rln\",\"raddr\":%llu}\n", Offset);
    if (FAILED(hRes))
    {
        dprintf("[sync] rln: TunnelSend failed\n");
        goto Exit;
    }

    // Let time for the IDB client to reply if it exists
    Sleep(150);

    // Poll tunnel
    hRes = TunnelPoll(&NbBytesRecvd, &msg);
    if (FAILED(hRes))
    {
        dprintf("[sync] rln poll failed\n");
        goto Exit;
    }

    if ((NbBytesRecvd == 0) || (msg == NULL))
    {
        dprintf("    -> no reply\n");
        goto Exit;
    }

    if (isspace(msg[NbBytesRecvd-1]))
    {
        msg[NbBytesRecvd-1] = 0;
    }

    // trim received sym
    sym = trim_entry(msg);
    dprintf("> resolved symbol: \"%s\"\n", sym);

    /*
    msdn: The AddSyntheticSymbol method adds a synthetic symbol to a module in the current process.
    */
    hRes = g_ExtSymbols->AddSyntheticSymbol(Offset, 1, sym, DEBUG_ADDSYNTHSYM_DEFAULT, NULL);
    if (FAILED(hRes))
    {
        if (hRes == 0x800700b7)
        {
            dprintf("[sync] AddSyntheticSymbol error: a symbol already exists\n");
            hRes = g_ExtSymbols->GetNearNameByOffset(Offset, 0, NameBuffer, _countof(NameBuffer), &NameSize, &Displacement);
            if (hRes == S_OK) {
                dprintf("> current symbol \"%s\" (disp: %#x)\n", NameBuffer, Displacement);
            }
        }
        else
        {
            dprintf("[sync] rln: AddSyntheticSymbol failed, 0x%x\n", hRes);
        }
    }

Exit:
    // Re-enable tunnel polling
    CreatePollTimer();

    if (msg){
        free(msg);
    }

    return hRes;
}


HRESULT
CALLBACK
jmpraw(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes;
    ULONG64 Offset = 0;
    ULONG RemainderIndex;
    DEBUG_VALUE DebugValue = {};
    INIT_API();

    if (!Args || !*Args)
    {
        dprintf("[sync] !jumpraw <expression>\n");
        return E_FAIL;
    }

    /*
    msdn: Evaluate method evaluates an expression, returning the result.
    */
    hRes = g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT64, &DebugValue, &RemainderIndex);
    if (FAILED(hRes))
    {
        dprintf("[sync] jumpraw: failed to evaluate expression\n");
        return E_FAIL;
    }

    Offset = (ULONG64)DebugValue.I64;

    hRes = TunnelSend("[sync]{\"type\":\"loc\",\"offset\":%llu}\n", Offset);

    return hRes;
}


HRESULT
CALLBACK
modmap(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes;
    ULONG64 ModBase = 0;
    ULONG ModSize;
    ULONG RemainderIndex;
    DEBUG_VALUE DebugValue = {};
    INIT_API();

    if (!Args || !*Args)
    {
        dprintf("[sync] !modmap <mod base> <mod size> <mod name>\n");
        return E_FAIL;
    }

    /*
    msdn: Evaluate method evaluates an expression, returning the result.
    */
    hRes = g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT64, &DebugValue, &RemainderIndex);
    if (FAILED(hRes))
    {
        dprintf("[sync] modmap: failed to evaluate module base\n");
        return E_FAIL;
    }

    ModBase = (ULONG64)DebugValue.I64;
    Args += RemainderIndex;

    hRes = g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT32, &DebugValue, &RemainderIndex);
    if (FAILED(hRes))
    {
        dprintf("[sync] modmap: failed to evaluate module size\n");
        return E_FAIL;
    }

    ModSize = (ULONG64)DebugValue.I32;
    Args += RemainderIndex;

    StrTrim((LPSTR)Args, " ");

    if (!*Args)
    {
        dprintf("[sync] modmap: failed to evaluate module name\n");
        return E_FAIL;
    }

    /*
    msdn: The AddSyntheticModule method adds a synthetic module to the module list the debugger
    maintains for the current process.
    */
    hRes = g_ExtSymbols->AddSyntheticModule(ModBase, ModSize, Args, Args, DEBUG_ADDSYNTHMOD_DEFAULT);
    if (FAILED(hRes))
    {
        dprintf("[sync] modmap: AddSyntheticModule failed\n");
        return E_FAIL;
    }

    /*
    msdn: The AddSyntheticSymbol method adds a synthetic symbol to a module in the current process.
    */
    hRes = g_ExtSymbols->AddSyntheticSymbol(ModBase, ModSize, Args, DEBUG_ADDSYNTHSYM_DEFAULT, NULL);
    if (FAILED(hRes))
    {
        dprintf("[sync] modmap: AddSyntheticSymbol failed\n");
        hRes = g_ExtSymbols->RemoveSyntheticModule(ModBase);
        if (FAILED(hRes))
        {
            dprintf("[sync] modmap: RemoveSyntheticModule failed\n");
        }
        return E_FAIL;
    }

    return hRes;
}


HRESULT
CALLBACK
modunmap(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    ULONG64 ModBase = 0;
    ULONG RemainderIndex;
    DEBUG_VALUE DebugValue = {};
    INIT_API();

    if (!Args || !*Args)
    {
        dprintf("[sync] !modunmap <mod base>\n");
        return E_FAIL;
    }

    /*
    msdn: Evaluate method evaluates an expression, returning the result.
    */
    hRes = g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT64, &DebugValue, &RemainderIndex);
    if (FAILED(hRes))
    {
        dprintf("[sync] modunmap: failed to evaluate module base\n");
        return E_FAIL;
    }

    ModBase = (ULONG64)DebugValue.I64;

    /*
    msdn: The RemoveSyntheticModule method removes a synthetic module from the module list
    the debugger maintains for the current process.
    */
    hRes = g_ExtSymbols->RemoveSyntheticModule(ModBase);
    if (FAILED(hRes))
    {
        dprintf("[sync] modunmap: RemoveSyntheticModule failed\n");
        return E_FAIL;
    }

    return hRes;
}


HRESULT
CALLBACK
bpcmds(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    char *msg, *decoded, *query;
    LPSTR pszString;
    int NbBytesRecvd;
    size_t cbBinary;
    INIT_API();

#if VERBOSE >= 2
    dprintf("[sync] !bpcmds  called\n");
#endif

    if (!g_Synchronized)
    {
        dprintf("[sync] please enable sync\n");
        return E_FAIL;
    }

    if (!Args || !*Args){
        msg = "query";
    }
    else {
        msg = (char *)Args;
    }

    ReleasePollTimer();

    if ((strncmp("load", msg, 4) == 0) || (strncmp("query", msg, 5) == 0))
    {
        dprintf("[sync] query idb for bpcmds\n");
        hRes = TunnelSend("[sync]{\"type\":\"bps_get\"}\n");
    }
    else if (strncmp("save", msg, 4) == 0)
    {
        dprintf("[sync] dumping bpcmds to idb\n");

        hRes = LocalCmd(Client, ".bpcmds");
        if (FAILED(hRes) || FAILED(g_CmdBuffer.hRes))
        {
            dprintf("[sync] failed to evaluate .bpcmds command\n");
            goto TIMER_REARM_EXIT;
        }

        cbBinary = g_CmdBuffer.len;

        // local output
        dprintf("%s\n", g_CmdBuffer.buffer);

        hRes = ToBase64((const byte *)g_CmdBuffer.buffer, (unsigned int)cbBinary, &pszString);
        if (SUCCEEDED(hRes))
        {
            hRes = TunnelSend("[sync]{\"type\":\"bps_set\",\"msg\":\"%s\"}\n", pszString);
            free(pszString);
        }

        g_CmdBuffer.len = 0;
        ZeroMemory(g_CmdBuffer.buffer, MAX_CMD);
    }
    else
    {
        dprintf("[sync] usage !bpcmds <||query|save|load|\n");
        goto TIMER_REARM_EXIT;
    }

    // Check if we failed to query the idb client
    if (FAILED(hRes)){
        dprintf("[sync] !bpcmds failed\n");
        goto TIMER_REARM_EXIT;
    }

    // Get result from idb client
    hRes = TunnelReceive(&NbBytesRecvd, &query);
    if (!(SUCCEEDED(hRes) & (NbBytesRecvd > 0) & (query != NULL)))
    {
        dprintf("[sync] !bpcmds failed\n");
        goto TIMER_REARM_EXIT;
    }

    // Handle result
    if (strncmp("load", msg, 4) == 0)
    {
        hRes = FromBase64(query, (BYTE **)(&decoded));
        if (SUCCEEDED(hRes)) {
            hRes = ExecCmdList(decoded);
            free(decoded);
        }
    }
    else if (strncmp("query", msg, 5) == 0)
    {
        hRes = FromBase64(query, (BYTE **)(&decoded));
        if (SUCCEEDED(hRes)) {
            dprintf("[sync] idb's saved bpcmds:\n %s\n", decoded);
            free(decoded);
        }
    }
    else
    {
        dprintf("%s\n", query);
    }

    free(query);

TIMER_REARM_EXIT:
    CreatePollTimer();
    return hRes;
}


HRESULT
modmd5(LPSTR *hexhash)
{
    HRESULT hRes;
    HANDLE hFile = NULL;
    DEBUG_MODULE_PARAMETERS ModParams;
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE *pbHashData = NULL;
    BYTE buffer[BUFSIZE];
    DWORD cbHash = 0;
    DWORD cbRead = 0;
    BOOL bResult = FALSE;

    /*
     msdn: returns parameters for modules in the target.
     */
    hRes = g_ExtSymbols->GetModuleParameters(1, &g_Base, 0, &ModParams);
    if (FAILED(hRes))
    {
        dprintf("[sync] modcheck: failed get module parameters\n");
        return E_FAIL;
    }

    dprintf("[sync] modcheck:\n"
        "       File: %s\n"
        "       Size: 0x%x\n"
        "       TimeDateStamp: 0x%x\n", g_NameBuffer, ModParams.Size, ModParams.TimeDateStamp);

    hRes = E_FAIL;

    hFile = CreateFile(g_NameBuffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        dprintf("[sync] failed at opening file: %d\n", GetLastError());
        return hRes;
    }

    if (!(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)))
    {
        dprintf("[sync] CryptAcquireContext failed\n");
        goto Exit;
    }

    if (!(CryptCreateHash(hCryptProv, CALG_MD5, NULL, NULL, &hHash)))
    {
        dprintf("[sync] CryptCreateHash failed\n");
        goto Exit;
    }

    while ((bResult = ReadFile(hFile, buffer, BUFSIZE, &cbRead, NULL)))
    {
        if (cbRead == 0){
            break;
        }

        if (!(CryptHashData(hHash, buffer, cbRead, NULL)))
        {
            dprintf("[sync] CryptHashData failed\n");
            goto Exit;
        }
    }

    if (!bResult)
    {
        dprintf("[sync] ReadFile failed\n");
        goto Exit;
    }

    if (!(CryptGetHashParam(hHash, HP_HASHVAL, NULL, &cbHash, 0)))
    {
        dprintf("[sync] CryptGetHashParam failed\n");
        goto Exit;
    }

    pbHashData = (BYTE *)malloc(cbHash);
    if (pbHashData == NULL){
        dprintf("[sync] failed at allocate buffer: %d\n", GetLastError());
        goto Exit;
    }

    if (!(CryptGetHashParam(hHash, HP_HASHVAL, pbHashData, &cbHash, 0)))
    {
        dprintf("[sync] CryptGetHashParam failed\n");
        goto Exit;
    }

    hRes = ToHexString((const byte *)pbHashData, (unsigned int)cbHash, hexhash);

Exit:
    if (hFile){
        CloseHandle(hFile);
    }
    if (pbHashData){
        free(pbHashData);
    }
    if (hHash){
        CryptDestroyHash(hHash);
    }
    if (hCryptProv){
        CryptReleaseContext(hCryptProv, 0);
    }

    return hRes;
}


HRESULT
CALLBACK
modcheck(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes;
    DWORD cbBinary;
    int NbBytesRecvd = 0;
    LPSTR pszResString = NULL;
    const CHAR* type;
    CHAR *msg = NULL;
    CHAR cmd[64] = { 0 };
    BOOL bUsePdb = TRUE;
    INIT_API();

    if (!g_Synchronized)
    {
        dprintf("[sync] please enable sync\n");
        return E_FAIL;
    }

    if (!(*g_NameBuffer))
    {
        dprintf("[sync] no module\n");
        return E_FAIL;
    }

    // check args
    // md5 is accepted only with local debuggee
    if (!Args || !*Args)
    {
        bUsePdb = TRUE;
    }
    else if (strcmp("md5", Args) == 0)
    {
        bUsePdb = FALSE;

        if (!(IsLocalDebuggee()))
        {
            dprintf("[sync] can't use md5 check with non local debuggee\n");
            return E_FAIL;
        }
    }
    else
        dprintf("[sync] unknown argument, defaulting to pdb match\n");

    // The debugger does not know if an IDB client
    // is actually connected to the dispatcher.

    // First disable tunnel polling for commands (happy race...)
    ReleasePollTimer();

    // default behavior is to used !IToldYouSo  command.
    if (bUsePdb)
    {
        type = "pdb";
        _snprintf_s(cmd, 64, _TRUNCATE, "!itoldyouso  %I64x", g_Base);

        // return value for command exec
        hRes = LocalCmd(Client, cmd);
        if (FAILED(hRes) || FAILED(g_CmdBuffer.hRes))
        {
            dprintf("[sync] failed to evaluate !ItoldYouSo  command\n");
            goto Exit;
        }

        cbBinary = (DWORD)g_CmdBuffer.len;
        if (cbBinary == 0)
        {
            dprintf("     ItoldYouSo return empty result\n");
            goto Exit;
        }

        dprintf("%s\n", g_CmdBuffer.buffer);

        hRes = ToBase64((const byte *)g_CmdBuffer.buffer, cbBinary, &pszResString);
        if (FAILED(hRes))
        {
            dprintf("[sync] modcheck ToBase64 failed\n");
            goto Exit;
        }

        g_CmdBuffer.len = 0;
        ZeroMemory(g_CmdBuffer.buffer, MAX_CMD);
    }
    else
    {
        type = "md5";
        hRes = modmd5(&pszResString);
        if (FAILED(hRes))
        {
            dprintf("[sync] modcheck modmd5 failed\n");
            goto Exit;
        }

        dprintf("       MD5: %s\n", pszResString);
    }

    hRes = TunnelSend("[sync]{\"type\":\"modcheck\",\"%s\":\"%s\"}\n", type, pszResString);
    if (FAILED(hRes))
    {
        dprintf("[sync] modcheck send failed\n");
        goto Exit;
    }

    // Let time for the IDB client to reply if it exists
    Sleep(150);

    // Poll tunnel
    hRes = TunnelPoll(&NbBytesRecvd, &msg);
    if (FAILED(hRes))
    {
        dprintf("[sync] modcheck poll failed\n");
        goto Exit;
    }

    if ((NbBytesRecvd > 0) && (msg != NULL))
    {
        dprintf("%s\n", msg);
    }
    else
    {
        dprintf("    -> no reply, make sure an idb is enabled first\n");
    }

Exit:
    // Re-enable tunnel polling
    CreatePollTimer();

    if (pszResString){
        free(pszResString);
    }
    if (msg){
        free(msg);
    }

    return hRes;
}


HRESULT
KsParseLine(char *cmd, ULONG ProcType)
{
    HRESULT hRes = E_FAIL;
    int i;
    int nbArgs = (ProcType == IMAGE_FILE_MACHINE_AMD64) ? 4 : 3;
    char *ctx = NULL, *childebp = NULL, *retaddr = NULL, *arg = NULL;

    // match hex address...
    if (!(((*cmd >= 0x30) && (*cmd <= 0x39)) || ((*cmd >= 0x61) && (*cmd <= 0x66))))
    {
        hRes = g_ExtControl->ControlledOutput(
            DEBUG_OUTCTL_AMBIENT_TEXT,
            DEBUG_OUTPUT_NORMAL,
            "%s\n", cmd);
        goto Exit;
    }


    childebp = strtok_s(cmd, " ", &ctx);
    retaddr = strtok_s(NULL, " ", &ctx);

    if (childebp == NULL || retaddr == NULL)
        goto Exit;

    // output Child-SP and RetAddr (respectively with 'dc' and '!jmpto' as DML)
    hRes = g_ExtControl->ControlledOutput(
        DEBUG_OUTCTL_AMBIENT_DML,
        DEBUG_OUTPUT_NORMAL,
        "<?dml?><exec cmd=\"dc %s\">%s</exec> <exec cmd=\"!jmpto %s\">%s</exec> ",
        childebp, childebp, retaddr, retaddr);

    if (FAILED(hRes)){
        goto Exit;
    }

    if (ProcType == IMAGE_FILE_MACHINE_AMD64){
        dprintf(": ");
    }

    // output arguments, 4 when x64, 3 when x86 (with 'dc' as DML)
    for (i = 0; i < nbArgs; i++)
    {
        arg = strtok_s(NULL, " ", &ctx);
        if (arg == NULL)
            goto Exit;

        hRes = g_ExtControl->ControlledOutput(
            DEBUG_OUTCTL_AMBIENT_DML,
            DEBUG_OUTPUT_NORMAL,
            "<exec cmd=\"dc %s\">%s</exec> ",
            arg, arg);

        if (FAILED(hRes)){
            goto Exit;
        }
    }

    if (ProcType == IMAGE_FILE_MACHINE_AMD64){
        dprintf(": ");
    }

    // output Call Site (with '!jmpto' DML as well)
    hRes = g_ExtControl->ControlledOutput(
        DEBUG_OUTCTL_AMBIENT_DML,
        DEBUG_OUTPUT_NORMAL,
        "<exec cmd=\"!jmpto %s\">%s</exec>\n",
        ctx, ctx);

Exit:
    return hRes;
}


HRESULT
CALLBACK
ks(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes = S_OK;
    BOOL bDisableDML = false;
    ULONG ProcType;
    char *cmd, *ptr, *end;
    UNREFERENCED_PARAMETER(Args);
    INIT_API();

    hRes = LocalCmd(Client, ".prefer_dml");
    if (FAILED(hRes) || FAILED(g_CmdBuffer.hRes))
    {
        dprintf("[sync] failed to evaluate .prefer_dml command, %x, %x\n", hRes, g_CmdBuffer.hRes);
        goto Exit;
    }

    // disable DML temporarily, to get a raw kv output
    if (strcmp(g_CmdBuffer.buffer, "DML versions of commands on by default\n") == 0)
    {
        bDisableDML = true;
        hRes = LocalCmd(Client, ".prefer_dml 0");
        if (FAILED(hRes) || FAILED(g_CmdBuffer.hRes))
        {
            dprintf("[sync] failed to evaluate .prefer_dml command, %x, %x\n", hRes, g_CmdBuffer.hRes);
            goto Exit;
        }
    }

    /*
    msdn: returns the effective processor type of the processor of the computer that is running the target.
    */
    if (FAILED(hRes = g_ExtControl->GetEffectiveProcessorType(&ProcType)))
    {
        dprintf("[sync] failed to get effective processor type\n");
        goto Exit;
    }

    hRes = LocalCmd(Client, "kv");
    if (FAILED(hRes) || FAILED(g_CmdBuffer.hRes) || (g_CmdBuffer.len == 0))
    {
        dprintf("[sync] failed to evaluate ks command, %x, %x\n", hRes, g_CmdBuffer.hRes);
        goto Exit;
    }

    cmd = (char *)(g_CmdBuffer.buffer);
    ptr = cmd;
    end = ptr + strlen(cmd);

    // parse lines
    while (cmd < end)
    {
        ptr = (char *)strchr(cmd, 0x0A);
        if (ptr == NULL)
            break;

        *ptr = 0;

        if (FAILED(hRes = KsParseLine(cmd, ProcType))){
            break;
        }

        cmd = ptr + 1;
    }

Exit:
    // re-enable DML
    if (bDisableDML)
        hRes = LocalCmd(Client, ".prefer_dml 1");

    g_CmdBuffer.len = 0;
    ZeroMemory(g_CmdBuffer.buffer, MAX_CMD);
    return hRes;
}


HRESULT
CALLBACK
translate(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    HRESULT hRes;
    ULONG64 Base, BaseRemote, Offset;
    ULONG RemainderIndex;
    ULONG Type;
    DEBUG_VALUE DebugValue = {};
    INIT_API();

    if (!Args || !*Args)
    {
        dprintf("[sync] !translate <base> <address> <module>\n");
        return E_FAIL;
    }

    /*
    msdn: Evaluate method evaluates an expression, returning the result.
    */
    hRes = g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT64, &DebugValue, &RemainderIndex);
    if (FAILED(hRes))
    {
        dprintf("[sync] translate: failed to evaluate expression\n");
        return E_FAIL;
    }

    BaseRemote = (ULONG64)DebugValue.I64;
    Args += RemainderIndex;

    /*
    msdn: Evaluate method evaluates an expression, returning the result.
    */
    hRes = g_ExtControl->Evaluate(Args, DEBUG_VALUE_INT64, &DebugValue, &RemainderIndex);
    if (FAILED(hRes))
    {
        dprintf("[sync] translate: failed to evaluate expression\n");
        return E_FAIL;
    }

    Offset = (ULONG64)DebugValue.I64;
    Args += RemainderIndex;

    StrTrim((LPSTR)Args, " ");
    if (!*Args)
    {
        dprintf("[sync] translat: failed to evaluate module name\n");
        return E_FAIL;
    }

    hRes = g_ExtSymbols->GetModuleByModuleName(Args, 0, NULL, &Base);
    if (FAILED(hRes))
    {
        dprintf("[sync] translate: failed to find module %s by its name\n", Args);
        return E_FAIL;
    }

    Offset = Offset - BaseRemote + Base;

    // properly mask addresses to display if target is x86
    hRes = g_ExtControl->GetActualProcessorType(&Type);
    if (SUCCEEDED(hRes))
    {
        if (Type == IMAGE_FILE_MACHINE_I386)
        {
            Offset &= 0xFFFFFFFF;
            Base &= 0xFFFFFFFF;
        }
    }

    hRes = g_ExtControl->ControlledOutput(
        DEBUG_OUTCTL_AMBIENT_DML,
        DEBUG_OUTPUT_NORMAL,
        "<?dml?>-> module <exec cmd=\"lmDvm%s\">%s</exec>"\
        " based at 0x%I64x, rebased address: 0x%I64x"\
        " (<exec cmd=\"bp 0x%I64x\">bp</exec>,"\
        " <exec cmd=\"ba e 1 0x%I64x\">hbp</exec>,"\
        " <exec cmd=\"dc 0x%I64x\">dc</exec>,"\
        " <exec cmd=\"r $ip=0x%I64x; r; !sync\">ip</exec>,"\
        " <exec cmd=\"u 0x%I64x\">u</exec>)\n",
        Args, Args, Base, Offset, Offset, Offset, Offset, Offset, Offset);

    return hRes;
}


HRESULT
CALLBACK
synchelp(PDEBUG_CLIENT4 Client, PCSTR Args)
{
    INIT_API();
    HRESULT hRes = S_OK;
    UNREFERENCED_PARAMETER(Args);

    dprintf("[sync] extension commands help:\n"
        " > !sync <host>                   = synchronize with <host> or the default value\n"
        " > !syncoff                       = stop synchronization\n"
        " > !cmt [-a address] <string>     = add comment at current eip (or [addr]) in IDA\n"
        " > !rcmt [-a address] <string>    = reset comments at current eip (or [addr]) in IDA\n"
        " > !fcmt [-a address] <string>    = add a function comment for 'f = get_func(eip)' (or [addr]) in IDA\n"
        " > !lbl [-a address] <string>     = add a label name at current eip (or [addr]) in IDA\n"
        " > !raddr <expression>            = add a comment with rebased address evaluated from expression\n"
        " > !rln <expression>              = get symbol from the idb for the given address\n"
        " > !cmd <string>                  = execute command <string> and add its output as comment at current eip in IDA\n"
        " > !bc <||on|off|set 0xBBGGRR>    = enable/disable path coloring in IDA\n"
        "                                    color a single instruction at current eip if called without argument\n"
        "                                    'set' is used with an hex rgb code (ex: 0xFFFFFF)\n"
        " > !idblist                       = display list of all IDB clients connected to the dispatcher\n"
        " > !idb <module name>             = set given module as the active idb (see !modlist)\n"
        " > !idbn <n>                      = set active idb to the n_th client. n should be a valid decimal value\n"
        " > !syncmodauto <on|off>          = enable/disable idb auto switch based on module name\n"
        " > !jmpto <expression>            = evaluate expression and sync IDA with result address\n"
        "                                    (switch idb and rebase address if necessary)\n"
        " > !jmpraw <expression>           = evaluate expression and sync IDA with result address\n"
        "                                    (use current idb, no idb switch or address rebase)\n"
        " > !curmod                        = display module infomation for current instruction offset (for troubleshooting)\n"
        " > !modlist                       = DML enhanced module list smoothing active idb switching\n"
        " > !modcheck <||md5>              = check current module pdb info or md5 with respect to idb's input file\n"
        " > !modmap <base> <size> <name>   = map a synthetic module over memory range specified by base and size params\n"
        " > !modunmap <base>               = unmap a synthetic module at base address\n"
        " > !bpcmds <||save|load|>         = .bpcmds wrapper, save and reload .bpcmds output to current idb\n"
        " > !ks                            = wrapper for kv command using DML\n"
        " > !translate <base> <addr> <mod> = rebase an address with respect to local module's base\n\n");

    return hRes;
}
