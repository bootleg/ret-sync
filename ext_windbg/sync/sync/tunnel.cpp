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

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <strsafe.h>

#include "sync.h"
#include "tunnel.h"

#define MAX_SEND 8192

static CHAR SendBuffer[MAX_SEND];
static CHAR RecvBuffer[MAX_SEND];
BOOL g_Synchronized;
SOCKET g_Sock = INVALID_SOCKET;
WSADATA wsaData;

#if _NT_TARGET_VERSION_WINXPOR2K3
void
trimcrlf(LPSTR pszSrcString)
{
    LPSTR pszDestString = pszSrcString;

    while(*pszSrcString)
    {
        if (*pszSrcString == 0x0D)
        {
            pszSrcString++;
            pszSrcString++;
        }
        else
        {
            *pszDestString=*pszSrcString;
            pszDestString++;
            pszSrcString++;
        }
    }

    *pszDestString= *pszSrcString;
}
#endif


HRESULT
FromBase64(LPCSTR pszString, BYTE **ppbBinary)
{
	BOOL bRes = FALSE;
    HRESULT hRes = S_OK;
    DWORD cbBinary = 0;

	bRes = CryptStringToBinary(pszString, 0, CRYPT_STRING_BASE64, NULL, &cbBinary, NULL, NULL);
	if (!bRes){
        dprintf("[sync] failed at CryptStringToBinaryA: %d\n", GetLastError());
        return E_FAIL;
    }

    *ppbBinary = (BYTE *) malloc(cbBinary+1);

    if (ppbBinary==NULL){
        dprintf("[sync] failed at allocate buffer: %d\n", GetLastError());
        return E_FAIL;
    }

	bRes = CryptStringToBinaryA(pszString, 0, CRYPT_STRING_BASE64, *ppbBinary, &cbBinary, NULL, NULL);
	if (!bRes){
        dprintf("[sync] failed at CryptStringToBinaryA: %d\n", GetLastError());
        return E_FAIL;
    }

    *((char *)((*ppbBinary)+cbBinary)) = 0;

    return hRes;
}


HRESULT
ToStringEnc(DWORD dwFlags, const BYTE *pbBinary, DWORD cbBinary, LPSTR *pszString)
{
	BOOL bRes = FALSE;
    HRESULT hRes=S_OK;
    DWORD cchString = 0;

	bRes = CryptBinaryToStringA(pbBinary, cbBinary, dwFlags, NULL, &cchString);
	if (!bRes){
        dprintf("[sync] send failed at CryptBinaryToString: %d\n", GetLastError());
        return E_FAIL;
    }

    *pszString = (LPSTR) malloc(cchString);

    if (*pszString==NULL){
        dprintf("[sync] failed at allocate buffer: %d\n", GetLastError());
        return E_FAIL;
    }

	bRes = CryptBinaryToStringA(pbBinary, cbBinary, dwFlags, *pszString, &cchString);
	if (!bRes){
        dprintf("[sync] failed at CryptBinaryToString: %d\n", GetLastError());
        if (*pszString)
        {
            free(*pszString);
            *pszString = NULL;
        }
        return E_FAIL;
    }

    /*
    CRYPT_STRING_NOCRLF 0x40000000
    Windows Server 2003 and Windows XP: This value is not supported
    */

    #if _NT_TARGET_VERSION_WINXPOR2K3
    trimcrlf(*pszString);
    #endif

    return hRes;
}


HRESULT
ToBase64(const BYTE *pbBinary, DWORD cbBinary, LPSTR *pszString)
{
    HRESULT hRes;

    hRes = ToStringEnc(CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, pbBinary, cbBinary, pszString);
    return hRes;
}


HRESULT
ToHexString(const BYTE *pbBinary, DWORD cbBinary, LPSTR *pszString)
{
    HRESULT hRes;

    hRes = ToStringEnc(CRYPT_STRING_HEX|CRYPT_STRING_NOCRLF, pbBinary, cbBinary, pszString);
    return hRes;
}


// return S_OK if socket is created and synchronized
HRESULT TunnelIsUp()
{
    HRESULT hRes=S_OK;

    if ((g_Sock==INVALID_SOCKET) | (!g_Synchronized)){
        hRes = E_FAIL;
    }

    return hRes;
}


HRESULT
TunnelCreate(PCSTR Host, PCSTR Port)
{
    HRESULT hRes=S_OK;
    struct addrinfo *result = NULL, *ptr = NULL, hints;
    int iResult;
    int bOptLen = sizeof (BOOL);
    BOOL bOptVal = FALSE;

    if (FAILED(hRes = WSAStartup(MAKEWORD(2,2), &wsaData))) {
        dprintf("[sync] WSAStartup failed with error %d\n", hRes);
        goto err_clean;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2 )
    {
        dprintf("[sync] WSAStartup failed, Winsock version not supported\n");
        hRes = E_FAIL;
        goto err_clean;
    }

    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(Host, Port, &hints, &result);
    if ( iResult != 0 ) {
        dprintf("[sync] getaddrinfo failed with error: %d\n", iResult);
        hRes = E_FAIL;
        goto err_clean;
    }

    #if VERBOSE >= 2
    dprintf("[sync] getaddrinfo ok\n");
    #endif

    // Attempt to connect to an address until one succeeds
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {

        // Create a SOCKET for connecting to server
        g_Sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (g_Sock == INVALID_SOCKET) {
            dprintf("[sync] socket failed with error: %ld\n", WSAGetLastError());
            hRes = E_FAIL;
            goto err_clean;
        }

        #if VERBOSE >= 2
        dprintf("[sync] socket ok\n");
        #endif

        bOptVal = TRUE;
        iResult = setsockopt(g_Sock, SOL_SOCKET, SO_KEEPALIVE, (char *) &bOptVal, bOptLen);
        if (iResult == SOCKET_ERROR)
        {
            dprintf("[sync] setsockopt for SO_KEEPALIVE failed with error: %u\n", WSAGetLastError());
        }

        #if VERBOSE >= 2
        dprintf("[sync] Set SO_KEEPALIVE: ON\n");
        #endif

        iResult = setsockopt(g_Sock, IPPROTO_TCP, TCP_NODELAY, (char *) &bOptVal, bOptLen);
        if (iResult == SOCKET_ERROR)
        {
            dprintf("[sync] setsockopt for IPPROTO_TCP failed with error: %u\n", WSAGetLastError());
        }

        #if VERBOSE >= 2
        dprintf("[sync] Set TCP_NODELAY: ON\n");
        #endif

        // Connect to server.
        iResult = connect(g_Sock, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR)
        {
            closesocket(g_Sock);
            g_Sock = INVALID_SOCKET;
            dprintf("[sync] connect failed (check if broker is running)\n");
            continue;
        }

        dprintf("[sync] sync success, sock 0x%x\n", g_Sock);
        break;
    }

    if (g_Sock == INVALID_SOCKET){
        goto err_clean;
    }

    freeaddrinfo(result);
    g_Synchronized = TRUE;

    return S_OK;

err_clean:
    WSACleanup();
    return hRes;
}


HRESULT TunnelClose()
{
    HRESULT hRes=S_OK;
    int iResult;

    if (SUCCEEDED(TunnelIsUp()))
    {
        hRes=TunnelSend("[notice]{\"type\":\"dbg_quit\",\"msg\":\"dbg disconnected\"}\n");
        if (FAILED(hRes)){
            return hRes;
        }
    }

    if (!(g_Sock == INVALID_SOCKET))
    {
        iResult = closesocket(g_Sock);
        g_Sock = INVALID_SOCKET;

        if (iResult == SOCKET_ERROR){
            dprintf("[sync] closesocket failed with error %d\n", WSAGetLastError());
        }
    }

    dprintf("[sync] sync is off\n");
    g_Synchronized = FALSE;
    WSACleanup();
    return hRes;
}


HRESULT TunnelPoll(int *lpNbBytesRecvd, LPSTR *lpBuffer)
{
    HRESULT hRes=S_OK;
    int iResult;
    u_long iMode = 1;

    iResult = ioctlsocket(g_Sock, FIONBIO, &iMode);
    if (iResult != NO_ERROR)
    {
        printf("[sync] TunnelPoll ioctlsocket failed with error: %ld\n", iResult);
        return E_FAIL;
    }

    hRes = TunnelReceive(lpNbBytesRecvd, lpBuffer);
    if (FAILED(hRes)){
        return hRes;
    }

    iMode = 0;
    iResult = ioctlsocket(g_Sock, FIONBIO, &iMode);

    if (iResult != NO_ERROR)
    {
        printf("[sync] TunnelPoll ioctlsocket failed with error: %ld\n", iResult);
        return E_FAIL;
    }
    return hRes;
}


HRESULT TunnelReceive(int *lpNbBytesRecvd, LPSTR *lpBuffer)
{
    HRESULT hRes=S_OK;
    int iResult;
    errno_t err;
    *lpNbBytesRecvd = 0;

    if (FAILED(hRes=TunnelIsUp()))
    {
        dprintf("[sync] TunnelReceive: tunnel is not available\n");
        return hRes;
    }

    iResult = recv(g_Sock, RecvBuffer, MAX_SEND, 0);
    if ( iResult == SOCKET_ERROR )
    {
        iResult =  WSAGetLastError();
        if (iResult == WSAEWOULDBLOCK)
        {
            return hRes;
        }
        else
        {
            dprintf("[sync] recv failed with error: %d, 0x%x\n", iResult, g_Sock);
            WsaErrMsg(iResult);
            goto error_close;
        }
    }
    else if ( iResult == 0 ) {
        dprintf("[sync] recv: connection closed\n");
        goto error_close;
    }

    *lpBuffer = (LPSTR) calloc(iResult+1, sizeof(CHAR));
    if (lpBuffer == NULL) {
        dprintf("[sync] failed at allocate buffer: %d\n", GetLastError());
        return E_FAIL;
    }

    err = memcpy_s(*lpBuffer, iResult+1, RecvBuffer, iResult);
    if (err) {
        dprintf("[sync] memcpy_s failed to copy received buffer\n");
        free(*lpBuffer);
        *lpBuffer = NULL;
        hRes = E_FAIL;
    } else {
        *lpNbBytesRecvd = iResult;
    }

    return hRes;

error_close:
    g_Synchronized = FALSE;
    TunnelClose();
    return E_FAIL;
}


HRESULT TunnelSend(PCSTR Format, ...)
{
    HRESULT hRes=S_OK;
    va_list Args;
    int iResult;
    size_t cbRemaining;

    if (FAILED(hRes=TunnelIsUp()))
    {
        dprintf("[sync] TunnelSend: tunnel is unavailable\n");
        return hRes;
    }

    va_start(Args, Format);
    hRes = StringCbVPrintfEx(SendBuffer, MAX_SEND, NULL, &cbRemaining, STRSAFE_NULL_ON_FAILURE, Format, Args);
    va_end(Args);

    if (FAILED(hRes)){
        return hRes;
    }

    #if VERBOSE >= 2
    dprintf("[sync] send 0x%x bytes, %s\n", MAX_SEND-cbRemaining, SendBuffer);
    #endif

    iResult = send(g_Sock, (const char *)SendBuffer, MAX_SEND-((unsigned int)cbRemaining), 0);
    if (iResult == SOCKET_ERROR)
    {
        iResult = WSAGetLastError();
        dprintf("[sync] send failed with error %d, 0x%x\n", iResult, g_Sock);
        WsaErrMsg(iResult);
        g_Synchronized = FALSE;
        TunnelClose();
        hRes=E_FAIL;
    }

    return hRes;
}


HRESULT WsaErrMsg(int LastError)
{
    HRESULT hRes=S_OK;

    switch(LastError){
        case WSAECONNRESET:
            dprintf("        -> Connection reset by peer\n");
            break;
        case WSAENOTCONN:
            dprintf("        -> Socket is not connected\n");
            break;
        case WSAECONNABORTED:
            dprintf("        -> Software caused connection abort\n");
            break;
        default:
            break;
    }

    return hRes;
}
