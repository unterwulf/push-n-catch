#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include "common.h"
#include "resource.h"
#include "libcatch.h"

#define WM_TRAYICON             (WM_USER+1)
#define WM_NETTHREAD_TERMINATED (WM_USER+2)
#define WM_PROGRESS             (WM_USER+3)

HWND hWndMain;
HMENU hTrayMenu;
HANDLE hTermEvent;
HANDLE hNetThread;

BOOL bAcceptWithoutConfirmation;

const char szRegKey[] = "Software\\kp4 labs\\wincatch";

static char szCurFilename[MAX_PATH];

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
DWORD WINAPI NetThreadProc(LPVOID lpParameter);

LSTATUS ReadStrFromRegistry(LPCSTR lpValue, LPSTR pBuf, LPDWORD pcbBuf)
{
    HKEY hRegKey;
    LSTATUS ret = RegOpenKeyEx(HKEY_CURRENT_USER, szRegKey, 0, KEY_QUERY_VALUE,
                               &hRegKey);
    if (ret == ERROR_SUCCESS) {
        DWORD type;
        ret = RegQueryValueEx(hRegKey, lpValue, 0, &type, (LPBYTE)pBuf, pcbBuf);
        if (ret == ERROR_SUCCESS) {
            if (type != REG_SZ && type != REG_EXPAND_SZ)
                ret = ERROR_FILE_NOT_FOUND;
        }
        RegCloseKey(hRegKey);
    }
    return ret;
}

void ReadConfig(void)
{
    HKEY hRegKey;
    LSTATUS ret = RegOpenKeyEx(HKEY_CURRENT_USER, szRegKey, 0, KEY_QUERY_VALUE,
                               &hRegKey);
    if (ret == ERROR_SUCCESS) {
        DWORD cbData;
        cbData = sizeof bAcceptWithoutConfirmation;
        RegQueryValueEx(hRegKey, "AcceptWithoutConfirmation", 0, NULL,
                        (LPBYTE)&bAcceptWithoutConfirmation, &cbData);
        RegCloseKey(hRegKey);
    }
}

const char *MyPeerName(void)
{
    static char name[PEERNAME_MAX];
    DWORD len = sizeof name;
    name[0] = '\0';

    ReadStrFromRegistry("Name", name, &len);
    if (!name[0]) {
        if (gethostname(name, PEERNAME_MAX) == 0) {
            name[PEERNAME_MAX] = '\0';
        } else {
            strcpy(name, "wincatch");
        } 
    }
    return name;
}

void ChangeDirectoryToConfigured(void)
{
    char dir[MAX_PATH];
    DWORD len = sizeof dir;

    if (ReadStrFromRegistry("Directory", dir, &len) == ERROR_SUCCESS) {
        if (!SetCurrentDirectory(dir)) {
            char curdir[MAX_PATH];
            char msg[2*MAX_PATH + 48];
            if (GetCurrentDirectory(sizeof curdir, curdir) == 0)
                strcpy(curdir, "<unknown>");
            snprintf(msg, sizeof msg,
                     "Unable to change directory to:\n\n  %s\n\n"
                     "will stay at:\n\n  %s", dir, curdir);
            MessageBox(hWndMain, msg, "Wincatch", MB_OK | MB_ICONEXCLAMATION);
        }
    }
}

void Die(const char *fmt, ...)
{
    char msg[2048];
    size_t sz = sizeof msg;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sz, fmt, ap);
    MessageBox(hWndMain, msg, "Wincatch", MB_OK | MB_ICONERROR);
    ExitProcess(-1);
}

void InitNetwork(void)
{
    WSADATA wsaData;
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0)
        Die("WSAStartup failed with error: %d", err);
}

void UpdateTrayTip(const char *fmt, ...)
{
    NOTIFYICONDATA nid;
    va_list ap;
    va_start(ap, fmt);

    ZeroMemory(&nid, sizeof nid);
    nid.cbSize   = sizeof nid;
    nid.uVersion = NOTIFYICON_VERSION;
    nid.hWnd     = hWndMain;
    nid.uID      = 0;
    nid.uFlags   = NIF_TIP;
    vsnprintf(nid.szTip, sizeof nid.szTip, fmt, ap);
    Shell_NotifyIcon(NIM_MODIFY, &nid);
}

void ShowTrayBalloon(const char *fmt, ...)
{
    NOTIFYICONDATA nid;
    va_list ap;
    va_start(ap, fmt);

    ZeroMemory(&nid, sizeof nid);
    nid.cbSize   = sizeof nid;
    nid.uVersion = NOTIFYICON_VERSION;
    nid.hWnd     = hWndMain;
    nid.uID      = 0;
    nid.uFlags   = NIF_INFO;
    vsnprintf(nid.szInfo, sizeof nid.szInfo, fmt, ap);
    nid.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIcon(NIM_MODIFY, &nid);
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    MSG msg;
    WNDCLASSEX wcex;
    NOTIFYICONDATA nid;
    static const char *classname = "Wincatch";
    static const char *title = "Wincatch";
    UNUSED(hPrevInstance);
    UNUSED(lpCmdLine);
    UNUSED(nCmdShow);

    if (CreateMutex(NULL, TRUE, title)) {
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            MessageBox(NULL, "Another instance of Wincatch is already run.",
                       "Wincatch", MB_OK | MB_ICONERROR);
            return -1;
        }
    }

    ZeroMemory(&wcex, sizeof wcex);
    wcex.cbSize        = sizeof wcex;
    wcex.style         = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc   = WndProc;
    wcex.hInstance     = hInstance;
    wcex.hIcon         = LoadIcon(NULL, (LPCTSTR)IDI_INFORMATION);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName  = NULL; //(LPCSTR)IDC_VIEW;
    wcex.lpszClassName = classname;
    wcex.hIconSm       = LoadIcon(NULL, (LPCTSTR)IDI_INFORMATION);

    RegisterClassEx(&wcex);

    hWndMain = CreateWindow(classname, title,
        WS_CAPTION |
        WS_THICKFRAME |
        WS_SYSMENU,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

    if (!hWndMain)
        return FALSE;

    InitNetwork();
    ReadConfig();

    SetWindowPos(hWndMain, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    //ShowWindow(hWndMain, SW_MAXIMIZE);
    hTrayMenu = GetSubMenu(LoadMenu(hInstance, MAKEINTRESOURCE(IDM_TRAY_MENU)), 0);

    ZeroMemory(&nid, sizeof nid);
    nid.cbSize   = sizeof nid;
    nid.uVersion = NOTIFYICON_VERSION;
    nid.hWnd     = hWndMain;
    nid.uID      = 0;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.uFlags   = NIF_TIP | NIF_ICON | NIF_MESSAGE;
    strcpy(nid.szTip, "Wincatch");
    nid.hIcon    = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_WINCATCH));

    if (!Shell_NotifyIcon(NIM_ADD, &nid))
        return FALSE;

    ChangeDirectoryToConfigured();
    ShowTrayBalloon("Wincatch has started");

    hTermEvent = CreateEvent(NULL, TRUE, FALSE, "Terminate");
    ResetEvent(hTermEvent);
    hNetThread = CreateThread(NULL, 0, &NetThreadProc, 0, 0, NULL);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

//    TerminateThread(hNetThread, -1);
    Shell_NotifyIcon(NIM_DELETE, &nid);

    return msg.wParam;
}

void OpenIncomingFolder(void)
{
    char dir[MAX_PATH];
    DWORD len = GetCurrentDirectory(sizeof dir, dir);
    if (len > 0 && len < sizeof dir)
        ShellExecute(NULL, "explore", dir, NULL, NULL, SW_SHOWNORMAL);
}

INT_PTR CALLBACK DlgSettingsProc(HWND hDlg, UINT message, WPARAM wParam,
                                 LPARAM lParam)
{
    UNUSED(lParam);

    switch (message) {
        case WM_INITDIALOG:
            return TRUE;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                EndDialog(hDlg, LOWORD(wParam));
                return TRUE;
            }
            break;
    }
    return FALSE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_APP_OPEN:
                    OpenIncomingFolder();
                    break;
                case ID_APP_SETTINGS:
                    DialogBox(NULL, (LPCTSTR)IDD_SETTINGS, hWnd, DlgSettingsProc);
                    break;
                case ID_APP_EXIT:
//                    if (WaitForSingleObject(hTermEvent, 0) != WAIT_OBJECT_0)
//                        SetEvent(hTermEvent);
                    PostQuitMessage(0);
                    break;
            }
            break;

        case WM_TRAYICON:
            switch (lParam) {
                case WM_LBUTTONDBLCLK:
                    PostMessage(hWnd, WM_COMMAND, ID_APP_OPEN, 0);
                    break;
                case WM_RBUTTONUP: {
                    POINT pos;
                    GetCursorPos(&pos);
                    SetForegroundWindow(hWnd);
                    TrackPopupMenu(hTrayMenu, 0, pos.x, pos.y, 0, hWnd, NULL);
                    PostMessage(hWnd, WM_NULL, 0, 0);
                    break;
                }
            }
            break;

        case WM_PROGRESS: {
            if (wParam == 100) {
                ShowTrayBalloon("Received %s", szCurFilename);
            }
            break;
        }

        case WM_DESTROY:
        case WM_NETTHREAD_TERMINATED:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
   }
   return 0;
}

void ReportProgress(off_t npassed, off_t ntotal)
{
    unsigned int percent = (npassed == 0) ? 0 : 100.0*npassed/ntotal;
    PostMessage(hWndMain, WM_PROGRESS, percent, 0);
}

int ConfirmIncomingFile(const char *filename, off_t filelen)
{
    strncpy(szCurFilename, filename, sizeof szCurFilename - 1);
    szCurFilename[sizeof szCurFilename - 1] = '\0';

    if (!bAcceptWithoutConfirmation) {
        char msg[1024];
        snprintf(msg, sizeof msg,
                 "Do you want to accept file?\n\n  %s\n\nSize: %llu bytes",
                 filename, (unsigned long long)filelen);
        if (MessageBox(hWndMain, msg, "Incoming push request",
                       MB_YESNO | MB_ICONQUESTION) != IDYES)
            return FALSE;
    }

    UpdateTrayTip("Wincatch:\nReceiving %s...", szCurFilename);

    return TRUE;
}

int IsTerminationRequested(void)
{
    return (WaitForSingleObject(hTermEvent, 0) == WAIT_OBJECT_0);
}

void DieNetError(const char *fmt, ...)
{
    char msg[2048];
    int sz = sizeof msg;
    int nrequired;
    va_list ap;
    va_start(ap, fmt);
    nrequired = vsnprintf(msg, sz, fmt, ap);
    if (nrequired < sz) {
        int wsa_last_error = WSAGetLastError();
        sz -= nrequired;
        snprintf(&msg[nrequired], sz, ": %d", wsa_last_error);
    }
    MessageBox(hWndMain, msg, "Wincatch", MB_OK | MB_ICONERROR);
    PostMessage(hWndMain, WM_NETTHREAD_TERMINATED, 0, 0);
    ExitThread(-1);
}

DWORD WINAPI NetThreadProc(LPVOID lpParameter)
{
    struct sockaddr_in sa;
    struct libcatch_ctx ctx;
    SOCKET tcpfd, udpfd;
    UNUSED(lpParameter);

    ctx.report_progress = &ReportProgress;
    ctx.confirm_file = &ConfirmIncomingFile;
    ctx.is_termination_requested = &IsTerminationRequested;
//    MessageBox(hWndMain, "Net thread started", "Debug", MB_OK);

    tcpfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcpfd == INVALID_SOCKET)
        DieNetError("Cannot create TCP socket");

    sa.sin_family = AF_INET;
    sa.sin_port = htons(CATCH_PORT);
    sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(tcpfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        DieNetError("Cannot bind to TCP port %hu", CATCH_PORT);

    if (listen(tcpfd, 1) != 0)
        DieNetError("Cannot listen to TCP socket");

    udpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpfd == INVALID_SOCKET)
        DieNetError("Cannot create UDP socket");

    if (bind(udpfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        DieNetError("Cannot bind to UDP port %hu", CATCH_PORT);

    while (!ctx.is_termination_requested()) {
        fd_set rfds;
        int retval;

        FD_ZERO(&rfds);
        FD_SET(tcpfd, &rfds);
        FD_SET(udpfd, &rfds);

        UpdateTrayTip("Wincatch: ready for connection");
        retval = select(udpfd + 1, &rfds, NULL, NULL, NULL);

        if (retval == SOCKET_ERROR)
            DieNetError("select()");
        else if (retval > 0) {
            if (FD_ISSET(udpfd, &rfds)) {
                libcatch_handle_discovery(udpfd, MyPeerName());
            } else {
                struct sockaddr_in sa;
                int sa_len = sizeof sa;
                int connfd = accept(tcpfd, (struct sockaddr *)&sa, &sa_len);
                if (connfd >= 0) {
                    while (libcatch_handle_request(&ctx, connfd) == 0)
                        ;
                    closesocket(connfd);
                } else {
                    neterr("Cannot accept TCP connection");
                }
            }
        }
    }

    closesocket(udpfd);
    closesocket(tcpfd);
    MessageBox(hWndMain, "Net thread finished", "Debug", MB_OK);
    PostMessage(hWndMain, WM_NETTHREAD_TERMINATED, 0, 0);
    return 0;
}
