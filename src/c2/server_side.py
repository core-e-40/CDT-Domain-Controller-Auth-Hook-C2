import socket
import threading
from datetime import datetime

HOST = "0.0.0.0"
PORT = 4444
LOGFILE = "agents.log"

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOGFILE, "a") as f:
        f.write(line + "\n")

def handle_agent(conn, addr):
    log(f"Agent connected from {addr[0]}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            log(f"{addr[0]} → {data.decode('utf-8', errors='ignore')}")
    except Exception as e:
        log(f"Agent {addr[0]} error: {e}")
    finally:
        conn.close()
        log(f"Agent {addr[0]} disconnected")

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(64)
    log(f"Listening on port {PORT}...")

    while True:
        conn, addr = srv.accept()
        # each agent gets its own thread
        t = threading.Thread(target=handle_agent, args=(conn, addr))
        t.daemon = True
        t.start()

if __name__ == "__main__":
    main()