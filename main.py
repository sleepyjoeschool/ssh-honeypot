import paramiko
import threading
import logging
import re

# Logging info
logging.basicConfig(filename='log.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

# Allow username and password
ALLOWED_USER = "admin"
ALLOWED_PASSWORD = "admin"


class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        # Login attempt logger
        logging.info(f"Login attempt: Username - {username}, Password - {password}")
        if username == ALLOWED_USER and password == ALLOWED_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_client(client):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(paramiko.RSAKey.generate(2048))
        server = SSHHoneypot()
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return

        # Client auth
        chan = transport.accept(20)#Disconnected after 20s while not respond
        if chan is None:
            return

        # Waiting commend
        server.event.wait(30)#Disconnected after 30s while not respond
        if not server.event.is_set():
            return

        # Welcome message
        chan.send(" Welcome to Router CIL access\n")
        input_buffer = ""
        while True:
            # User info
            chan.send("user@router:~#")
            while True:
                char = chan.recv(1).decode()
                if not char:
                    break
                if char == '\n':
                    command = input_buffer.strip()
                    input_buffer = ""
                    if command:
                        # Record user command
                        logging.info(f"User command: {command}")
                        # Command output
                        response = handle_command(command)
                        # \n
                        response = response.replace('\n', '\r\n')
                        chan.send(response + '\r\n')
                    break
                else:
                    input_buffer += char

    except Exception as e:
        logging.error(f"Error handling client: {e}")
    finally:
        try:
            transport.close()
        except NameError:
            pass


def handle_command(command):
    parts = command.split()
    cmd = parts[0]
    args = parts[1:]

    if cmd == "ls":
        return "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
    elif cmd == "pwd":
        return "/root"
    elif cmd == "whoami":
        return "user"
    elif cmd == "ping":
        if args:
            return f"PING {args[0]} (1.2.3.4) 56(84) bytes of data.\n64 bytes from 1.2.3.4: icmp_seq=1 ttl=64 time=0.032 ms\n--- {args[0]} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 0.032/0.032/0.032/0.000 ms"
        else:
            return "ping: usage: ping [-aAbBdDfhLnOqrRUvV] [-c count] [-i interval] [-I interface] [-m mark] [-M pmtudisc_option] [-l preload] [-p pattern] [-Q tos] [-s packetsize] [-S sndbuf] [-t ttl] [-T timestamp_option] [-w deadline] [-W timeout] [hop1 ...] destination"
    elif cmd == "exit":
        return "Connection closed."
    else:
        return f"{cmd}: command not found"


if __name__ == "__main__":
    import socket

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 22))
    server_socket.listen(100)

    print("SSH Honeypot service is now listening on port 22...")

    while True:
        client, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()
    
