import time
import random
import paramiko
import threading
import os
import logging

# Logging
logging.basicConfig(filename='attempts.txt', level=logging.INFO, format='%(message)s')

# RSA Key setting
def generate_or_load_rsa_key():
    if not os.path.exists('RSAKey.key'):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file('RSAKey.key')
    return paramiko.RSAKey.from_private_key_file('RSAKey.key')

# SSH Info
class HoneyPotSSHServer(paramiko.ServerInterface):
    def __init__(self, transport):
        self.event = threading.Event()
        self.transport = transport

    def check_auth_password(self, username, password):
        client_ip = self.transport.getpeername()[0]
        logging.info(f"{client_ip} - {username} - {password}")
        write_attempt_password = open("passwords.txt", "a")
        write_attempt_password.write(password,"\n")
        write_attempt_password.close()
        random_waiting_time_in_ms = random.randint(100, 400)
        random_waiting_time_in_s =  random_waiting_time_in_ms/ 1000
        time.sleep(random_waiting_time_in_ms)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

# SSH Connection
def handle_connection(client, addr):
    try:
        transport = paramiko.Transport(client)
        #Setup server type
        transport.local_version = 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5'
        transport.add_server_key(generate_or_load_rsa_key())
        # Banner
        banner = "Debian GNU/Linux 12 \n\nLast login: Thu Apr  4 12:00:00 2024 from 192.168.1.100\n"
        transport.banner = banner.encode()

        server = HoneyPotSSHServer(transport)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            print('[ERROR]: Failed to negotiate with SSH client (Protocol invalid)')
            return
        # 60S Timeout
        channel = transport.accept(60)
        if channel is None:
            print('[ERROR]: Channel does not open (timeout / invalid config)')
            # If you change any setting and find this error being printed, you should consider undo your config
            return
        channel.send("Permission denied, please try again.\n")
        channel.close()
        transport.close()
    except Exception as e:
        print(f"[ERROR]: Failed to process a SSH request (This request cannot be complete): {e}")
    finally:
        client.close()

# Main
def main():
    import socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 22))
    server_socket.listen(100)
    print('The SSH honeypot is now listening to port 22@All IP addresses.')
    while True:
        try:
            client, addr = server_socket.accept()
            print(f'Request from {addr} has been accepted.')
            threading.Thread(target=handle_connection, args=(client, addr)).start()
        except KeyboardInterrupt:
            print('Keyboard interrupt: the program is now terminated.')
            break
    server_socket.close()

if __name__ == "__main__":
    main()
