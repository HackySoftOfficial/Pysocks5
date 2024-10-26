# -*- coding: utf-8 -*-
"""
 Small Socks5 Proxy Server in Python
 from https://github.com/MisterDaneel/
"""

# Network
import socket
import select
from struct import pack, unpack
# System
import traceback
from threading import Thread, activeCount
from signal import signal, SIGINT, SIGTERM
from time import sleep
import sys

#
# Configuration
#
MAX_THREADS = 200
BUFSIZE = 2048
TIMEOUT_SOCKET = 5
LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 9050
USERNAME = 'user'  # Change as needed
PASSWORD = 'pass'  # Change as needed

#
# Constants
#
'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = b'\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = b'\x00'
# '02' USERNAME/PASSWORD AUTHENTICATION
M_USERNAMEPASS = b'\x02'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = b'\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = b'\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'


class ExitStatus:
    """ Manage exit status """
    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ set exit status """
        self.exit = status

    def get_status(self):
        """ get exit status """
        return self.exit


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print("{} - Code: {}, Message: {}".format(msg, str(err[0]), err[1]))
    else:
        traceback.print_exc()


def proxy_loop(socket_src, socket_dst):
    """ Wait for network activity """
    while not EXIT.get_status():
        try:
            reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
        except select.error as err:
            error("Select failed", err)
            return
        if not reader:
            continue
        try:
            for sock in reader:
                data = sock.recv(BUFSIZE)
                if not data:
                    return
                if sock is socket_dst:
                    socket_src.send(data)
                else:
                    socket_dst.send(data)
        except socket.error as err:
            error("Loop failed", err)
            return


def connect_to_dst(dst_addr, dst_port):
    """ Connect to desired destination """
    sock = create_socket()
    try:
        sock.connect((dst_addr, dst_port))
        return sock
    except socket.error as err:
        error("Failed to connect to DST", err)
        return 0


def request_client(wrapper):
    """ Client request details """
    try:
        s5_request = wrapper.recv(BUFSIZE)
    except ConnectionResetError:
        if wrapper != 0:
            wrapper.close()
        error()
        return False

    if (
            s5_request[0:1] != VER or
            s5_request[1:2] != CMD_CONNECT or
            s5_request[2:3] != b'\x00'
    ):
        return False

    if s5_request[3:4] == ATYP_IPV4:
        dst_addr = socket.inet_ntoa(s5_request[4:-2])
        dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
    elif s5_request[3:4] == ATYP_DOMAINNAME:
        sz_domain_name = s5_request[4]
        dst_addr = s5_request[5: 5 + sz_domain_name].decode()
        port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
        dst_port = unpack('>H', port_to_unpack)[0]
    else:
        return False

    print(dst_addr, dst_port)
    return (dst_addr, dst_port)


def request(wrapper):
    """ Handle the SOCKS request """
    dst = request_client(wrapper)
    rep = b'\x07'
    bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'

    if dst:
        socket_dst = connect_to_dst(dst[0], dst[1])
    if not dst or socket_dst == 0:
        rep = b'\x01'
    else:
        rep = b'\x00'
        bnd = socket.inet_aton(socket_dst.getsockname()[0])
        bnd += pack(">H", socket_dst.getsockname()[1])

    reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
    try:
        wrapper.sendall(reply)
    except socket.error:
        if wrapper != 0:
            wrapper.close()
        return

    # start proxy
    if rep == b'\x00':
        proxy_loop(wrapper, socket_dst)
    if wrapper != 0:
        wrapper.close()
    if socket_dst != 0:
        socket_dst.close()


def authenticate(wrapper):
    """ Handle username/password authentication """
    try:
        auth_request = wrapper.recv(BUFSIZE)
    except socket.error:
        error()
        return False

    if auth_request[0:1] != VER:
        return False

    nmethods = auth_request[1]
    methods = auth_request[2:2+nmethods]

    if M_USERNAMEPASS in methods:
        reply = VER + M_USERNAMEPASS
    else:
        return False

    wrapper.sendall(reply)

    # Receive username and password
    auth_data = wrapper.recv(BUFSIZE)
    ulen = auth_data[1]
    username = auth_data[2:2 + ulen].decode()
    plen = auth_data[2 + ulen]
    password = auth_data[3 + ulen:3 + ulen + plen].decode()

    if username == USERNAME and password == PASSWORD:
        auth_reply = b'\x01'  # success
    else:
        auth_reply = b'\x00'  # failure

    wrapper.sendall(VER + auth_reply)

    return auth_reply == b'\x01'


def subnegotiation(wrapper):
    """ Handle method selection and authentication """
    if not authenticate(wrapper):
        return False
    return True


def connection(wrapper):
    """ Function run by a thread """
    if subnegotiation(wrapper):
        request(wrapper)


def create_socket():
    """ Create an INET, STREAMing socket """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SOCKET)
    except socket.error as err:
        error("Failed to create socket", err)
        sys.exit(0)
    return sock


def bind_port(sock):
    """ Bind the socket to address and listen for connections made to the socket """
    try:
        print('Bind {}'.format(str(LOCAL_PORT)))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOCAL_ADDR, LOCAL_PORT))
    except socket.error as err:
        error("Bind failed", err)
        sock.close()
        sys.exit(0)

    # Listen
    try:
        sock.listen(10)
    except socket.error as err:
        error("Listen failed", err)
        sock.close()
        sys.exit(0)
    return sock


def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print('Signal handler called with signal', signum)
    EXIT.set_status(True)


def main():
    """ Main function """
    new_socket = create_socket()
    bind_port(new_socket)
    signal(SIGINT, exit_handler)
    signal(SIGTERM, exit_handler)
    while not EXIT.get_status():
        if activeCount() > MAX_THREADS:
            sleep(3)
            continue
        try:
            wrapper, _ = new_socket.accept()
            wrapper.setblocking(1)
        except socket.timeout:
            continue
        except socket.error:
            error()
            continue
        except TypeError:
            error()
            sys.exit(0)
        recv_thread = Thread(target=connection, args=(wrapper,))
        recv_thread.start()
    new_socket.close()


EXIT = ExitStatus()
if __name__ == '__main__':
    main()
