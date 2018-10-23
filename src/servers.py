#!/usr/bin/env python3.7

import os
import sys
import socket
import selectors
from typing import Union, Tuple

import multiprocessing as mp
import multiprocessing.connection as mpc

import multiprocessing.dummy as mt
import multiprocessing.dummy.connection as mtc
# TODO check w/@Castleton about similar architecture to std lib . . .

import src.serverutils as serverutils
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.dirname(os.path.abspath(__file__))
SELECTOR = selectors.SelectSelector  # vs DefaultSelector ?


class SimpleServer:  # HTTP/1.1 - Default: address='localhost', port=8000

    max_clients = 7
    max_time = 11  # ?

    def __init__(self,
                 _address: Union[int, str] = serverutils.HOST,
                 _port: int = serverutils.PORT,
                 _forking: bool = False):
        self._started: bool = False

        self.address = _address
        self.port = _port

        # move to setup/bind ?
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket connected to the client
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allows re-use by default
        self.name: str = None
        self.socket_fn: int = None

        self.packet: serverutils.PacketData = None  # TODO change to be similar to Message/RequestHandler class ? - Request class?
        self.client_address: int = None  # TODO multiple, persistent clients addressES
        self.multi = mt
        if _forking:
            self.multi = mp

    def setup(self):  # post-init setup stuff
        try:
            self.bind()
            self.socket.listen(self.max_clients)
        except OSError:
            self.shutdown()
            raise

    def accept_client(self) -> Tuple:
        return self.socket.accept()

    def bind(self):
        self.socket.bind((self.address, self.port))
        # TODO self.socket.setblocking(False) ? use selector . . .
        self.name = socket.getfqdn(self.address)
        self.socket_fn = self.socket.fileno()

    # Reference: https://docs.python.org/3/library/multiprocessing.html#multiprocessing
    def startup(self):
        self.setup()
        with self.multi.Pool(processes=self.max_clients) as request_pool:
            while self._started:
                conn = self.accept_client()
                result = request_pool.apply_async(self.service_client, args=conn)  # TODO callback/error_callback args
                # TODO check result . . .

        # self.packet = serverutils.PacketData()
        # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        #     sock.bind((host_address, port))
        #     sock.listen()
        #     print("listening . . .")
        #     self.request, self.client_address = sock.accept()
        #     with self.request:
        #         print("Connected by: ", self.client_address)
        #         while True:
        #             try:
        #                 data = self.request.recv(serverutils.BUFFER_SIZE)
        #             except BlockingIOError:
        #                 pass
        #             else:
        #                 if data:
        #                     self.packet.buffer += data
        #                     serverutils.process_packet(self.packet)
        #
        #                     if self.packet.content is not None:
        #                         pass  # TODO stuff
        #                 else:
        #                     raise RuntimeError('No packet sent from client')

    def shutdown(self):
        self.socket.close()

    def process_packet(self, ):
        pass

    def service_client(self, client_address: Union[int, str], connection: socket):
        # with self.multi.connection.Listener((self.address, self.port), family=socket.AF_INET) as listener:
        #     with listener.accept() as conn:

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()  # cleanup
