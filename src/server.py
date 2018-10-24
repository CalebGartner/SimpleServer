#!/usr/bin/env python3.7

import os
import sys
import socket
import selectors
from typing import Union

import multiprocessing
import multiprocessing.dummy as multithreading

import src.serverutils as serverutils

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.dirname(os.path.abspath(__file__))
SELECTOR = selectors.DefaultSelector  # vs SelectSelector ?

# TODO find best tool for personal project wiki/docs
# SimpleServer Control Flow:
#     startup() -> setup() -> bind() -> serve() -> accept_client() -> serve_client() -> process_request()
#         -> RequestProcessor


class SimpleServer:  # HTTP/1.1 - Default: address='localhost', port=8000

    max_clients = 10
    max_time = 250  # per-request - what's reasonable?  # TODO persistent connections as well . . .

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

        self.forking = _forking
        self.request_pool: mp.Pool = None

    # Reference: https://docs.python.org/3/library/multiprocessing.html#multiprocessing
    def startup(self):
        self.setup()
        # with selectors.DefaultSelector() as selector:  # needed? do something else . . . ?
        #     selector.register(self.socket, selectors.EVENT_READ)

        if self.forking:
            with multiprocessing.Pool(processes=self.max_clients) as self.request_pool:
                self.serve()
        else:
            with multithreading.Pool(processes=self.max_clients) as self.request_pool:
                self.serve()

    def setup(self):  # post-init setup stuff - called by startup
        try:
            self.bind()
            self.socket.listen(self.max_clients)
        except OSError:
            self.shutdown()
            raise

    def bind(self):  # called by setup
        self.socket.bind((self.address, self.port))
        # TODO self.socket.setblocking(False) ? use selector . . .
        self.name = socket.getfqdn(self.address)
        self.socket_fn = self.socket.fileno()

    def serve(self):  # called by startup, self.request_pool has been initialized
        while self._started:  # and request_pool.processes < self.max_clients ?
            try:
                conn = self.accept_client()
            except OSError:
                pass
            else:
                self.serve_client(conn)

    def accept_client(self):  # called by serve, accepts a new client
        return self.socket.accept()

    def serve_client(self, client_connection):
        # TODO callback/error_callback args
        result = self.request_pool.apply_async(self.process_request, args=client_connection)
        # TODO check result . . .

    # @staticmethod
    @classmethod
    # TODO add timeout param + ensure the process/thread respects it (for both the socket/process-thread?)
    def process_request(cls, *args):
        # Separate process/thread begins . . .
        serverutils.RequestProcessor(*args, cls.max_time)

    def shutdown(self):
        self.socket.close()
        self.request_pool = None

    # def fileno(self):
    #     """Return socket file number. Interface required by selector."""
    #     return self.socket.fileno()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()  # cleanup
