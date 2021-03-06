#!/usr/bin/env python3.7

import os
import sys
import socket
import selectors
import multiprocessing
from typing import Union, Tuple, Any

import serverutils

HOST, PORT = '127.0.0.1', 8434  # defaults - random port for testing
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.dirname(os.path.abspath(__file__))

# TODO logging ?
# TODO find best tool for personal project wiki/docs - comments are good, but don't quite cut it
# SimpleServer Control Flow:
#     startup() -> setup() -> bind() -> serve() . . .
#         -> accept_client() -> serve_client() -> process_request() -> ClientProcessor
#         . . .


class SimpleServer:  # HTTP/1.1 - Default: address='localhost', port=8434

    max_clients = 5
    max_time = 275

    def __init__(self, address: Union[int, str] = HOST, port: int = PORT):
        self._started: bool = False

        self.address = address
        self.port = port

        # move to setup/bind ?
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP socket that accepts new clients
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # allows re-use by default
        self.name: str = None
        self.socket_fn: int = None

        self.request_pool = None

    def setup(self):  # post-init setup stuff - called by startup
        try:
            self.bind()
            self.socket.listen(self.max_clients)
        except OSError:
            self.shutdown()
            raise

    def bind(self):  # called by setup
        # self.socket.setblocking(False) ? use selector . . . not necessary because of address reuse?
        self.socket.bind((self.address, self.port))
        self.name = socket.getfqdn(self.address)  # fully qualified domain name
        self.socket_fn = self.socket.fileno()

    def startup(self):
        self.setup()
        self._started = True
        # use multi.Listener instead?
        with multiprocessing.Pool(processes=self.max_clients) as self.request_pool:  # TODO refactor this somehow
            self.serve()

    def serve(self):
        """
Called by startup(). self.request_pool has already been initialized. Continues to serve in a loop until shutdown.
        """
        # select()-based selector allows for fewer wasted CPU cycles; event-driven
        with selectors.SelectSelector() as selector:  # needed? do something else . . . ?
            selector.register(self.socket, selectors.EVENT_READ)
            while self._started:  # and request_pool.processes < self.max_clients ?
                if selector.select():  # since timeout is none, it waits until the socket is ready
                    try:
                        conn = self.accept_client()
                    except OSError:
                        self._started = False
                    else:
                        self.serve_client(conn)

    def accept_client(self):  # called by serve, accepts a new client
        # Do I need to check if it's a previous connection? I shouldn't have to . . .
        return self.socket.accept()  # TODO should I set sock options here for returned socket, set non-blocking, etc. ?

    def serve_client(self, client_connection):
        result = self.request_pool.apply_async(self.process_request, args=client_connection)
        result.wait(self.max_time)  # cuts off at max_time

    @staticmethod
    def process_request(client_connection):
        # Separate process/thread begins . . .
        serverutils.ClientProcessor(client_connection)

    def shutdown(self):
        self.socket.close()

        self.request_pool.join()  # TODO find out which to use . . . necessary? - using context manager . . .
        self.request_pool.close()
        self.request_pool.terminate()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()  # cleanup


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Start the HTTP server on a specific port.')
    parser.add_argument('--port', '-p', '--server-port', default=PORT,
                        type=int, nargs='?',
                        help='The port number of the listening server socket. Defaults to 8000.')
    parser.add_argument('--address', '-a', default=HOST,
                        metavar='ADDRESS',
                        help=f'Specify alternate bind address. [DEFAULT]: {HOST}')
    parser.add_argument('--directory', '-d', default=CONTENT_DIR,
                        help=f'Specify server content directory. [DEFAULT]: {CONTENT_DIR}')

    args = parser.parse_args()

    simpleserver = SimpleServer(args.address, args.port)
    sa = simpleserver.socket.getsockname()
    simpleserver.startup()
    serve_message = "Serving HTTP on {host} port {port} (http://{host}:{port}/) ..."
    print(serve_message.format(host=sa[0], port=sa[1]))
