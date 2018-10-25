#!/usr/bin/env python3.7

import os
import socket

import server
# TODO move this to server module ?
# TODO implement server as cmdloop shell w/prompt (http-server) _

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Start the HTTP server on a specific port.')
    parser.add_argument('--port', '-p', '--server-port', default=server.PORT,
                        type=int, nargs='?',
                        help='The port number of the listening server socket. Defaults to 8000.')
    parser.add_argument('--address', '-a', default=server.HOST,
                        metavar='ADDRESS',
                        help=f'Specify alternate bind address. [DEFAULT]: {server.HOST}')
    parser.add_argument('--directory', '-d', default=server.CONTENT_DIR,
                        help=f'Specify server content directory. [DEFAULT]: {server.CONTENT_DIR}')

    args = parser.parse_args()

    simpleserver = server.SimpleServer(args.address, args.port)  # TODO pass this to cmdloop class instead
    sa = simpleserver.socket.getsockname()
    serve_message = "Serving HTTP on {host} port {port} (http://{host}:{port}/) ..."
    print(serve_message.format(host=sa[0], port=sa[1]))
