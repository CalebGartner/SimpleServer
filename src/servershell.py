#!/usr/bin/env python3.7

import os
import socket

import serverutils
import server

# TODO implement server as cmdloop shell w/prompt (http-server)
# TODO startup/shutdown/port/etc. methods

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Start the HTTP server on a specific port.')
    parser.add_argument('-p', '--port', '--server-port',
                        default=serverutils.PORT,
                        help='The port number of the listening server socket. Defaults to 8000.',
                        action='store', type=int, nargs='?')

    args = parser.parse_args()

    if args.LAN:  # TODO add LAN arg back in?
        host = socket.gethostbyname(socket.gethostname())
    else:
        host = serverutils.HOST

    simpleserver = server.SimpleServer()
    simpleserver.startup(host, args.port)  # TODO pass this to cmdloop class instead
