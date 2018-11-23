import socket
import sys
import json
import struct
import hashlib
from typing import Dict, Union, Tuple, Any  # TODO change to serverlib ? httplib ? - move headers from init?

from src import Status

# References:
#     - https://realpython.com/python-sockets
#     - https://docs.python.org/3/library/socketserver.html

ENCODING = 'utf-8'
BUFFER_SIZE = 4096
BYTEORDER = sys.byteorder
PROTO_HEADER_LENGTH = 2  # bytes


class RequestProcessor:

    __slots__ = ['buffer', 'content', 'header_len', 'header', 'md5sum',
                 'finished', 'client_address', 'connection', 'timeout']

    def __init__(self, _client_connection: Tuple[socket, Any], _timeout: int):  # TODO extract 'Packet' into data-class?
        self.client_address = _client_connection[1]
        self.connection: socket = _client_connection[0]
        self.timeout = self.connection.gettimeout()

        self.buffer: bytearray = bytearray()
        self.content: bytearray = None

        self.header_len: int = None
        self.header: Dict = None

        self.md5sum: str = None  # updated per-packet

        self.finished = False

        self.service_request()

    def service_request(self):  # TODO add service_client method + rename to ClientProcessing/or instead?
        with self.connection:
            print("Connected by: ", self.client_address)
            while not self.finished:
                try:
                    data = self.connection.recv(BUFFER_SIZE)
                except BlockingIOError:
                    pass
                else:
                    if data:
                        self.buffer += data
                        self.process_packet()

                        if self.content is not None:
                            pass  # TODO stuff
                        # TODO check for shutdown-request from client, etc
                        try:  # explicitly shutdown.  socket.close() merely releases the socket and waits for GC to perform the actual close.
                            self.connection.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass  # some platforms may raise ENOTCONN here
                        self.connection.close()
                        break
                    else:
                        raise RuntimeError('No packet sent from client')

    def clear_packet(self):
        self.content = None
        self.header = None
        self.header_len = None
        self.md5sum = None

    def process_proto_header(self):
        if len(self.buffer) >= PROTO_HEADER_LENGTH:
            self.header_len = struct.unpack(">H", self.buffer[:PROTO_HEADER_LENGTH])[0]
            self.buffer = self.buffer[PROTO_HEADER_LENGTH:]

    def process_header(self):
        if len(self.buffer) >= self.header_len:
            self.header = decode(self.buffer[:self.header_len])
            if any(hdr not in self.header for hdr in HEADERS):
                raise ValueError("invalid self: missing required header")
            if self.header['action'] not in ACTIONS:
                raise ValueError(f"invalid self: invalid action specification '{self.header[HEADERS.ACTION]}'")
            self.buffer = self.buffer[self.header_len:]

    def process_content(self):
        content_len = self.header[HEADERS.CONTENT_LEN]
        if len(self.buffer) < content_len:
            return
        self.content = self.buffer[:content_len]
        self.buffer = self.buffer[content_len:]

    def process_packet(self):
        if self.header_len is None:  # process proto-header
            self.process_proto_header()

        if self.header_len is not None:  # process packet header
            if self.header is None:
                self.process_header()

        if self.header is not None:  # process packet content
            if self.content is None:
                self.process_content()


def encode(packet_data: Union[Dict, str]) -> bytes:
    return json.dumps(packet_data, ensure_ascii=False).encode(encoding=ENCODING)


def decode(packet_data: Union[bytes, bytearray]) -> Dict:
    return json.loads(packet_data.decode(encoding=ENCODING))


def create_packet(packet_content: Union[bytes, bytearray, str], action: str, additional_headers: Dict = None):
    if not isinstance(packet_content, (bytes, bytearray)):
        packet_content = encode(packet_content)

    header = {HEADERS.BYTEORDER: sys.byteorder,  # remove/specify '>' ? - parse/convert to client sys.byteorder ?
              HEADERS.ACTION: action,
              HEADERS.CONTENT_LEN: len(packet_content)}

    if additional_headers is not None:
        header.update(additional_headers)

    packet_header = encode(header)
    proto_header = struct.pack(">H", len(packet_header))
    message = proto_header + packet_header + packet_content
    return message


def packet_md5sum(data: Union[bytes, bytearray]):
    return hashlib.md5(data).hexdigest()
