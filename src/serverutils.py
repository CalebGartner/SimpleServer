import os
import sys
import json
import struct
import hashlib

from typing import Dict, Union
from types import SimpleNamespace

# References:
#     - https://realpython.com/python-sockets
#     - https://docs.python.org/3/library/socketserver.html

HOST, PORT = '127.0.0.1', 8000  # defaults

ENCODING = 'utf-8'
BUFFER_SIZE = 4096
BYTEORDER = sys.byteorder
PROTO_HEADER_LENGTH = 2  # bytes


# TODO headers, etc.


class PacketData(SimpleNamespace):

    def __init__(self):
        super(PacketData, self).__init__()
        self.buffer: bytearray = bytearray()
        self.content: bytearray = None
        self.header_len: int = None
        self.header: Dict = None
        self.checksum: str = None  # updated per-packet

    def reset(self):
        self.content = None
        self.header = None
        self.header_len = None
        self.checksum = None


def process_proto_header(packet: PacketData):
    if len(packet.buffer) >= PROTO_HEADER_LENGTH:
        packet.header_len = struct.unpack(">H", packet.buffer[:PROTO_HEADER_LENGTH])[0]
        packet.buffer = packet.buffer[PROTO_HEADER_LENGTH:]


def process_header(packet: PacketData):
    if len(packet.buffer) >= packet.header_len:
        packet.header = decode(packet.buffer[:packet.header_len])
        if any(hdr not in packet.header for hdr in HEADERS):
            raise ValueError("invalid packet: missing required header")
        if packet.header['action'] not in ACTIONS:
            raise ValueError(f"invalid packet: invalid action specification '{packet.header[HEADERS.ACTION]}'")
        packet.buffer = packet.buffer[packet.header_len:]


def process_content(packet: PacketData):
    content_len = packet.header[HEADERS.CONTENT_LEN]
    if len(packet.buffer) < content_len:
        return
    packet.content = packet.buffer[:content_len]
    packet.buffer = packet.buffer[content_len:]


def process_packet(packet: PacketData):
    if packet.header_len is None:  # process proto-header
        process_proto_header(packet)

    if packet.header_len is not None:  # process packet header
        if packet.header is None:
            process_header(packet)

    if packet.header is not None:  # process packet content
        if packet.content is None:
            process_content(packet)


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
