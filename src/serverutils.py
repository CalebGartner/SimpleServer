import datetime
import email.utils
import html
import http.client
import io
import mimetypes
import os
import posixpath
import shutil
import socketserver
import time
import urllib.parse
from dataclasses import dataclass
from functools import partial

import socket
import sys
import json
import struct
import hashlib
from typing import Dict, Union, Tuple, Any  # TODO change to serverlib ? httplib ?

from src import Status

# References:
#     - https://realpython.com/python-sockets
#     - https://docs.python.org/3/library/socketserver.html

ENCODING = 'iso-8859-1'  # standard for compatibility
BYTEORDER = sys.byteorder


@dataclass
class Request:

    command: str
    request: str
    version: str
    status_line: str
    headers: Dict
    type: str  # close/keep-alive/etc.


class ClientProcessor:
    """Class to process a HTTP client and their request(s).
Control Flow:
    __init__ --> service_client (loop the following)
                 --> service_request
                     --> parse_request
                 --> process_<command>_request
    """

    read_buffer: bytearray
    write_buffer: bytearray
    request: Request
    connection: socket

    max_time = 250  # per-request
    buffer_size = 4096  # bytes

    default_http_version = "HTTP/0.9"  # no status line . . .

    # __slots__ = ['buffer', 'content', 'header_len', 'header', 'md5sum',
    #              'finished', 'client_address', 'connection', 'timeout']

    def __init__(self, client_connection: Tuple[socket, Any]):
        self.client_address = client_connection[1]
        self.connection = client_connection[0]
        self.timeout = self.connection.gettimeout()  # need to set timeout?

        self.write_buffer = bytearray()
        self.read_buffer = bytearray()
        self.request = None

        # self.header_len: int = None
        # self.header: Dict = None

        # self.md5sum: str = None  # updated per-packet

        self.finished = False

        self.service_client()

    def service_client(self):
        with self.connection:
            print("Connected by: ", self.client_address)
            while not self.finished:
                try:
                    data = self.connection.recv(self.buffer_size)
                except BlockingIOError:
                    pass
                else:
                    if data:  # duplicate check in service_request of read_buffer?
                        self.read_buffer += data
                        self.service_request()
                    else:
                        raise RuntimeError('No data sent from client')

                    if self.finished:
                        try:  # explicitly shutdown.  socket.close() merely releases the socket and waits for GC to perform the actual close.
                            self.connection.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass  # some platforms may raise ENOTCONN here

    def service_request(self):
        try:
            if len(self.read_buffer) > 8192:
                self.request = None
                # self.send_error(Status.REQUEST_URI_TOO_LONG)
                return
            if len(self.read_buffer) == 0:  # needed?
                self.finished = True
                return

            self.parse_request()

            method_name = f"process_{self.request.command}_request"
            request_processing = getattr(self, method_name, None)
            if request_processing is None:
                # self.send_error(Status.NOT_IMPLEMENTED, f"Unsupported method {self.request.command}")
                return
            else:
                request_processing()

            self.write_buffer.clear()  # TODO actually send the response if not already done.
        except socket.timeout as e:
            # a read or a write timed out. Discard this connection
            self.finished = True
            return

    def parse_request(self):  # TODO document influence from std lib
        """Parse a request (internal).

        The request should be stored in self.raw_requestline; the results
        are in self.command, self.path, self.request_version and
        self.headers.

        Return True for success, False for failure; on failure, any relevant
        error response has already been sent back.

        """
        self.request.command = None  # set in case of error on the first line
        self.request.version = self.default_http_version

        status_line = self.read_buffer.decode(ENCODING)
        status_line = status_line.rstrip('\r\n')  # remove CR/LF
        self.request.status_line = status_line

        words = status_line.split()
        if len(words) == 0:  # checked above right? not necessary?
            raise ConnectionError

        if len(words) == 2:
            self.finished = True
            if words[0] != 'GET':  # command
                self.send_request_error(
                    Status.BAD_REQUEST,
                    f"Bad HTTP/0.9 request type ({words[0]})")
                raise ConnectionError

        if len(words) >= 3:  # Enough to determine protocol version
            version = words[-1]  # wouldn't this include data/headers as well?
            try:
                # RFC 2145 section 3.1 - parsing HTTP requests (Status Line)
                if not version.startswith('HTTP/'):
                    raise ValueError

                # There can only be one '.' - divides major/minor version numbers
                major_minor_versions = version.replace('HTTP/', '')
                version_numbers = major_minor_versions.split('.')

                # Version numbers should be parsed as separate ints - ignores leading 0s
                if len(version_numbers) != 2:
                    raise ValueError

                version_numbers = int(version_numbers[0]), int(version_numbers[1])
            except (ValueError, IndexError):
                self.send_request_error(
                    Status.BAD_REQUEST,
                    f"Bad request version ({version})")
                raise ConnectionError

            if any(n > 1 for n in version_numbers):
                self.send_request_error(
                    Status.HTTP_VERSION_NOT_SUPPORTED,
                    f"Invalid HTTP version ({major_minor_versions})")
                raise ConnectionError

            self.request.version = version

        if not 2 <= len(words) <= 3:
            self.send_request_error(
                Status.BAD_REQUEST,
                f"Bad request syntax ({status_line})")
            raise ConnectionError

        command, path = words[:2]
        self.request.command, self.request.path = command, path

        # Examine the headers and look for a Connection directive.
        try:
            self.request.headers = http.client.parse_headers(io.BytesIO(self.read_buffer))
        except http.client.LineTooLong as err:
            self.send_request_error(
                Status.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Line too long",
                str(err))
            raise ConnectionError
        except http.client.HTTPException as err:
            self.send_request_error(
                Status.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Too many headers",
                str(err)
            )
            raise ConnectionError

        self.request.type = self.request.headers.get('Connection', "")
        if self.request.type.lower() == 'close':
            self.finished = True
        elif self.request.type.lower() == 'keep-alive' and self.request.version >= "HTTP/1.1":
            self.finished = False

        # Examine the headers and look for an Expect directive
        expect = self.request.headers.get('Expect', "")
        if expect.lower() == "100-continue" and self.request.version >= "HTTP/1.1":
            self.send_response_only(Status.CONTINUE)
            self.write_buffer.append(b"\r\n")  # mark end of headers
            self.flush_write_buffer()

    def send_request_error(self, code, header=None, descriptor=None):  # TODO no descriptor necessary?

        if code not in Status:
            _header, _descriptor = '???', '???'
        else:
            _header, _descriptor = code.header, code.descriptor

        if header is None:
            header = _header
        if descriptor is None:
            descriptor = _descriptor
        self.send_response(code, header)
        self.send_header('Connection', 'close')

        # RFC2616: 4.3
        # All 1xx (informational), 204 (no content), and 304 (not modified) responses
        # MUST NOT include a message-body. All other responses do include a message-body,
        # although it MAY be of zero length.
        content = None
        if (code >= 200 and
            code not in (Status.NO_CONTENT,
                         Status.RESET_CONTENT,
                         Status.NOT_MODIFIED)):
            message_body = {
                'code': str(code),
                'message': header,
                'explain': descriptor,
            }
            content = encode(message_body)
            content_type = 'Content-Type: application/json'
            content_length = 'Content-Length: {}'.format(len(content))

            self.write_buffer.extend([content_type.encode(ENCODING),
                                      content_length.encode(ENCODING)])
        self.write_buffer.append(b"\r\n")  # mark end of headers
        self.flush_write_buffer()  # send all headers to client

        if self.request.command != 'HEAD' and content is not None:
            self.write_buffer.append(content)
            self.flush_write_buffer()

    def send_response(self, code, message=None):
        """Add the response header to the headers buffer and log the
        response code.

        Also send two standard headers with the server software
        version and the current date.

        """
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())

    def send_response_only(self, code, message=None):
        """Send the response header only."""
        if self.request_version != 'HTTP/0.9':
            if message is None:
                if code in self.responses:
                    message = self.responses[code][0]
                else:
                    message = ''
            if not hasattr(self, '_headers_buffer'):
                self._headers_buffer = []
            self._headers_buffer.append(("%s %d %s\r\n" %
                    (self.protocol_version, code, message)).encode(
                        'latin-1', 'strict'))

    def send_header(self, keyword, value):
        """Send a MIME header to the headers buffer."""
        if self.request_version != 'HTTP/0.9':
            if not hasattr(self, '_headers_buffer'):
                self._headers_buffer = []
            self._headers_buffer.append(
                ("%s: %s\r\n" % (keyword, value)).encode('latin-1', 'strict'))

        if keyword.lower() == 'connection':
            if value.lower() == 'close':
                self.close_connection = True
            elif value.lower() == 'keep-alive':
                self.close_connection = False

    def end_headers(self):  # remove - not necessary?
        """Send the blank line ending the MIME headers."""
        if self.request_version != 'HTTP/0.9':
            self._headers_buffer.append(b"\r\n")
            self.flush_headers()

    def flush_write_buffer(self):
        if self.write_buffer:
            self.connection.send(b"\r\n".join(self.write_buffer))
            self.write_buffer.clear()


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
