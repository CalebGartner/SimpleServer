import datetime
import email.utils
import http.client
import io
import mimetypes
import os
import posixpath
import time
import urllib.parse
import socket
import sys
import json
import hashlib
from dataclasses import dataclass
from typing import Dict, Union, Tuple, Any  # TODO change to serverlib ? httplib ?

from src import Status

# References:
#     - https://realpython.com/python-sockets
#     - https://www.cs.cmu.edu/%7Eprs/15-441-F16/project1/project1.pdf
#     - https://www.cs.cmu.edu/~prs/15-441-F16/project1/rfc
#     - https://www.cs.cmu.edu/~prs/15-441-F16/project1/FAQ
#     - https://docs.python.org/3/library/socketserver.html
#     - https://github.com/python/cpython/blob/3.7/Lib/http/server.py
#     - https://github.com/python/cpython/blob/3.7/Lib/socketserver.py

ENCODING = 'iso-8859-1'  # standard for compatibility
BYTEORDER = sys.byteorder


@dataclass
class Request:  # TODO response dataclass?

    command: str
    request: str
    path: str
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
                self.send_request_error(Status.REQUEST_URI_TOO_LONG)
                return
            if len(self.read_buffer) == 0:  # needed?
                self.finished = True
                return

            self.parse_request()

            method_name = f"process_{self.request.command}_request"
            request_processing = getattr(self, method_name, None)
            if request_processing is None:
                self.send_request_error(Status.NOT_IMPLEMENTED, f"Unsupported method {self.request.command}")
                return
            else:
                request_processing()

            self.flush_write_buffer()  # just clear instead?
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
            version = words[-1]  # last word of status line
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
            self.request.headers = http.client.parse_headers(io.BytesIO(self.read_buffer))  # parses using std lib
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
            self.send_status(Status.CONTINUE)
            self.write_buffer.append(b"\r\n")  # mark end of headers
            self.flush_write_buffer()

    def send_request_error(self, code, header=None, descriptor=None):

        if code not in Status:
            _header, _descriptor = '???', '???'
        else:
            _header, _descriptor = code.header, code.descriptor

        if header is None:
            header = _header
        if descriptor is None:
            descriptor = _descriptor

        response = f"{self.default_http_version} {code} {header}\r\n".encode(ENCODING)
        self.write_buffer.append(response)

        version = "Python/" + sys.version.split()[0]
        version_header = f'Server: HTTP/1.1 {version}'.encode(ENCODING)

        date_time = email.utils.formatdate(time.time(), usegmt=True)
        date_time_header = f'Date: {date_time}'.encode(ENCODING)

        close_header = 'Connection: close'.encode(ENCODING)
        self.finished = True

        self.write_buffer.extend([version_header, date_time_header, close_header])

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

            self.write_buffer.extend(
                [content_type.encode(ENCODING),
                 content_length.encode(ENCODING)])
        self.write_buffer.append(b"\r\n")  # mark end of headers
        self.flush_write_buffer()  # send all headers to client

        if self.request.command != 'HEAD' and content is not None:
            self.write_buffer.append(content)
            self.flush_write_buffer()

    def send_status(self, code, header=None):
            if header is None:
                if code in Status:
                    header = Status[code][0]
                else:
                    header = ''
            status = f"{self.default_http_version} {code} {header}\r\n".encode(ENCODING)
            self.write_buffer.append(status)

    def flush_write_buffer(self):
        if self.write_buffer:
            self.connection.send(b"\r\n".join(self.write_buffer))
            self.write_buffer.clear()

    def process_GET_request(self):
        f = self.send_response_and_headers()  # returns file-like object (optional)
        if f:
            try:
                eof = False
                offset = 0

                while not eof:
                    f.seek(offset)
                    file_data = f.read(self.buffer_size)
                    offset = f.tell()

                    if not file_data:  # No data left, server has met EOF
                        eof = True
                    else:
                        self.write_buffer.append(file_data)
                        self.flush_write_buffer()
            finally:
                f.close()

    def process_HEAD_request(self):
        f = self.send_response_and_headers()
        if f:
            f.close()

    def send_response_and_headers(self):  # partially from std lib

        path = self.sanitize_path(self.request.path)
        f = None
        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self.request.path)
            if not parts.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_status(Status.MOVED_PERMANENTLY)
                new_parts = (parts[0], parts[1], parts[2] + '/',
                             parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                location_header = f'Location: {new_url}'.encode(ENCODING)
                self.write_buffer.append(location_header)
                self.flush_write_buffer()
                return

        ctype = self.guess_type(path)
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_request_error(Status.NOT_FOUND, "File not found")
            return None

        try:
            fs = os.fstat(f.fileno())
            # Use browser cache if possible
            if ("If-Modified-Since" in self.request.headers
                    and "If-None-Match" not in self.request.headers):
                # compare If-Modified-Since and time of last file modification
                try:
                    ims = email.utils.parsedate_to_datetime(
                        self.request.headers["If-Modified-Since"])
                except (TypeError, IndexError, OverflowError, ValueError):
                    # ignore ill-formed values
                    pass
                else:
                    if ims.tzinfo is None:
                        # obsolete format with no timezone, cf.
                        # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
                        ims = ims.replace(tzinfo=datetime.timezone.utc)
                    if ims.tzinfo is datetime.timezone.utc:
                        # compare to UTC datetime of last modification
                        last_modif = datetime.datetime.fromtimestamp(
                            fs.st_mtime, datetime.timezone.utc)
                        # remove microseconds, like in If-Modified-Since
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            self.send_status(Status.NOT_MODIFIED)
                            self.write_buffer.append(b"\r\n")  # mark end of headers
                            self.flush_write_buffer()
                            f.close()
                            return None

            self.send_status(Status.OK)

            type_header = f"Content-type: {ctype}".encode(ENCODING)
            self.write_buffer.append(type_header)

            length_header = f"Content-Length: {str(fs[6])}".encode(ENCODING)
            self.write_buffer.append(length_header)

            f_time = email.utils.formatdate(fs.st_mtime, usegmt=True)
            f_time_header = f"Last-Modified: {f_time}".encode(ENCODING)
            self.write_buffer.append(f_time_header)

            self.write_buffer.append(b"\r\n")  # mark end of headers
            self.flush_write_buffer()
            return f
        except:
            f.close()
            raise

    def sanitize_path(self, path: str):  # refactor . . . partially from std lib
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        trailing_slash = path.rstrip().endswith('/')

        try:
            path = urllib.parse.unquote(path, errors='surrogatepass')
        except UnicodeDecodeError:
            path = urllib.parse.unquote(path)
        path = posixpath.normpath(path)
        words = path.split('/')
        words = filter(None, words)
        path = os.getcwd()
        for word in words:
            if os.path.dirname(word) or word in (os.curdir, os.pardir):
                # Ignore components that are not a simple file/directory name
                continue
            path = os.path.join(path, word)
        if trailing_slash:
            path += '/'
        return path

    def guess_type(self, path: str):  # taken from std lib

        base, ext = os.path.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()


def encode(packet_data: Union[Dict, str]) -> bytes:
    return json.dumps(packet_data, ensure_ascii=False).encode(encoding=ENCODING)


def decode(packet_data: Union[bytes, bytearray]) -> Dict:
    return json.loads(packet_data.decode(encoding=ENCODING))
