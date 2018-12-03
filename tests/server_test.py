import unittest
import http.client

from src import Status
from src.server import SimpleServer


class ServerTestCase(unittest.TestCase):

    def test_GET_request(self):

        conn = http.client.HTTPConnection("127.0.0.1", 8434)
        conn.request("GET", "/piano.png")

        res = conn.getresponse()
        data = res.read()

        print(data.decode("utf-8"))


if __name__ == '__main__':
    unittest.main()
