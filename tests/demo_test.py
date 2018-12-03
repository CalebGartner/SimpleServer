import unittest
import http.client

from src import Status
from src.server import SimpleServer


class DemoTestCase(unittest.TestCase):

    def test_requests(self):

        conn = http.client.HTTPConnection("35.239.145.222", 8434)

        conn.request("GET", "/")  # VALID
        res = conn.getresponse()

        self.assertEqual(res.status, 200)
        self.assertEqual(res.reason, 'OK')
        self.assertNotEqual(res.read(), 0)  # reads response body

        self.assertEqual(res.closed, False)  # persistent connection

        conn.request("GET", "/piano.png")  # INVALID
        res = conn.getresponse()

        self.assertEqual(res.status, 404)
        self.assertEqual(res.reason, 'File not found')
        self.assertNotEqual(res.read(), 0)

        self.assertEqual(res.closed, False)

        conn.request("HEAD", "/")  # VALID
        res = conn.getresponse()

        self.assertEqual(res.status, 200)
        self.assertEqual(res.reason, 'OK')
        self.assertEqual(len(res.read()), 0)  # NO BODY

        conn.request("HEAD", "/non-existent-file.txt")  # INVALID
        res = conn.getresponse()

        self.assertEqual(res.status, 404)
        self.assertEqual(res.reason, 'File not found')
        self.assertEqual(len(res.read()), 0)  # NO BODY

        conn.close()


if __name__ == '__main__':
    unittest.main()
