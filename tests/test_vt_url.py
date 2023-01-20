import unittest
from __init__ import *

from virustotal_automator import vt_exceptions
from virustotal_automator.vt_url import VTUrl
from virustotal_automator.vt_file import VTFile

class TestVT(unittest.TestCase):
    def setUp(self):
        self.valid_url = r'https://www.google.com'
        self.valid_file = r'C:\Users\liavt\Downloads\IMDB Top 250 Movies.csv'
        self.valid_key = get_api_key()
        self.invalid_url = 'not a valid url'
        self.invalid_file_path = 'not a valid file path'
        self.invalid_key = 'not a valid key'


    # _____url_____ #
    def test_init_valid_input_url(self):
        vt = VTUrl(url=(self.valid_url,), vt_key=self.valid_key)
        self.assertEqual(vt.url, (self.valid_url,))
        self.assertEqual(vt.vt_key, self.valid_key)

    def test_init_invalid_url(self):
        with self.assertRaises(vt_exceptions.UrlError):
            VTUrl(url=(self.invalid_url,), vt_key=self.valid_key)

    def test_init_invalid_key_vt_url(self):
        with self.assertRaises(vt_exceptions.ApiKeyError):
            VTUrl(url=(self.valid_url,), vt_key=self.invalid_key)

    def test_get_req_url_valid_input(self):
        vt = VTUrl(url=(self.valid_url,), vt_key=self.valid_key)
        response = vt._get_req_url(self.valid_url)
        self.assertIsInstance(response, dict)
        self.assertIn('data', response)

    # ____file____ #

    def test_init_valid_input_file(self):
        vt = VTFile(file=(self.valid_file,), vt_key=self.valid_key)
        self.assertEqual(vt.file, (self.valid_file,))
        self.assertEqual(vt.vt_key, self.valid_key)

    def test_init_invalid_file(self):
        with self.assertRaises(vt_exceptions.FileError):
            VTFile(file=(self.invalid_file_path,), vt_key=self.valid_key)

    def test_init_invalid_key_vt_file(self):
        with self.assertRaises(vt_exceptions.ApiKeyError):
            VTFile(file=(self.valid_file,), vt_key=self.invalid_key)


    # first post! to register file in virustotal system and then get
    def test_get_req_file_valid_input(self):
        vt = VTFile(file=(self.valid_file,), vt_key=self.valid_key)
        # response_post = vt._post_req_file(self.valid_file)
        response_get = vt._get_req_file(self.valid_file)
        self.assertIsInstance(response_get, dict)
        self.assertIn('data', response_get)


if __name__ == '__main__':
    unittest.main()
