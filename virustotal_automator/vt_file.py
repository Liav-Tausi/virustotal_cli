from concurrent.futures import ThreadPoolExecutor, as_completed
from vt_base import *
import vt_exeptions
import mimetypes
import requests
import hashlib
import time
import os



class VTFile(VTAutomator):

    def __init__(self, file: tuple['os.path', ...], vt_key: str, password: str = None, workers: int = 7):
        """
        sets the initial values for the file(s) to be scanned, the VirusTotal API key,
        the password for the file (if any) and the number of worker threads to use.
        It also checks the validity of the passed values and raises exceptions if they are invalid.
        :param file: tuple['os.path', ...] file/s for scanning
        :param vt_key: str API key
        :param password: str = None file password
        :param workers: int = 7 max thread workers
        """

        super().__init__()
        for every_file in file:
            if not os.path.exists(every_file):
                raise vt_exeptions.FileError()
            self.__file: tuple['os.path', ...] = file

        if not isinstance(vt_key, str) or not vt_key:
            raise vt_exeptions.ApiKeyError()
        self.__vt_key: str = vt_key

        if password is not None and not isinstance(password, str):
            raise vt_exeptions.FilePasswordError()
        self.__password: str = password

        if not isinstance(workers, int):
            raise vt_exeptions.ThreadingError()
        self.__workers: int = workers

    @property
    def file(self) -> tuple['os.path', ...]:
        return self.__file

    @property
    def vt_key(self):
        return self.__vt_key

    @property
    def password(self):
        return self.__password

    @property
    def workers(self) -> int:
        return self.__workers

    def _get_req_file(self, _file) -> dict[str, dict]:
        """

        sends a GET request to the VirusTotal API to retrieve information about a file.
        It uses the file's SHA256 hash as the identifier.
        raises exceptions if the request fails or returns empty content.
        :param _file:
        :return: dict

        """
        if self.requests_amount_limit_counter < 500 and \
                self.requests_per_minute_limit_counter < 4:

            self.set_amount_limit_counter()
            self.set_per_minute_limit_counter()

            headers = {
                "accept": "application/json",
                "x-apikey": self.vt_key
            }
            with open(_file, 'rb') as file:
                file_hash = file.read()

            # SHA256 hash as the identifier
            hashed = hashlib.sha256(file_hash)
            hex_hash = hashed.hexdigest()

            # API request
            req: 'requests' = requests.get(self.get_vt_api_file + hex_hash, headers=headers)

            if req.status_code >= 400:
                raise vt_exeptions.RequestFailed()
            if bool(req.json()):
                # return dict[str, dict]
                return req.json()
            else:
                raise vt_exeptions.EmptyContentError()

    def _post_req_file(self, _file) -> dict[str, dict]:
        """

        sends a POST request to the VirusTotal API to upload a file for scanning.
        It also includes the password for the file (if any) in the request.
        It raises exceptions if the request fails or returns empty content.
        :param _file:
        :return: dict[str,dict]

        """
        if self.requests_amount_limit_counter < 500 and \
                self.requests_per_minute_limit_counter < 4:

            self.set_amount_limit_counter()
            self.set_per_minute_limit_counter()

            mime_type, encoding = mimetypes.guess_type(_file)

            fh = open(_file, "rb")
            files = {"file": (str(_file), fh, mime_type)}

            payload = {"password": self.password}
            headers = {
                "accept": "application/json",
                "x-apikey": self.vt_key
            }

            # bigger files endpoint
            if (os.path.getsize(_file) / 1048576) >= 24:
                api = r'https://www.virustotal.com/api/v3/files/upload_url'
            else:
                api = self.post_vt_api_file

            # API request
            if self.password is None:
                req = requests.post(api, files=files, headers=headers)
            else:
                req = requests.post(api, data=payload, files=files, headers=headers)

            fh.close()

            if req.status_code >= 400:
                raise vt_exeptions.RequestFailed()
            if bool(req.json()):
                # return dict[str,dict]
                return req.json()
            else:
                raise vt_exeptions.EmptyContentError()

    @VTAutomator.get_cache_file
    def _gets_a_file(self) -> int:
        """
        decorator function that retrieves the file information from the cache if it exists,
        otherwise it calls the _get_req_file function to get the information from the API.
        :return: int
        """
        rep: int = self['data']['attributes']['reputation']
        if rep is not None:
            return rep
        else:
            raise FileNotFoundError()

    def get_file(self) -> tuple[str, int]:
        """
        function dedicated for GET action on one file
        :return:
        """
        return self.file[0], self._gets_a_file(self.file[0])


    def post_file(self, _file: str = None) -> str:
        """
        function dedicated for POST action on file
        :param _file:
        :return: 'analysis'
        """
        rep: str = self._post_req_file(_file).get('data')['type']
        if rep is not None:
            return rep
        else:
            raise FileNotFoundError()


    def post_get_file(self, _file: str = None) -> tuple[str, int]:
        """
        used to both upload and retrieve the scan results of a file.
        It starts by uploading the file to VirusTotal API by calling the post_file function.
        It iterates over the file(s) and calls the _gets_a_file function to get the scan results of the file.
        :param _file:
        :return: tuple[str, int]
        """
        if _file is None:
            _url = self.file
        for file in self.file:
            self.post_file(_file)
            for _ in range(1):
                res_code = self._gets_a_file(_file)
                if isinstance(res_code, int):
                    return _file, res_code
                else:
                    time.sleep(20)

    def post_get_files(self) -> list[tuple]:
        """

        Takes the files specified in the constructor and scans them using the VirusTotal API.
        It uses the ThreadPoolExecutor to execute the requests concurrently and the as_completed function
        to retrieve the results as soon as they are available.
        :return: list[tuple]

        """
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            future = [executor.submit(self.post_get_file, _file) for _file in self.file]
            for f in as_completed(future):
                results.append(f.result())
        return results


    def _get_req_url(self, _url):
        pass

    def _post_req_url(self, _url):
        pass
