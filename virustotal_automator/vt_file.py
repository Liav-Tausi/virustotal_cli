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
        super().__init__()
        for index, every_url in enumerate(file):
            if not os.path.exists(file[index]):
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
    def file(self) -> 'os.path':
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

    def _get_req_file(self):
        if self.requests_amount_limit_counter < 500 and \
                self.requests_per_minute_limit_counter < 4:

            self.set_amount_limit_counter()
            self.set_per_minute_limit_counter()

            for index, every_file in enumerate(self.file):
                headers = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key
                }
                with open(self.file[index], 'rb') as file:
                    file_hash = file.read()

                hashed = hashlib.sha256(file_hash)
                hex_hash = hashed.hexdigest()

                req: 'requests' = requests.get(self.get_vt_api_file + hex_hash, headers=headers)

                if req.status_code >= 400:
                    raise vt_exeptions.RequestFailed()
                if bool(req.json()):
                    return req.json()
                else:
                    raise vt_exeptions.EmptyContentError()

    def _post_req_file(self):
        if self.requests_amount_limit_counter < 500 and \
                self.requests_per_minute_limit_counter < 4:

            self.set_amount_limit_counter()
            self.set_per_minute_limit_counter()

            for index, every_file in enumerate(self.file):
                mime_type, encoding = mimetypes.guess_type(self.file[index])

                fh = open(self.file[index], "rb")
                files = {"file": (str(self.file[index]), fh, mime_type)}

                payload = {"password": self.password}
                headers = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key
                }

                if (os.path.getsize(self.file[index]) / 1048576) >= 24:
                    api = r'https://www.virustotal.com/api/v3/files/upload_url'
                else:
                    api = self.post_vt_api_file

                if self.password is None:
                    req = requests.post(api, files=files, headers=headers)
                else:
                    req = requests.post(api, data=payload, files=files, headers=headers)

                fh.close()

                if req.status_code >= 400:
                    raise vt_exeptions.RequestFailed()
                if bool(req.json()):
                    return req.json()
                else:
                    raise vt_exeptions.EmptyContentError()

    @VTAutomator.get_cache_file
    def get_file(self):
        rep: int = self['data']['attributes']['reputation']
        if rep is not None:
            return rep
        else:
            raise FileNotFoundError()

    def post_file(self):
        rep: str = self._get_req_file().get('data')['type']
        if rep is not None:
            return rep
        else:
            raise FileNotFoundError()

    def post_get_file(self, _file: str = None) -> tuple[str, int]:
        if _file is None:
            _file = self.file
        self.post_file()
        for _ in range(10):
            res_code = self.get_file()
            if isinstance(res_code, int):
                return _file, res_code
            else:
                time.sleep(30)

    def post_get_files(self) -> list[tuple]:
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            future = [executor.submit(self.post_get_file, _file) for _file in self.file]
            for f in as_completed(future):
                results.append(f.result())
        return results


    def _get_req_url(self):
        pass

    def _post_req_url(self):
        pass
