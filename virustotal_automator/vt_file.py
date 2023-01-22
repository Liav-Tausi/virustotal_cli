"""
vt_automator.
created by: liav tausi
date: 1/12/2023
"""

import hashlib
import mimetypes
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

import requests
import vt_exceptions
from vt_base import VTAutomator, is_letters_and_digits


class VTFile(VTAutomator):

    def __init__(self, file: tuple[str, ...], vt_key: str, password: str = None, workers: int = 7):
        """
        sets the initial values for the file(s) to be scanned, the VirusTotal API key,
        the password for the file (if any) and the number of worker threads to use.
        It also checks the validity of the passed values and raises exceptions if they are invalid.
        :param file: tuple['os.path', ...] file/s for scanning
        :param vt_key: str API key
        :param password: str = None file password
        :param workers: int = 7 max thread workers

        """
        self.set_api_key(vt_key)
        super().__init__()
        for every_file in file:
            if not os.path.exists(every_file):
                raise vt_exceptions.FileError()
            self.__file: tuple[str, ...] = file

        if not is_letters_and_digits(vt_key):
            raise vt_exceptions.ApiKeyError()
        self.__vt_key: str = vt_key

        if password is not None and not isinstance(password, str):
            raise vt_exceptions.FilePasswordError()
        self.__password: str = password

        if not isinstance(workers, int):
            raise vt_exceptions.ThreadingError()
        self.__workers: int = workers



    @property
    def file(self) -> tuple[str, ...]:
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


    def _get_req_file(self, _file, _id: str = None, limit: int = None, cursor: str = None) -> dict[str, dict]:
        """
        sends a GET request to the VirusTotal API to retrieve information about a file.
        It uses the file's SHA256 hash as the identifier.
        raises exceptions if the request fails or returns empty content.
        :param _file: a file
        :return: dict[str, dict]

        """
        if self._restrictions():
            self.set_limit_counters()

            headers = {
                "accept": "application/json",
                "x-apikey": self.vt_key
            }
            if (_id is None or len(_id) < 50) or not limit:
                with open(_file, 'rb') as file:
                    file_hash = file.read()
                # SHA256 hash as the identifier
                hashed = hashlib.sha256(file_hash)
                hex_hash = hashed.hexdigest()

                api = self.get_vt_api_file + hex_hash

            if limit and _id:
                if cursor:
                    ret = '/comments' + f'?limit={limit}' + f'&cursor={cursor}'
                else:
                    ret = '/comments' + f'?limit={limit}'
                api = self.get_vt_api_file_ret_comment + _id + ret

            # API request
            req = requests.get(url=api, headers=headers)

            if req.status_code >= 400:
                raise vt_exceptions.RequestFailed()
            if req.json():
                # return dict[str, dict]
                return req.json()
            else:
                raise vt_exceptions.EmptyContentError()
        else:
            raise vt_exceptions.RestrictionsExclusion()



    def _post_req_file(self, _file, _id: str = False, rescan: bool = False, comment: str = False,
                       verdict: str = None) -> dict[str, dict]:
        """
        sends a POST request to the VirusTotal API to upload a file for scanning.
        It also includes the password for the file (if any) in the request.
        It raises exceptions if the request fails or returns empty content.
        :param _file: a file
        :return: dict[str,dict]

        """
        if self._restrictions():
            self.set_limit_counters()

            mime_type, encoding = mimetypes.guess_type(_file)

            fh = open(_file, "rb")
            files = {"file": (str(_file), fh, mime_type)}


            if (_id is False) or (len(_id) < 50) or not (rescan or comment or verdict):
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

            # whether if rescan
            if rescan and not comment:
                files = None
                payload = None
                headers = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key
                }
                api = self.post_vt_api_file_rescan + _id + '/analyse'

            # whether if comment
            if comment and not rescan:
                files = None
                headers = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key,
                    "content-type": "application/json"
                }
                payload = {"data": {
                    "type": "comment",
                    "attributes": {"text": comment}
                }}
                api = self.post_vt_api_file_add_comment + _id + '/comments'


            if verdict:
                headers: dict = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key,
                    "content-type": "application/json"
                }
                payload = {"data": {
                    "type": "vote",
                    "attributes": {"verdict": verdict}
                }}
                api = self.post_vt_file_add_vote + _id + '/votes'

            # API request
            if comment or verdict:
                # for adding a comment
                req = requests.post(api, json=payload, headers=headers)
                if req.status_code == 400:
                    raise vt_exceptions.VoteError()
                if req.status_code == 409:
                    raise vt_exceptions.IdenticalCommentExistError()
            else:
                # all other requests
                req = requests.post(api, data=payload, files=files, headers=headers)

            fh.close()

            if req.status_code >= 400:
                raise vt_exceptions.RequestFailed()
            if req.json():
                # return dict[str,dict]
                return req.json()
            else:
                raise vt_exceptions.EmptyContentError()
        else:
            raise vt_exceptions.RestrictionsExclusion()



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
            vt_exceptions.VtFileNotFoundError()



    def get_file(self) -> tuple[str, int]:
        """
        function dedicated for GET action on one file
        :return: tuple[str, int]
        """
        return self.file[0], self._gets_a_file(self.file[0])



    def get_files(self) -> list[tuple[str, int]]:
        """
        creates a list of futures by submitting the method self._gets_a_file with each file
        :return: list[tuple[str, int]]

        """
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            futures = [executor.submit(self._gets_a_file, _file) for _file in self.file]
            for future in as_completed(futures):
                file = self.file[futures.index(future)]
                results.append((file, future.result()))
        if len(results) == len(self.file):
            return results
        else:
            vt_exceptions.VtFileNotFoundError()



    def get_file_comments(self, limit: int = None, cursor: str = None, comment_file_limit: tuple[str, int, str | None] = None,
                    return_cursor: bool = None) -> list[str]:
        """
        function dedicated for adding a comment on a scanned file
        force virustotal for analysis
        :param return_cursor: if dev wants cursor
        :param cursor: continuation cursor
        :param limit: limit of comments to retrieve
        :param comment_file_limit: if many
        :return: list[str]
        """
        if comment_file_limit:
            _cursor = comment_file_limit[2]
            _limit = comment_file_limit[1]
            _file = comment_file_limit[0]
        else:
            _file = self.file[0]
            _limit = limit
            _cursor = cursor

        if _file in self.cache_file_dict:
            _id: str = self.cache_file_dict[_file]['data']['id']
            rep: dict = self._get_req_file(_file, _id=_id, limit=_limit, cursor=_cursor)
            try:
                if rep.get('data')[0]['type'] == 'comment':
                    comments: list = list()
                    for index in range(int(_limit)):
                        try:
                            for data in rep.get('data')[index]['attributes']:
                                if data == 'text':
                                    comments.append(rep.get('data')[index]['attributes']['text'])
                        except IndexError:
                            return comments
                    return comments
                elif (len(rep) < 10) and return_cursor is None:
                    return rep.get('meta')['cursor']
                else:
                    raise vt_exceptions.VtFileNotFoundError()
            except IndexError:
                raise vt_exceptions.NoCommentsError()
        else:
            raise vt_exceptions.NotInCacheError()


    def get_files_comments(self, limit: int, cursor: str = None) -> list[list, ...]:
        """
        function dedicated for adding a comments on a scanned files
        force virustotal for analysis
        :param cursor: continuation cursor
        :param limit: limit of comments to retrieve
        :return: list[list, ...]
        """
        results = []
        with ThreadPoolExecutor(self.workers) as executor:
            file_limit_cursor_tuples = [(file, limit, cursor) for file in self.file]
            for data in file_limit_cursor_tuples:
                post_with_args = partial(self.get_file_comments, comment_file_limit=data)
                results.append(list(executor.map(post_with_args, file_limit_cursor_tuples))[0])
        return results



    def post_file(self, _file = None) -> True:
        """
        function dedicated for POST action on file
        :return: 'analysis'
        """
        if _file is None:
            _file = self.file[0]
        rep: str = self._post_req_file(_file).get('data')['type']
        if rep == 'analysis':
            return True
        else:
            vt_exceptions.VtFileNotFoundError()



    def post_files(self) -> tuple[bool, int]:
        """
        creates a list of futures by submitting the method self.post_file with each file
        :return: list[tuple[str, int]]

        """
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            futures = [executor.submit(self.post_file, _file) for _file in self.file]
            for future in as_completed(futures):
                results.append(future.result())
        if len(results) == len(self.file):
            return True, len(results)
        else:
            vt_exceptions.VtFileNotFoundError()


    def post_rescan(self, _file = None) -> True:
        """
        function dedicated for POST "rescan" action on file
        force virustotal for analysis
        :param _file:
        :return: True
        """
        if _file is None:
            _file = self.file[0]
        if _file in self.cache_file_dict:
            _id: str = self.cache_file_dict[_file]['data']['id']
            rep: str = self._post_req_file(_file, _id = _id).get('data')['type']
            if rep == 'analysis':
                return True
            else:
                raise FileNotFoundError()
        else:
            raise vt_exceptions.RescanError()


    def post_rescans(self) -> tuple[bool, int]:
        """
        creates a list of futures by submitting the method self.post_rescan with each file
        :return: list[tuple[str, int]]

        """
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            futures = [executor.submit(self.post_rescan, _file) for _file in self.file]
            for future in as_completed(futures):
                results.append(future.result())
        if len(results) == len(self.file):
            return True, len(results)
        else:
            raise vt_exceptions.RescanError()


    def post_file_comment(self, comment: str = None, comment_file: tuple[str, str] = None) -> True:
        """
        function dedicated for adding a comment on a scanned file
        force virustotal for analysis
        :param comment_file: if many
        :param comment: if one
        :return: True
        """
        if comment_file:
            _file = comment_file[1]
            _comment = comment_file[0]
        else:
            _file = self.file[0]
            _comment = comment

        if _file in self.cache_file_dict:
            _id: str = self.cache_file_dict[_file]['data']['id']
            rep: str = self._post_req_file(_file, _id=_id, comment=_comment).get('data')['type']
            if rep == 'comment':
                return True
            else:
                raise vt_exceptions.VtFileNotFoundError()
        else:
            raise vt_exceptions.NotInCacheError()


    def post_files_comments(self, comments: tuple[str, ...]) -> tuple[bool, int]:
        """
        function dedicated for adding a comments on a scanned files
        force virustotal for analysis
        :param comments: tuple of str comments
        :return: True
        """
        with ThreadPoolExecutor(self.workers) as executor:
            comment_file_tuples = [(comment, file) for comment, file in zip(comments, self.file)]
            post_comment_with_args = partial(self.post_file_comment, self)
            results = list(executor.map(post_comment_with_args, comment_file_tuples))
        if len(results) == len(comments):
            return True, len(results)
        else:
            raise vt_exceptions.NotInCacheError()


    def post_vote(self, verdict: str, _file = None) -> True:
        if verdict not in ['malicious', 'harmless']:
            raise vt_exceptions.VerdictError()

        if _file is None:
            _file = self.file[0]
        if _file in self.cache_file_dict:
            _id: str = self.cache_file_dict[_file]['data']['id']
            rep: str = self._post_req_file(_file, _id=_id, verdict=verdict).get('data')['type']
            if rep == 'vote':
                return True
            else:
                raise vt_exceptions.VtFileNotFoundError()
        else:
            raise vt_exceptions.NotInCacheError()



    def post_get_file(self, _file: str = None) -> tuple[str, int]:
        """
        used to both upload and retrieve the scan results of a file.
        It starts by uploading the file to VirusTotal API by calling the post_file function.
        It iterates over the file(s) and calls the _gets_a_file function to get the scan results of the file.
        :param _file:
        :return: tuple[str, int]

        """
        if _file is None:
            _file = self.file
        for _ in self.file:
            self.post_file()
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
        if len(results) == len(self.file):
            return results
        else:
            raise vt_exceptions.VtFileNotFoundError()



    def _get_req_url(self, _url):
        pass

    def _post_req_url(self, _url):
        pass
