"""
vt_automator.
created by: liav tausi
date: 1/12/2023
"""

import base64
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

import requests
import validators

import vt_exceptions
from vt_base import VTAutomator, is_letters_and_digits


class VTUrl(VTAutomator):

    def __init__(self, url: tuple[str, ...], vt_key: str, workers: int = 7):
        """
        sets the initial values for the url(s) to be scanned, the VirusTotal API key,
        and the number of worker threads to use.
        It also checks the validity of the passed values and raises exceptions if they are invalid.
        :param url: tuple[str, ...] url/s for scanning
        :param vt_key: str API key
        :param workers: int = 7 max thread workers

        """
        self.set_api_key(vt_key)
        super().__init__()
        if not isinstance(workers, int):
            raise vt_exceptions.ThreadingError()
        self.__workers: int = workers

        for every_url in url:
            if not validators.url(every_url):
                raise vt_exceptions.UrlError()
            self.__url: tuple[str, ...] = url

        if not is_letters_and_digits(vt_key):
            raise vt_exceptions.ApiKeyError()
        self.__vt_key: str = vt_key



    @property
    def url(self) -> tuple[str, ...]:
        return self.__url

    @property
    def workers(self) -> int:
        return self.__workers

    @property
    def vt_key(self) -> str:
        return self.__vt_key



    def _get_req_url(self, _url: str, _id: str = None, limit: int = None, cursor: str = None) -> dict[str, dict]:
        """
        sends a GET request to a specific URL and returns the response in the form of a dictionary.
        It uses the urls base64 hash as the identifier.
        raises exceptions if the request fails or returns empty content.
        :param _url: an url
        :return: dict[str, dict]

        """
        if self._restrictions():
            self.set_limit_counters()
            headers: dict = {
                "accept": "application/json",
                "x-apikey": self.vt_key
            }
            if (_id is None or len(_id) < 50) or not limit:
                url_id: str = base64.urlsafe_b64encode(f'{_url}'.encode()).decode().strip('=')
                api = self.get_vt_api_url + url_id

            if limit and _id:
                if cursor:
                    ret = '/comments' + f'?limit={limit}'  + f'&cursor={cursor}'
                else:
                    ret = '/comments' + f'?limit={limit}'
                api = self.get_vt_api_url_ret_comment + _id + ret

            # API request
            req = requests.get(url=api, headers=headers)

            if req.status_code >= 400:
                raise vt_exceptions.RequestFailed()
            elif req.json():
                # return dict[str, dict]
                return req.json()
            else:
                raise vt_exceptions.EmptyContentError()
        else:
            raise vt_exceptions.RestrictionsExclusion()



    def _post_req_url(self, _url: str, _id: str = None, rescan: bool = None,
                      comment: str = None, verdict: str = None) -> dict[str, dict]:
        """
        sends a POST request to a specific URL and returns the response in the form of a dictionary.
        raises exceptions if the request fails or returns empty content.
        :param _url: an url
        :return: dict[str, dict]

        """
        if self._restrictions():
            self.set_limit_counters()

            # regular post request
            if (_id is None or len(_id) < 50) or not (rescan or comment or verdict):
                payload: str | dict | None = f"url={_url}"
                headers: dict = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key,
                    "content-type": "application/x-www-form-urlencoded"
                }
                api = self.post_vt_api_url

            # whether if rescan
            if rescan and not comment:
                payload = None
                headers: dict = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key,
                    "content-type": "application/x-www-form-urlencoded"
                }
                api = self.post_vt_api_url_rescan + _id + '/analyse'

            # whether if comment
            if comment and not rescan:
                headers: dict = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key,
                    "content-type": "application/json"
                }
                payload = {"data": {
                    "type": "comment",
                    "attributes": {"text": comment}
                }}
                api = self.post_vt_api_url_add_comment + _id + '/comments'

            # whether if vote
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
                api = self.post_vt_url_add_vote + _id + '/votes'

            # API request
            if comment or verdict:
                # for adding a comment
                req = requests.post(url=api, json=payload, headers=headers)
                if req.status_code == 400:
                    raise vt_exceptions.VoteError()
                if req.status_code == 409:
                    raise vt_exceptions.IdenticalCommentExistError()
            else:
                # all other requests
                req = requests.post(url=api, data=payload, headers=headers)
            if req.status_code >= 400:
                raise vt_exceptions.RequestFailed()
            if req.json():
                # return dict[str, dict]
                return req.json()
            else:
                raise vt_exceptions.EmptyContentError()
        else:
            raise vt_exceptions.RestrictionsExclusion()



    @VTAutomator.get_cache_url
    def _gets_a_url(self) -> int:
        """
        decorator function that retrieves the url information from the cache if it exists,
        otherwise it calls the _get_req_url function to get the information from the API.
        :return: int

        """
        rep: int = self['data']['attributes']['reputation']
        if rep is not None:
            return rep
        else:
            raise vt_exceptions.UrlNotFoundError()



    def get_url(self) -> tuple[str, int]:
        """
        function dedicated for GET action on one url
        :return: tuple[str, int]

        """
        return self.url[0], self._gets_a_url(self.url[0])



    def get_urls(self) -> list[tuple[str, int]]:
        """
        creates a list of futures by submitting the method self._gets_a_url with each URL
        :return: list[tuple[str, int]]

        """
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            futures = [executor.submit(self._gets_a_url, _url) for _url in self.url]
            for future in as_completed(futures):
                url = self.url[futures.index(future)]
                results.append((url, future.result()))
        if len(results) == len(self.url):
            return results
        else:
            vt_exceptions.UrlNotFoundError()



    def get_url_comments(self, limit: int = None, cursor: str = None, comment_url_limit: tuple[str, int, str | None] = None,
                    return_cursor: bool = None) -> list[str]:
        """
        function dedicated for adding a comment on a scanned url
        force virustotal for analysis
        :param return_cursor: if dev wants cursor
        :param cursor: continuation cursor
        :param limit: limit of comments to retrieve
        :param comment_url_limit: if many
        :return: list[str]
        """
        if comment_url_limit:
            _cursor = comment_url_limit[2]
            _limit = comment_url_limit[1]
            _url = comment_url_limit[0]
        else:
            _url = self.url[0]
            _limit = limit
            _cursor = cursor

        if _url in self.cache_url_dict:
            _id: str = self.cache_url_dict[_url]['data']['id']
            rep: dict = self._get_req_url(_url, _id=_id, limit=_limit, cursor=_cursor)
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
                    raise vt_exceptions.UrlNotFoundError()
            except IndexError:
                raise vt_exceptions.NoCommentsError()
        else:
            raise vt_exceptions.NotInCacheError()


    def get_urls_comments(self, limit: int, cursor: str = None) -> list[list, ...]:
        """
        function dedicated for adding a comments on a scanned urls
        force virustotal for analysis
        :param cursor: continuation cursor
        :param limit: limit of comments to retrieve
        :return: list[list, ...]
        """
        results = []
        with ThreadPoolExecutor(self.workers) as executor:
            url_limit_cursor_tuples = [(url, limit, cursor) for url in self.url]
            for data in url_limit_cursor_tuples:
                post_with_args = partial(self.get_url_comments, comment_url_limit=data)
                results.append(list(executor.map(post_with_args, url_limit_cursor_tuples))[0])
        return results


    def post_url(self, _url = None) -> True:
        """
        function dedicated for POST action on url
        :return: 'analysis'

        """
        if _url is None:
            _url = self.url[0]
        rep: str = self._post_req_url(_url).get('data')['type']
        if rep == 'analysis':
             return True
        else:
             vt_exceptions.UrlNotFoundError()



    def post_urls(self) -> tuple[bool, int]:
        """
        creates a list of futures by submitting the method self.post_url with each url
        :return: list[tuple[str, int]]

        """
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            futures = [executor.submit(self.post_url, _url) for _url in self.url]
            for future in as_completed(futures):
                results.append(future.result())
        if len(results) == len(self.url):
            return True, len(results)
        else:
            vt_exceptions.UrlNotFoundError()



    def post_rescan(self, _url = None) -> True:
        """
        function dedicated for POST "rescan" action on url
        force virustotal for analysis
        :param _url:
        :return:
        """
        if _url is None:
            _url = self.url[0]
        if _url in self.cache_url_dict:
            _id: str = self.cache_url_dict[_url]['data']['id']
            rep: str = self._post_req_url(_url, _id=_id).get('data')['type']
            if rep == 'analysis':
                return True
            else:
                raise vt_exceptions.UrlNotFoundError()
        else:
            raise vt_exceptions.RescanError()



    def post_rescans(self) -> tuple[bool, int]:
        """
        creates a list of futures by submitting the method self.post_rescan with each url
        :return: list[tuple[str, int]]

        """
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            futures = [executor.submit(self.post_rescan, _url) for _url in self.url]
            for future in as_completed(futures):
                results.append(future.result())
        if len(results) == len(self.url):
            return True, len(results)
        else:
            raise vt_exceptions.RescanError()



    def post_url_comment(self, comment = None, comment_url: tuple[str, str] = None) -> True:
        """
        function dedicated for adding a comment on a scanned url
        force virustotal for analysis
        :param comment_url: if many
        :param comment: if one
        :return: True
        """
        if comment_url:
            _url = comment_url[1]
            _comment = comment_url[0]
        else:
            _url = self.url[0]
            _comment = comment

        if _url in self.cache_url_dict:
            _id: str = self.cache_url_dict[_url]['data']['id']
            rep: str = self._post_req_url(_url, _id=_id, comment=_comment).get('data')['type']
            if rep == 'comment':
                return True
            else:
                raise vt_exceptions.UrlNotFoundError()
        else:
            raise vt_exceptions.NotInCacheError()



    def post_urls_comments(self, comments: tuple[str, ...]) -> tuple[bool, int]:
        """
        function dedicated for adding a comments on a scanned urls
        force virustotal for analysis
        :param comments: tuple of str comments
        :return: True
        """
        with ThreadPoolExecutor(self.workers) as executor:
            comment_url_tuples = [(comment, url) for comment, url in zip(comments, self.url)]
            post_comment_with_args = partial(self.post_url_comment, self)
            results = list(executor.map(post_comment_with_args, comment_url_tuples))
        if len(results) == len(comments):
            return True, len(results)
        else:
            raise vt_exceptions.NotInCacheError()


    def post_vote(self, verdict: str, _url = None) -> True:
        """
        This function allows for voting on a URL's verdict, with the options being "malicious" or "harmless."
        :param verdict:
        :param _url:
        :return: True
        """
        if verdict not in ['malicious', 'harmless']:
            raise vt_exceptions.VerdictError()

        if _url is None:
            _url = self.url[0]
        if _url in self.cache_url_dict:
            _id: str = self.cache_url_dict[_url]['data']['id']
            rep: str = self._post_req_url(_url, _id=_id ,verdict=verdict).get('data')['type']
            if rep == 'vote':
                return True
            else:
                raise vt_exceptions.UrlNotFoundError()
        else:
            raise vt_exceptions.NotInCacheError()



    def post_get_url(self, _url: str = None) -> tuple[str, int]:
        """
        used to both upload and retrieve the scan results of an url.
        It starts by uploading the url to VirusTotal API by calling the post_url function.
        It iterates over the url(s) and calls the _gets_a_url function to get the scan results of the url.
        :param _url: an url
        :return: tuple[str, int]

        """
        if _url is None:
            _url = self.url
        for _ in self.url:
            self.post_url()
            for _ in range(1):
                res_code = self._gets_a_url(_url)
                if isinstance(res_code, int):
                    return _url, res_code
                else:
                    time.sleep(20)



    def post_get_urls(self) -> list[tuple]:
        """
        Takes the urls specified in the constructor and scans them using the VirusTotal API.
        It uses the ThreadPoolExecutor to execute the requests concurrently and the as_completed function
        to retrieve the results as soon as they are available.
        :return: list[tuple]

        """
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            future = [executor.submit(self.post_get_url, _url) for _url in self.url]
            for f in as_completed(future):
                results.append(f.result())
        if len(results) == len(self.url):
            return results
        else:
            raise vt_exceptions.UrlNotFoundError()



    def _get_req_file(self, _file):
        pass

    def _post_req_file(self, _file):
        pass


