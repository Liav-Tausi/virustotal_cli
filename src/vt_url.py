"""
vt_automator.
created by: liav tausi
date: 1/12/2023
"""

import base64
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from typing import Any

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
        super().__init__(vt_key=vt_key)
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



    def _get_req(self, _url: str, _id: str = None, limit: int = None, cursor: str = None, verdict: bool = False) -> dict[str, dict]:
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
            # regular get request
            if (_id is None or len(_id) < 50) or not limit:
                url_id: str = base64.urlsafe_b64encode(f'{_url}'.encode()).decode().strip('=')
                api = self.get_vt_api_url + url_id

            # whether comment
            if (limit and _id) and not verdict:
                if cursor:
                    ret = '/comments' + f'?limit={limit}' + f'&cursor={cursor}'
                else:
                    ret = '/comments' + f'?limit={limit}'
                api = self.get_vt_api_url_ret_comment + _id + ret

            # whether vote
            if verdict:
                if cursor and limit:
                    ret = '/votes' + f'?limit={limit}' + f'&cursor={cursor}'
                elif limit:
                    ret = '/votes' + f'?limit={limit}'
                elif cursor:
                    ret = '/votes' + f'&cursor={cursor}'
                else:
                    ret = '/votes'
                api = self.get_vt_url_ret_vote + _id + ret

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



    def _post_req(self, _url: str, _id: str = None, rescan: bool = None,
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
        otherwise it calls the _get_req function to get the information from the API.
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
        try:
            return_cursor = comment_url_limit[3]
        except IndexError:
            _cursor = comment_url_limit[2]
            _limit = comment_url_limit[1]
            _url = comment_url_limit[0]
        else:
            _url = self.url[0]
            _limit = limit
            _cursor = cursor

        if _url in self.cache_url_dict:
            _id: str = self.cache_url_dict[_url]['data']['id']
            rep: dict = self._get_req(_url, _id=_id, limit=_limit, cursor=_cursor)
            try:
                if return_cursor:
                    return rep.get('meta')['cursor']
                elif rep.get('data')[0]['type'] == 'comment':
                    comments: list = list()
                    for index in range(int(_limit)):
                        try:
                            for data in rep.get('data')[index]['attributes']:
                                if data == 'text':
                                    comments.append(rep.get('data')[index]['attributes']['text'])
                        except IndexError:
                            return comments
                    return comments

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



    def get_url_votes(self, limit: int = 1 ,_url: str = None, cursor: str = None, return_cursor: bool = False,
                      vote_url_limit: tuple[str, int, str | None] = None) -> list | Any:
        """
        This function allows getting your vote on a URL
        :param vote_url_limit: if many
        :param return_cursor: if dev wants cursor
        :param cursor: continuation cursor
        :param limit: limit of votes to retrieve
        :param _url: url
        :return: dict[str]

        """
        try:
            return_cursor = vote_url_limit[3]
        except IndexError:
            _cursor = vote_url_limit[2]
            _limit = vote_url_limit[1]
            _url = vote_url_limit[0]
        else:
            _url = self.url[0]
            _limit = limit
            _cursor = cursor

        if _url in self.cache_url_dict:
            _id: str = self.cache_url_dict[_url]['data']['id']
            rep: dict = self._get_req(_url, _id=_id, limit=_limit, cursor=_cursor, verdict=True)
            try:
                if return_cursor:
                    return rep.get('meta')['cursor']
                elif rep.get('data')[0]['type'] == 'vote':
                    votes: list = list()
                    for index in range(int(_limit)):
                        try:
                            for data in rep.get('data')[index]['attributes']:
                                if data == 'verdict':
                                    votes.append(rep.get('data')[index]['attributes']['verdict'])
                        except IndexError:
                            return votes
                    return votes
                else:
                    raise vt_exceptions.UrlNotFoundError()
            except IndexError:
                raise vt_exceptions.NoVoteError()
        else:
            raise vt_exceptions.NotInCacheError()


    def get_urls_votes(self, limit: int = 1, cursor: str = None) -> list[list, ...]:
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
                get_with_args = partial(self.get_url_votes, vote_url_limit=data)
                results.append(list(executor.map(get_with_args, url_limit_cursor_tuples))[0])
        return results


    def post_url(self, _url = None) -> True:
        """
        function dedicated for POST action on url
        :return: 'analysis'

        """
        if _url is None:
            _url = self.url[0]
        rep: str = self._post_req(_url).get('data')['type']
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
            rep: str = self._post_req(_url, _id=_id).get('data')['type']
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
            rep: str = self._post_req(_url, _id=_id, comment=_comment).get('data')['type']
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


    def post_url_vote(self, verdict: str = None, verdict_url: tuple[str, str] = None) -> True:
        """
          This function allows for voting on a URL's verdict, with the options being "malicious" or "harmless."
          :param verdict_url: if many
          :param verdict: vote
          :return: True
          """
        if verdict_url:
            _url = verdict_url[1]
            _verdict = verdict_url[0]
        else:
            _url = self.url[0]
            _verdict = verdict

        if _verdict not in ['malicious', 'harmless']:
            raise vt_exceptions.VerdictError()

        if _url is None:
            _url= self.url[0]
        if _url in self.cache_url_dict:
            _id: str = self.cache_url_dict[_url]['data']['id']
            try:
                rep: str = self._post_req(_url, _id=_id, verdict=_verdict).get('data')['type']
            except vt_exceptions.IdenticalCommentExistError:
                raise vt_exceptions.VoteError()
            if rep == 'vote':
                return True
            else:
                raise vt_exceptions.UrlNotFoundError()
        else:
            raise vt_exceptions.NotInCacheError()


    def post_urls_votes(self, verdicts: tuple[str, ...]) -> tuple[bool, int]:
        """
        This function allows for voting on a URL's verdict, with the options being "malicious" or "harmless."
        :param verdicts: votes, "malicious" or "harmless"
        :return: True, amount of votes
        """
        with ThreadPoolExecutor(self.workers) as executor:
            votes_url_tuples = [(vote, url) for vote, url in zip(verdicts, self.url)]
            results = []
            for data in votes_url_tuples:
                post_vote_with_args = partial(self.post_url_vote, verdict_url=data)
                results.append(executor.submit(post_vote_with_args))
        if len(results) == len(verdicts):
            return True, len(results)
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


