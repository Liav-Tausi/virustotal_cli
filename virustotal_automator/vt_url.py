"""
vt_automator.
created by: liav tausi
date: 1/12/2023
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from vt_base import *
import vt_exceptions
import requests
import base64
import time


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
            if not isinstance(every_url, str):
                raise vt_exceptions.UrlError()
            self.__url: tuple[str, ...] = url

        if not isinstance(vt_key, str) or not vt_key:
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

    def _get_req_url(self, _url) -> dict[str, dict]:
        """
        sends a GET request to a specific URL and returns the response in the form of a dictionary.
        It uses the url's base64 hash as the identifier.
        raises exceptions if the request fails or returns empty content.
        :param _url: a url
        :return: dict[str, dict]

        """
        if self._restrictions():
            self.set_limit_counters()

            headers: dict = {
                "accept": "application/json",
                "x-apikey": self.vt_key
            }
            # API request
            url_id: str = base64.urlsafe_b64encode(f'{_url}'.encode()).decode().strip('=')
            req: 'requests' = requests.get(url=self.get_vt_api_url + url_id, headers=headers)

            if req.status_code >= 400:
                raise vt_exceptions.RequestFailed()
            elif bool(req.json()):
                # return dict[str, dict]
                return req.json()
            else:
                raise vt_exceptions.EmptyContentError()
        else:
            raise vt_exceptions.RestrictionsExclusion()

    def _post_req_url(self, _url) -> dict[str, dict]:
        """
        sends a POST request to a specific URL and returns the response in the form of a dictionary.
        raises exceptions if the request fails or returns empty content.
        :param _url: a url
        :return: dict[str, dict]

        """
        if self._restrictions():
            self.set_limit_counters()

            payload: str = f"url={_url}"
            headers: dict = {
                "accept": "application/json",
                "x-apikey": self.vt_key,
                "content-type": "application/x-www-form-urlencoded"
            }

            # API request
            req: 'requests' = requests.post(self.post_vt_api_url, data=payload, headers=headers)
            if req.status_code >= 400:
                raise vt_exceptions.RequestFailed()
            if bool(req.json()):
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
            raise FileNotFoundError()

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
        return results



    def post_url(self, _url: str = None) -> bool:
        """
        function dedicated for POST action on file
        :param _url: an url
        :return: 'analysis'

        """
        rep: str = self._post_req_url(_url).get('data')['type']
        if rep == 'analysis':
            return True
        else:
            raise FileNotFoundError()

    def post_urls(self) -> bool:
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
            return True

    def post_get_url(self, _url: str = None) -> tuple[str, int]:
        """
        used to both upload and retrieve the scan results of an url.
        It starts by uploading the url to VirusTotal API by calling the post_file function.
        It iterates over the url(s) and calls the _gets_a_url function to get the scan results of the url.
        :param _url: an url
        :return: tuple[str, int]

        """
        if _url is None:
            _url = self.url
        for _ in self.url:
            self.post_url(_url)
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
        return results

    def _get_req_file(self, _file):
        pass

    def _post_req_file(self, _file):
        pass
