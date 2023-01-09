from concurrent.futures import ThreadPoolExecutor, as_completed
from vt_base import *
import vt_exeptions
import requests
import base64
import time


class VTUrl(VTAutomator):

    def __init__(self, url: tuple[str, ...], vt_key: str, workers: int = 7):
        super().__init__()

        if not isinstance(workers, int):
            raise vt_exeptions.ThreadingError()
        self.__workers: int = workers

        for every_url in url:
            if not isinstance(every_url, str):
                raise vt_exeptions.UrlError()
        self.__url: tuple[str, ...] = url

        if not isinstance(vt_key, str) or not vt_key:
            raise vt_exeptions.ApiKeyError()
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

    def _get_req_url(self) -> dict[str, dict]:
        if self.requests_amount_limit_counter < 500 and \
                self.requests_per_minute_limit_counter < 4:

            self.set_amount_limit_counter()
            self.set_per_minute_limit_counter()

            for index, every_url in enumerate(self.url):
                headers: dict = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key
                }
                url_id: str = base64.urlsafe_b64encode(f'{self.url[index]}'.encode()).decode().strip('=')
                req: 'requests' = requests.get(url=self.get_vt_api_url + url_id, headers=headers)

                if req.status_code >= 400:
                    raise vt_exeptions.RequestFailed()
                elif bool(req.json()):
                    return req.json()
                else:
                    raise vt_exeptions.EmptyContentError()

    def _post_req_url(self) -> dict[str, dict]:
        if self.requests_amount_limit_counter < 500 and \
                self.requests_per_minute_limit_counter < 4:

            self.set_amount_limit_counter()
            self.set_per_minute_limit_counter()

            for index, every_url in enumerate(self.url):
                payload: str = f"url={self.url[index]}"

                headers: dict = {
                    "accept": "application/json",
                    "x-apikey": self.vt_key,
                    "content-type": "application/x-www-form-urlencoded"
                }
                req: 'requests' = requests.post(self.post_vt_api_url, data=payload, headers=headers)

                if req.status_code >= 400:
                    raise vt_exeptions.RequestFailed()
                if bool(req.json()):
                    return req.json()
                else:
                    raise vt_exeptions.EmptyContentError()

    @VTAutomator.get_cache_url
    def get_url(self):
        rep: int = self['data']['attributes']['reputation']
        if rep is not None:
            return rep
        else:
            raise FileNotFoundError()

    def post_url(self) -> str:
        rep: str = self._post_req_url().get('data')['type']
        if rep is not None:
            return rep
        else:
            raise FileNotFoundError()

    def post_get_url(self, _url: str = None) -> tuple[str, int]:
        if _url is None:
            _url = self.url
        self.post_url()
        for _ in range(10):
            res_code = self.get_url()
            if isinstance(res_code, int):
                return _url, res_code
            else:
                time.sleep(30)

    def post_get_urls(self) -> list[tuple]:
        results: list = list()
        with ThreadPoolExecutor(self.workers) as executor:
            future = [executor.submit(self.post_get_url, _url) for _url in self.url]
            for f in as_completed(future):
                results.append(f.result())
        return results


    def _get_req_file(self):
        pass

    def _post_req_file(self):
        pass
