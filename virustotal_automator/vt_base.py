
from datetime import timedelta, date, datetime
from abc import ABC, abstractmethod
from threading import Lock
import functools
import atexit
import pytz
import time
import json
import os


class VTAutomator(ABC):
    # _____urls_____ #
    __GET_VT_API_URL: str = r'https://www.virustotal.com/api/v3/urls/'
    __POST_VT_API_URL: str = r'https://www.virustotal.com/api/v3/urls'

    # _____files_____ #
    __GET_VT_API_FILE: str = r'https://www.virustotal.com/api/v3/files/'
    __POST_VT_API_FILE: str = r'https://www.virustotal.com/api/v3/files'

    def __init__(self, ref_cache_month: int = 1):
        atexit.register(self.save_data)

        self.__requests_amount_limit: int = 500
        self.__requests_amount_limit_counter: int = 0

        self.__requests_per_minute_limit: int = 4
        self.__requests_per_minute_limit_counter = 0

        if ref_cache_month < 1:
            ref_cache_month = 1
        ref_date = date.today() + timedelta(weeks=4 * ref_cache_month)
        self.__ref_cache_month: date.month = ref_date.month

        self.lock1 = Lock()
        self.lock2 = Lock()

        try:
            if os.path.exists('vt_cache_url.json'):
                with open('vt_cache_url.json', 'r') as fh1:
                    self.__cache_url_dict = json.load(fh1)
            if os.path.exists('vt_cache_file.json'):
                with open('vt_cache_file.json', 'r') as fh2:
                    self.__cache_file_dict = json.load(fh2)
        except FileNotFoundError:
            self.__cache_url_dict = dict()
            self.__cache_file_dict = dict()


    # _____property_____ #

    @property
    def get_vt_api_url(self) -> str:
        return self.__GET_VT_API_URL

    @property
    def post_vt_api_url(self) -> str:
        return self.__POST_VT_API_URL

    @property
    def get_vt_api_file(self) -> str:
        return self.__GET_VT_API_FILE

    @property
    def post_vt_api_file(self) -> str:
        return self.__POST_VT_API_FILE

    @property
    def requests_amount_limit(self) -> int:
        return self.__requests_amount_limit

    @property
    def requests_amount_limit_counter(self) -> int:
        return self.__requests_amount_limit_counter

    @property
    def requests_per_minute_limit(self) -> int:
        return self.__requests_per_minute_limit

    @property
    def requests_per_minute_limit_counter(self) -> int:
        return self.__requests_per_minute_limit_counter

    @property
    def ref_cache_month(self) -> int:
        return self.__ref_cache_month

    @property
    def cache_url_dict(self) -> dict:
        return self.__cache_url_dict

    @property
    def cache_file_dict(self) -> dict:
        return self.__cache_file_dict

    # _____abstractmethod_urls____ #

    @abstractmethod
    def _get_req_url(self, _url):
        pass

    @abstractmethod
    def _post_req_url(self, _url):
        pass

    # _____abstractmethod_files____ #

    @abstractmethod
    def _get_req_file(self, _file):
        pass

    @abstractmethod
    def _post_req_file(self, _file):
        pass

    # _____setters_____#

    def set_amount_limit_counter(self) -> None:
        with self.lock1:
            self.__requests_amount_limit_counter += 1.

    def set_per_minute_limit_counter(self) -> None:
        with self.lock2:
            self.__requests_amount_limit_counter += 1

    def set_amount_limit_refresh(self) -> None:
        day = timedelta(hours=24)
        while True:
            time.sleep(day.total_seconds())
            self.__requests_amount_limit_counter = 0

    def set_per_minute_limit_refresh(self) -> None:
        while True:
            time.sleep(60)
            self.__requests_amount_limit_counter = 0

    def _update_cache_url_dict(self, url_inx, result):
        with self.lock1:
            self.__cache_url_dict[url_inx] = result

    def _update_cache_file_dict(self, path, result):
        with self.lock2:
            self.__cache_file_dict[path] = result

    # ______decorators______ #

    @staticmethod
    def get_cache_url(func):
        @functools.wraps(func)
        def wrapper(*args):
            url = args[1]
            self = args[0]
            if url in self.__cache_url_dict:
                dict_path = self.__cache_url_dict[url]
                last_analysis_epoch = dict_path.get('data')['attributes']["last_analysis_date"]
                last_analysis_utc = datetime.utcfromtimestamp(last_analysis_epoch).astimezone(pytz.UTC)
                now = datetime.utcnow().astimezone(tz=pytz.UTC)
                expire_date = last_analysis_utc + timedelta(self.ref_cache_month)
                if now >= expire_date:
                    self.__cache_url_dict.pop(url)
                else:
                    return func(self.__cache_url_dict[url])
            else:
                result = self._get_req_url(url)
                self._update_cache_url_dict(url_inx=url, result=result)
                return func(self.__cache_url_dict[url])

        return wrapper

    @staticmethod
    def get_cache_file(func):
        @functools.wraps(func)
        def wrapper(*args):
            path = args[1]
            self = args[0]
            if path in self.__cache_file_dict:
                dict_path = self.__cache_file_dict[path]
                last_analysis_epoch = dict_path.get('data')['attributes']["last_analysis_date"]
                last_analysis_utc = datetime.utcfromtimestamp(last_analysis_epoch).astimezone(tz=pytz.UTC)
                now = datetime.utcnow().astimezone(tz=pytz.UTC)
                expire_date = last_analysis_utc + timedelta(self.ref_cache_month)
                if now >= expire_date:
                    self.__cache_file_dict.pop(path)
                else:
                    return func(self.cache_file_dict[path])
            else:
                result = self._get_req_file(path)
                self._update_cache_file_dict(path=path, result=result)
                return func(self.cache_file_dict[path])

        return wrapper

    def save_data(self):
        with open('vt_cache_url.json', 'w') as fh1:
            json.dump(self.cache_url_dict, fh1)

        with open('vt_cache_file.json', 'w') as fh2:
            json.dump(self.cache_file_dict, fh2)
