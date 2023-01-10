
from datetime import timedelta, date, datetime
from abc import ABC, abstractmethod
from threading import Lock
import functools
import pytz
import time


class VTAutomator(ABC):
    # _____urls_____ #
    __GET_VT_API_URL: str = r'https://www.virustotal.com/api/v3/urls/'
    __POST_VT_API_URL: str = r'https://www.virustotal.com/api/v3/urls'
    __CACHE_URL_DICT: dict = dict()

    # _____files_____ #
    __GET_VT_API_FILE: str = r'https://www.virustotal.com/api/v3/files/'
    __POST_VT_API_FILE: str = r'https://www.virustotal.com/api/v3/files'
    __CACHE_FILE_DICT: dict = dict()

    def __init__(self, ref_cache_month: int = 1):
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
    def cache_url_dict(self) -> dict['pytz.UTC', list[str, dict]]:
        return self.__CACHE_URL_DICT

    @property
    def cache_file_dict(self) -> dict['pytz.UTC', list[str, dict]]:
        return self.__CACHE_FILE_DICT

    # _____abstractmethod_urls____ #

    @abstractmethod
    def _get_req_url(self):
        pass

    @abstractmethod
    def _post_req_url(self):
        pass

    # _____abstractmethod_files____ #

    @abstractmethod
    def _get_req_file(self):
        pass

    @abstractmethod
    def _post_req_file(self):
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

    # ______decorators______ #

    @staticmethod
    def get_cache_url(func):
        @functools.wraps(func)
        def wrapper(*args):
            for url_inx in args[0].url:
                if url_inx in args[0].cache_url_dict:
                    result = args[0].cache_url_dict[url_inx]
                    last_analysis_epoch = result.get('data')['attributes']["last_analysis_date"]
                    last_analysis_utc = datetime.utcfromtimestamp(last_analysis_epoch).astimezone(pytz.UTC)
                    now = datetime.utcnow().astimezone(tz=pytz.UTC)
                    expire_date = last_analysis_utc + timedelta(args[0].ref_cache_month)
                    if now >= expire_date:
                        args[0].cache_url_dict.pop(datetime.utcnow().astimezone(tz=pytz.UTC))
                    else:
                        return func(args[0]._get_req_url())
                else:
                    args[0].cache_url_dict[url_inx] = args[0]._get_req_url()
                    return func(args[0].cache_url_dict[url_inx])

        return wrapper

    @staticmethod
    def get_cache_file(func):
        @functools.wraps(func)
        def wrapper(*args):
            for path in args[0].file:
                if path in args[0].cache_file_dict:
                    result = args[0].cache_file_dict[path]
                    last_analysis_epoch = result.get('data')['attributes']["last_analysis_date"]
                    last_analysis_utc = datetime.utcfromtimestamp(last_analysis_epoch).astimezone(pytz.UTC)
                    now = datetime.utcnow().astimezone(tz=pytz.UTC)
                    expire_date = last_analysis_utc + timedelta(args[0].ref_cache_month)
                    if now >= expire_date:
                        args[0].cache_file_dict.pop(datetime.utcnow().astimezone(tz=pytz.UTC))
                    else:
                        return func(args[0]._get_req_file())
                else:
                    args[0].cache_file_dict[path] = args[0]._get_req_file()
                    return func(args[0].cache_file_dict[path])

        return wrapper

