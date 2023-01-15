"""
vt_automator.
created by: liav tausi
date: 1/12/2023
"""

from datetime import timedelta, date, datetime
from abc import ABC, abstractmethod
from threading import Lock
import vt_exceptions
import functools
import requests
import atexit
import pytz
import json
import os




class VTAutomator(ABC):
    """
    store the URLs of the VirusTotal APIs GET and POST endpoints for URLs and files.
    """
    # _____stats____ #
    __USER_QUOTA_SUMMARY: str = 'https://www.virustotal.com/api/v3/users/'

    # _____urls_____ #
    __GET_VT_API_URL: str = r'https://www.virustotal.com/api/v3/urls/'
    __POST_VT_API_URL: str = r'https://www.virustotal.com/api/v3/urls'

    # _____files_____ #
    __GET_VT_API_FILE: str = r'https://www.virustotal.com/api/v3/files/'
    __POST_VT_API_FILE: str = r'https://www.virustotal.com/api/v3/files'

    def __init__(self, ref_cache_month: int = 1):
        """
        this is an abstract base/father class for the ather class.
        it stores info and creates structured base.
        it tries to open and read the data from two json files 'vt_cache_url.json' and 'vt_cache_file.json'
        and loads the data in the dicts __cache_url_dict and __cache_file_dict.
        It also sets the requests amount and requests per minute limits for interacting with the VirusTotal API.
        param ref_cache_month: cache refresh rate
        """
        # registering a save_data function to be called when the program exits
        atexit.register(self.save_data)
        self.__api_key = self.api_key
        self._get_allaowens()

        self.__requests_monthly_amount_limit = self.requests_monthly_amount_limit
        self.__requests_monthly_amount_limit_counter = self.requests_monthly_amount_limit_counter

        self.__requests_daily_amount_limit = self.requests_daily_amount_limit
        self.__requests_daily_amount_limit_counter = self.requests_daily_amount_limit_counter

        self.__requests_hourly_amount_limit = self.requests_hourly_amount_limit
        self.__requests_hourly_amount_limit_counter = self.requests_hourly_amount_limit_counter

        if ref_cache_month < 1:
            ref_cache_month = 1
        ref_date = date.today() + timedelta(weeks=4 * ref_cache_month)
        self.__ref_cache_month: date.month = ref_date.month

        # threading locks
        self.lock1 = Lock()
        self.lock2 = Lock()
        self.lock3 = Lock()
        self.lock4 = Lock()
        self.lock5 = Lock()
        self.lock6 = Lock()
        self.lock7 = Lock()
        self.lock8 = Lock()
        self.lock9 = Lock()
        self.lock10 = Lock()

        self.__cache_url_dict = dict()
        self.__cache_file_dict = dict()

        # cache dicts
        try:
            # open and read the data from two json files 'vt_cache_url.json' and 'vt_cache_file.json'
            if not os.path.exists('vt_cache_url.json'):
                with open('vt_cache_url.json', 'x') as fh:
                    pass
            else:
                with open('vt_cache_url.json', 'r') as fh1:
                    self.__cache_url_dict = json.load(fh1)

            if not os.path.exists('vt_cache_file.json'):
                with open('vt_cache_file.json', 'x') as fh:
                    pass
            else:
                with open('vt_cache_file.json', 'r') as fh2:
                    self.__cache_file_dict = json.load(fh2)

        except FileNotFoundError:
            self.__cache_url_dict = dict()
            self.__cache_file_dict = dict()

    # _____property_____ #

    @property
    def api_key(self) -> str:
        return self.__api_key

    @property
    def get_user_quota_summary(self) -> str:
        return self.__USER_QUOTA_SUMMARY

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
    def requests_monthly_amount_limit(self) -> int:
        return self.__requests_monthly_amount_limit

    @property
    def requests_monthly_amount_limit_counter(self) -> int:
        return self.__requests_monthly_amount_limit_counter

    @property
    def requests_daily_amount_limit(self) -> int:
        return self.__requests_daily_amount_limit

    @property
    def requests_daily_amount_limit_counter(self) -> int:
        return self.__requests_daily_amount_limit_counter

    @property
    def requests_hourly_amount_limit(self) -> int:
        return self.__requests_hourly_amount_limit

    @property
    def requests_hourly_amount_limit_counter(self) -> int:
        return self.__requests_hourly_amount_limit_counter

    # @property
    # def requests_per_minute_limit(self) -> int:
    #     return self.__requests_per_minute_limit

    # @property
    # def requests_per_minute_limit_counter(self) -> int:
    #     return self.__requests_per_minute_limit_counter

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
    # monthly limit
    def set_requests_monthly_amount_limit(self, limit: int) -> None:
        with self.lock4:
            self.__requests_monthly_amount_limit = limit

    # monthly limit counter
    def set_requests_monthly_amount_limit_counter(self, limit: int) -> None:
        with self.lock5:
            self.__requests_monthly_amount_limit_counter = limit

    # daily limit
    def set_requests_daily_amount_limit(self, limit: int) -> None:
        with self.lock6:
            self.__requests_daily_amount_limit = limit

    # daily limit counter
    def set_requests_daily_amount_limit_counter(self, limit: int) -> None:
        with self.lock7:
            self.__requests_daily_amount_limit_counter = limit

    # hourly limit
    def set_requests_hourly_amount_limit(self, limit: int) -> None:
        with self.lock8:
            self.__requests_hourly_amount_limit = limit

    # hourly limit counter
    def set_requests_hourly_amount_limit_counter(self, limit: int) -> None:
        with self.lock9:
            self.__requests_hourly_amount_limit_counter = limit

    def set_api_key(self, key: str = None) -> None:
        self.__api_key = key

    # update counters
    def set_limit_counters(self) -> None:
        with self.lock1:
            self.__requests_monthly_amount_limit_counter += 1
            self.__requests_daily_amount_limit_counter += 1
            self.__requests_hourly_amount_limit_counter += 1

    # update dict from url decorator
    def _update_cache_url_dict(self, url_inx, result) -> None:
        with self.lock2:
            self.__cache_url_dict[url_inx] = result

    # update dict from file decorator
    def _update_cache_file_dict(self, path, result) -> None:
        with self.lock3:
            self.__cache_file_dict[path] = result

    # ______decorators______ #
    @staticmethod
    def get_cache_url(func):
        """
        The decorator checks if the given url is present in the __cache_url_dict,
        if present it fetches the dict path, last analysis date and time, current date and time and expire date.
        If the current date and time is greater than or equal to the expire date, it removes the url from the cache.
        Else it returns the result of the original function by passing the dict path.
        f the url is not present in the dict, it calls the _get_req_url method
        and updates the cache dict by calling the _update_cache_url_dict method and returns the result of the original
        function by passing the dict path.
        :param func:
        :return:
        """

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
        """
        The decorator checks if the given file is present in the __cache_file_dict,
        if present it fetches the dict path, last analysis date and time, current date and time and expire date.
        If the current date and time is greater than or equal to the expire date, it removes the file from the cache.
        Else it returns the result of the original function by passing the dict path.
        If the file is not present in the dict, it calls the _get_req_file method
        and updates the cache dict by calling the _update_cache_file_dict method and returns the result of the original
        function by passing the dict path.
        :param func:
        :return:
        """

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

    def save_data(self) -> None:
        """
        save data in cache to 'vt_cache_url.json' and 'vt_cache_file.json'.
        :return: None
        """
        with open('vt_cache_url.json', 'w') as fh1:
            json.dump(self.cache_url_dict, fh1)

        with open('vt_cache_file.json', 'w') as fh2:
            json.dump(self.cache_file_dict, fh2)

    def _get_user_quora_summary(self) -> dict[str, dict]:

        headers: dict = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        # API request
        req: 'requests' = requests.get(url=self.get_user_quota_summary + self.api_key + '/overall_quotas',
                                       headers=headers)
        if req.status_code >= 400:
            raise vt_exceptions.RequestFailed()
        elif bool(req.json()):
            # return dict[str, dict]
            return req.json()
        else:
            raise vt_exceptions.EmptyContentError()

    def _get_allaowens(self):
        summary: dict = self._get_user_quora_summary()
        if summary is not None:
            hourly_info = summary.get("data")["api_requests_hourly"]
            self.set_requests_hourly_amount_limit(hourly_info["user"]["allowed"])
            self.set_requests_hourly_amount_limit_counter(hourly_info["user"]["used"])

            daily_info = summary.get("data")["api_requests_daily"]
            self.set_requests_daily_amount_limit(daily_info["user"]["allowed"])
            self.set_requests_daily_amount_limit_counter(daily_info["user"]["used"])

            monthly_info = summary.get("data")["api_requests_monthly"]
            self.set_requests_monthly_amount_limit(monthly_info["user"]["allowed"])
            self.set_requests_monthly_amount_limit_counter(monthly_info["user"]["used"])

    def _restrictions(self) -> bool:
        if self.requests_hourly_amount_limit_counter < self.requests_hourly_amount_limit \
                or self.requests_daily_amount_limit_counter < self.requests_daily_amount_limit \
                or self.requests_monthly_amount_limit_counter < self.requests_monthly_amount_limit:
            return True
        else:
            return False



