"""
vt_automator.
created by: liav tausi
date: 1/12/2023
"""

import functools
import json
import os
import re
from abc import ABC, abstractmethod
from datetime import date, datetime, timedelta
from threading import Lock

import pytz
import requests

import vt_exceptions


# VTAutomator is a wrapper for virustotal,
# this program is an CLI running scanner that allows users to scan multiple files and URLs for potential malware and viruses.
# It utilizes the VirusTotal database API and retrieve scan results and reputation scores for the given files or URLs.

# notice_ that you'll have to have a VirusTotal API key!

# validation for api_key
def is_letters_and_digits(key):
    return bool(re.match("^(?=.*[a-zA-Z])(?=.*[0-9])[a-zA-Z0-9]+$", key))


class VTAutomator(ABC):
    """
    store the URLs of the VirusTotal APIs GET and POST endpoints for URLs and files.
    """
    # _____stats____ #
    __USER_QUOTA_SUMMARY: str = 'https://www.virustotal.com/api/v3/users/'

    # ____rescans____ #
    __POST_VT_API_URL_RESCAN: str = r'https://www.virustotal.com/api/v3/urls/'
    __POST_VT_API_FILE_RESCAN: str = r'https://www.virustotal.com/api/v3/files/'

    # _____url_____ #
    __GET_VT_API_URL: str = r'https://www.virustotal.com/api/v3/urls/'
    __POST_VT_API_URL: str = r'https://www.virustotal.com/api/v3/urls'

    # ___url_comments___ #
    __POST_VT_API_URL_ADD_COMMENT: str = r'https://www.virustotal.com/api/v3/urls/'
    __GET_VT_API_URL_RET_COMMENT: str = r'https://www.virustotal.com/api/v3/urls/'

    # ___url_votes___ #
    __POST_VT_URL_ADD_VOTE: str = r'https://www.virustotal.com/api/v3/urls/'
    __GET_VT_URL_RET_VOTE: str = r'https://www.virustotal.com/api/v3/urls/'

    # _____file_____ #
    __GET_VT_API_FILE: str = r'https://www.virustotal.com/api/v3/files/'
    __POST_VT_API_FILE: str = r'https://www.virustotal.com/api/v3/files'

    #___file_comments___ #
    __POST_VT_API_FILE_ADD_COMMENT: str = r'https://www.virustotal.com/api/v3/files/'
    __GET_VT_API_FILE_RET_COMMENT: str = r'https://www.virustotal.com/api/v3/files/'

    # ___file_votes___ #
    __POST_VT_FILE_ADD_VOTE: str = r'https://www.virustotal.com/api/v3/files/'
    __GET_VT_FILE_RET_VOTE: str = r'https://www.virustotal.com/api/v3/files/'

    def __init__(self, vt_key: str, ref_cache_month: int = 1):
        """
        this is an abstract base/father class for the ather class.
        it stores info and creates structured base.
        it tries to open and read the data from two json files 'vt_cache_url.json' and 'vt_cache_file.json'
        and loads the data in the dicts __cache_url_dict and __cache_file_dict.
        It also sets the requests amount and requests per minute limits for interacting with the VirusTotal API.
        param ref_cache_month: cache refresh rate
        """

        # registering a save_data function to be called when the program exits

        self.__api_key: str = vt_key
        self._get_params()

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

        self.__cache_url_dict = dict()
        self.__cache_file_dict = dict()

        # cache dicts
        try:
            # open and read the data from two json files 'vt_cache_url.json' and 'vt_cache_file.json'
            if not os.path.exists('vt_cache_url.json'):
                with open('vt_cache_url.json', 'a') as fh:
                    data: dict = dict()
                    json.dump(data, fh)
            else:
                with open('vt_cache_url.json', 'r') as fh1:
                    data = json.load(fh1)
                    if isinstance(data, dict):
                        self.__cache_url_dict = data

            if not os.path.exists('vt_cache_file.json'):
                with open('vt_cache_file.json', 'a') as fh:
                    data: dict = dict()
                    json.dump(data, fh)
            else:
                with open('vt_cache_file.json', 'r') as fh2:
                    data = json.load(fh2)
                    if isinstance(data, dict):
                        self.__cache_file_dict = data

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
    def post_vt_api_url_rescan(self) -> str:
        return self.__POST_VT_API_URL_RESCAN

    @property
    def post_vt_api_url_add_comment(self) -> str:
        return self.__POST_VT_API_URL_ADD_COMMENT

    @property
    def get_vt_api_url_ret_comment(self) -> str:
        return self.__GET_VT_API_URL_RET_COMMENT

    @property
    def post_vt_api_file_add_comment(self) -> str:
        return self.__POST_VT_API_FILE_ADD_COMMENT

    @property
    def get_vt_api_file_ret_comment(self) -> str:
        return self.__GET_VT_API_FILE_RET_COMMENT

    @property
    def post_vt_url_add_vote(self) -> str:
        return self.__POST_VT_URL_ADD_VOTE

    @property
    def get_vt_url_ret_vote(self) -> str:
        return self.__GET_VT_URL_RET_VOTE

    @property
    def post_vt_file_add_vote(self) -> str:
        return self.__POST_VT_FILE_ADD_VOTE

    @property
    def get_vt_file_ret_vote(self) -> str:
        return self.__GET_VT_FILE_RET_VOTE

    @property
    def get_vt_api_file(self) -> str:
        return self.__GET_VT_API_FILE

    @property
    def post_vt_api_file(self) -> str:
        return self.__POST_VT_API_FILE

    @property
    def post_vt_api_file_rescan(self) -> str:
        return self.__POST_VT_API_FILE_RESCAN

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

    # _____abstractedness_____ #

    @abstractmethod
    def _get_req(self, _url_file):
        raise NotImplementedError()

    @abstractmethod
    def _post_req(self, _url_file):
        raise NotImplementedError()

    # _____setters_____#

    # monthly limit
    def set_requests_monthly_amount_limit(self, limit: int) -> None:
        self.__requests_monthly_amount_limit = limit

    # monthly limit counter
    def set_requests_monthly_amount_limit_counter(self, limit: int) -> None:
        self.__requests_monthly_amount_limit_counter = limit

    # daily limit
    def set_requests_daily_amount_limit(self, limit: int) -> None:
        self.__requests_daily_amount_limit = limit

    # daily limit counter
    def set_requests_daily_amount_limit_counter(self, limit: int) -> None:
        self.__requests_daily_amount_limit_counter = limit

    # hourly limit
    def set_requests_hourly_amount_limit(self, limit: int) -> None:
        self.__requests_hourly_amount_limit = limit

    # hourly limit counter
    def set_requests_hourly_amount_limit_counter(self, limit: int) -> None:
        self.__requests_hourly_amount_limit_counter = limit


    # update counters
    def set_limit_counters(self) -> None:
        with self.lock1:
            self.__requests_monthly_amount_limit_counter += 1
            self.__requests_daily_amount_limit_counter += 1
            self.__requests_hourly_amount_limit_counter += 1

    # ____body____ #

    def _get_user_quora_summary(self) -> dict[str, dict]:

        headers: dict = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        # API request
        req = requests.get(url=self.get_user_quota_summary + self.api_key + '/overall_quotas',
                           headers=headers)
        if req.status_code >= 400:
            raise vt_exceptions.RequestFailed()
        elif req.json():
            # return dict[str, dict]
            return req.json()
        else:
            raise vt_exceptions.EmptyContentError()

    def _get_params(self):
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

    # ______decorators______ #

    @staticmethod
    def get_cache_url(func):
        """
        The decorator checks if the given url is present in the __cache_url_dict,
        if present it fetches the dict path, last analysis date and time, current date and time and expire date.
        If the current date and time is greater than or equal to the expired date, it removes the url from the cache.
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
        If the current date and time is greater than or equal to the expired date, it removes the file from the cache.
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

    @staticmethod
    def save_cache_url(func):
        """
        this decorator uploads the self.cache_url_dict to a json file for every new url
        :param func:
        :return:
        """

        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            finally:
                with open('vt_cache_url.json', 'w') as fh:
                    json.dump(args[0].cache_url_dict, fh)

        return wrapper

    @staticmethod
    def save_cache_file(func):
        """
        this decorator uploads the self.cache_file_dict to a json file for every new file
        :param func:
        :return:
        """

        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            finally:
                with open('vt_cache_file.json', 'w') as fh:
                    json.dump(args[0].cache_file_dict, fh)

        return wrapper

    # update dict from url decorator
    @save_cache_url
    def _update_cache_url_dict(self, url_inx, result) -> None:
        with self.lock2:
            self.__cache_url_dict[url_inx] = result

    # update dict from file decorator
    @save_cache_file
    def _update_cache_file_dict(self, path, result) -> None:
        with self.lock3:
            self.__cache_file_dict[path] = result
