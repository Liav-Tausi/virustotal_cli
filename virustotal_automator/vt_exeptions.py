import datetime


class VTAutomatorError(Exception):
    pass


class RequestFailed(VTAutomatorError):
    def __init__(self):
        super().__init__("Unable to fulfill request status over 400.")


class ApiKeyError(VTAutomatorError):
    def __init__(self):
        super().__init__("Invalid api key.")


class FileDescError(VTAutomatorError):
    def __init__(self):
        super().__init__("Invalid File Description.")


class UrlError(VTAutomatorError):
    def __init__(self):
        super().__init__("Invalid url.")


class FileError(VTAutomatorError):
    def __init__(self):
        super().__init__("Invalid path.")


class EmptyContentError(VTAutomatorError):
    def __init__(self):
        super().__init__("Empty return.")


class FilePasswordError(VTAutomatorError):
    def __init__(self):
        super().__init__("Password Error.")


class CacheExpiredError(VTAutomatorError):
    def __init__(self, url: str, last_analysis_utc: 'datetime', expire_date: 'datetime'):
        super().__init__(f"Cache expired. url:{url},"
                         f" last_analysis: {last_analysis_utc},"
                         f" expire_date:{expire_date}")

# raise vt_exeptions.CacheExpiredError(url=self.url,
#                                                      last_analysis_utc=last_analysis_utc,
#                                                         expire_date=expire_date)


