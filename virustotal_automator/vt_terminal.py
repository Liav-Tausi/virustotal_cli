"""
vt_automator.
created by: liav tausi
date: 1/12/2023
"""



import argparse

import vt_exceptions
from vt_file import VTFile
from vt_url import VTUrl


class Scan:
    """
    orders the terminal command line.
    """
    def __init__(self, type_of, vt_key, workers):
        self.__type_of = type_of
        self.__vt_key = vt_key
        self.__workers = workers

    @property
    def workers(self):
        return self.__workers

    @property
    def vt_key(self):
        return self.__vt_key

    @property
    def type_of(self):
        return self.__type_of

    def scan(self, file_paths=None, urls=None, method=None, password=None, comment = None, comments = None):
        """
        Scans files or urls using the VirusTotal API
        :param comments: optional comments for File/url
        :param comment: optional comment for File/url
        :param password: optional file password
        :param file_paths: list of file paths to scan
        :param urls: list of urls to scan
        :param method: method to run (get, post, post_get)
        """
        if self.type_of == 'file':
            return self._scan_files(file_paths, method, password, comment, comments)
        elif self.type_of == 'url':
            return self._scan_urls(urls, method, comment, comments)
        else:
            raise ValueError(f"Invalid scan type: {self.type_of}")


    def _scan_files(self, file_paths: tuple[str, ...], method: str, password: str, comment: str, comments: tuple[str, ...]):
        """
        Scans files using the VirusTotal API
        :param file_paths: list of file paths to scan
        :param method: method to run (get, post, post_get)
        """
        vt_file: VTFile = VTFile(file=file_paths, vt_key=self.vt_key, workers=self.workers, password=password)
        if method == 'get_file':
            return vt_file.get_file()
        elif method == 'get_files':
            return vt_file.get_files()
        elif method == 'post_file':
            return vt_file.post_file()
        elif method == 'post_files':
            return vt_file.get_files()
        elif method == 'post_rescan':
            return vt_file.post_rescan()
        elif method == 'post_rescans':
            return vt_file.post_rescans()
        elif method == 'post_comment':
            return vt_file.post_comment(comment=comment)
        elif method == 'post_comments':
            return vt_file.post_comments(comments=comments)
        elif method == 'post_get_file':
            return vt_file.post_get_file()
        elif method == 'post_get_files':
            return vt_file.post_get_files()
        else:
            raise ValueError()

    def _scan_urls(self, urls: tuple[str, ...], method: str, comment: str, comments: tuple[str, ...]):
        """
        Scans urls using the VirusTotal API
        :param urls: list of urls to scan
        :param method: method to run (get, post, post_get)
        """
        vt_url: VTUrl = VTUrl(url=urls, vt_key=self.vt_key, workers=self.workers)
        if method == 'get_url':
            return vt_url.get_url()
        elif method == 'get_urls':
            return vt_url.get_urls()
        elif method == 'post_url':
            return vt_url.post_url()
        elif method == 'post_urls':
            return vt_url.post_urls()
        elif method == 'post_rescan':
            return vt_url.post_rescan()
        elif method == 'post_rescans':
            return vt_url.post_rescans()
        elif method == 'post_comment':
            return vt_url.post_comment(comment=comment)
        elif method == 'post_comments':
            return vt_url.post_comments(comments=comments)
        elif method == 'post_get_url':
            return vt_url.post_get_url()
        elif method == 'post_get_urls':
            return vt_url.post_get_urls()
        else:
            raise vt_exceptions.MethodError()



def main() -> tuple[str, int] | str | list[tuple]:
    """
    entry point of the program.
    A new ArgumentParser object is created, which is used to parse command-line
    :return: tuple[str, int] | str | list[tuple]
    """
    parser = argparse.ArgumentParser(description="""The program will take in url/s or file/s as input 
                                                 and return the scan results from the VirusTotal database
                                                 created by: liav tausi""")
    parser.add_argument('type', help='type of scan (file or url)')
    parser.add_argument('--workers', type=int, default=7, help='number of workers')
    parser.add_argument('method', help='method to run')
    parser.add_argument('vt_key', help='VirusTotal API key')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', nargs='+', help='a list of files')
    group.add_argument('--url', nargs='+', help='a list of URLs')
    parser.add_argument('--password', help='optional file password', nargs='?', required=False)
    parser.add_argument('--comment', help='a comment for URL/file', nargs='?', required=False)
    parser.add_argument('--comments', help='a comment for URL/file', nargs='+', required=False)


    args = parser.parse_args()
    scanning: Scan = Scan(args.type, args.vt_key, args.workers)
    return scanning.scan(file_paths=args.file, urls=args.url, method=args.method,
                         password=args.password, comment=args.comment, comments=args.comments)
