"""
__author__ = "Alexander Sahm"
__copyright__ = "Copyright 2020, Pomfort GmbH"

__license__ = "MIT"
__maintainer__ = "Patrick Renner, Alexander Sahm"
__email__ = "opensource@pomfort.com"
"""

import datetime
import time
import os
from pathlib import Path, PurePosixPath, PureWindowsPath


def matches_prefixes(text: str, prefixes: list):
    for prefix in prefixes:
        if text.startswith(prefix):
            return True
    return False


def datetime_isostring(date, keep_microseconds=False):
    """create an iso string representation for a date object
    e.g. for use in XML tags and attributes

    arguments:
    date -- date object
    keep_microseconds -- include microseconds in iso
    """
    utc_offset_sec = time.altzone if time.localtime().tm_isdst == 1 else time.timezone
    utc_offset = datetime.timedelta(seconds=-utc_offset_sec)

    if keep_microseconds:
        date_to_format = date
    else:
        date_to_format = date.replace(microsecond=0)

    return date_to_format.replace(tzinfo=datetime.timezone(offset=utc_offset)).isoformat()


def datetime_now_isostring():
    return datetime_isostring(datetime.datetime.now())


def datetime_now_filename_string():
    """create a string representation for now() for use as part of the MHL filename"""
    return datetime.datetime.strftime(datetime.datetime.now(datetime.timezone.utc), "%Y-%m-%d_%H%M%SZ")


def datetime_now_isostring_with_microseconds():
    return datetime_isostring(datetime.datetime.now(), keep_microseconds=True)


def convert_local_path_to_posix(path: str) -> str:
    return str(Path(path).as_posix())


def convert_posix_to_local_path(path: str) -> str:
    if os.name == "nt":
        return str(PureWindowsPath(PurePosixPath(path)))
    return path
