"""Imports all standard library dependencies to document what is used and allow for an easy spot to patch."""
from socketwrench.settings import raise_import_error_if_testing, config

sm = config.get("socket_module", None)
if sm:
    socket = sm
else:
    import socket

try:
    raise_import_error_if_testing('any')
    import builtins
    import inspect
    from sys import argv
    from argparse import ArgumentParser
    from tempfile import TemporaryFile
    from zipfile import ZipFile
    from functools import wraps, partial
    import dataclasses
    from datetime import datetime
    from pathlib import Path
    from json import dumps, loads
    import logging
    from time import sleep
    from threading import Event, Thread
    from concurrent.futures import ThreadPoolExecutor
    threading_available = True
    from traceback import format_exception
    import importlib
    from sys import modules
except ImportError:
    from socketwrench.fake_imports import (
        builtins,
        inspect,
        argv,
        ArgumentParser,
        TemporaryFile,
        ZipFile,
        wraps,
        partial,
        dataclasses,
        datetime,
        Path,
        dumps,
        loads,
        logging,
        sleep,
        Event,
        Thread,
        ThreadPoolExecutor,
        threading_available,
        format_exception,
        importlib,
        modules
    )