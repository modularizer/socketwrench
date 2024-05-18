import logging


CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0

_levelToName = {
    CRITICAL: 'CRITICAL',
    ERROR: 'ERROR',
    WARNING: 'WARNING',
    INFO: 'INFO',
    DEBUG: 'DEBUG',
    NOTSET: 'NOTSET',
}
_nameToLevel = {
    'CRITICAL': CRITICAL,
    'FATAL': FATAL,
    'ERROR': ERROR,
    'WARN': WARNING,
    'WARNING': WARNING,
    'INFO': INFO,
    'DEBUG': DEBUG,
    'NOTSET': NOTSET,
}

class Logger:
    root_level = NOTSET

    def __init__(self, name, level=DEBUG):
        self.name = name
        self.level = level

    def info(self, msg, *args):
        self.log(INFO, msg, *args)

    def debug(self, msg, *args):
        self.log(DEBUG, msg, *args)
        
    def error(self, msg, *args):
        self.log(ERROR, msg, *args)
        
    def warning(self, msg, *args):
        self.log(WARNING, msg, *args)
        
    def critical(self, msg, *args):
        self.log(CRITICAL, msg, *args)
        
    def exception(self, msg, *args):
        self.log(ERROR, msg,*args)
        
    def log(self, level, msg, *args):
        if level < (self.level or self.root_level):
            print(level, self.level, self.root_level)
            return
        if level in _levelToName:
            name = _levelToName[level]
            closest_name = name
        else:
            closest_level = (10 * (1 + ((level - 5) // 10))) if level < 50 else 50
            closest_name = _levelToName[closest_level]
            diff = level - closest_level
            diff_str = f"+{diff}" if diff > 0 else str(diff) if diff < 0 else ""
            name = closest_name + diff_str
        if args:
            try:
                msg = msg % args
            except TypeError:
                pass
        colors = {
            "CRITICAL": "\033[91m",
            "ERROR": "\033[91m",
            "WARNING": "\033[93m",
            "INFO": "\033[94m",
            "DEBUG": "\033[90m",
            "NOTSET": "\033[90m",
        }
        end = "\033[0m"
        print(f"{colors[closest_name]}{name}: {msg}{end}")
        
    def setLevel(self, level):
        if isinstance(level, str):
            level = _nameToLevel[level]
        self.level = level


class logging:
    DEBUG = DEBUG
    INFO = INFO
    WARNING = WARNING
    ERROR = ERROR
    CRITICAL = CRITICAL
    NOTSET = NOTSET
    Logger = Logger

    _loggers = {}

    @classmethod
    def getLogger(cls, name="", level=NOTSET):
        if name not in cls._loggers:
            cls._loggers[name] = Logger(name, level)
        return cls._loggers[name]

    @classmethod
    def basicConfig(cls, level=INFO):
        Logger.root_level = level
