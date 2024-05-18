class datetime:
    def __init__(self, year, month, day, hour, minute, second, microsecond):
        self.year = year
        self.month = month
        self.day = day
        self.hour = hour
        self.minute = minute
        self.second = second
        self.microsecond = microsecond

    @classmethod
    def now(cls):
        return cls(2020, 1, 1, 0, 0, 0, 0)

    def isoformat(self):
        return f"{self.year}-{self.month}-{self.day}T{self.hour}:{self.minute}:{self.second}.{self.microsecond}"

    @classmethod
    def fromtimestamp(cls, timestamp):
        return cls(2020, 1, 1, timestamp // 3600, timestamp // 60, timestamp % 60, timestamp % 1)